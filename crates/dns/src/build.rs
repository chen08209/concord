use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use concord_common::DnsMode;
use concord_config::dns::{
    DnsConfig, EnhancedMode, FakeIpFilterMode, PolicyEntry, PolicyKey, Upstream, UpstreamScheme,
};
use concord_config::hosts::HostsConfig;

use crate::client::{ClientRef, DisableTypes, EcsClient, Params, RcodeClient};
use crate::dialer::{Connector, Shared, Via};
use crate::doh::{DohClient, DohTarget};
use crate::doh3::{Doh3Client, PreferH3Client};
use crate::doq::DoqClient;
use crate::dot::DotClient;
use crate::engine::{Resolver, ResolverDeps, rcode_of};
use crate::enhance::Enhancer;
use crate::fakeip::{FakeIpPool, STORE_SIZE, STORED_SIZE};
use crate::hosts::Hosts;
use crate::matchers::{CidrSet, FilterRule, GeoFallback, Skipper, domain_matchers};
use crate::plain::{PlainClient, Transport};
use crate::resolver::{Group, GroupParts, PolicyItem};
use crate::system::{SystemClient, SystemServers};
use crate::trie::{DomainSet, DomainTrie};
use crate::{DnsError, DomainMatch, IpMatch, RuleEnv};

const FALLBACK_SYSTEM_SERVERS: [&str; 2] = ["114.114.114.114:53", "8.8.8.8:53"];

fn wrapper_only(key: &str) -> bool {
    matches!(
        key,
        "ecs" | "ecs-override" | "disable-ipv4" | "disable-ipv6"
    ) || key.starts_with("disable-qtype-")
}

struct Builder<'a> {
    shared: Arc<Shared>,
    system_client: ClientRef,
    rules: &'a dyn RuleEnv,
    raw: HashMap<String, ClientRef>,
    all: Vec<ClientRef>,
    bootstrap: Option<Arc<Group>>,
    prefer_h3: bool,
}

impl Builder<'_> {
    fn transport_key(up: &Upstream, via: &Via, bootstrap: bool) -> String {
        let mut params: Vec<(&String, &String)> = up
            .params
            .iter()
            .filter(|(key, _)| !wrapper_only(key))
            .collect();
        params.sort();
        format!(
            "{bootstrap}|{:?}|{}|{}|{}|{via:?}|{params:?}",
            up.scheme, up.host, up.port, up.path
        )
    }

    fn raw_client(&mut self, up: &Upstream, via: Via) -> Result<ClientRef, DnsError> {
        let key = Self::transport_key(up, &via, self.bootstrap.is_some());
        if let Some(client) = self.raw.get(&key) {
            return Ok(Arc::clone(client));
        }
        let connector = Arc::new(Connector::new(
            Arc::clone(&self.shared),
            via,
            self.bootstrap.clone(),
        ));
        let params = Params(up);
        let io = |err: std::io::Error| DnsError::config(format!("{}: {err}", up.text));
        let client: ClientRef = match &up.scheme {
            UpstreamScheme::Udp => Arc::new(PlainClient::new(
                Transport::Udp,
                up.host.clone(),
                up.port,
                connector,
            )),
            UpstreamScheme::Tcp => Arc::new(PlainClient::new(
                Transport::Tcp,
                up.host.clone(),
                up.port,
                connector,
            )),
            UpstreamScheme::Tls => {
                Arc::new(DotClient::new(up.host.clone(), up.port, connector, &params).map_err(io)?)
            }
            UpstreamScheme::Https | UpstreamScheme::Http => {
                let secure = up.scheme == UpstreamScheme::Https;
                let target = DohTarget {
                    secure,
                    host: up.host.clone(),
                    port: up.port,
                    path: up.path.clone(),
                };
                let h3_only = secure && params.is_true("h3");
                let h3_target = || DohTarget {
                    secure,
                    host: target.host.clone(),
                    port: target.port,
                    path: target.path.clone(),
                };
                if h3_only {
                    Arc::new(Doh3Client::new(target, connector, &params).map_err(io)?)
                } else if secure && self.prefer_h3 {
                    let h3 = Arc::new(
                        Doh3Client::new(h3_target(), Arc::clone(&connector), &params)
                            .map_err(io)?,
                    );
                    let h2 = Arc::new(DohClient::new(target, connector, &params).map_err(io)?);
                    Arc::new(PreferH3Client::new(h3, h2))
                } else {
                    Arc::new(DohClient::new(target, connector, &params).map_err(io)?)
                }
            }
            UpstreamScheme::System | UpstreamScheme::Dhcp(_) => Arc::clone(&self.system_client),
            UpstreamScheme::Rcode(code) => Arc::new(RcodeClient::new(rcode_of(*code), &up.host)),
            UpstreamScheme::Quic => {
                Arc::new(DoqClient::new(up.host.clone(), up.port, connector, &params).map_err(io)?)
            }
        };
        self.raw.insert(key, Arc::clone(&client));
        self.all.push(Arc::clone(&client));
        Ok(client)
    }

    fn client(&mut self, up: &Upstream, respect_rules: bool) -> Result<ClientRef, DnsError> {
        let via = Via::from_fragment(up.proxy.as_deref(), respect_rules);
        let raw = self.raw_client(up, via)?;
        let params = Params(up);
        Ok(EcsClient::wrap(DisableTypes::wrap(raw, &params), &params))
    }

    fn clients(
        &mut self,
        list: &[Upstream],
        respect_rules: bool,
    ) -> Result<Vec<ClientRef>, DnsError> {
        list.iter()
            .map(|up| self.client(up, respect_rules))
            .collect()
    }

    fn policy(
        &mut self,
        entries: &[PolicyEntry],
        respect_rules: bool,
        what: &str,
    ) -> Result<Vec<PolicyItem>, DnsError> {
        let mut items = Vec::new();
        let mut trie: Option<DomainTrie<Vec<ClientRef>>> = None;
        for (index, entry) in entries.iter().enumerate() {
            let clients = self.clients(&entry.servers, respect_rules)?;
            let matcher = match &entry.key {
                PolicyKey::Domain(pattern) => {
                    trie.get_or_insert_with(DomainTrie::new)
                        .insert(pattern, clients)
                        .map_err(|err| DnsError::config(format!("{what}[{index}]: {err}")))?;
                    continue;
                }
                PolicyKey::GeoSite(name) => self.rules.geosite(name),
                PolicyKey::RuleSet(name) => self.rules.domain_rule_set(name),
            }
            .map_err(|err| DnsError::rule(format!("{what}[{index}]: {err}"), err))?;
            items.extend(trie.take().map(PolicyItem::Trie));
            items.push(PolicyItem::Matcher(matcher, clients));
        }
        items.extend(trie.take().map(PolicyItem::Trie));
        Ok(items)
    }
}

struct Filters {
    domain: Vec<Arc<dyn DomainMatch>>,
    ip: Vec<Arc<dyn IpMatch>>,
}

fn fallback_filters(config: &DnsConfig, rules: &dyn RuleEnv) -> Result<Filters, DnsError> {
    let mut filters = Filters {
        domain: Vec::new(),
        ip: Vec::new(),
    };
    if config.fallback.is_empty() {
        return Ok(filters);
    }
    let source = &config.fallback_filter;
    if source.geoip && source.geoip_code.is_empty() {
        tracing::warn!(
            "DNS fallback-filter.geoip is on without a geoip-code; the GeoIP filter is skipped"
        );
    } else if source.geoip {
        let lookup = rules.geoip().map_err(|err| {
            DnsError::rule(format!("load GeoIP dns fallback filter error, {err}"), err)
        })?;
        filters
            .ip
            .push(Arc::new(GeoFallback::new(lookup, &source.geoip_code)));
    }
    if !source.ipcidr.is_empty() {
        filters
            .ip
            .push(Arc::new(CidrSet::new(source.ipcidr.clone())));
    }
    if !source.domain.is_empty() {
        let mut set = DomainSet::new();
        for (index, pattern) in source.domain.iter().enumerate() {
            set.insert(pattern).map_err(|err| {
                DnsError::config(format!("DNS FallbackDomain[{index}] format error: {err}"))
            })?;
        }
        filters.domain.push(Arc::new(set));
    }
    for (index, name) in source.geosite.iter().enumerate() {
        filters.domain.push(rules.geosite(name).map_err(|err| {
            DnsError::rule(
                format!("DNS FallbackGeosite[{index}] format error: {err}"),
                err,
            )
        })?);
    }
    Ok(filters)
}

fn skipper(config: &DnsConfig, rules: &dyn RuleEnv) -> Result<Skipper, DnsError> {
    if config.fake_ip_filter_mode == FakeIpFilterMode::Rule {
        let compiled = config
            .fake_ip_filter_rules
            .iter()
            .map(|def| FilterRule::compile(def, rules))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Skipper::Rules(compiled));
    }
    Ok(Skipper::Hosts {
        matchers: domain_matchers(&config.fake_ip_filter, "dns.fake-ip-filter", rules)?,
        whitelist: config.fake_ip_filter_mode == FakeIpFilterMode::Whitelist,
    })
}

fn enhancer(
    config: &DnsConfig,
    ipv6: bool,
    stored: bool,
    rules: &dyn RuleEnv,
) -> Result<Enhancer, DnsError> {
    let pool = |range| FakeIpPool::with_size(range, if stored { STORED_SIZE } else { STORE_SIZE });
    let mut enhancer = Enhancer::plain(config.use_hosts, ipv6);
    match config.enhanced_mode {
        EnhancedMode::Normal => return Ok(enhancer),
        EnhancedMode::RedirHost => enhancer.mode = DnsMode::RedirHost,
        EnhancedMode::FakeIp => {
            enhancer.mode = DnsMode::FakeIp;
            enhancer.skipper = Some(skipper(config, rules)?);
            enhancer.fake_ttl = config.fake_ip_ttl.max(1);
            enhancer.pool4 = config.fake_ip_range.map(pool).transpose()?;
            if ipv6 {
                enhancer.pool6 = config.fake_ip_range6.map(pool).transpose()?;
            }
            if enhancer.pool4.is_none() && enhancer.pool6.is_none() {
                return Err(DnsError::config(
                    "disallow `fake-ip-range` and `fake-ip-range6` both empty with fake-ip mode",
                ));
            }
        }
    }
    Ok(enhancer.with_mapping())
}

impl Resolver {
    /// Builds everything from the configuration; nothing is dialed until the
    /// first question.
    pub fn new(
        config: &DnsConfig,
        hosts: &HostsConfig,
        deps: ResolverDeps,
    ) -> Result<Arc<Self>, DnsError> {
        let shared = Arc::new(Shared {
            sockets: deps.sockets,
            dialer: deps.dialer,
            sock_opts: deps.sock_opts,
            trust: deps.trust,
            ipv6: deps.ipv6,
            tasks: deps.tasks,
        });
        let tasks = shared.tasks.clone();
        let system = Arc::new(SystemServers::new(deps.platform));
        let default_ns = if config.enable {
            Vec::new()
        } else {
            FALLBACK_SYSTEM_SERVERS
                .iter()
                .filter_map(|text| text.parse::<SocketAddr>().ok())
                .collect()
        };
        let system_client: ClientRef = Arc::new(SystemClient::new(
            Arc::clone(&system),
            Arc::clone(&shared),
            default_ns,
        ));
        let mut builder = Builder {
            shared: Arc::clone(&shared),
            system_client: Arc::clone(&system_client),
            rules: deps.rules.as_ref(),
            raw: HashMap::new(),
            all: vec![system_client],
            bootstrap: None,
            prefer_h3: config.prefer_h3,
        };
        let timeout = Duration::from_millis(u64::from(config.ipv6_timeout));
        let parts =
            |main, fallback, filters: Filters, lazy, policy, config: &DnsConfig| GroupParts {
                main,
                fallback,
                fallback_domain: filters.domain,
                fallback_ip: filters.ip,
                fallback_lazy: lazy,
                policy: Arc::new(policy),
                cache_algorithm: config.cache_algorithm.clone(),
                cache_size: config.cache_max_size,
                ipv6_timeout: timeout,
                tasks: tasks.clone(),
            };
        let no_filters = || Filters {
            domain: Vec::new(),
            ip: Vec::new(),
        };
        let events = &deps.events;
        let plain = |clients| {
            let parts = parts(clients, Vec::new(), no_filters(), false, Vec::new(), config);
            Group::new(parts, Arc::clone(events))
        };

        let ipv6 = config.ipv6 && deps.ipv6;
        let enhancer = if config.enable {
            enhancer(config, ipv6, deps.store_fake_ip, deps.rules.as_ref())?
        } else {
            Enhancer::plain(config.use_hosts, ipv6)
        };
        let hosts = Hosts::from_config(hosts, config.enable && config.use_system_hosts)?;

        if !config.enable {
            let main = plain(vec![Arc::clone(&builder.system_client)]);
            return Ok(Arc::new(Resolver {
                default: Arc::clone(&main),
                main,
                proxy: None,
                direct: None,
                hosts,
                enhancer,
                ipv6: AtomicBool::new(deps.ipv6),
                clients: builder.all,
                system,
                scripts: crate::scripted::ScriptAnswers::new(deps.scripts),
                dial: Arc::clone(&shared),
            }));
        }

        let default_clients = builder.clients(&config.default_nameserver, false)?;
        let default = plain(default_clients);
        builder.bootstrap = Some(Arc::clone(&default));

        let respect = config.respect_rules;
        let main_clients = builder.clients(&config.nameserver, respect)?;
        let main_policy =
            builder.policy(&config.nameserver_policy, respect, "dns.nameserver-policy")?;
        let fallback = builder.clients(&config.fallback, respect)?;
        let filters = fallback_filters(config, deps.rules.as_ref())?;
        let main = Group::new(
            parts(
                main_clients,
                fallback,
                filters,
                config.fallback_lazy_query,
                main_policy,
                config,
            ),
            Arc::clone(&deps.events),
        );

        let proxy = if config.proxy_server_nameserver.is_empty() {
            None
        } else {
            let clients = builder.clients(&config.proxy_server_nameserver, false)?;
            let policy = builder.policy(
                &config.proxy_server_nameserver_policy,
                false,
                "dns.proxy-server-nameserver-policy",
            )?;
            Some(Group::new(
                parts(clients, Vec::new(), no_filters(), false, policy, config),
                Arc::clone(&deps.events),
            ))
        };

        let direct = if config.direct_nameserver.is_empty() {
            None
        } else {
            let clients = builder.clients(&config.direct_nameserver, false)?;
            let mut direct_parts =
                parts(clients, Vec::new(), no_filters(), false, Vec::new(), config);
            if config.direct_nameserver_follow_policy {
                direct_parts.policy = main.policy();
            }
            Some(Group::new(direct_parts, Arc::clone(&deps.events)))
        };

        Ok(Arc::new(Resolver {
            main,
            proxy,
            direct,
            default,
            hosts,
            enhancer,
            ipv6: AtomicBool::new(deps.ipv6),
            clients: builder.all,
            system,
            scripts: crate::scripted::ScriptAnswers::new(deps.scripts),
            dial: Arc::clone(&shared),
        }))
    }
}
