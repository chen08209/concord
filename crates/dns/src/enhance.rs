use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Mutex;

use concord_common::scripts::DnsScriptAnswer;
use concord_common::sync::lock;
use concord_common::{DnsMode, Host, Initiator};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::RecordType;

use crate::engine::Resolver;
use crate::fakeip::FakeIpPool;
use crate::lru::LruCache;
use crate::matchers::Skipper;
use crate::msg;
use crate::resolver::Group;
use std::sync::Arc;

const MAPPING_SIZE: usize = 4096;
const FAKE_RECORD_TTL: u32 = 600;
const HOSTS_TTL: u32 = 10;

/// What fake-ip and redir-host add on top of the plain resolver: the pools, the
/// address-to-name memory the tunnel reads, and the filter.
pub(crate) struct Enhancer {
    pub mode: DnsMode,
    pub pool4: Option<FakeIpPool>,
    pub pool6: Option<FakeIpPool>,
    pub skipper: Option<Skipper>,
    pub fake_ttl: u32,
    pub mapping: Option<Mutex<LruCache<IpAddr, String>>>,
    pub use_hosts: bool,
    pub ipv6: bool,
}

impl Enhancer {
    pub(crate) fn plain(use_hosts: bool, ipv6: bool) -> Self {
        Enhancer {
            mode: DnsMode::Normal,
            pool4: None,
            pool6: None,
            skipper: None,
            fake_ttl: 1,
            mapping: None,
            use_hosts,
            ipv6,
        }
    }

    pub(crate) fn with_mapping(mut self) -> Self {
        self.mapping = Some(Mutex::new(LruCache::new(MAPPING_SIZE)));
        self
    }

    pub(crate) fn insert_mapping(&self, ip: IpAddr, host: &str) {
        if let Some(mapping) = &self.mapping {
            lock(mapping).insert(ip, host.to_string());
        }
    }

    pub(crate) fn fake_ip_enabled(&self) -> bool {
        self.mode == DnsMode::FakeIp
    }

    pub(crate) fn pools(&self) -> impl Iterator<Item = &FakeIpPool> {
        self.pool4.iter().chain(self.pool6.iter())
    }

    pub(crate) fn patch_from(&self, old: &Enhancer) {
        if let (Some(mine), Some(theirs)) = (&self.mapping, &old.mapping)
            && !std::ptr::eq(mine, theirs)
        {
            let mut mine = lock(mine);
            let theirs = lock(theirs);
            for (ip, host) in theirs.entries_oldest_first() {
                mine.insert(ip, host.clone());
            }
        }
        if let (Some(mine), Some(theirs)) = (&self.pool4, &old.pool4) {
            mine.adopt(theirs);
        }
        if let (Some(mine), Some(theirs)) = (&self.pool6, &old.pool6) {
            mine.adopt(theirs);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Hosts,
    FakeIp,
    Mapping,
    Resolver,
}

type Served<'a> = Pin<Box<dyn Future<Output = io::Result<Message>> + Send + 'a>>;

fn query_host(req: &Message) -> String {
    msg::msg_domain(req)
}

impl Resolver {
    fn stage_after(&self, from: Option<Stage>) -> Stage {
        let en = &self.enhancer;
        let order = [
            (Stage::Hosts, en.use_hosts),
            (Stage::FakeIp, en.mode == DnsMode::FakeIp),
            (Stage::Mapping, en.mode != DnsMode::Normal),
        ];
        let mut passed = from.is_none();
        for (stage, enabled) in order {
            if !passed {
                passed = Some(stage) == from;
                continue;
            }
            if enabled {
                return stage;
            }
        }
        Stage::Resolver
    }

    /// The server-side handler chain of mihomo: hosts, fake-ip, mapping, then
    /// the resolver.
    pub(crate) async fn serve(&self, req: &Message, initiator: Initiator) -> io::Result<Message> {
        if req.queries.is_empty() {
            return Err(io::Error::other("at least one question is required"));
        }
        self.serve_stage(self.stage_after(None), req.clone(), initiator)
            .await
    }

    fn next_stage<'a>(&'a self, from: Stage, req: Message, initiator: Initiator) -> Served<'a> {
        self.serve_stage(self.stage_after(Some(from)), req, initiator)
    }

    fn serve_stage<'a>(&'a self, stage: Stage, req: Message, initiator: Initiator) -> Served<'a> {
        Box::pin(async move {
            match stage {
                Stage::Hosts => self.hosts_stage(req, initiator).await,
                Stage::FakeIp => self.fake_ip_stage(req, initiator).await,
                Stage::Mapping => self.mapping_stage(req, initiator).await,
                Stage::Resolver => self.resolver_stage(req, initiator).await,
            }
        })
    }

    async fn hosts_stage(&self, req: Message, initiator: Initiator) -> io::Result<Message> {
        let Some(query) = msg::first_query(&req).cloned() else {
            return self.next_stage(Stage::Hosts, req, initiator).await;
        };
        if !msg::is_ip_request(&query) {
            return self.next_stage(Stage::Hosts, req, initiator).await;
        }
        let host = query_host(&req);
        let qtype = query.query_type;
        if let Some(script) = self.hosts.script_for(&host) {
            let mut resp = msg::empty_answer(&req);
            match self.scripts.answer(&script, &host).await {
                DnsScriptAnswer::Addresses { ips, ttl } => {
                    let ttl = ttl.map_or(HOSTS_TTL, |ttl| {
                        u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX)
                    });
                    self.push_ips(&mut resp, &query, &host, &ips, ttl);
                }
                DnsScriptAnswer::Servers(servers) => {
                    resp = self.ask_servers(&servers, &req, initiator).await?;
                }
                DnsScriptAnswer::Resolve => {
                    return self.next_stage(Stage::Hosts, req, initiator).await;
                }
            }
            return Ok(resp);
        }
        let want_domain = !matches!(qtype, RecordType::A | RecordType::AAAA);
        let (record, matched) = self.hosts.search(&host, want_domain);
        if !matched {
            if let Some(record) = record.filter(|record| record.is_domain) {
                let mut rewritten = req.clone();
                if let (Some(q), Some(name)) = (
                    rewritten.queries.first_mut(),
                    msg::fqdn_name(&record.domain),
                ) {
                    q.name = name;
                }
                let mut resp = self.next_stage(Stage::Hosts, rewritten, initiator).await?;
                resp.metadata.id = req.metadata.id;
                resp.queries = req.queries.clone();
                if let Some(cname) = msg::cname_record(&query.name, HOSTS_TTL, &record.domain) {
                    resp.answers.insert(0, cname);
                }
                return Ok(resp);
            }
            return self.next_stage(Stage::Hosts, req, initiator).await;
        }
        let Some(record) = record else {
            return self.next_stage(Stage::Hosts, req, initiator).await;
        };
        let mut resp = msg::empty_answer(&req);
        match qtype {
            RecordType::A | RecordType::AAAA => {
                self.push_ips(&mut resp, &query, &host, &record.ips, HOSTS_TTL);
            }
            RecordType::CNAME => {
                if let Some(cname) = msg::cname_record(&query.name, HOSTS_TTL, &record.domain) {
                    resp.answers.insert(0, cname);
                }
            }
            _ => return self.next_stage(Stage::Hosts, req, initiator).await,
        }
        Ok(resp)
    }

    fn push_ips(&self, resp: &mut Message, query: &Query, host: &str, ips: &[IpAddr], ttl: u32) {
        for ip in ips {
            match (ip, query.query_type) {
                (IpAddr::V4(v4), RecordType::A) => {
                    resp.answers.push(msg::a_record(&query.name, ttl, *v4));
                }
                (IpAddr::V6(v6), RecordType::AAAA) => {
                    resp.answers.push(msg::aaaa_record(&query.name, ttl, *v6));
                }
                _ => continue,
            }
            self.enhancer.insert_mapping(*ip, host);
        }
    }

    async fn fake_ip_stage(&self, req: Message, initiator: Initiator) -> io::Result<Message> {
        let en = &self.enhancer;
        let Some(query) = msg::first_query(&req).cloned() else {
            return self.next_stage(Stage::FakeIp, req, initiator).await;
        };
        let host = query_host(&req);
        let qtype = query.query_type;
        if en
            .skipper
            .as_ref()
            .is_some_and(|skipper| skipper.should_skip(&host))
        {
            let resp = self.next_stage(Stage::FakeIp, req, initiator).await;
            return resp.map(|mut resp| {
                if matches!(qtype, RecordType::HTTPS | RecordType::SVCB) {
                    msg::strip_ip_hints(&mut resp);
                }
                resp
            });
        }
        let record = match qtype {
            RecordType::A => {
                let Some(IpAddr::V4(ip)) = en.pool4.as_ref().and_then(|pool| pool.lookup(&host))
                else {
                    return Ok(msg::empty_answer(&req));
                };
                msg::a_record(&query.name, FAKE_RECORD_TTL, ip)
            }
            RecordType::AAAA => {
                let Some(IpAddr::V6(ip)) = en.pool6.as_ref().and_then(|pool| pool.lookup(&host))
                else {
                    return Ok(msg::empty_answer(&req));
                };
                msg::aaaa_record(&query.name, FAKE_RECORD_TTL, ip)
            }
            RecordType::SVCB | RecordType::HTTPS => return Ok(msg::empty_answer(&req)),
            _ => return self.next_stage(Stage::FakeIp, req, initiator).await,
        };
        let mut resp = msg::empty_answer(&req);
        resp.answers.push(record);
        msg::set_msg_ttl(&mut resp, en.fake_ttl);
        Ok(resp)
    }

    async fn mapping_stage(&self, req: Message, initiator: Initiator) -> io::Result<Message> {
        let is_ip = msg::first_query(&req).is_some_and(msg::is_ip_request);
        let host = query_host(&req);
        let resp = self.next_stage(Stage::Mapping, req, initiator).await?;
        if is_ip {
            for ip in msg::answer_ips(&resp) {
                if concord_platform::is_global_unicast(ip) {
                    self.enhancer.insert_mapping(ip, &host);
                }
            }
        }
        Ok(resp)
    }

    async fn resolver_stage(&self, req: Message, initiator: Initiator) -> io::Result<Message> {
        let qtype = msg::first_query(&req).map(|q| q.query_type);
        if !self.enhancer.ipv6 && qtype == Some(RecordType::AAAA) {
            return Ok(msg::empty_answer(&req));
        }
        let group: &Arc<Group> = &self.main;
        let mut resp = group.exchange(&req, initiator).await?;
        let rcode = resp.metadata.response_code;
        msg::set_reply(&mut resp, &req, rcode);
        resp.metadata.authoritative = true;
        if !self.enhancer.ipv6 && matches!(qtype, Some(RecordType::HTTPS | RecordType::SVCB)) {
            msg::strip_ipv6_hints(&mut resp);
        }
        Ok(resp)
    }

    pub(crate) async fn answer(&self, req: &Message, initiator: Initiator) -> Message {
        match self.serve(req, initiator).await {
            Ok(mut resp) => {
                msg::echo_edns(req, &mut resp);
                resp
            }
            Err(err) => {
                tracing::debug!("[DNS Server] exchange failed: {err}");
                let mut resp = msg::error_reply(req, ResponseCode::ServFail);
                msg::echo_edns(req, &mut resp);
                resp
            }
        }
    }

    pub(crate) fn host_for(&self, ip: IpAddr) -> Option<Host> {
        if let Some(host) = self.fake_ip_host(ip) {
            return Some(host);
        }
        let mapping = self.enhancer.mapping.as_ref()?;
        let mut mapping = lock(mapping);
        mapping.get(&ip).map(|host| Host::from(host.as_str()))
    }

    pub(crate) fn fake_ip_host(&self, ip: IpAddr) -> Option<Host> {
        self.enhancer
            .pools()
            .find_map(|pool| pool.look_back(ip))
            .map(|host| Host::from(host.as_str()))
    }
}
