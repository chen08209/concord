//! The DNS, hosts, TUN routes and proxy bypass a module asks for, from Surge's and Loon's
//! `[General]` and `[Host]`, in the profile's own syntax.

use std::net::IpAddr;

use ipnetwork::IpNetwork;
use serde::Serialize;

use super::source::{ListMark, list_mark};

/// How a module changes one of the profile's lists: `before` goes ahead of it, `after` behind
/// it, and with `replace` the profile's own entries are dropped.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ListEdit {
    pub replace: bool,
    pub before: Vec<String>,
    pub after: Vec<String>,
}

impl ListEdit {
    fn of(mark: ListMark, loon: bool, values: Vec<String>) -> ListEdit {
        match mark {
            ListMark::Insert => ListEdit {
                before: values,
                ..ListEdit::default()
            },
            ListMark::Append => ListEdit {
                after: values,
                ..ListEdit::default()
            },
            ListMark::Plain if loon => ListEdit {
                after: values,
                ..ListEdit::default()
            },
            ListMark::Plain => ListEdit {
                replace: true,
                before: values,
                after: Vec::new(),
            },
        }
    }

    /// This edit, then `next` over its result.
    pub fn then(self, next: ListEdit) -> ListEdit {
        if next.replace {
            return next;
        }
        let mut before = next.before;
        before.extend(self.before);
        let mut after = self.after;
        after.extend(next.after);
        ListEdit {
            replace: self.replace,
            before,
            after,
        }
    }
}

/// In mihomo's keys: `dns.nameserver`, `dns.default-nameserver`, `dns.fake-ip-filter`,
/// `dns.nameserver-policy`, `hosts`, `tun.route-address`, `tun.route-exclude-address` and
/// the host's proxy bypass list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDef {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nameserver: Option<ListEdit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_nameserver: Option<ListEdit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fake_ip_filter: Option<ListEdit>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nameserver_policy: Vec<DomainEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<DomainEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub route_address: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_exclude_address: Option<ListEdit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bypass_domain: Option<ListEdit>,
    /// The lines that ask for any of it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<u32>,
}

/// A domain and what it maps to: DNS servers, or addresses and aliases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DomainEntry {
    pub domain: String,
    pub values: Vec<String>,
}

impl NetworkDef {
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    PlainDns,
    EncryptedDns,
    FakeIpFilter,
    RouteExclude,
    Bypass,
}

/// What a module's lines ask for, before Loon's and Surge's readings of an unmarked list are
/// told apart.
#[derive(Debug, Default)]
pub(super) struct NetworkEdits {
    edits: Vec<(Key, ListMark, Vec<String>)>,
    def: NetworkDef,
    /// A key only Loon writes.
    pub(super) loon: bool,
}

/// Why a `[General]` or `[Host]` line was not taken.
pub(super) enum Refused {
    Setting,
    Unreadable(String),
}

impl NetworkEdits {
    /// A `[General]` line other than `force-http-engine-hosts`.
    pub(super) fn read_general(
        &mut self,
        key: &str,
        value: &str,
        line: u32,
    ) -> Result<(), Refused> {
        let (mark, value) = list_mark(value);
        let items: Vec<&str> = value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .collect();
        let read = |parse: fn(&str) -> Option<String>| -> Result<Vec<String>, Refused> {
            items
                .iter()
                .map(|item| parse(item).ok_or_else(|| Refused::Unreadable(format!("{item:?}"))))
                .collect()
        };
        let plain = |items: &[&str]| items.iter().map(|item| item.to_string()).collect();
        if matches!(
            key,
            "doh-server" | "doh3-server" | "doq-server" | "bypass-tun" | "include-tun" | "real-ip"
        ) {
            self.loon = true;
        }
        match key {
            "dns-server" => self.edit(Key::PlainDns, mark, read(dns_server)?),
            "encrypted-dns-server" | "doh-server" | "doh3-server" | "doq-server" => {
                self.edit(Key::EncryptedDns, mark, read(dns_server)?)
            }
            "skip-proxy" => self.edit(Key::Bypass, mark, plain(&items)),
            "tun-excluded-routes" | "bypass-tun" => {
                self.edit(Key::RouteExclude, mark, read(route)?)
            }
            "tun-included-routes" | "include-tun" => {
                let routes = read(route)?;
                self.def.route_address.extend(routes);
            }
            "always-real-ip" | "real-ip" => self.edit(Key::FakeIpFilter, mark, plain(&items)),
            _ => return Err(Refused::Setting),
        }
        self.def.lines.push(line);
        Ok(())
    }

    fn edit(&mut self, key: Key, mark: ListMark, values: Vec<String>) {
        self.edits.push((key, mark, values));
    }

    /// `domain = address[, address]`, `domain = alias` or `domain = server:<dns server>`.
    pub(super) fn read_host(&mut self, text: &str, line: u32) -> Result<(), Refused> {
        let (host, value) = text
            .split_once('=')
            .map(|(host, value)| (host.trim(), value.trim()))
            .filter(|(host, value)| is_host(host) && !value.is_empty())
            .ok_or_else(|| Refused::Unreadable("expected domain = address".to_string()))?;
        if let Some(server) = value
            .get(..7)
            .filter(|head| head.eq_ignore_ascii_case("server:"))
            .and_then(|_| value.get(7..))
        {
            let server =
                dns_server(server).ok_or_else(|| Refused::Unreadable(format!("{server:?}")))?;
            put(&mut self.def.nameserver_policy, host, vec![server]);
        } else {
            let targets: Vec<String> = value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(String::from)
                .collect();
            if let Some(bad) = targets
                .iter()
                .find(|target| target.parse::<IpAddr>().is_err() && !is_host(target))
            {
                return Err(Refused::Unreadable(format!("{bad:?}")));
            }
            put(&mut self.def.hosts, host, targets);
        }
        self.def.lines.push(line);
        Ok(())
    }

    /// Surge reads its plain servers only for the encrypted ones' domains once any encrypted
    /// one is set, which is mihomo's `default-nameserver`; Loon uses both.
    pub(super) fn finish(self, loon: bool) -> NetworkDef {
        let NetworkEdits {
            edits,
            mut def,
            loon: loon_key,
        } = self;
        let loon = loon || loon_key;
        let fold = |key: Key| {
            edits
                .iter()
                .filter(|(each, ..)| *each == key)
                .map(|(_, mark, values)| ListEdit::of(*mark, loon, values.clone()))
                .reduce(ListEdit::then)
        };
        let plain = fold(Key::PlainDns);
        let encrypted = fold(Key::EncryptedDns);
        def.default_nameserver = match (&plain, &encrypted) {
            (Some(plain), Some(_)) if !loon => Some(ListEdit {
                replace: plain.replace,
                before: plain
                    .before
                    .iter()
                    .filter(|s| is_plain_dns(s))
                    .cloned()
                    .collect(),
                after: plain
                    .after
                    .iter()
                    .filter(|s| is_plain_dns(s))
                    .cloned()
                    .collect(),
            }),
            _ => None,
        };
        def.nameserver = match (plain, encrypted) {
            (Some(plain), Some(encrypted)) if loon => Some(plain.then(encrypted)),
            (_, Some(encrypted)) => Some(encrypted),
            (plain, None) => plain,
        };
        def.fake_ip_filter = fold(Key::FakeIpFilter);
        def.route_exclude_address = fold(Key::RouteExclude);
        def.bypass_domain = fold(Key::Bypass);
        def
    }
}

/// A later line for the same domain replaces an earlier one.
fn put(list: &mut Vec<DomainEntry>, domain: &str, values: Vec<String>) {
    match list.iter_mut().find(|entry| entry.domain == domain) {
        Some(entry) => entry.values = values,
        None => list.push(DomainEntry {
            domain: domain.to_string(),
            values,
        }),
    }
}

fn is_host(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "*+._-".contains(c))
}

/// A DNS server as mihomo writes one: Surge's `system` and Loon's `h3://` read as
/// `system://` and DoH over HTTP/3.
fn dns_server(server: &str) -> Option<String> {
    let value = server.trim();
    if value == "system" || value == "syslib" {
        return Some("system://".to_string());
    }
    if let Some(rest) = value.strip_prefix("h3://") {
        let mark = if rest.contains('#') { '&' } else { '#' };
        return Some(format!("https://{rest}{mark}h3=true"));
    }
    if let Some((scheme, rest)) = value.split_once("://")
        && [
            "udp", "tcp", "tls", "https", "http", "quic", "system", "dhcp", "rcode",
        ]
        .contains(&scheme)
        && !rest.is_empty()
        && !rest.contains(char::is_whitespace)
    {
        return Some(value.to_string());
    }
    plain_address(value).map(|_| value.to_string())
}

fn plain_address(value: &str) -> Option<IpAddr> {
    if let Some(rest) = value.strip_prefix('[') {
        let (address, port) = rest.split_once(']')?;
        return (port.is_empty() || port.strip_prefix(':').is_some_and(is_port))
            .then(|| address.parse().ok())
            .flatten();
    }
    if let Ok(address) = value.parse() {
        return Some(address);
    }
    let (address, port) = value.rsplit_once(':')?;
    if is_port(port) {
        address.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
    } else {
        None
    }
}

fn is_port(text: &str) -> bool {
    !text.is_empty() && text.len() <= 5 && text.bytes().all(|b| b.is_ascii_digit())
}

fn is_plain_dns(server: &str) -> bool {
    server == "system://" || plain_address(server).is_some()
}

/// A route as a CIDR; an address alone covers that host.
fn route(text: &str) -> Option<String> {
    let value = text.trim();
    if value.contains('/') {
        return value.parse::<IpNetwork>().ok().map(|_| value.to_string());
    }
    let address: IpAddr = value.parse().ok()?;
    let bits = if address.is_ipv4() { 32 } else { 128 };
    Some(format!("{value}/{bits}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surge_moves_plain_servers_to_the_bootstrap_list() {
        let mut edits = NetworkEdits::default();
        assert!(
            edits
                .read_general("dns-server", "223.5.5.5, system", 2)
                .is_ok()
        );
        assert!(
            edits
                .read_general(
                    "encrypted-dns-server",
                    "%INSERT% https://a.test/dns-query",
                    3
                )
                .is_ok()
        );
        assert!(
            edits
                .read_general("skip-proxy", "%APPEND% a.test, b.test", 4)
                .is_ok()
        );
        assert!(matches!(
            edits.read_general("loglevel", "info", 5),
            Err(Refused::Setting)
        ));
        assert!(matches!(
            edits.read_general("dns-server", "nonsense", 6),
            Err(Refused::Unreadable(_))
        ));
        let def = edits.finish(false);
        let servers = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            def.nameserver,
            Some(ListEdit {
                replace: false,
                before: servers(&["https://a.test/dns-query"]),
                after: vec![]
            })
        );
        assert_eq!(
            def.default_nameserver,
            Some(ListEdit {
                replace: true,
                before: servers(&["223.5.5.5", "system://"]),
                after: vec![]
            })
        );
        assert_eq!(
            def.bypass_domain.map(|edit| edit.after),
            Some(servers(&["a.test", "b.test"]))
        );
        assert_eq!(def.lines, [2, 3, 4]);
    }

    #[test]
    fn hosts_map_domains_to_addresses_or_servers() {
        let mut edits = NetworkEdits::default();
        assert!(edits.read_host("a.test = 1.2.3.4, b.test", 1).is_ok());
        assert!(
            edits
                .read_host("*.c.test = server:h3://dns.test/q", 2)
                .is_ok()
        );
        assert!(edits.read_host("d.test = bad host", 3).is_err());
        let def = edits.finish(false);
        let entry = |domain: &str, values: &[&str]| DomainEntry {
            domain: domain.to_string(),
            values: values.iter().map(|value| value.to_string()).collect(),
        };
        assert_eq!(def.hosts, [entry("a.test", &["1.2.3.4", "b.test"])]);
        assert_eq!(
            def.nameserver_policy,
            [entry("*.c.test", &["https://dns.test/q#h3=true"])]
        );
    }
}
