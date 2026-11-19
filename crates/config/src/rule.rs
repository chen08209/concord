use std::fmt;

use crate::error::{ConfigError, Result};
use crate::filter;
use crate::net::{IpCidr, PortRange, parse_port_ranges, parse_unsigned_ranges};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkKind {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UidRange {
    pub start: u32,
    pub end: u32,
}

/// A list of ranges with the text it was written as, which is what a rule's payload
/// reports: `80-80` stays `80-80`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ports {
    pub ranges: Vec<PortRange>,
    pub text: String,
}

impl std::ops::Deref for Ports {
    type Target = [PortRange];

    fn deref(&self) -> &[PortRange] {
        &self.ranges
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cond {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(String),
    DomainWildcard(String),
    GeoSite(String),
    GeoIp(String),
    SrcGeoIp(String),
    IpAsn(String),
    SrcIpAsn(String),
    IpCidr(IpCidr),
    IpCidr6(IpCidr),
    SrcIpCidr(IpCidr),
    IpSuffix(IpCidr),
    SrcIpSuffix(IpCidr),
    SrcPort(Ports),
    DstPort(Ports),
    InPort(Ports),
    Dscp(Ports),
    ProcessName(String),
    ProcessPath(String),
    ProcessNameRegex(String),
    ProcessPathRegex(String),
    ProcessNameWildcard(String),
    ProcessPathWildcard(String),
    Network(NetworkKind),
    Uid(Vec<UidRange>),
    InType(Vec<String>),
    InUser(Vec<String>),
    InName(Vec<String>),
    RematchName(Vec<String>),
    /// Matched against an HTTP request's full URL; a flow whose requests the MITM engine
    /// does not read leaves it undecided.
    UrlRegex(String),
    /// A `*`/`?` pattern over the request's User-Agent header, case-sensitive.
    UserAgent(String),
    And(Vec<Cond>),
    Or(Vec<Cond>),
    Not(Box<Cond>),
    RuleSet(String),
    SubRule(Box<Cond>),
    /// Surge's `SCRIPT`: the `rule` script of this name decides, with the address the
    /// host resolves to when `requires-resolve` asks for it.
    Script {
        name: String,
        requires_resolve: bool,
    },
    Match,
    /// A child of a logic rule that carried `src` or `no-resolve`.
    Flagged {
        cond: Box<Cond>,
        src: bool,
        no_resolve: bool,
    },
}

impl Cond {
    pub fn type_name(&self) -> &'static str {
        match self {
            Cond::Domain(_) => "DOMAIN",
            Cond::DomainSuffix(_) => "DOMAIN-SUFFIX",
            Cond::DomainKeyword(_) => "DOMAIN-KEYWORD",
            Cond::DomainRegex(_) => "DOMAIN-REGEX",
            Cond::DomainWildcard(_) => "DOMAIN-WILDCARD",
            Cond::GeoSite(_) => "GEOSITE",
            Cond::GeoIp(_) => "GEOIP",
            Cond::SrcGeoIp(_) => "SRC-GEOIP",
            Cond::IpAsn(_) => "IP-ASN",
            Cond::SrcIpAsn(_) => "SRC-IP-ASN",
            Cond::IpCidr(_) => "IP-CIDR",
            Cond::IpCidr6(_) => "IP-CIDR6",
            Cond::SrcIpCidr(_) => "SRC-IP-CIDR",
            Cond::IpSuffix(_) => "IP-SUFFIX",
            Cond::SrcIpSuffix(_) => "SRC-IP-SUFFIX",
            Cond::SrcPort(_) => "SRC-PORT",
            Cond::DstPort(_) => "DST-PORT",
            Cond::InPort(_) => "IN-PORT",
            Cond::Dscp(_) => "DSCP",
            Cond::ProcessName(_) => "PROCESS-NAME",
            Cond::ProcessPath(_) => "PROCESS-PATH",
            Cond::ProcessNameRegex(_) => "PROCESS-NAME-REGEX",
            Cond::ProcessPathRegex(_) => "PROCESS-PATH-REGEX",
            Cond::ProcessNameWildcard(_) => "PROCESS-NAME-WILDCARD",
            Cond::ProcessPathWildcard(_) => "PROCESS-PATH-WILDCARD",
            Cond::Network(_) => "NETWORK",
            Cond::Uid(_) => "UID",
            Cond::InType(_) => "IN-TYPE",
            Cond::InUser(_) => "IN-USER",
            Cond::InName(_) => "IN-NAME",
            Cond::RematchName(_) => "REMATCH-NAME",
            Cond::UrlRegex(_) => "URL-REGEX",
            Cond::UserAgent(_) => "USER-AGENT",
            Cond::And(_) => "AND",
            Cond::Or(_) => "OR",
            Cond::Not(_) => "NOT",
            Cond::RuleSet(_) => "RULE-SET",
            Cond::SubRule(_) => "SUB-RULE",
            Cond::Script { .. } => "SCRIPT",
            Cond::Match => "MATCH",
            Cond::Flagged { cond, .. } => cond.type_name(),
        }
    }

    pub fn rule_sets<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Cond::RuleSet(name) => out.push(name),
            Cond::And(items) | Cond::Or(items) => items.iter().for_each(|c| c.rule_sets(out)),
            Cond::Not(inner) | Cond::SubRule(inner) => inner.rule_sets(out),
            Cond::Flagged { cond, .. } => cond.rule_sets(out),
            _ => {}
        }
    }

    pub fn scripts<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Cond::Script { name, .. } => out.push(name),
            Cond::And(items) | Cond::Or(items) => items.iter().for_each(|c| c.scripts(out)),
            Cond::Not(inner) | Cond::SubRule(inner) => inner.scripts(out),
            Cond::Flagged { cond, .. } => cond.scripts(out),
            _ => {}
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleDef {
    pub cond: Cond,
    pub target: String,
    pub no_resolve: bool,
    pub src: bool,
    /// Surge's `extended-matching` on a DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD or
    /// DOMAIN-WILDCARD rule: the name the flow was dialed by and the request's Host header
    /// are matched too.
    pub extended: bool,
    pub text: String,
}

impl fmt::Display for RuleDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Rule lines as written, in one allocation: a large profile holds millions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleLines {
    text: String,
    ends: Vec<u32>,
}

impl RuleLines {
    pub fn with_text_capacity(bytes: usize) -> Self {
        RuleLines {
            text: String::with_capacity(bytes),
            ends: Vec::new(),
        }
    }

    pub fn push(&mut self, line: &str) {
        self.text.push_str(line);
        self.ends.push(self.text.len() as u32);
    }

    pub fn len(&self) -> usize {
        self.ends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&str> {
        let end = *self.ends.get(index)? as usize;
        let start = match index.checked_sub(1) {
            Some(before) => *self.ends.get(before)? as usize,
            None => 0,
        };
        self.text.get(start..end)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        (0..self.len()).map(|index| self.get(index).unwrap_or_default())
    }

    pub fn shrink_to_fit(&mut self) {
        self.text.shrink_to_fit();
        self.ends.shrink_to_fit();
    }
}

impl<'a> FromIterator<&'a str> for RuleLines {
    fn from_iter<I: IntoIterator<Item = &'a str>>(lines: I) -> Self {
        let mut out = RuleLines::default();
        for line in lines {
            out.push(line);
        }
        out
    }
}

impl<const N: usize> PartialEq<[&str; N]> for RuleLines {
    fn eq(&self, other: &[&str; N]) -> bool {
        self.iter().eq(other.iter().copied())
    }
}

pub const T0_RULE_TYPES: &[&str] = &[
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "GEOSITE",
    "GEOIP",
    "SRC-GEOIP",
    "IP-CIDR",
    "IP-CIDR6",
    "SRC-IP-CIDR",
    "IP-SUFFIX",
    "SRC-IP-SUFFIX",
    "SRC-PORT",
    "DST-PORT",
    "IN-PORT",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "PROCESS-NAME-REGEX",
    "PROCESS-PATH-REGEX",
    "PROCESS-NAME-WILDCARD",
    "PROCESS-PATH-WILDCARD",
    "NETWORK",
    "UID",
    "IN-TYPE",
    "IN-USER",
    "AND",
    "OR",
    "NOT",
    "RULE-SET",
    "MATCH",
];

pub const T1_RULE_TYPES: &[&str] = &[
    "SUB-RULE",
    "IP-ASN",
    "SRC-IP-ASN",
    "DOMAIN-WILDCARD",
    "DSCP",
    "IN-NAME",
    "REMATCH-NAME",
    "URL-REGEX",
    "USER-AGENT",
    "SCRIPT",
];

pub fn rule_type_names() -> impl Iterator<Item = &'static str> {
    T0_RULE_TYPES.iter().chain(T1_RULE_TYPES).copied()
}

struct Parts {
    kind: String,
    payload: String,
    target: String,
    params: Vec<String>,
}

/// Types whose payload Surge lets a line double-quote to hold commas.
const QUOTED_PAYLOAD: &[&str] = &["URL-REGEX", "USER-AGENT"];

/// The quoted payload of a [QUOTED_PAYLOAD] line and the items after it. The closing quote
/// is the first one followed by a comma or the end of the line.
fn split_quoted(line: &str) -> Option<(String, Vec<&str>)> {
    let (_, rest) = line.split_once(',')?;
    let body = rest.trim_start_matches(' ').strip_prefix('"')?;
    let close = body.match_indices('"').find_map(|(at, _)| {
        let after = body.get(at + 1..)?.trim_start_matches(' ');
        (after.is_empty() || after.starts_with(',')).then_some((at, after))
    })?;
    let (at, after) = close;
    let payload = body.get(..at)?.to_string();
    let items = after
        .strip_prefix(',')
        .map(|tail| tail.split(',').map(|part| part.trim_matches(' ')).collect())
        .unwrap_or_default();
    Some((payload, items))
}

/// A classical rule-set entry of a type whose payload may be quoted, with `target` after its
/// payload.
pub fn with_quoted_target(entry: &str, target: &str) -> Option<String> {
    let kind = entry.split(',').next()?.trim_matches(' ').to_uppercase();
    if !QUOTED_PAYLOAD.contains(&kind.as_str()) {
        return None;
    }
    let (payload, params) = split_quoted(entry)?;
    let mut line = format!("{kind},\"{payload}\",{target}");
    for param in params {
        line.push(',');
        line.push_str(param);
    }
    Some(line)
}

fn split_rule(line: &str, need_target: bool) -> Parts {
    let items: Vec<&str> = line.split(',').map(|part| part.trim_matches(' ')).collect();
    let kind = items.first().copied().unwrap_or_default().to_uppercase();
    if QUOTED_PAYLOAD.contains(&kind.as_str())
        && let Some((payload, rest)) = split_quoted(line)
    {
        let (target, params) = match rest.split_first() {
            Some((target, params)) if need_target => ((*target).to_string(), params),
            _ => (String::new(), rest.as_slice()),
        };
        return Parts {
            kind,
            payload,
            target,
            params: params.iter().map(|p| (*p).to_string()).collect(),
        };
    }
    let mut parts = Parts {
        kind,
        payload: String::new(),
        target: String::new(),
        params: Vec::new(),
    };
    if items.len() < 2 {
        return parts;
    }
    match parts.kind.as_str() {
        "MATCH" => {
            parts.target = items.get(1).copied().unwrap_or_default().to_string();
        }
        "NOT" | "OR" | "AND" | "SUB-RULE" | "DOMAIN-REGEX" | "PROCESS-NAME-REGEX"
        | "PROCESS-PATH-REGEX" => {
            let mut body = items.get(1..).unwrap_or_default();
            if need_target && let Some((last, rest)) = items.split_last() {
                parts.target = (*last).to_string();
                body = rest.get(1..).unwrap_or_default();
            }
            parts.payload = body.join(",");
        }
        _ => {
            parts.payload = items.get(1).copied().unwrap_or_default().to_string();
            let rest = items.get(2..).unwrap_or_default();
            if need_target {
                if let Some((target, params)) = rest.split_first() {
                    parts.target = (*target).to_string();
                    parts.params = params.iter().map(|p| (*p).to_string()).collect();
                }
            } else {
                parts.params = rest.iter().map(|p| (*p).to_string()).collect();
            }
        }
    }
    parts
}

pub fn parse_rule(line: &str) -> Result<RuleDef> {
    let parts = split_rule(line, true);
    if parts.target.is_empty() {
        return Err(ConfigError::new("format invalid"));
    }
    let (cond, src, no_resolve) = build_cond(&parts)?;
    let extended = parts.params.iter().any(|p| p == EXTENDED_MATCHING)
        && matches!(
            cond,
            Cond::Domain(_)
                | Cond::DomainSuffix(_)
                | Cond::DomainKeyword(_)
                | Cond::DomainWildcard(_)
        );
    Ok(RuleDef {
        cond,
        target: parts.target,
        no_resolve,
        src,
        extended,
        text: line.to_string(),
    })
}

pub const EXTENDED_MATCHING: &str = "extended-matching";
pub const REQUIRES_RESOLVE: &str = "requires-resolve";

fn flags(params: &[String]) -> (bool, bool) {
    let src = params.iter().any(|p| p == "src");
    let no_resolve = src || params.iter().any(|p| p == "no-resolve");
    (src, no_resolve)
}

fn payload_error() -> ConfigError {
    ConfigError::new("payloadRule error")
}

fn cidr_payload(payload: &str) -> Result<IpCidr> {
    IpCidr::parse(payload).ok_or_else(payload_error)
}

fn ports(payload: &str) -> Result<Ports> {
    let ranges = parse_port_ranges(payload)
        .map_err(|err| ConfigError::new(format!("payloadRule error, {}", err.message)))?;
    if ranges.is_empty() {
        return Err(payload_error());
    }
    Ok(Ports {
        ranges,
        text: payload.to_string(),
    })
}

fn slash_list(payload: &str, what: &str) -> Result<Vec<String>> {
    payload
        .split('/')
        .map(|item| {
            let item = item.trim();
            if item.is_empty() {
                Err(ConfigError::new(format!("{what} couldn't be empty")))
            } else {
                Ok(item.to_string())
            }
        })
        .collect()
}

const IN_TYPES: &[&str] = &[
    "HTTP",
    "HTTPS",
    "SOCKS4",
    "SOCKS5",
    "SHADOWSOCKS",
    "SNELL",
    "VMESS",
    "VLESS",
    "REDIR",
    "TPROXY",
    "TROJAN",
    "TUNNEL",
    "TUN",
    "TUIC",
    "HYSTERIA2",
    "ANYTLS",
    "MIERU",
    "SUDOKU",
    "TRUSTTUNNEL",
    "SHADOWQUIC",
    "INNER",
    "SOCKS",
];

fn build_cond(parts: &Parts) -> Result<(Cond, bool, bool)> {
    let kind = parts.kind.as_str();
    let payload = parts.payload.as_str();
    if kind != "MATCH" && payload.is_empty() {
        return Err(ConfigError::new(format!(
            "missing subsequent parameters: {kind}"
        )));
    }
    let (src, no_resolve) = flags(&parts.params);
    let owned = || payload.to_string();
    let cond = match kind {
        "DOMAIN" => Cond::Domain(owned()),
        "DOMAIN-SUFFIX" => Cond::DomainSuffix(owned()),
        "DOMAIN-KEYWORD" => Cond::DomainKeyword(owned()),
        "DOMAIN-REGEX" => {
            filter::compile_pattern(payload, true)?;
            Cond::DomainRegex(owned())
        }
        "DOMAIN-WILDCARD" => Cond::DomainWildcard(payload.to_lowercase()),
        "GEOSITE" => Cond::GeoSite(owned()),
        "GEOIP" => Cond::GeoIp(owned()),
        "SRC-GEOIP" => return Ok((Cond::SrcGeoIp(owned()), true, true)),
        "IP-ASN" => Cond::IpAsn(owned()),
        "SRC-IP-ASN" => return Ok((Cond::SrcIpAsn(owned()), true, true)),
        "IP-CIDR" => Cond::IpCidr(cidr_payload(payload)?),
        "IP-CIDR6" => Cond::IpCidr6(cidr_payload(payload)?),
        "SRC-IP-CIDR" => return Ok((Cond::SrcIpCidr(cidr_payload(payload)?), true, true)),
        "IP-SUFFIX" => Cond::IpSuffix(cidr_payload(payload)?),
        "SRC-IP-SUFFIX" => return Ok((Cond::SrcIpSuffix(cidr_payload(payload)?), true, true)),
        "SRC-PORT" => Cond::SrcPort(ports(payload)?),
        "DST-PORT" => Cond::DstPort(ports(payload)?),
        "IN-PORT" => Cond::InPort(ports(payload)?),
        "DSCP" => {
            let ranges = parse_unsigned_ranges(payload, u64::from(u8::MAX)).map_err(|err| {
                ConfigError::new(format!("parse DSCP rule fail: {}", err.message))
            })?;
            if ranges.iter().any(|(_, end)| *end > 63) {
                return Err(ConfigError::new("DSCP couldn't be negative or exceed 63"));
            }
            Cond::Dscp(Ports {
                ranges: ranges
                    .into_iter()
                    .filter_map(|(start, end)| {
                        Some(PortRange {
                            start: u16::try_from(start).ok()?,
                            end: u16::try_from(end).ok()?,
                        })
                    })
                    .collect(),
                text: owned(),
            })
        }
        "PROCESS-NAME" => Cond::ProcessName(owned()),
        "PROCESS-PATH" => Cond::ProcessPath(owned()),
        "PROCESS-NAME-REGEX" => {
            filter::compile_pattern(payload, true)?;
            Cond::ProcessNameRegex(owned())
        }
        "PROCESS-PATH-REGEX" => {
            filter::compile_pattern(payload, true)?;
            Cond::ProcessPathRegex(owned())
        }
        "PROCESS-NAME-WILDCARD" => Cond::ProcessNameWildcard(owned()),
        "PROCESS-PATH-WILDCARD" => Cond::ProcessPathWildcard(owned()),
        "NETWORK" => match payload.to_uppercase().as_str() {
            "TCP" => Cond::Network(NetworkKind::Tcp),
            "UDP" => Cond::Network(NetworkKind::Udp),
            _ => {
                return Err(ConfigError::new("unsupported network type, only TCP/UDP"));
            }
        },
        "UID" => {
            let ranges = parse_unsigned_ranges(payload, u64::from(u32::MAX))
                .map_err(|err| ConfigError::new(format!("payloadRule error, {}", err.message)))?;
            if ranges.is_empty() {
                return Err(payload_error());
            }
            Cond::Uid(
                ranges
                    .into_iter()
                    .filter_map(|(start, end)| {
                        Some(UidRange {
                            start: u32::try_from(start).ok()?,
                            end: u32::try_from(end).ok()?,
                        })
                    })
                    .collect(),
            )
        }
        "IN-TYPE" => {
            let items = slash_list(payload, "in type")?;
            for item in &items {
                if !IN_TYPES.contains(&item.to_uppercase().as_str()) {
                    return Err(ConfigError::new(format!("unknown type: {item}")));
                }
            }
            Cond::InType(items.iter().map(|i| i.to_uppercase()).collect())
        }
        "IN-USER" => Cond::InUser(slash_list(payload, "in user")?),
        "IN-NAME" => Cond::InName(slash_list(payload, "in name")?),
        "REMATCH-NAME" => Cond::RematchName(slash_list(payload, "rematch name")?),
        "URL-REGEX" => {
            crate::mitm::check_pattern(payload).map_err(|err| ConfigError::new(err.to_string()))?;
            Cond::UrlRegex(owned())
        }
        "USER-AGENT" => Cond::UserAgent(owned()),
        "SCRIPT" => Cond::Script {
            name: owned(),
            requires_resolve: parts.params.iter().any(|p| p == REQUIRES_RESOLVE),
        },
        "AND" => Cond::And(parse_logic(payload)?),
        "OR" => Cond::Or(parse_logic(payload)?),
        "NOT" => Cond::Not(only_one(parse_logic(payload)?, "not rule")?),
        "SUB-RULE" => Cond::SubRule(only_one(
            parse_logic(&format!("({payload})"))?,
            "Sub-Rule rule",
        )?),
        "RULE-SET" => Cond::RuleSet(owned()),
        "MATCH" => return Ok((Cond::Match, false, false)),
        other => {
            return Err(ConfigError::new(format!("unsupported rule type: {other}")));
        }
    };
    Ok((cond, src, no_resolve))
}

fn only_one(mut inner: Vec<Cond>, what: &str) -> Result<Box<Cond>> {
    match (inner.pop(), inner.is_empty()) {
        (Some(only), true) => Ok(Box::new(only)),
        _ => Err(ConfigError::new(format!("{what} must contain one rule"))),
    }
}

fn parse_logic(payload: &str) -> Result<Vec<Cond>> {
    if !payload.starts_with('(') || !payload.ends_with(')') {
        return Err(ConfigError::new("payload format error"));
    }
    let ranges = paren_ranges(payload)?;
    let last = payload.len().saturating_sub(1);
    let mut top: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        if start == 0 && end == last {
            continue;
        }
        let covered = top.iter().any(|(s, e)| *s < start && *e > end);
        if !covered {
            top.push((start, end));
        }
    }
    let mut rules = Vec::with_capacity(top.len());
    for (start, end) in top {
        let sub = payload.get(start + 1..end).unwrap_or_default();
        rules.push(sub_rule(sub)?);
    }
    Ok(rules)
}

fn paren_ranges(payload: &str) -> Result<Vec<(usize, usize)>> {
    let mut stack: Vec<usize> = Vec::new();
    let mut ranges = Vec::new();
    let mut quoted = false;
    for (i, c) in payload.char_indices() {
        match c {
            '"' => quoted = !quoted,
            _ if quoted => {}
            '(' => stack.push(i),
            ')' => {
                let start = stack.pop().ok_or_else(|| ConfigError::new("missing '('"))?;
                ranges.push((start, i));
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err(ConfigError::new("format error is missing )"));
    }
    ranges.sort_by_key(|(start, _)| *start);
    Ok(ranges)
}

fn sub_rule(text: &str) -> Result<Cond> {
    let parts = split_rule(text, false);
    match parts.kind.as_str() {
        "MATCH" | "SUB-RULE" => Err(ConfigError::new(format!(
            "unsupported rule type [{}] on logic rule",
            parts.kind
        ))),
        "" => Err(ConfigError::new(format!("[{text}] format is error"))),
        _ => build_cond(&parts).map(|(cond, src, no_resolve)| {
            let source_variant = matches!(
                cond,
                Cond::SrcGeoIp(_) | Cond::SrcIpAsn(_) | Cond::SrcIpCidr(_) | Cond::SrcIpSuffix(_)
            );
            if (src || no_resolve) && !source_variant {
                Cond::Flagged {
                    cond: Box::new(cond),
                    src,
                    no_resolve,
                }
            } else {
                cond
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(line: &str) -> RuleDef {
        parse_rule(line).unwrap_or_else(|err| panic!("{line}: {err}"))
    }

    fn err(line: &str) -> String {
        parse_rule(line).expect_err(line).message
    }

    #[test]
    fn rematch_names_are_trimmed_and_empty_members_are_rejected() {
        assert_eq!(
            ok("REMATCH-NAME,First / second,DIRECT").cond,
            Cond::RematchName(vec!["First".into(), "second".into()])
        );
        assert!(
            err("REMATCH-NAME,first//second,DIRECT").contains("rematch name couldn't be empty")
        );
        assert!(matches!(
            ok("AND,((REMATCH-NAME,first),(NETWORK,tcp)),DIRECT").cond,
            Cond::And(_)
        ));
    }

    #[test]
    fn http_rules_take_a_quoted_payload() {
        let rule = ok(r#"URL-REGEX,"^http:\/\/a\.com\/(x|y),?z",REJECT-TINYGIF"#);
        assert_eq!(
            rule.cond,
            Cond::UrlRegex(r"^http:\/\/a\.com\/(x|y),?z".into())
        );
        assert_eq!(rule.target, "REJECT-TINYGIF");
        let rule = ok(r#"USER-AGENT, "httpdns*", REJECT"#);
        assert_eq!(rule.cond, Cond::UserAgent("httpdns*".into()));
        assert_eq!(rule.target, "REJECT");
        assert_eq!(
            ok("USER-AGENT,Apple*,DIRECT").cond,
            Cond::UserAgent("Apple*".into())
        );
        let rule =
            ok(r#"AND,((URL-REGEX,"^http:\/\/.+\/amdc\/(a|b)\)"),(USER-AGENT,"Alibaba*")),REJECT"#);
        assert_eq!(
            rule.cond,
            Cond::And(vec![
                Cond::UrlRegex(r"^http:\/\/.+\/amdc\/(a|b)\)".into()),
                Cond::UserAgent("Alibaba*".into()),
            ])
        );
        assert!(parse_rule("URL-REGEX,^a(b,DIRECT").is_err());
        assert_eq!(
            with_quoted_target(r#"URL-REGEX,"a,b",extended-matching"#, "DIRECT").as_deref(),
            Some(r#"URL-REGEX,"a,b",DIRECT,extended-matching"#)
        );
        assert_eq!(with_quoted_target("DOMAIN,a.com", "DIRECT"), None);
    }

    #[test]
    fn every_type_parses() {
        let lines = [
            "DOMAIN,example.com,PROXY",
            "DOMAIN-SUFFIX,example.com,PROXY",
            "DOMAIN-KEYWORD,ads,REJECT",
            "DOMAIN-REGEX,^ad[0-9]+\\.com$,REJECT",
            "DOMAIN-WILDCARD,*.example.com,PROXY",
            "GEOSITE,cn,DIRECT",
            "GEOIP,CN,DIRECT,no-resolve",
            "SRC-GEOIP,CN,DIRECT",
            "IP-ASN,13335,PROXY",
            "SRC-IP-ASN,13335,PROXY",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR6,2001:db8::/32,DIRECT",
            "SRC-IP-CIDR,192.168.1.0/24,DIRECT",
            "IP-SUFFIX,0.0.0.1/8,DIRECT",
            "SRC-IP-SUFFIX,0.0.0.1/8,DIRECT",
            "SRC-PORT,1000-2000,DIRECT",
            "DST-PORT,80/443,PROXY",
            "IN-PORT,7890,DIRECT",
            "DSCP,46,DIRECT",
            "PROCESS-NAME,curl,DIRECT",
            "PROCESS-PATH,/usr/bin/curl,DIRECT",
            "PROCESS-NAME-REGEX,^curl.*$,DIRECT",
            "PROCESS-PATH-REGEX,^/usr/.*,DIRECT",
            "PROCESS-NAME-WILDCARD,cur*,DIRECT",
            "PROCESS-PATH-WILDCARD,/usr/*,DIRECT",
            "NETWORK,udp,DIRECT",
            "UID,1000-1999,DIRECT",
            "IN-TYPE,HTTP/SOCKS,DIRECT",
            "IN-USER,alice/bob,DIRECT",
            "IN-NAME,in1,DIRECT",
            "RULE-SET,ads,REJECT,no-resolve",
            "MATCH,PROXY",
        ];
        for line in lines {
            let rule = ok(line);
            assert_eq!(rule.text, line);
            assert!(!rule.target.is_empty());
        }
    }

    #[test]
    fn extended_matching_marks_only_the_four_name_rules() {
        assert!(ok("DOMAIN-SUFFIX,a.com,REJECT,extended-matching").extended);
        assert!(ok("DOMAIN-WILDCARD,*.a.com,REJECT,extended-matching").extended);
        assert!(!ok("DOMAIN-SUFFIX,a.com,REJECT").extended);
        assert!(!ok("DOMAIN-REGEX,a,REJECT,extended-matching").extended);
        assert!(!ok("IP-CIDR,10.0.0.0/8,REJECT,extended-matching").extended);
    }

    #[test]
    fn params_follow_the_target() {
        let rule = ok("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve");
        assert!(rule.no_resolve && !rule.src);
        let rule = ok("GEOIP,CN,DIRECT,src");
        assert!(rule.src && rule.no_resolve);
        let rule = ok("GEOIP,CN,DIRECT");
        assert!(!rule.src && !rule.no_resolve);
        let rule = ok("SRC-GEOIP,CN,DIRECT");
        assert!(rule.src && rule.no_resolve);
    }

    #[test]
    fn logic_rules_keep_commas_in_the_payload() {
        let rule = ok("AND,((DOMAIN,baidu.com),(NETWORK,UDP)),DIRECT");
        assert_eq!(rule.target, "DIRECT");
        match rule.cond {
            Cond::And(items) => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0], Cond::Domain("baidu.com".into()));
                assert_eq!(items[1], Cond::Network(NetworkKind::Udp));
            }
            other => panic!("{other:?}"),
        }
        let rule = ok("OR,((DOMAIN,a.com),(AND,((DOMAIN-KEYWORD,b),(NOT,((GEOIP,CN)))))),PROXY");
        let Cond::Or(items) = rule.cond else {
            panic!("not an OR")
        };
        assert_eq!(items.len(), 2);
        let Cond::And(inner) = &items[1] else {
            panic!("not an AND")
        };
        assert!(matches!(inner[1], Cond::Not(_)));
        let rule = ok("NOT,((DOMAIN,x.com)),REJECT");
        assert!(matches!(rule.cond, Cond::Not(_)));
    }

    #[test]
    fn logic_children_keep_their_flags() {
        let rule =
            ok("AND,((IP-CIDR,10.0.0.0/8,no-resolve),(GEOIP,CN,src),(IP-CIDR,1.0.0.0/8)),DIRECT");
        let Cond::And(items) = rule.cond else {
            panic!("not an AND")
        };
        assert!(matches!(
            &items[0],
            Cond::Flagged {
                src: false,
                no_resolve: true,
                ..
            }
        ));
        assert!(matches!(
            &items[1],
            Cond::Flagged {
                src: true,
                no_resolve: true,
                ..
            }
        ));
        assert!(matches!(&items[2], Cond::IpCidr(_)));
        assert_eq!(items[0].type_name(), "IP-CIDR");
    }

    #[test]
    fn regex_payloads_may_contain_commas() {
        let rule = ok("DOMAIN-REGEX,^a{1,3}\\.com$,DIRECT");
        assert_eq!(rule.cond, Cond::DomainRegex("^a{1,3}\\.com$".into()));
        assert_eq!(rule.target, "DIRECT");
    }

    #[test]
    fn sub_rule_wraps_a_single_condition() {
        let rule = ok("SUB-RULE,(NETWORK,tcp),inner");
        assert_eq!(rule.target, "inner");
        assert!(matches!(rule.cond, Cond::SubRule(_)));
        assert_eq!(
            err("SUB-RULE,(MATCH),inner"),
            "unsupported rule type [MATCH] on logic rule"
        );
    }

    #[test]
    fn malformed_rules_are_hard_errors() {
        assert_eq!(err("DOMAIN"), "format invalid");
        assert_eq!(err("MATCH"), "format invalid");
        assert_eq!(err("FOO,bar,DIRECT"), "unsupported rule type: FOO");
        assert_eq!(
            err("DOMAIN,,DIRECT"),
            "missing subsequent parameters: DOMAIN"
        );
        assert_eq!(err("IP-CIDR,10.0.0.1,DIRECT"), "payloadRule error");
        assert_eq!(err("IP-CIDR,10.0.0.0/33,DIRECT"), "payloadRule error");
        assert_eq!(
            err("DST-PORT,abc,DIRECT"),
            "payloadRule error, intRanges error, can't parse \"abc\""
        );
        assert_eq!(
            err("DST-PORT,70000,DIRECT"),
            "payloadRule error, intRanges error, 70000 is out of range"
        );
        assert_eq!(
            err("DSCP,64,DIRECT"),
            "DSCP couldn't be negative or exceed 63"
        );
        assert_eq!(
            err("NETWORK,icmp,DIRECT"),
            "unsupported network type, only TCP/UDP"
        );
        assert_eq!(err("IN-TYPE,FOO,DIRECT"), "unknown type: FOO");
        assert_eq!(err("IN-USER,a//b,DIRECT"), "in user couldn't be empty");
        assert!(err("DOMAIN-REGEX,(abc,DIRECT").starts_with("error parsing regexp"));
        assert_eq!(err("AND,DOMAIN,a.com,DIRECT"), "payload format error");
        assert_eq!(
            err("NOT,((DOMAIN,a),(DOMAIN,b)),X"),
            "not rule must contain one rule"
        );
        assert_eq!(err("AND,((DOMAIN,a),DIRECT"), "format error is missing )");
        assert_eq!(err("AND,(DOMAIN,a)),DIRECT"), "missing '('");
        assert_eq!(
            err("OR,((MATCH)),DIRECT"),
            "unsupported rule type [MATCH] on logic rule"
        );
    }

    #[test]
    fn spaces_around_fields_are_trimmed() {
        let rule = ok("DOMAIN , example.com , PROXY");
        assert_eq!(rule.cond, Cond::Domain("example.com".into()));
        assert_eq!(rule.target, "PROXY");
    }

    #[test]
    fn rule_set_names_are_collected_from_nested_logic() {
        let rule = ok("AND,((RULE-SET,a),(NOT,((RULE-SET,b)))),DIRECT");
        let mut names = Vec::new();
        rule.cond.rule_sets(&mut names);
        assert_eq!(names, ["a", "b"]);
    }

    #[test]
    fn thirty_nine_types_are_known() {
        assert_eq!(rule_type_names().count(), 40);
    }
}
