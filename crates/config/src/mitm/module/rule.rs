//! A module's rules, in Concord's rule syntax with the policy kept apart, so the host's
//! mapping of a module's policy names to its own outbounds applies.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::IgnoreReason;
use super::resource::is_url;
use super::source::{split_commas, unquote};

/// A built-in policy in its Surge name, or one the host maps to an outbound.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Policy {
    /// `DIRECT`, or one of `REJECT`, `REJECT-DROP`, `REJECT-NO-DROP`, `REJECT-TINYGIF`,
    /// `REJECT-DICT`, `REJECT-ARRAY` and `REJECT-200`.
    Builtin(&'static str),
    Named(String),
}

/// A rule without its policy: what goes before it in a profile's `rules` line. HTTP rules
/// (`URL-REGEX`, `USER-AGENT`) stay as written, inside a logical rule too; a `URL-REGEX`
/// payload may hold commas.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleRule {
    pub rule: String,
    pub policy: Policy,
    pub no_resolve: bool,
    /// Surge's `extended-matching`: a domain also matches the SNI and the Host header.
    pub extended_matching: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RuleSetSource {
    /// Downloaded every `interval` seconds, 0 for never; none given, the host's default.
    Url { url: String, interval: Option<u64> },
    /// A `[Ruleset <name>]` section's lines, translated. Sections of one name add up across
    /// modules.
    Inline { rules: Vec<InlineRule> },
    /// Surge's internal `LAN` and `SYSTEM` sets.
    Builtin { rules: &'static [&'static str] },
    /// An attached file.
    File { file: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InlineRule {
    pub line: u32,
    pub rule: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleSetDef {
    /// `mitm-` and a hash of where the set comes from, so one set shared by modules is one
    /// provider.
    pub name: String,
    /// Surge's `DOMAIN-SET`: one domain per line.
    pub domain: bool,
    pub source: RuleSetSource,
}

/// Surge's internal rule sets as rules/ruleset.html lists them.
const LAN: &[&str] = &[
    "DOMAIN-SUFFIX,local",
    "IP-CIDR,0.0.0.0/8",
    "IP-CIDR,10.0.0.0/8",
    "IP-CIDR,100.64.0.0/10",
    "IP-CIDR,127.0.0.0/8",
    "IP-CIDR,169.254.0.0/16",
    "IP-CIDR,172.16.0.0/12",
    "IP-CIDR,192.0.0.0/24",
    "IP-CIDR,192.0.2.0/24",
    "IP-CIDR,192.168.0.0/16",
    "IP-CIDR,224.0.0.0/4",
    "IP-CIDR6,::1/128",
    "IP-CIDR6,fc00::/7",
    "IP-CIDR6,fe80::/10",
];

const SYSTEM: &[&str] = &[
    "DOMAIN,api.smoot.apple.com",
    "DOMAIN,captive.apple.com",
    "DOMAIN,xp.apple.com",
    "DOMAIN,configuration.apple.com",
    "DOMAIN,guzzoni.apple.com",
    "DOMAIN,smp-device-content.apple.com",
    "DOMAIN,aod.itunes.apple.com",
    "DOMAIN,mesu.apple.com",
    "DOMAIN,api.smoot.apple.cn",
    "DOMAIN,gs-loc.apple.com",
    "DOMAIN,mvod.itunes.apple.com",
    "DOMAIN,streamingaudio.itunes.apple.com",
    "DOMAIN-SUFFIX,ess.apple.com",
    "DOMAIN-SUFFIX,push-apple.com.akadns.net",
    "DOMAIN-SUFFIX,push.apple.com",
    "DOMAIN-SUFFIX,lcdn-locator.apple.com",
    "DOMAIN-SUFFIX,lcdn-registration.apple.com",
    "DOMAIN-SUFFIX,ls.apple.com",
    "PROCESS-NAME,trustd",
    "PROCESS-NAME,netbiosd",
];

/// Rule types Surge and Loon write, by the name Concord gives the same condition.
const TYPES: &[(&str, &str)] = &[
    ("DOMAIN", "DOMAIN"),
    ("DOMAIN-SUFFIX", "DOMAIN-SUFFIX"),
    ("DOMAIN-KEYWORD", "DOMAIN-KEYWORD"),
    ("DOMAIN-WILDCARD", "DOMAIN-WILDCARD"),
    ("DOMAIN-REGEX", "DOMAIN-REGEX"),
    ("IP-CIDR", "IP-CIDR"),
    ("IP-CIDR6", "IP-CIDR6"),
    ("SRC-IP", "SRC-IP-CIDR"),
    ("SRC-IP-CIDR", "SRC-IP-CIDR"),
    ("DEST-PORT", "DST-PORT"),
    ("DST-PORT", "DST-PORT"),
    ("SRC-PORT", "SRC-PORT"),
    ("IN-PORT", "IN-PORT"),
    ("PROCESS-NAME", "PROCESS-NAME"),
    ("PROCESS-PATH", "PROCESS-PATH"),
    ("GEOIP", "GEOIP"),
    ("IP-ASN", "IP-ASN"),
    ("GEOSITE", "GEOSITE"),
    ("NETWORK", "NETWORK"),
    ("URL-REGEX", "URL-REGEX"),
    ("USER-AGENT", "USER-AGENT"),
];

/// Rules on what only an Apple device knows of its network or itself.
const DEVICE_TYPES: &[&str] = &[
    "CELLULAR-RADIO",
    "CELLULAR-CARRIER",
    "SUBNET",
    "DEVICE-NAME",
    "MAC-ADDRESS",
    "HOSTNAME-TYPE",
];

/// Options after the policy that say nothing of what a rule matches; Loon leaves the policy
/// out for DIRECT.
const OPTIONS: &[&str] = &["no-resolve", "extended-matching", "pre-matching"];

pub(super) type Refusal = (IgnoreReason, Option<String>);

fn refuse(reason: IgnoreReason) -> Refusal {
    (reason, None)
}

/// What a module's rule lines need besides themselves: the inline sets it declares, its
/// attachments, and the sets its rules name so far.
pub(super) struct RuleReader<'a> {
    pub(super) sets: Vec<RuleSetDef>,
    inline: Vec<String>,
    attachments: &'a BTreeMap<String, String>,
    /// Stash's `rule-providers` by name: the set's key and where it comes from.
    providers: BTreeMap<String, (String, RuleSetSource)>,
}

impl<'a> RuleReader<'a> {
    pub(super) fn new(inline: Vec<String>, attachments: &'a BTreeMap<String, String>) -> Self {
        RuleReader {
            sets: Vec::new(),
            inline,
            attachments,
            providers: BTreeMap::new(),
        }
    }

    /// A `[Rule]` line: `TYPE,payload,policy[,options]`, or Loon's `url,policy`.
    pub(super) fn read(&mut self, line: &str) -> Result<ModuleRule, Refusal> {
        let parts = rule_parts(without_comment(line));
        let kind = parts
            .first()
            .copied()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if kind == "FINAL" || kind == "MATCH" {
            return Err(refuse(IgnoreReason::FinalRule));
        }
        if DEVICE_TYPES.contains(&kind.as_str()) {
            return Err(refuse(IgnoreReason::DeviceRule));
        }
        let first = parts.first().copied().unwrap_or_default();
        if is_url(first) {
            let policy = parts.get(1).map_or("DIRECT", |policy| unquote(policy));
            let options = parts.get(2..).unwrap_or_default();
            return self.rule_set(first, policy, options, false);
        }
        let named = parts.get(2).is_some_and(|part| {
            !part.is_empty() && !OPTIONS.contains(&part.to_ascii_lowercase().as_str())
        });
        let policy = if named {
            parts.get(2).map_or("DIRECT", |policy| unquote(policy))
        } else {
            "DIRECT"
        };
        let options = parts.get(if named { 3 } else { 2 }..).unwrap_or_default();
        let payload = parts.get(1).copied().unwrap_or_default();
        match kind.as_str() {
            "RULE-SET" if !payload.is_empty() => {
                return self.rule_set(unquote(payload), policy, options, false);
            }
            "DOMAIN-SET" if !payload.is_empty() => {
                return self.rule_set(unquote(payload), policy, options, true);
            }
            _ => {}
        }
        let (rule, resolves) = translate(&kind, payload, false)?;
        Ok(ModuleRule {
            rule,
            policy: policy_of(policy)?,
            no_resolve: resolves && has(options, "no-resolve"),
            extended_matching: has(options, "extended-matching"),
        })
    }

    fn rule_set(
        &mut self,
        value: &str,
        policy: &str,
        options: &[&str],
        domain: bool,
    ) -> Result<ModuleRule, Refusal> {
        let policy = policy_of(policy)?;
        let (key, source) = if is_url(value) {
            let interval = options.iter().find_map(|option| {
                let (key, value) = option.split_once('=')?;
                (key.trim() == "update-interval").then(|| value.trim().parse::<i64>().ok())?
            });
            let kind = if domain { "domain-set:" } else { "" };
            let source = RuleSetSource::Url {
                url: value.to_string(),
                interval: interval.map(|seconds| u64::try_from(seconds).unwrap_or(0)),
            };
            (format!("{kind}{value}"), source)
        } else if let Some(rules) = builtin(value) {
            (
                format!("surge:{}", value.to_ascii_uppercase()),
                RuleSetSource::Builtin { rules },
            )
        } else if let Some((key, source)) = self.providers.get(value) {
            (key.clone(), source.clone())
        } else if self.inline.iter().any(|name| name == value) {
            (
                inline_key(value),
                RuleSetSource::Inline { rules: Vec::new() },
            )
        } else {
            let file = self
                .attachments
                .get(value)
                .ok_or_else(|| refuse(IgnoreReason::NoAttachment))?;
            let kind = if domain { "domain-set:" } else { "" };
            (
                format!("file:{kind}{file}"),
                RuleSetSource::File { file: file.clone() },
            )
        };
        let name = self.add_set(&key, domain, source);
        Ok(ModuleRule {
            rule: format!("RULE-SET,{name}"),
            policy,
            no_resolve: has(options, "no-resolve"),
            extended_matching: false,
        })
    }

    /// Loon's `[Remote Rule]`: `url, policy=P, tag=T, enabled=B`, or the policy second
    /// (Rule/sub_rule); a rule with no policy is `DIRECT`.
    pub(super) fn remote(&mut self, line: &str) -> Result<Option<ModuleRule>, Refusal> {
        let parts = split_commas(line);
        let (url, options) = parts
            .split_first()
            .ok_or_else(|| refuse(IgnoreReason::Unreadable))?;
        if !is_url(url) {
            return Err(refuse(IgnoreReason::Unreadable));
        }
        let mut policy = "DIRECT";
        for (at, option) in options.iter().enumerate() {
            match option.split_once('=') {
                Some((key, value)) => match key.trim().to_ascii_lowercase().as_str() {
                    "policy" => policy = value.trim(),
                    "enabled" if value.trim().eq_ignore_ascii_case("false") => return Ok(None),
                    _ => {}
                },
                None if at == 0 && !option.is_empty() => policy = option,
                None => {}
            }
        }
        self.rule_set(url, policy, &[], false).map(Some)
    }

    /// A Stash rule provider `RULE-SET,<name>` names; `rules` are an inline one's.
    pub(super) fn provider(&mut self, name: &str, source: RuleSetSource) {
        let key = match &source {
            RuleSetSource::Url { url, .. } => url.clone(),
            _ => format!("stash:{name}"),
        };
        self.providers.insert(name.to_string(), (key, source));
    }

    /// A rule of an inline provider's payload, as a `[Ruleset]` line is read.
    pub(super) fn inline_rule(line: &str) -> Result<String, Refusal> {
        let parts = rule_parts(without_comment(line));
        let kind = parts
            .first()
            .copied()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if kind == "RULE-SET" || kind == "DOMAIN-SET" {
            return Err(refuse(IgnoreReason::NestedRuleSet));
        }
        if DEVICE_TYPES.contains(&kind.as_str()) {
            return Err(refuse(IgnoreReason::DeviceRule));
        }
        let (mut rule, resolves) =
            translate(&kind, parts.get(1).copied().unwrap_or_default(), false)?;
        if resolves && has(parts.get(2..).unwrap_or_default(), "no-resolve") {
            rule.push_str(",no-resolve");
        }
        Ok(rule)
    }

    fn add_set(&mut self, key: &str, domain: bool, source: RuleSetSource) -> String {
        let name = set_name(key);
        if !self.sets.iter().any(|set| set.name == name) {
            self.sets.push(RuleSetDef {
                name: name.clone(),
                domain,
                source,
            });
        }
        name
    }

    /// A line of `[Ruleset <set>]`: a rule without a policy.
    pub(super) fn read_inline(
        &mut self,
        set: &str,
        line: &str,
        number: u32,
    ) -> Result<(), Refusal> {
        let rule = Self::inline_rule(line)?;
        let name = self.add_set(
            &inline_key(set),
            false,
            RuleSetSource::Inline { rules: Vec::new() },
        );
        if let Some(RuleSetDef {
            source: RuleSetSource::Inline { rules },
            ..
        }) = self.sets.iter_mut().find(|each| each.name == name)
        {
            rules.push(InlineRule { line: number, rule });
        }
        Ok(())
    }
}

/// Surge's `[IP Rewrite]` `address = action`: `reject` answers and `drop` stays silent, as
/// the rules that do the same.
pub(super) fn ip_rewrite(line: &str) -> Result<ModuleRule, Refusal> {
    let unreadable = || {
        (
            IgnoreReason::Unreadable,
            Some("expected address = action".to_string()),
        )
    };
    let (address, action) = line.split_once('=').ok_or_else(unreadable)?;
    let cidr = cidr(address.trim()).ok_or_else(unreadable)?;
    let policy = match action.trim().to_ascii_lowercase().as_str() {
        "reject" => "REJECT",
        "drop" => "REJECT-DROP",
        "reflect" => return Err(refuse(IgnoreReason::Reflect)),
        _ => return Err(unreadable()),
    };
    let kind = if cidr.contains(':') {
        "IP-CIDR6"
    } else {
        "IP-CIDR"
    };
    Ok(ModuleRule {
        rule: format!("{kind},{cidr}"),
        policy: Policy::Builtin(policy),
        no_resolve: true,
        extended_matching: false,
    })
}

fn has(options: &[&str], option: &str) -> bool {
    options.iter().any(|each| each.eq_ignore_ascii_case(option))
}

fn builtin(name: &str) -> Option<&'static [&'static str]> {
    match name.to_ascii_uppercase().as_str() {
        "LAN" => Some(LAN),
        "SYSTEM" => Some(SYSTEM),
        _ => None,
    }
}

fn inline_key(name: &str) -> String {
    format!("ruleset:{name}")
}

fn set_name(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let hex = hex::encode(digest);
    format!("mitm-{}", hex.get(..12).unwrap_or_default())
}

/// A built-in policy, or a name the host maps; Quantumult X writes Loon's `PROXY` as `proxy`.
/// An argument left unexpanded names nothing.
pub(super) fn policy_of(policy: &str) -> Result<Policy, Refusal> {
    let builtin = match policy.to_ascii_uppercase().as_str() {
        "DIRECT" => "DIRECT",
        "REJECT" => "REJECT",
        "REJECT-DROP" => "REJECT-DROP",
        "REJECT-NO-DROP" => "REJECT-NO-DROP",
        "REJECT-TINYGIF" | "REJECT-IMG" => "REJECT-TINYGIF",
        "REJECT-DICT" => "REJECT-DICT",
        "REJECT-ARRAY" => "REJECT-ARRAY",
        "REJECT-200" | "REJECT-VIDEO" => "REJECT-200",
        _ if policy.is_empty() || policy.contains("${") || policy.contains("{{{") => {
            return Err((IgnoreReason::Policy, Some(policy.to_string())));
        }
        _ if policy == "proxy" => return Ok(Policy::Named("PROXY".to_string())),
        _ => return Ok(Policy::Named(policy.to_string())),
    };
    Ok(Policy::Builtin(builtin))
}

/// A rule line without its inline comment: `//`, `#` or `;` after a space, outside quotes
/// (rules/overview.html, Composition).
fn without_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut after_space = false;
    for (at, c) in line.char_indices() {
        if c == '"' {
            quoted = !quoted;
        } else if !quoted && after_space {
            let rest = line.get(at..).unwrap_or_default();
            if rest.starts_with("//") || rest.starts_with('#') || rest.starts_with(';') {
                return line.get(..at).unwrap_or(line).trim_end();
            }
        }
        after_space = c == ' ' || c == '\t';
    }
    line
}

/// Splits on commas outside double quotes, and for a logical rule outside parentheses.
pub(super) fn rule_parts(text: &str) -> Vec<&str> {
    let kind = text.split(',').next().unwrap_or_default().trim();
    let nested = ["AND", "OR", "NOT"]
        .iter()
        .any(|logic| kind.eq_ignore_ascii_case(logic));
    split_rule(text, nested)
}

fn split_rule(text: &str, nested: bool) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut quoted, mut start) = (0i32, false, 0);
    for (at, c) in text.char_indices() {
        match c {
            '"' => quoted = !quoted,
            '(' if nested && !quoted => depth += 1,
            ')' if nested && !quoted => depth -= 1,
            ',' if !quoted && depth == 0 => {
                parts.push(text.get(start..at).unwrap_or_default().trim());
                start = at + 1;
            }
            _ => {}
        }
    }
    parts.push(text.get(start..).unwrap_or_default().trim());
    parts
}

/// A condition in Concord's syntax, and whether `no-resolve` means anything to it.
fn translate(kind: &str, payload: &str, nested: bool) -> Result<(String, bool), Refusal> {
    match kind {
        "AND" | "OR" | "NOT" => return logical(kind, payload),
        "PROTOCOL" => {
            let network = match payload.trim().to_ascii_uppercase().as_str() {
                "TCP" => "TCP",
                "UDP" => "UDP",
                "QUIC" if nested => "UDP",
                _ => return Err((IgnoreReason::RuleType, Some(format!("PROTOCOL,{payload}")))),
            };
            return Ok((format!("NETWORK,{network}"), false));
        }
        _ => {}
    }
    let Some((_, target)) = TYPES.iter().find(|(name, _)| *name == kind) else {
        return Err((IgnoreReason::RuleType, Some(kind.to_string())));
    };
    let value = unquote(payload.trim());
    let invalid = || (IgnoreReason::Unreadable, Some(format!("{target},{value}")));
    let value = match *target {
        "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "DOMAIN-WILDCARD" => {
            if value.is_empty() || value.contains(|c: char| c.is_whitespace() || ",()".contains(c))
            {
                return Err(invalid());
            }
            value.to_string()
        }
        "IP-CIDR" | "IP-CIDR6" | "SRC-IP-CIDR" => cidr(value).ok_or_else(invalid)?,
        "DST-PORT" | "SRC-PORT" | "IN-PORT" => {
            let ports = port_range(value).unwrap_or_else(|| value.to_string());
            if !valid_ports(&ports) {
                return Err(invalid());
            }
            ports
        }
        "IP-ASN" if value.parse::<u32>().is_err() => return Err(invalid()),
        "NETWORK" => match value.to_ascii_uppercase().as_str() {
            network @ ("TCP" | "UDP") => network.to_string(),
            _ => return Err(invalid()),
        },
        "URL-REGEX" | "USER-AGENT" if !value.is_empty() => value.to_string(),
        _ if value.is_empty() || value.contains(',') => return Err(invalid()),
        _ => value.to_string(),
    };
    let resolves = matches!(*target, "IP-CIDR" | "IP-CIDR6" | "GEOIP" | "IP-ASN");
    Ok((format!("{target},{value}"), resolves))
}

/// `AND,((A,a),(B,b))`; `NOT` takes one operand.
fn logical(kind: &str, payload: &str) -> Result<(String, bool), Refusal> {
    let unreadable = || (IgnoreReason::Unreadable, Some(format!("{kind},{payload}")));
    let inner = payload
        .trim()
        .strip_prefix('(')
        .and_then(|text| text.strip_suffix(')'))
        .ok_or_else(unreadable)?;
    let mut operands = Vec::new();
    for part in split_rule(inner, true) {
        let operand = part
            .strip_prefix('(')
            .and_then(|text| text.strip_suffix(')'))
            .ok_or_else(unreadable)?;
        let parts = rule_parts(operand);
        let kind = parts
            .first()
            .copied()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if DEVICE_TYPES.contains(&kind.as_str()) {
            return Err(refuse(IgnoreReason::DeviceRule));
        }
        let payload = match kind.as_str() {
            "AND" | "OR" | "NOT" => operand.get(kind.len() + 1..).unwrap_or_default(),
            _ => parts.get(1).copied().unwrap_or_default(),
        };
        operands.push(translate(&kind, payload, true)?.0);
    }
    if operands.is_empty() || (kind == "NOT" && operands.len() != 1) {
        return Err(unreadable());
    }
    let body = operands
        .iter()
        .map(|operand| format!("({operand})"))
        .collect::<Vec<_>>()
        .join(",");
    Ok((format!("{kind},({body})"), false))
}

/// An address or CIDR as `address/prefix`, the address in its usual form.
fn cidr(text: &str) -> Option<String> {
    if text.contains('%') {
        return None;
    }
    let (address, prefix) = match text.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (text, None),
    };
    let address: IpAddr = address.parse().ok()?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(prefix) => prefix.parse::<u8>().ok().filter(|prefix| *prefix <= max)?,
        None => max,
    };
    Some(format!("{address}/{prefix}"))
}

/// `>=443` and the like as the range of ports they cover.
fn port_range(value: &str) -> Option<String> {
    let value = value.trim();
    let operator_end = value.find(|c: char| c.is_ascii_digit())?;
    let (operator, port) = value.split_at(operator_end);
    let port: u32 = port.trim().parse().ok().filter(|port| *port <= 65535)?;
    let (low, high) = match operator.trim() {
        ">=" | "=>" => (port, 65535),
        ">" => (port + 1, 65535),
        "<=" | "=<" => (0, port),
        "<" => (0, port.checked_sub(1)?),
        _ => return None,
    };
    (low <= high).then(|| format!("{low}-{high}"))
}

/// `80`, `80-90`, `80/443/8000-9000`.
fn valid_ports(text: &str) -> bool {
    text.split('/').all(|range| {
        let mut ends = range.splitn(2, '-');
        ends.all(|port| {
            !port.is_empty()
                && port.len() <= 5
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u32>().is_ok_and(|port| port <= 65535)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(line: &str) -> Result<ModuleRule, Refusal> {
        let attachments = BTreeMap::from([("set.list".to_string(), "abc.list".to_string())]);
        RuleReader::new(vec!["Mine".to_string()], &attachments).read(line)
    }

    fn rule(line: &str) -> (String, Policy, bool) {
        let rule = read(line).unwrap();
        (rule.rule, rule.policy, rule.no_resolve)
    }

    #[test]
    fn rules_translate_to_concord_types() {
        assert_eq!(
            rule("DEST-PORT,>=8000,Proxy"),
            (
                "DST-PORT,8000-65535".into(),
                Policy::Named("Proxy".into()),
                false
            )
        );
        assert_eq!(
            rule("IP-CIDR,10.0.0.1,REJECT-TINYGIF,no-resolve"),
            (
                "IP-CIDR,10.0.0.1/32".into(),
                Policy::Builtin("REJECT-TINYGIF"),
                true
            )
        );
        assert_eq!(
            rule("DOMAIN,a.test,REJECT //note"),
            ("DOMAIN,a.test".into(), Policy::Builtin("REJECT"), false)
        );
        assert_eq!(
            rule("DOMAIN-SUFFIX,a.test,no-resolve"),
            (
                "DOMAIN-SUFFIX,a.test".into(),
                Policy::Builtin("DIRECT"),
                false
            )
        );
        assert_eq!(
            rule(r#"AND,((URL-REGEX,"^https?://a\.test/x{1,2}"),(USER-AGENT,Foo*)),REJECT"#),
            (
                r"AND,((URL-REGEX,^https?://a\.test/x{1,2}),(USER-AGENT,Foo*))".into(),
                Policy::Builtin("REJECT"),
                false
            )
        );
        assert_eq!(
            rule("OR,((AND,((DOMAIN,a.test),(PROTOCOL,QUIC))),(SRC-IP,10.0.0.0/8)),proxy"),
            (
                "OR,((AND,((DOMAIN,a.test),(NETWORK,UDP))),(SRC-IP-CIDR,10.0.0.0/8))".into(),
                Policy::Named("PROXY".into()),
                false
            )
        );
    }

    #[test]
    fn rules_concord_cannot_take_are_ignored_with_a_reason() {
        for (line, reason) in [
            ("FINAL,DIRECT", IgnoreReason::FinalRule),
            ("SUBNET,SSID:home,DIRECT", IgnoreReason::DeviceRule),
            ("SCRIPT,x,DIRECT", IgnoreReason::RuleType),
            ("PROTOCOL,QUIC,REJECT", IgnoreReason::RuleType),
            ("DOMAIN,a.test,${policy}", IgnoreReason::Policy),
            ("IP-CIDR,300.0.0.1/8,DIRECT", IgnoreReason::Unreadable),
            (
                "NOT,((DOMAIN,a),(DOMAIN,b)),DIRECT",
                IgnoreReason::Unreadable,
            ),
            ("RULE-SET,other.list,DIRECT", IgnoreReason::NoAttachment),
            ("DOMAIN,a.test,${p} // note", IgnoreReason::Policy),
        ] {
            assert_eq!(
                read(line).err().map(|refusal| refusal.0),
                Some(reason),
                "{line}"
            );
        }
    }

    #[test]
    fn rule_sets_get_a_name_of_their_source() {
        let attachments = BTreeMap::new();
        let mut reader = RuleReader::new(vec!["Mine".to_string()], &attachments);
        let url = reader
            .read("RULE-SET,https://a.test/r.list,REJECT,update-interval=-1")
            .unwrap();
        let again = reader
            .read("DOMAIN-SET,https://a.test/r.list,DIRECT")
            .unwrap();
        let lan = reader.read("RULE-SET,LAN,DIRECT").unwrap();
        reader.read_inline("Mine", "DEST-PORT,53", 9).unwrap();
        let mine = reader.read("RULE-SET,Mine,Proxy").unwrap();
        assert_ne!(url.rule, again.rule);
        assert!(lan.rule.starts_with("RULE-SET,mitm-"));
        assert_eq!(reader.sets.len(), 4);
        assert_eq!(
            reader.sets[0].source,
            RuleSetSource::Url {
                url: "https://a.test/r.list".into(),
                interval: Some(0)
            }
        );
        assert!(reader.sets[1].domain);
        let inline = reader
            .sets
            .iter()
            .find(|set| mine.rule.ends_with(&set.name))
            .unwrap();
        assert_eq!(
            inline.source,
            RuleSetSource::Inline {
                rules: vec![InlineRule {
                    line: 9,
                    rule: "DST-PORT,53".into()
                }]
            }
        );
    }

    #[test]
    fn ip_rewrites_are_rules() {
        assert_eq!(
            ip_rewrite("1.2.3.0/24 = drop").unwrap().rule,
            "IP-CIDR,1.2.3.0/24"
        );
        assert_eq!(
            ip_rewrite("::1 = reflect").err().map(|r| r.0),
            Some(IgnoreReason::Reflect)
        );
    }
}
