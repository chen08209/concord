//! Quantumult X's lines (its sample.conf): `[rewrite_local]`, `[filter_local]` and
//! `[task_local]`, which a snippet also writes outside any section.

use http::header::CONTENT_TYPE;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

use super::IgnoreReason;
use super::loon::{Out, unreadable};
use super::rule::Refusal;
use super::source::unquote;
use crate::mitm::script::EVENT_NETWORK_CHANGED;
use crate::mitm::{
    BodyActionDef, BodyRewriteDef, HeadConditionsDef, HeaderEditDef, HeaderRewriteDef,
    MapLocalBody, MapLocalDef, ScriptDef, ScriptKind, UrlAction, UrlRewriteDef,
};

/// The forms a line of Quantumult X takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// A key of `[mitm]`, `hostname` included.
    Mitm,
    Filter,
    Task,
    Rewrite,
}

const MITM_KEYS: [&str; 6] = [
    "hostname",
    "skip_dst_ip",
    "skip_src_ip",
    "skip_validating_cert",
    "passphrase",
    "p12",
];

const FILTERS: [(&str, &str); 10] = [
    ("host", "DOMAIN"),
    ("host-suffix", "DOMAIN-SUFFIX"),
    ("host-keyword", "DOMAIN-KEYWORD"),
    ("host-wildcard", "DOMAIN-WILDCARD"),
    ("ip-cidr", "IP-CIDR"),
    ("ip6-cidr", "IP-CIDR6"),
    ("geoip", "GEOIP"),
    ("ip-asn", "IP-ASN"),
    ("user-agent", "USER-AGENT"),
    ("final", "FINAL"),
];

/// The options after a filter's policy that pick an interface, which Concord's rules do not.
const INTERFACE_OPTIONS: [&str; 4] = [
    "force-cellular",
    "multi-interface",
    "multi-interface-balance",
    "via-interface",
];

/// Each script rewrite's phase, and whether it waits for the body.
const SCRIPTS: [(&str, ScriptKind, bool); 6] = [
    ("script-request-header", ScriptKind::HttpRequest, false),
    ("script-request-body", ScriptKind::HttpRequest, true),
    ("script-response-header", ScriptKind::HttpResponse, false),
    ("script-response-body", ScriptKind::HttpResponse, true),
    ("script-echo-response", ScriptKind::HttpRequest, false),
    (
        "script-analyze-echo-response",
        ScriptKind::HttpRequest,
        true,
    ),
];

pub(super) fn kind(line: &str) -> Option<Kind> {
    let lower = line.to_ascii_lowercase();
    let head = lower.split(['=', ',']).next().unwrap_or_default().trim();
    if lower.contains('=') && MITM_KEYS.contains(&head) {
        return Some(Kind::Mitm);
    }
    if lower.contains(',') && FILTERS.iter().any(|(name, _)| *name == head) {
        return Some(Kind::Filter);
    }
    if lower.starts_with("event-") || cron(line).is_some() {
        return Some(Kind::Task);
    }
    let mut words = line.split_whitespace();
    let rewrite =
        words.nth(1) == Some("url") && words.next().is_some() || line.contains(" url-and-header ");
    rewrite.then_some(Kind::Rewrite)
}

/// A filter as the rule Concord reads: its type in Surge's name, and its policy with the
/// options Concord has.
pub(super) fn filter(line: &str) -> Result<String, Refusal> {
    let parts: Vec<&str> = line.split(',').map(str::trim).collect();
    let (Some(kind), Some(value)) = (parts.first(), parts.get(1)) else {
        return Err(unreadable("expected type, value, policy"));
    };
    let lower = kind.to_ascii_lowercase();
    if lower == "final" {
        return Err((IgnoreReason::FinalRule, None));
    }
    let Some((_, surge)) = FILTERS.iter().find(|(name, _)| *name == lower) else {
        return Err(unreadable(format!("unknown filter {kind}")));
    };
    let Some(policy) = parts.get(2).filter(|policy| !policy.is_empty()) else {
        return Err(unreadable("expected a policy"));
    };
    let mut rule = format!("{surge},{value},{policy}");
    for option in parts.iter().skip(3) {
        let name = option
            .split('=')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !INTERFACE_OPTIONS.contains(&name.as_str()) {
            rule.push(',');
            rule.push_str(option);
        }
    }
    Ok(rule)
}

/// `pattern url type ...`, or `pattern head url-and-header type ...` whose head is matched
/// against the request's.
pub(super) fn rewrite(line: &str) -> Result<Out, Refusal> {
    let (pattern, head, rest) = match line.split_once(" url-and-header ") {
        Some((before, rest)) => {
            let before = before.trim();
            let (pattern, head) = before
                .split_once(char::is_whitespace)
                .ok_or_else(|| unreadable("expected a pattern and a head"))?;
            (pattern, Some(head.trim().to_string()), rest.trim())
        }
        None => {
            let (pattern, after) = line
                .trim()
                .split_once(char::is_whitespace)
                .unwrap_or_default();
            let after = after.trim_start();
            let rest = after
                .strip_prefix("url")
                .filter(|rest| rest.starts_with(char::is_whitespace))
                .ok_or_else(|| unreadable("expected url or url-and-header"))?;
            (pattern, None, rest.trim())
        }
    };
    let (kind, rest) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    let kind = kind.to_ascii_lowercase();
    let rest = rest.trim();
    let rule = Rule {
        pattern: pattern.to_string(),
        conditions: HeadConditionsDef {
            request: head.clone(),
            response: None,
        },
    };
    if let Some((_, script_kind, body)) = SCRIPTS.iter().find(|(name, ..)| *name == kind) {
        return rule.script(rest, *script_kind, *body);
    }
    match kind.as_str() {
        "reject" | "reject-200" | "reject-img" | "reject-dict" | "reject-array"
            if rest.is_empty() =>
        {
            Ok(rule.url(head, String::new(), reject(&kind)))
        }
        "302" | "307" if rest.is_empty() || rest.contains(char::is_whitespace) => {
            Err(unreadable(format!("{kind} takes one target")))
        }
        "302" | "307" => {
            let action = if kind == "302" {
                UrlAction::Redirect302
            } else {
                UrlAction::Redirect307
            };
            Ok(rule.url(head, rest.to_string(), action))
        }
        "request-header" | "response-header" => {
            let (regex, replacement) = repeated(rest, &kind)?;
            Ok(Out::Header(Ok(HeaderRewriteDef {
                response: kind == "response-header",
                pattern: rule.pattern,
                conditions: rule.conditions,
                edit: HeaderEditDef::Text(regex, replacement),
            })))
        }
        "request-body" | "response-body" => {
            let pair = repeated(rest, &kind)?;
            Ok(rule.body(kind == "response-body", BodyActionDef::Replace(vec![pair])))
        }
        "jsonjq-request-body" | "jsonjq-response-body" if !rest.is_empty() => {
            let jq = BodyActionDef::Jq(unquote(rest).to_string());
            Ok(rule.body(kind == "jsonjq-response-body", jq))
        }
        "echo-response" => rule.echo(rest),
        _ => Err(unreadable(format!("unknown rewrite type {kind}"))),
    }
}

fn reject(kind: &str) -> UrlAction {
    match kind {
        "reject-200" => UrlAction::Reject200,
        "reject-img" => UrlAction::RejectImg,
        "reject-dict" => UrlAction::RejectDict,
        "reject-array" => UrlAction::RejectArray,
        _ => UrlAction::Reject,
    }
}

/// `value type value`, the type written again between the two values a body or head
/// rewrite takes, either of which may hold spaces; authors leave out the space before it
/// when the first value ends in a comma.
fn repeated(rest: &str, kind: &str) -> Result<(String, String), Refusal> {
    let separator = format!("{kind} ");
    rest.match_indices(separator.as_str())
        .find(|(at, _)| *at > 0)
        .and_then(|(at, _)| Some((rest.get(..at)?, rest.get(at + separator.len()..)?)))
        .map(|(first, second)| (first.trim().to_string(), second.trim().to_string()))
        .filter(|(first, _)| !first.is_empty())
        .ok_or_else(|| unreadable(format!("expected a value, {kind} and a value")))
}

struct Rule {
    pattern: String,
    conditions: HeadConditionsDef,
}

impl Rule {
    fn url(self, head: Option<String>, replacement: String, action: UrlAction) -> Out {
        Out::Url(Ok(UrlRewriteDef {
            pattern: self.pattern,
            head,
            replacement,
            action,
        }))
    }

    fn body(self, response: bool, action: BodyActionDef) -> Out {
        Out::Body(Ok(BodyRewriteDef {
            response,
            pattern: self.pattern,
            conditions: self.conditions,
            action,
        }))
    }

    fn script(self, rest: &str, kind: ScriptKind, requires_body: bool) -> Result<Out, Refusal> {
        let path = rest.split_whitespace().next().unwrap_or_default();
        if path.is_empty() {
            return Err(unreadable("expected a script"));
        }
        Ok(Out::Script(ScriptDef {
            pattern: Some(self.pattern),
            conditions: self.conditions,
            requires_body,
            ..script(path, kind)
        }))
    }

    /// `type[\r\nName: value...] echo-response file`: the file sent back with that type and
    /// those headers.
    fn echo(self, rest: &str) -> Result<Out, Refusal> {
        let (head, file) = repeated(rest, "echo-response")?;
        let mut lines = head.split("\\r\\n");
        let mut header = HeaderMap::new();
        let content_type = lines.next().unwrap_or_default().trim();
        let value = |text: &str| {
            HeaderValue::from_str(text)
                .map_err(|_| unreadable(format!("invalid header value {text:?}")))
        };
        header.insert(CONTENT_TYPE, value(content_type)?);
        for line in lines {
            let (name, text) = line
                .split_once(':')
                .ok_or_else(|| unreadable(format!("expected Name: value, not {line:?}")))?;
            let name = HeaderName::from_bytes(name.trim().as_bytes())
                .map_err(|_| unreadable(format!("invalid header name {name:?}")))?;
            header.append(name, value(text.trim())?);
        }
        Ok(Out::MapLocal(Ok(MapLocalDef {
            pattern: self.pattern,
            conditions: self.conditions,
            body: MapLocalBody::File { base64: false },
            data: file,
            status: StatusCode::OK,
            header,
            content_type: "application/octet-stream",
            request: false,
        })))
    }
}

fn script(path: &str, kind: ScriptKind) -> ScriptDef {
    let name = path
        .split(['#', '?'])
        .next()
        .and_then(|path| path.rsplit('/').next())
        .unwrap_or(path);
    ScriptDef {
        name: name.to_string(),
        path: path.to_string(),
        kind,
        pattern: None,
        conditions: HeadConditionsDef::default(),
        requires_body: false,
        binary_body: false,
        max_size: 0,
        cronexp: String::new(),
        event: String::new(),
        timeout: None,
        argument: None,
    }
}

/// A cron expression of five or six fields, then the script.
fn cron(line: &str) -> Option<(String, &str)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let is_field = |field: &&str| {
        field
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "*?/,-#".contains(c))
    };
    [5, 6].into_iter().find_map(|count| {
        let script = fields.get(count)?;
        let fits = fields.iter().take(count).all(is_field)
            && (script.contains("://") || script.contains(".js"));
        if !fits {
            return None;
        }
        let mut rest = line.trim_start();
        for _ in 0..count {
            rest = rest.split_once(char::is_whitespace)?.1.trim_start();
        }
        Some((fields.get(..count)?.join(" "), rest))
    })
}

/// A task: a cron line, `event-network` or `event-interaction`, then the script and
/// `, tag=, enabled=, img-url=, require-devices=`; `None` when `enabled=false`.
pub(super) fn task(line: &str) -> Result<Option<ScriptDef>, Refusal> {
    let lower = line.to_ascii_lowercase();
    let (kind, cronexp, rest) = if let Some(rest) = lower.strip_prefix("event-network") {
        (
            ScriptKind::Event,
            String::new(),
            line.get(line.len() - rest.len()..),
        )
    } else if let Some(rest) = lower.strip_prefix("event-interaction") {
        (
            ScriptKind::Generic,
            String::new(),
            line.get(line.len() - rest.len()..),
        )
    } else if let Some((expression, rest)) = cron(line) {
        (ScriptKind::Cron, expression, Some(rest))
    } else if lower.starts_with("event-") {
        return Err((IgnoreReason::Event, None));
    } else {
        return Err(unreadable("expected a cron expression or an event"));
    };
    let rest = rest.unwrap_or_default().trim();
    let (path, params) = rest.split_once(',').unwrap_or((rest, ""));
    let path = path.trim();
    if path.is_empty() {
        return Err(unreadable("expected a script"));
    }
    let mut def = script(path, kind);
    def.cronexp = cronexp;
    if kind == ScriptKind::Event {
        def.event = EVENT_NETWORK_CHANGED.to_string();
    }
    // Quantumult X sets a task no time limit; the core caps a script at 60 seconds.
    def.timeout = Some(60.0);
    let mut key = String::new();
    for param in params.split(',').map(str::trim) {
        let value = match param.split_once('=') {
            Some((name, value)) => {
                key = name.trim().to_ascii_lowercase();
                value.trim()
            }
            None => param,
        };
        match key.as_str() {
            "tag" if !value.is_empty() => def.name = value.to_string(),
            "enabled" if value.eq_ignore_ascii_case("false") => return Ok(None),
            "require-devices" => {
                return Err((
                    IgnoreReason::Requirement,
                    Some("require-devices".to_string()),
                ));
            }
            _ => {}
        }
    }
    Ok(Some(def))
}
