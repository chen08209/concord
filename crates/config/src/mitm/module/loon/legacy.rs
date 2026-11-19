//! Loon's legacy lines (Rewrite/, Script/): `pattern action values...` split on spaces, and a
//! script's plugin arguments written `argument=[{a},{b}]` or `argument={a,b}`.

use std::collections::BTreeMap;

use http::StatusCode;
use http::header::{HeaderName, HeaderValue};
use serde_json::{Map, Value};

use super::action::{content_type, header_name, jq_path, json_edit, local};
use super::condition::Match;
use super::{Out, Refusal, unreadable};
use crate::mitm::module::ArgumentDef;
use crate::mitm::script::split_script_line;
use crate::mitm::text::decode_base64;
use crate::mitm::{
    BodyActionDef, BodyRewriteDef, HeadConditionsDef, HeaderEditDef, HeaderRewriteDef, LineError,
    MapLocalBody, UrlAction, UrlRewriteDef, parse_url_rewrite,
};

struct Token {
    text: String,
    end: usize,
}

/// Splits on spaces; a run in double quotes, or in single quotes that open a token or a
/// value, stays whole without its quotes.
fn tokens(line: &str) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = line.char_indices().peekable();
    while let Some(&(start, c)) = chars.peek() {
        if c == ' ' || c == '\t' {
            chars.next();
            continue;
        }
        let mut text = String::new();
        let mut quote: Option<char> = None;
        let mut end = line.len();
        while let Some((at, c)) = chars.next() {
            if let Some(mark) = quote {
                if mark == '"' && c == '\\' && chars.peek().is_some_and(|&(_, next)| next == '"') {
                    chars.next();
                    text.push('"');
                } else if c == mark {
                    quote = None;
                } else {
                    text.push(c);
                }
                continue;
            }
            if c == ' ' || c == '\t' {
                end = at;
                break;
            }
            let opens_value = at == start || line.get(..at).is_some_and(|head| head.ends_with('='));
            if c == '"' || (c == '\'' && opens_value) {
                quote = Some(c);
            } else {
                text.push(c);
            }
        }
        if quote.is_some() {
            return None;
        }
        tokens.push(Token { text, end });
    }
    Some(tokens)
}

pub(in crate::mitm::module) fn read_legacy(line: &str) -> Result<Vec<Out>, Refusal> {
    let tokens = tokens(line).ok_or_else(|| unreadable("unclosed quote"))?;
    let (Some(first), Some(second)) = (tokens.first(), tokens.get(1)) else {
        return Err(unreadable("expected a pattern and an action"));
    };
    let pattern = first.text.clone();
    let mut at = 1;
    if matches!(second.text.as_str(), "-" | "_") && tokens.len() > 2 {
        at = 2;
    }
    let action_token = tokens.get(at).unwrap_or(second);
    let action = action_token.text.to_ascii_lowercase();
    let values: Vec<&str> = tokens
        .iter()
        .skip(at + 1)
        .map(|token| token.text.as_str())
        .collect();
    let rest = line.get(action_token.end..).unwrap_or_default().trim();
    let matched = Match {
        url: pattern.clone(),
        single_url: true,
        url_guard: true,
        request: None,
        response: None,
    };
    if let Some(out) = reject(&action, &matched) {
        return Ok(vec![out]);
    }
    let url = |replacement: &str, action: UrlAction| {
        Out::Url(Ok(UrlRewriteDef {
            pattern: pattern.clone(),
            head: None,
            replacement: replacement.to_string(),
            action,
        }))
    };
    let named = |text: &str| match text {
        "302" => Some(UrlAction::Redirect302),
        "307" => Some(UrlAction::Redirect307),
        "header" => Some(UrlAction::Header),
        _ => None,
    };
    if let (Some(kind), Some(target)) = (named(&action), values.first()) {
        return Ok(vec![url(target, kind)]);
    }
    if tokens.len() == 3
        && let Some(kind) = tokens
            .get(2)
            .and_then(|token| named(&token.text.to_ascii_lowercase()))
    {
        return Ok(vec![url(&second.text, kind)]);
    }
    if action == "url" {
        return Ok(vec![Out::Url(parse_url_rewrite(line))]);
    }
    if tokens.len() == 2 && !action.contains('-') {
        return Ok(vec![url(&second.text, UrlAction::Header)]);
    }
    let (response, verb) = match action.strip_prefix("response-") {
        Some(verb) => (true, verb),
        None => (false, action.strip_prefix("request-").unwrap_or(&action)),
    };
    let body = |read: Result<BodyActionDef, LineError>| {
        Out::Body(read.map(|action| BodyRewriteDef {
            response,
            pattern: pattern.clone(),
            conditions: HeadConditionsDef::default(),
            action,
        }))
    };
    Ok(match verb {
        "header-add" | "header-del" | "header-replace" | "header-replace-regex" => {
            match header_edits(verb, &values) {
                Ok(edits) => edits
                    .into_iter()
                    .map(|edit| {
                        Out::Header(Ok(HeaderRewriteDef {
                            response,
                            pattern: pattern.clone(),
                            conditions: HeadConditionsDef::default(),
                            edit,
                        }))
                    })
                    .collect(),
                Err(err) => vec![Out::Header(Err(err))],
            }
        }
        "body-replace-regex" => vec![body(replacements(&values))],
        "body-json-jq" => vec![body(Ok(BodyActionDef::Jq(unquoted(rest).to_string())))],
        "body-json-add" | "body-json-replace" | "body-json-del" => {
            let edit = verb.rsplit('-').next().unwrap_or_default();
            vec![body(json_edits(edit, rest).map(BodyActionDef::Jq))]
        }
        "mock-request-body" | "mock-response-body" if !response => {
            vec![mock(&matched, &values, action == "mock-request-body")]
        }
        _ => return Err(unreadable(format!("unknown action {action}"))),
    })
}

fn reject(action: &str, matched: &Match) -> Option<Out> {
    let kind = match action {
        "reject" | "reject-drop" | "reject-no-drop" => UrlAction::Reject,
        "reject-200" => UrlAction::Reject200,
        "reject-img" | "reject-tinygif" => UrlAction::RejectImg,
        "reject-dict" => UrlAction::RejectDict,
        "reject-array" => UrlAction::RejectArray,
        "reject-video" => {
            let def = local(
                matched,
                MapLocalBody::Text,
                String::new(),
                StatusCode::OK,
                "video/mp4",
                false,
            );
            return Some(Out::MapLocal(Ok(def)));
        }
        _ => return None,
    };
    Some(Out::Url(Ok(UrlRewriteDef {
        pattern: matched.url.clone(),
        head: None,
        replacement: String::new(),
        action: kind,
    })))
}

/// One edit per header the line names: `header-add A a B b`, `header-del A B`,
/// `header-replace-regex A re with B re with` (Loon's rewrite docs, on request headers).
fn header_edits(verb: &str, values: &[&str]) -> Result<Vec<HeaderEditDef>, LineError> {
    let width = match verb {
        "header-del" => 1,
        "header-replace-regex" => 3,
        _ => 2,
    };
    if values.is_empty() || !values.len().is_multiple_of(width) {
        return Err(LineError::syntax(format!(
            "{verb} takes {width} values per header"
        )));
    }
    values
        .chunks(width)
        .map(|chunk| {
            let name = name(chunk.first().copied().unwrap_or_default())?;
            let value = |at: usize| {
                let text = chunk.get(at).copied().unwrap_or_default();
                HeaderValue::from_str(text)
                    .map_err(|_| LineError::invalid(format!("invalid header value {text:?}")))
            };
            Ok(match verb {
                "header-add" => HeaderEditDef::Add(name, value(1)?),
                "header-replace" => HeaderEditDef::Replace(name, value(1)?),
                "header-del" => HeaderEditDef::Del(name),
                _ => HeaderEditDef::ReplaceRegex(
                    name,
                    chunk.get(1).copied().unwrap_or_default().to_string(),
                    chunk.get(2).copied().unwrap_or_default().to_string(),
                ),
            })
        })
        .collect()
}

fn name(text: &str) -> Result<HeaderName, LineError> {
    header_name(text).map_err(|(_, detail)| LineError::unsupported(detail.unwrap_or_default()))
}

fn replacements(values: &[&str]) -> Result<BodyActionDef, LineError> {
    if values.is_empty() || !values.len().is_multiple_of(2) {
        return Err(LineError::syntax("a regex is missing its replacement"));
    }
    Ok(BodyActionDef::Replace(
        values
            .chunks(2)
            .map(|pair| {
                let at = |i: usize| pair.get(i).copied().unwrap_or_default().to_string();
                (at(0), at(1))
            })
            .collect(),
    ))
}

fn unquoted(text: &str) -> &str {
    for mark in ['\'', '"'] {
        if text.len() >= 2 && text.starts_with(mark) && text.ends_with(mark) {
            return text.get(1..text.len() - 1).unwrap_or_default();
        }
    }
    text
}

/// `path value path value` or with `del` `path path`, as one jq expression.
fn json_edits(edit: &str, rest: &str) -> Result<String, LineError> {
    let args = json_args(rest).ok_or_else(|| LineError::syntax("unclosed quote or bracket"))?;
    let path = |text: &str| {
        jq_path(text).map_err(|(_, detail)| LineError::invalid(detail.unwrap_or_default()))
    };
    if args.is_empty() || (edit != "del" && !args.len().is_multiple_of(2)) {
        return Err(LineError::syntax("a key path is missing its value"));
    }
    if edit == "del" {
        let paths = args
            .iter()
            .map(|arg| path(arg))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(format!("del({})", paths.join(", ")));
    }
    let edits = args
        .chunks(2)
        .map(|pair| {
            let at = |i: usize| pair.get(i).map(String::as_str).unwrap_or_default();
            Ok(json_edit(edit, &path(at(0))?, &literal(at(1))))
        })
        .collect::<Result<Vec<_>, LineError>>()?;
    Ok(edits.join(" | "))
}

/// Splits on spaces outside quotes and brackets, keeping both.
fn json_args(text: &str) -> Option<Vec<String>> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    let mut quoted = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if quoted {
            current.push(c);
            if c == '\\' {
                current.extend(chars.next());
            } else if c == '"' {
                quoted = false;
            }
            continue;
        }
        if (c == ' ' || c == '\t') && depth == 0 {
            if !current.is_empty() {
                args.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(c);
        match c {
            '"' => quoted = true,
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            _ => {}
        }
    }
    if quoted || depth != 0 {
        return None;
    }
    if !current.is_empty() {
        args.push(current);
    }
    Some(args)
}

/// A value as JSON: JSON as written, else a string, quoted or not, `\x20` read as a space.
fn literal(text: &str) -> String {
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        return value.to_string();
    }
    let mut inner = text;
    for mark in ['"', '\''] {
        if text.len() > 1 && text.starts_with(mark) && text.ends_with(mark) {
            inner = text.get(1..text.len() - 1).unwrap_or_default();
        }
    }
    let mut out = String::with_capacity(inner.len());
    let mut rest = inner;
    while let Some(at) = rest.find("\\x") {
        out.push_str(rest.get(..at).unwrap_or_default());
        let code = rest
            .get(at + 2..at + 4)
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match code {
            Some(code) => {
                out.push(char::from(code));
                rest = rest.get(at + 4..).unwrap_or_default();
            }
            None => {
                out.push_str("\\x");
                rest = rest.get(at + 2..).unwrap_or_default();
            }
        }
    }
    out.push_str(rest);
    Value::String(out).to_string()
}

fn mock(matched: &Match, values: &[&str], request: bool) -> Out {
    let read = mock_def(matched, values, request);
    if request {
        Out::RequestBodyMock(read)
    } else {
        Out::MapLocal(read)
    }
}

fn mock_def(
    matched: &Match,
    values: &[&str],
    request: bool,
) -> Result<crate::mitm::MapLocalDef, LineError> {
    let mut params = BTreeMap::new();
    for value in values {
        let (key, value) = value
            .split_once('=')
            .ok_or_else(|| LineError::syntax(format!("expected key=value, got {value:?}")))?;
        params.insert(key.to_ascii_lowercase(), value);
    }
    let kind = params.get("data-type").copied().unwrap_or("text");
    let content_type = content_type(kind)
        .ok_or_else(|| LineError::unknown(format!("unknown data-type {kind:?}")))?;
    let base64 = params
        .get("mock-data-is-base64")
        .is_some_and(|flag| flag.eq_ignore_ascii_case("true"));
    let (body, data) = match (params.get("data-path"), base64) {
        (Some(path), base64) => (MapLocalBody::File { base64 }, (*path).to_string()),
        (None, true) => {
            let data = params.get("data").copied().unwrap_or_default();
            (MapLocalBody::Base64(decode_base64(data)?), String::new())
        }
        (None, false) => (
            MapLocalBody::Text,
            params.get("data").copied().unwrap_or_default().to_string(),
        ),
    };
    let mut status = StatusCode::OK;
    if let Some(text) = params.get("status-code").filter(|_| !request) {
        status = text
            .parse::<u16>()
            .ok()
            .filter(|code| (200..=599).contains(code))
            .and_then(|code| StatusCode::from_u16(code).ok())
            .ok_or_else(|| LineError::invalid(format!("invalid status-code {text:?}")))?;
    }
    Ok(local(matched, body, data, status, content_type, request))
}

/// A legacy script's `argument=[{a},{b}]` or `argument={a,b}`: the arguments it names, by
/// name and keeping their types (Loon's script docs, on the old syntax and the new).
pub(in crate::mitm::module) fn legacy_script(
    raw: &str,
    arguments: &[ArgumentDef],
    values: &BTreeMap<String, String>,
) -> Option<Value> {
    let (_, _, params) = split_script_line(raw).ok()?;
    let text = params.get("argument")?.trim();
    let names: Vec<&str> =
        if let Some(list) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
            list.split(',')
                .map(|item| {
                    item.trim()
                        .strip_prefix('{')
                        .and_then(|t| t.strip_suffix('}'))
                })
                .collect::<Option<_>>()?
        } else {
            let list = text.strip_prefix('{')?.strip_suffix('}')?;
            list.split(',').map(str::trim).collect()
        };
    let mut object = Map::new();
    for name in names {
        let argument = arguments.iter().find(|argument| argument.name == name)?;
        object.insert(
            name.to_string(),
            argument.typed(values).unwrap_or(Value::Null),
        );
    }
    (!object.is_empty()).then_some(Value::Object(object))
}
