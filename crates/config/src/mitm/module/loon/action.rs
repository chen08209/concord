//! A new-syntax rewrite's actions as Concord's definitions.

use http::StatusCode;
use http::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;

use super::condition::{Match, scoped};
use super::lexer::Token;
use super::{Cursor, Out, Refusal, Scope, condition, unreadable};
use crate::mitm::text::{canonical_header, decode_base64};
use crate::mitm::{
    BodyActionDef, BodyRewriteDef, HeadConditionsDef, HeaderEditDef, HeaderRewriteDef,
    MapLocalBody, MapLocalDef, UrlAction, UrlRewriteDef,
};

/// The content types Loon's mocks name (Loon's rewrite docs, on mocking a response body).
const CONTENT_TYPES: [(&str, &str); 14] = [
    ("json", "application/json"),
    ("text", "text/plain; charset=utf-8"),
    ("text/event-stream", "text/event-stream"),
    ("css", "text/css; charset=utf-8"),
    ("html", "text/html; charset=utf-8"),
    ("javascript", "text/javascript; charset=utf-8"),
    ("plain", "text/plain; charset=utf-8"),
    ("png", "image/png"),
    ("gif", "image/gif"),
    ("jpeg", "image/jpeg"),
    ("tiff", "image/tiff"),
    ("svg", "image/svg+xml"),
    ("mp4", "video/mp4"),
    ("form-data", "multipart/form-data"),
];

pub(super) fn content_type(name: &str) -> Option<&'static str> {
    let name = name.to_ascii_lowercase();
    CONTENT_TYPES
        .iter()
        .find(|(each, _)| *each == name)
        .map(|(_, content_type)| *content_type)
}

enum Arg {
    One(Token),
    Many(Vec<Token>),
}

pub(super) fn read(
    cursor: &mut Cursor,
    scope: &Scope<'_>,
    matched: &Match,
    response: bool,
) -> Result<Vec<Out>, Refusal> {
    let mut out = Vec::new();
    let mut mocks = 0;
    let mut other_than_headers = false;
    loop {
        let Some(Token::Word(name)) = cursor.next() else {
            return Err(unreadable("expected an action"));
        };
        let args = arguments(cursor)?;
        let action = Action {
            scope,
            matched,
            response,
            name: &name,
        };
        if name.starts_with("response.body.mock") {
            mocks += 1;
        } else if !name.starts_with("response.header.") {
            other_than_headers = true;
        }
        action.check_phase()?;
        let count = batch(&args)?;
        match count {
            None => {
                let args: Vec<Token> = args
                    .into_iter()
                    .filter_map(|arg| match arg {
                        Arg::One(token) => Some(token),
                        Arg::Many(_) => None,
                    })
                    .collect();
                action.one(&args, &mut out)?;
            }
            Some(count) => action.many(args, count, &mut out)?,
        }
        if !cursor.symbol("|") {
            break;
        }
    }
    if !cursor.done() {
        return Err(unreadable("unexpected text after the actions"));
    }
    if mocks > 1 || (mocks == 1 && other_than_headers) {
        return Err(unreadable(
            "a response mock goes alone or with response.header actions",
        ));
    }
    if mocks == 1 && matched.response.is_some() {
        return Err(unreadable("a response mock cannot test the response"));
    }
    Ok(out)
}

fn arguments(cursor: &mut Cursor) -> Result<Vec<Arg>, Refusal> {
    cursor.expect("(")?;
    let mut args = Vec::new();
    if cursor.symbol(")") {
        return Ok(args);
    }
    loop {
        if cursor.symbol("[") {
            let mut items = Vec::new();
            loop {
                items.push(cursor.next().ok_or_else(|| unreadable("unclosed ["))?);
                if !cursor.symbol(",") {
                    break;
                }
            }
            cursor.expect("]")?;
            args.push(Arg::Many(items));
        } else {
            args.push(Arg::One(
                cursor
                    .next()
                    .ok_or_else(|| unreadable("expected an argument"))?,
            ));
        }
        if !cursor.symbol(",") {
            break;
        }
    }
    cursor.expect(")")?;
    Ok(args)
}

/// The length of a batch, whose arguments are all arrays of one length.
fn batch(args: &[Arg]) -> Result<Option<usize>, Refusal> {
    let lengths: Vec<Option<usize>> = args
        .iter()
        .map(|arg| match arg {
            Arg::One(_) => None,
            Arg::Many(items) => Some(items.len()),
        })
        .collect();
    if lengths.iter().all(Option::is_none) {
        return Ok(None);
    }
    let first = lengths.first().copied().flatten();
    if lengths.iter().any(|length| *length != first) || first == Some(0) {
        return Err(unreadable(
            "a batch takes arrays of one length for every argument",
        ));
    }
    Ok(first)
}

struct Action<'a> {
    scope: &'a Scope<'a>,
    matched: &'a Match,
    response: bool,
    name: &'a str,
}

impl Action<'_> {
    fn check_phase(&self) -> Result<(), Refusal> {
        let (side, _) = self.name.split_once('.').unwrap_or_default();
        let phase_bound = match side {
            "request" => Some(false),
            "response" => Some(true),
            _ => None,
        };
        match phase_bound {
            Some(response) if response != self.response => Err(unreadable(format!(
                "{} does not run in this phase",
                self.name
            ))),
            None if self.matched.response.is_some() => Err(condition(format!(
                "{} runs before the response it tests",
                self.name
            ))),
            _ => Ok(()),
        }
    }

    fn conditions(&self) -> HeadConditionsDef {
        HeadConditionsDef {
            request: self.matched.request.clone(),
            response: self.matched.response.clone(),
        }
    }

    fn many(&self, args: Vec<Arg>, count: usize, out: &mut Vec<Out>) -> Result<(), Refusal> {
        let columns: Vec<Vec<Token>> = args
            .into_iter()
            .map(|arg| match arg {
                Arg::Many(items) => items,
                Arg::One(token) => vec![token],
            })
            .collect();
        let row = |at: usize| -> Vec<Token> {
            columns
                .iter()
                .filter_map(|column| column.get(at).cloned())
                .collect()
        };
        let verb = self.name.rsplit('.').next().unwrap_or_default();
        if self.name.contains(".json.") {
            let expression = if verb == "delete" {
                let paths = (0..count)
                    .map(|at| match row(at).as_slice() {
                        [path] => jq_path(&self.scope.string(path)?),
                        _ => Err(unreadable("json.delete takes key paths")),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                format!("del({})", paths.join(", "))
            } else {
                (0..count)
                    .map(|at| self.json_edit(verb, &row(at)))
                    .collect::<Result<Vec<_>, _>>()?
                    .join(" | ")
            };
            out.push(self.body(BodyActionDef::Jq(expression)));
            return Ok(());
        }
        if self.name.ends_with(".body.replace") {
            let pairs = (0..count)
                .map(|at| self.replacement(&row(at)))
                .collect::<Result<Vec<_>, _>>()?;
            out.push(self.body(BodyActionDef::Replace(pairs)));
            return Ok(());
        }
        if !self.name.contains(".header.") {
            return Err(unreadable(format!("{} takes no arrays", self.name)));
        }
        (0..count).try_for_each(|at| self.one(&row(at), out))
    }

    fn one(&self, args: &[Token], out: &mut Vec<Out>) -> Result<(), Refusal> {
        let name = self.name;
        let verb = name.rsplit('.').next().unwrap_or_default();
        match (name, args) {
            ("url.replace", [target]) => out.push(self.url(UrlAction::Header, target)?),
            ("redirect", [Token::Number(status), target]) => {
                let action = match status.as_str() {
                    "302" => UrlAction::Redirect302,
                    "307" => UrlAction::Redirect307,
                    _ => return Err(unreadable("redirect takes 302 or 307")),
                };
                out.push(self.url(action, target)?);
            }
            ("reject" | "reject_img" | "reject_dict" | "reject_array" | "reject_video", _) => {
                out.push(self.reject(args)?);
            }
            (_, _) if name.contains(".header.") => self.header(verb, args, out)?,
            (_, _) if name.ends_with(".body.replace") => {
                let pair = self.replacement(args)?;
                out.push(self.body(BodyActionDef::Replace(vec![pair])));
            }
            (_, [path]) if name.ends_with(".json.jq_file") => {
                out.push(self.body(BodyActionDef::JqFile(self.scope.string(path)?)));
            }
            (_, [expression]) if name.ends_with(".json.jq") => {
                out.push(self.body(BodyActionDef::Jq(self.scope.string(expression)?)));
            }
            (_, _) if name.contains(".json.") => {
                let edit = self.json_edit(verb, args)?;
                out.push(self.body(BodyActionDef::Jq(edit)));
            }
            (_, _) if name.contains(".body.mock") => out.push(self.mock(args)?),
            _ => return Err(unreadable(format!("{name} with these arguments"))),
        }
        Ok(())
    }

    fn url(&self, action: UrlAction, target: &Token) -> Result<Out, Refusal> {
        if !self.matched.single_url {
            return Err(unreadable(format!(
                "{} needs one URL regex every match passes",
                self.name
            )));
        }
        let Token::Template(parts) = target else {
            return Err(unreadable("expected a string"));
        };
        Ok(Out::Url(Ok(UrlRewriteDef {
            pattern: self.matched.url.clone(),
            head: self.matched.request.clone(),
            replacement: self.scope.text(parts, true)?,
            action,
        })))
    }

    fn reject(&self, args: &[Token]) -> Result<Out, Refusal> {
        let (status, body) = match args {
            [Token::Number(status)] => (status, None),
            [Token::Number(status), body] if self.name == "reject" => {
                (status, Some(self.scope.string(body)?))
            }
            _ => return Err(unreadable(format!("{} takes a status", self.name))),
        };
        let status: u16 = status
            .parse()
            .ok()
            .filter(|code| (100..=599).contains(code))
            .ok_or_else(|| unreadable(format!("invalid status {status}")))?;
        let quick = match self.name {
            "reject" => UrlAction::Reject200,
            "reject_img" => UrlAction::RejectImg,
            "reject_dict" => UrlAction::RejectDict,
            "reject_array" => UrlAction::RejectArray,
            _ => UrlAction::Header,
        };
        if status == 200 && body.is_none() && quick != UrlAction::Header {
            return Ok(Out::Url(Ok(UrlRewriteDef {
                pattern: self.matched.url.clone(),
                head: self.matched.request.clone(),
                replacement: String::new(),
                action: quick,
            })));
        }
        if status < 200 {
            return Err(condition("an informational status ends no exchange"));
        }
        let (body, data, content_type) = match self.name {
            "reject_img" => (MapLocalBody::TinyGif, String::new(), "image/gif"),
            "reject_dict" => (MapLocalBody::Text, "{}".to_string(), "application/json"),
            "reject_array" => (MapLocalBody::Text, "[]".to_string(), "application/json"),
            "reject_video" => (MapLocalBody::Text, String::new(), "video/mp4"),
            _ => (
                MapLocalBody::Text,
                body.unwrap_or_default(),
                "text/plain; charset=utf-8",
            ),
        };
        Ok(Out::MapLocal(Ok(local(
            self.matched,
            body,
            data,
            status_code(status)?,
            content_type,
            false,
        ))))
    }

    fn header(&self, verb: &str, args: &[Token], out: &mut Vec<Out>) -> Result<(), Refusal> {
        let name = header_name(
            &self.scope.string(
                args.first()
                    .ok_or_else(|| unreadable("expected a header name"))?,
            )?,
        )?;
        let value = |at: usize| -> Result<HeaderValue, Refusal> {
            let text = self.scope.string(
                args.get(at)
                    .ok_or_else(|| unreadable("expected a header value"))?,
            )?;
            HeaderValue::from_str(&text)
                .map_err(|_| unreadable(format!("invalid header value {text:?}")))
        };
        let edits = match (verb, args.len()) {
            ("add", 2) => vec![HeaderEditDef::Add(name, value(1)?)],
            ("set", 2) => vec![
                HeaderEditDef::Del(name.clone()),
                HeaderEditDef::Add(name, value(1)?),
            ],
            ("del", 1) => vec![HeaderEditDef::Del(name)],
            ("replace", 3) => {
                let (pattern, with) = self.replacement(args.get(1..).unwrap_or_default())?;
                vec![HeaderEditDef::ReplaceRegex(name, pattern, with)]
            }
            _ => return Err(unreadable(format!("{} with these arguments", self.name))),
        };
        for edit in edits {
            out.push(Out::Header(Ok(HeaderRewriteDef {
                response: self.response,
                pattern: self.matched.url.clone(),
                conditions: self.conditions(),
                edit,
            })));
        }
        Ok(())
    }

    /// A regex and its replacement, whose `$n` are the regex's own groups.
    fn replacement(&self, args: &[Token]) -> Result<(String, String), Refusal> {
        match args {
            [Token::Regex { source, flags }, with] => {
                Ok((scoped(source, flags), self.scope.string(with)?))
            }
            _ => Err(unreadable("expected a regex and its replacement")),
        }
    }

    fn body(&self, action: BodyActionDef) -> Out {
        Out::Body(Ok(BodyRewriteDef {
            response: self.response,
            pattern: self.matched.url.clone(),
            conditions: self.conditions(),
            action,
        }))
    }

    fn json_edit(&self, verb: &str, args: &[Token]) -> Result<String, Refusal> {
        let path = jq_path(
            &self.scope.string(
                args.first()
                    .ok_or_else(|| unreadable("expected a key path"))?,
            )?,
        )?;
        let value = || -> Result<String, Refusal> {
            let token = args.get(1).ok_or_else(|| unreadable("expected a value"))?;
            self.json_value(token).map(|value| value.to_string())
        };
        match (verb, args.len()) {
            ("add", 2) => Ok(json_edit("add", &path, &value()?)),
            ("replace", 2) => Ok(json_edit("replace", &path, &value()?)),
            ("delete", 1) => Ok(json_edit("del", &path, "")),
            _ => Err(unreadable(format!("{} with these arguments", self.name))),
        }
    }

    fn json_value(&self, token: &Token) -> Result<Value, Refusal> {
        match token {
            Token::Number(text) => {
                serde_json::from_str(text).map_err(|err| unreadable(err.to_string()))
            }
            Token::Word(word) => match word.as_str() {
                "true" => Ok(Value::Bool(true)),
                "false" => Ok(Value::Bool(false)),
                "null" => Ok(Value::Null),
                _ => Err(unreadable(format!("unexpected {word}"))),
            },
            Token::Var(name) => self.scope.argument(name),
            other => self.scope.string(other).map(Value::String),
        }
    }

    fn mock(&self, args: &[Token]) -> Result<Out, Refusal> {
        let request = !self.response;
        let file = self.name.ends_with("_file");
        let (kind, data) = match args {
            [kind, data, ..] => (self.scope.string(kind)?, self.scope.string(data)?),
            _ => return Err(unreadable("a mock takes a content type and its data")),
        };
        let content_type = content_type(&kind)
            .ok_or_else(|| unreadable(format!("unknown content type {kind:?}")))?;
        let (status, base64) = match (request, args.get(2..).unwrap_or_default()) {
            (_, []) => (200, None),
            (true, [flag]) => (200, Some(flag)),
            (false, [Token::Number(status)]) => (parse_status(status)?, None),
            (false, [Token::Number(status), flag]) => (parse_status(status)?, Some(flag)),
            _ => return Err(unreadable(format!("{} with these arguments", self.name))),
        };
        let base64 = match base64 {
            None => false,
            Some(Token::Word(word)) if word == "true" || word == "false" => word == "true",
            Some(_) => return Err(unreadable("the base64 flag is true or false")),
        };
        let body = match (file, base64) {
            (true, base64) => MapLocalBody::File { base64 },
            (false, true) => {
                MapLocalBody::Base64(decode_base64(&data).map_err(|err| unreadable(err.message))?)
            }
            (false, false) => MapLocalBody::Text,
        };
        let data = if matches!(body, MapLocalBody::Base64(_)) {
            String::new()
        } else {
            data
        };
        let def = local(
            self.matched,
            body,
            data,
            status_code(status)?,
            content_type,
            request,
        );
        Ok(if request {
            Out::RequestBodyMock(Ok(def))
        } else {
            Out::MapLocal(Ok(def))
        })
    }
}

fn parse_status(text: &str) -> Result<u16, Refusal> {
    text.parse::<u16>()
        .ok()
        .filter(|code| (200..=599).contains(code))
        .ok_or_else(|| unreadable(format!("invalid status {text}")))
}

fn status_code(status: u16) -> Result<StatusCode, Refusal> {
    StatusCode::from_u16(status).map_err(|_| unreadable(format!("invalid status {status}")))
}

pub(super) fn local(
    matched: &Match,
    body: MapLocalBody,
    data: String,
    status: StatusCode,
    content_type: &'static str,
    request: bool,
) -> MapLocalDef {
    let mut header = HeaderMap::new();
    header.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    MapLocalDef {
        pattern: matched.url.clone(),
        conditions: HeadConditionsDef {
            request: matched.request.clone(),
            response: None,
        },
        body,
        data,
        status,
        header,
        content_type,
        request,
    }
}

pub(super) fn header_name(text: &str) -> Result<HeaderName, Refusal> {
    let name = canonical_header(text);
    if matches!(name.as_str(), "Content-Length" | "Transfer-Encoding") {
        return Err(condition(format!(
            "{name} frames the message and cannot be rewritten"
        )));
    }
    HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| unreadable(format!("invalid header name {name:?}")))
}

/// Loon and Stash write a JSON key path dotted, `[n]` for an array's item: `data.apps[0].name`.
/// A leading `$` is JSONPath's root, which authors write though neither documents it.
pub(in crate::mitm::module) fn jq_path(path: &str) -> Result<String, Refusal> {
    let path = match path.strip_prefix('$') {
        Some(rest) if rest.is_empty() || rest.starts_with(['.', '[']) => {
            rest.strip_prefix('.').unwrap_or(rest)
        }
        _ => path,
    };
    let mut out = String::new();
    for segment in path.split('.') {
        let key_end = segment.find('[').unwrap_or(segment.len());
        let (key, indexes) = segment.split_at(key_end);
        if key.contains(']') || !indexes_valid(indexes) {
            return Err(unreadable(format!("invalid key path {path:?}")));
        }
        if !key.is_empty() {
            let plain = key
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if plain {
                out.push('.');
                out.push_str(key);
            } else {
                out.push('.');
                out.push_str(&Value::String(key.to_string()).to_string());
            }
        }
        out.push_str(indexes);
    }
    if out.is_empty() {
        return Ok(".".to_string());
    }
    if !out.starts_with('.') {
        out.insert(0, '.');
    }
    Ok(out)
}

fn indexes_valid(indexes: &str) -> bool {
    let mut rest = indexes;
    while !rest.is_empty() {
        let Some(inner) = rest.strip_prefix('[') else {
            return false;
        };
        let Some(end) = inner.find(']') else {
            return false;
        };
        let digits = inner.get(..end).unwrap_or_default();
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        rest = inner.get(end + 1..).unwrap_or_default();
    }
    true
}

/// Loon's JSON edits as jq: `replace` leaves a path that is not there as it is.
pub(super) fn json_edit(edit: &str, path: &str, value: &str) -> String {
    match edit {
        "add" => format!("{path} = {value}"),
        "replace" => format!("if {path} != null then {path} = {value} else . end"),
        _ => format!("del({path})"),
    }
}
