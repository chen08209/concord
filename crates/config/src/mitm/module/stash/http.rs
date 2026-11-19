//! An override's `http` lists and `cron` scripts, each item as Concord's definition.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::header::CONTENT_TYPE;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde_json::{Map, Value};

use super::{item_line, text_of};
use crate::mitm::module::loon::{Out, jq_path, unreadable};
use crate::mitm::module::resource::InlineFile;
use crate::mitm::module::rule::Refusal;
use crate::mitm::module::surge::Reader;
use crate::mitm::module::{HostLine, IgnoreReason, ModuleLine};
use crate::mitm::modules::stored_name;
use crate::mitm::{
    BodyActionDef, BodyRewriteDef, HeadConditionsDef, HeaderEditDef, HeaderRewriteDef,
    MapLocalBody, MapLocalDef, ScriptDef, ScriptKind, UrlAction, UrlRewriteDef, host_items,
};
use crate::yaml::SourceLines;

pub(super) fn read(
    reader: &mut Reader<'_>,
    http: &Map<String, Value>,
    scripts: &Map<String, Value>,
    lines: &SourceLines,
) {
    for (key, value) in http {
        let line = lines.keys.get(&format!("http.{key}")).copied().unwrap_or(1);
        let Value::Array(items) = value else {
            let reason = match key.as_str() {
                "ca" | "ca-passphrase" => IgnoreReason::ManagedCa,
                _ => IgnoreReason::Setting,
            };
            reader.ignore(line, reason, Some(format!("http.{key}")));
            continue;
        };
        let item_lines = lines
            .nested
            .get(&format!("http.{key}"))
            .map(Vec::as_slice)
            .unwrap_or_default();
        for (at, item) in items.iter().enumerate() {
            let number = item_line(item_lines, at, line);
            let read = match key.as_str() {
                "mitm" => {
                    mitm(reader, &text_of(item), number);
                    continue;
                }
                "force-http-engine" => {
                    reader.def.lists.force_http_hostname.push(ModuleLine {
                        line: number,
                        def: host_items(text_of(item).trim()),
                    });
                    continue;
                }
                "url-rewrite" | "rewrite" => url_rewrite(&text_of(item)),
                "header-rewrite" => header_rewrite(&text_of(item)),
                "body-rewrite" => body_rewrite(&text_of(item)),
                "mock" => mock(item),
                "script" => script(item, false, scripts)
                    .and_then(|(def, payload)| locate(reader, def, payload, number)),
                _ => {
                    reader.ignore(number, IgnoreReason::Setting, Some(format!("http.{key}")));
                    continue;
                }
            };
            place(reader, read, number);
        }
    }
}

pub(super) fn cron(
    reader: &mut Reader<'_>,
    cron: &Map<String, Value>,
    scripts: &Map<String, Value>,
    lines: &SourceLines,
) {
    for (key, value) in cron {
        let line = lines.keys.get(&format!("cron.{key}")).copied().unwrap_or(1);
        let Value::Array(items) = value.clone() else {
            reader.ignore(line, IgnoreReason::Setting, Some(format!("cron.{key}")));
            continue;
        };
        if key != "script" {
            reader.ignore(line, IgnoreReason::Setting, Some(format!("cron.{key}")));
            continue;
        }
        let item_lines = lines
            .nested
            .get("cron.script")
            .map(Vec::as_slice)
            .unwrap_or_default();
        for (at, item) in items.iter().enumerate() {
            let number = item_line(item_lines, at, line);
            let read = script(item, true, scripts)
                .and_then(|(def, payload)| locate(reader, def, payload, number));
            place(reader, read, number);
        }
    }
}

fn place(reader: &mut Reader<'_>, read: Result<Option<Out>, Refusal>, number: u32) {
    match read {
        Ok(Some(out)) => reader.place(number, out),
        Ok(None) => {}
        Err((reason, detail)) => reader.ignore(number, reason, detail),
    }
}

/// A host on 443 unless it names its port, and on every port with `:*`.
fn mitm(reader: &mut Reader<'_>, item: &str, number: u32) {
    let item = item.trim();
    let host = match item.rsplit_once(':') {
        Some((host, "*")) => format!("{host}:0"),
        Some((_, port)) if port.parse::<u16>().is_ok() => item.to_string(),
        _ => format!("{item}:443"),
    };
    reader.def.lists.hostname.push(ModuleLine {
        line: number,
        def: HostLine {
            insert: false,
            items: host_items(&host),
        },
    });
}

/// `pattern replacement type`, a rejection with `-` or nothing for the replacement.
fn url_rewrite(line: &str) -> Result<Option<Out>, Refusal> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let (pattern, replacement, kind) = match fields.as_slice() {
        [pattern, kind] => (*pattern, "", kind.to_ascii_lowercase()),
        [pattern, replacement, kind] => (*pattern, *replacement, kind.to_ascii_lowercase()),
        _ => return Err(unreadable("expected pattern, replacement and type")),
    };
    let action = match kind.as_str() {
        "reject" => UrlAction::Reject,
        "reject-200" => UrlAction::Reject200,
        "reject-img" => UrlAction::RejectImg,
        "reject-dict" => UrlAction::RejectDict,
        "reject-array" => UrlAction::RejectArray,
        "302" if !replacement.is_empty() => UrlAction::Redirect302,
        "307" if !replacement.is_empty() => UrlAction::Redirect307,
        "transparent" | "header" if !replacement.is_empty() => UrlAction::Header,
        other => return Err(unreadable(format!("unknown type {other}"))),
    };
    let rejects = !matches!(
        action,
        UrlAction::Redirect302 | UrlAction::Redirect307 | UrlAction::Header
    );
    Ok(Some(Out::Url(Ok(UrlRewriteDef {
        pattern: pattern.to_string(),
        head: None,
        replacement: if rejects {
            String::new()
        } else {
            replacement.to_string()
        },
        action,
    }))))
}

/// `pattern request-add|del|replace|replace-regex name [value | regex replacement]`, and the
/// same with `response-`.
fn header_rewrite(line: &str) -> Result<Option<Out>, Refusal> {
    let mut fields = line.trim().splitn(4, char::is_whitespace);
    let (Some(pattern), Some(action), Some(name)) = (fields.next(), fields.next(), fields.next())
    else {
        return Err(unreadable("expected pattern, action and header"));
    };
    let rest = fields.next().unwrap_or_default().trim();
    let (response, edit) = phase(action)?;
    let name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| unreadable(format!("invalid header name {name:?}")))?;
    let value = || {
        HeaderValue::from_str(rest)
            .map_err(|_| unreadable(format!("invalid header value {rest:?}")))
    };
    let edit = match edit {
        "add" => HeaderEditDef::Add(name, value()?),
        "del" => HeaderEditDef::Del(name),
        "replace" => HeaderEditDef::Replace(name, value()?),
        "replace-regex" => {
            let (regex, replacement) = rest
                .split_once(char::is_whitespace)
                .ok_or_else(|| unreadable("expected a regex and its replacement"))?;
            HeaderEditDef::ReplaceRegex(name, regex.to_string(), replacement.trim().to_string())
        }
        other => return Err(unreadable(format!("unknown action {other}"))),
    };
    Ok(Some(Out::Header(Ok(HeaderRewriteDef {
        response,
        pattern: pattern.to_string(),
        conditions: HeadConditionsDef::default(),
        edit,
    }))))
}

/// `request-…` or `response-…`: whether it is the response's, and the action.
fn phase(action: &str) -> Result<(bool, &str), Refusal> {
    if let Some(edit) = action.strip_prefix("request-") {
        return Ok((false, edit));
    }
    action
        .strip_prefix("response-")
        .map(|edit| (true, edit))
        .ok_or_else(|| unreadable(format!("unknown action {action}")))
}

/// `pattern action expression`: `replace-regex` pairs, `jq`, or the JSON edits.
fn body_rewrite(line: &str) -> Result<Option<Out>, Refusal> {
    let mut fields = line.trim().splitn(3, char::is_whitespace);
    let (Some(pattern), Some(action)) = (fields.next(), fields.next()) else {
        return Err(unreadable("expected pattern and action"));
    };
    let rest = fields.next().unwrap_or_default().trim();
    let (response, edit) = phase(action)?;
    let args: Vec<&str> = rest.split_whitespace().collect();
    let action = match edit {
        "replace-regex" if !args.is_empty() && args.len().is_multiple_of(2) => {
            BodyActionDef::Replace(
                args.chunks(2)
                    .filter_map(|pair| Some((pair.first()?.to_string(), pair.get(1)?.to_string())))
                    .collect(),
            )
        }
        "jq" if !rest.is_empty() => BodyActionDef::Jq(rest.to_string()),
        "json-add" | "json-replace" | "json-del" => BodyActionDef::Jq(json_edits(edit, &args)?),
        other => {
            return Err(unreadable(format!(
                "unknown action {other} or its arguments"
            )));
        }
    };
    Ok(Some(Out::Body(Ok(BodyRewriteDef {
        response,
        pattern: pattern.to_string(),
        conditions: HeadConditionsDef::default(),
        action,
    }))))
}

/// Stash's JSON edits as jq: `replace` and `del` touch a value that is neither null nor
/// false, `add` writes one that is missing or null.
fn json_edits(edit: &str, args: &[&str]) -> Result<String, Refusal> {
    let delete = edit == "json-del";
    let width = if delete { 1 } else { 2 };
    if args.is_empty() || !args.len().is_multiple_of(width) {
        return Err(unreadable(format!(
            "{edit} takes paths{}",
            if delete { "" } else { " and values" }
        )));
    }
    const PRESENT: &str = ". != null and . != false";
    args.chunks(width)
        .map(|chunk| {
            let path = jq_path(chunk.first().copied().unwrap_or_default())?;
            let value = chunk.get(1).map(|value| literal(value));
            Ok(match (edit, value) {
                ("json-add", Some(value)) => {
                    format!("if {path} == null then {path} = {value} else . end")
                }
                ("json-replace", Some(value)) => {
                    format!("if ({path} | {PRESENT}) then {path} = {value} else . end")
                }
                _ => format!("if ({path} | {PRESENT}) then del({path}) else . end"),
            })
        })
        .collect::<Result<Vec<_>, Refusal>>()
        .map(|edits| edits.join(" | "))
}

/// A value as written when it is JSON, else as a string.
fn literal(text: &str) -> String {
    match serde_json::from_str::<Value>(text) {
        Ok(value) => value.to_string(),
        Err(_) => Value::String(text.to_string()).to_string(),
    }
}

/// `match`, `text` or `base64`, `status-code` (200 by default) and `headers`.
fn mock(item: &Value) -> Result<Option<Out>, Refusal> {
    let pattern = item
        .get("match")
        .map(text_of)
        .filter(|text| !text.is_empty());
    let Some(pattern) = pattern else {
        return Err(unreadable("a mock needs match"));
    };
    let (body, data, content_type) = match (item.get("base64"), item.get("text")) {
        (Some(encoded), _) => {
            let bytes = STANDARD
                .decode(text_of(encoded).trim())
                .map_err(|err| unreadable(format!("invalid base64: {err}")))?;
            (
                MapLocalBody::Base64(bytes),
                String::new(),
                "application/octet-stream",
            )
        }
        (None, text) => (
            MapLocalBody::Text,
            text.map(text_of).unwrap_or_default(),
            "text/plain; charset=utf-8",
        ),
    };
    let status = match item.get("status-code") {
        None => StatusCode::OK,
        Some(code) => text_of(code)
            .trim()
            .parse::<u16>()
            .ok()
            .and_then(|code| StatusCode::from_u16(code).ok())
            .ok_or_else(|| unreadable(format!("invalid status-code {}", text_of(code))))?,
    };
    let mut header = HeaderMap::new();
    header.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Some(Value::Object(headers)) = item.get("headers") {
        for (name, value) in headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| unreadable(format!("invalid header name {name:?}")))?;
            header.remove(&name);
            let values = match value {
                Value::Array(values) => values.iter().map(text_of).collect(),
                other => vec![text_of(other)],
            };
            for value in values {
                let value = HeaderValue::from_str(&value)
                    .map_err(|_| unreadable(format!("invalid header value {value:?}")))?;
                header.append(name.clone(), value);
            }
        }
    }
    Ok(Some(Out::MapLocal(Ok(MapLocalDef {
        pattern,
        conditions: HeadConditionsDef::default(),
        body,
        data,
        status,
        header,
        content_type,
        request: false,
    }))))
}

/// An `http.script` or `cron.script` item, with the script its provider carries as `payload`.
fn script(
    item: &Value,
    cron: bool,
    providers: &Map<String, Value>,
) -> Result<(ScriptDef, Option<String>), Refusal> {
    let field = |key: &str| item.get(key).map(text_of).filter(|text| !text.is_empty());
    let on = |key: &str| field(key).is_some_and(|text| text.eq_ignore_ascii_case("true"));
    let kind = match (cron, field("type").as_deref()) {
        (true, _) => ScriptKind::Cron,
        (false, Some("request")) => ScriptKind::HttpRequest,
        (false, Some("response")) => ScriptKind::HttpResponse,
        (false, other) => {
            return Err((IgnoreReason::ScriptType, other.map(str::to_string)));
        }
    };
    let name = field("name").ok_or_else(|| unreadable("a script needs name"))?;
    let provider = |key: &str| {
        providers
            .get(&name)
            .and_then(|provider| provider.get(key))
            .map(text_of)
            .filter(|text| !text.is_empty())
    };
    let (path, payload) = match (
        provider("url").or_else(|| provider("path")),
        provider("payload"),
    ) {
        (Some(path), _) => (path, None),
        (None, Some(payload)) => (String::new(), Some(payload)),
        (None, None) => return Err(unreadable(format!("no script provider {name}"))),
    };
    let number = |key: &str| field(key).and_then(|text| text.trim().parse::<f64>().ok());
    Ok((
        ScriptDef {
            name,
            path,
            kind,
            pattern: if cron { None } else { field("match") },
            conditions: HeadConditionsDef::default(),
            requires_body: on("require-body"),
            binary_body: on("binary-mode"),
            max_size: field("max-size")
                .and_then(|text| text.trim().parse::<i64>().ok())
                .unwrap_or(0),
            cronexp: if cron {
                field("cron").unwrap_or_default()
            } else {
                String::new()
            },
            event: String::new(),
            timeout: number("timeout").filter(|seconds| seconds.is_finite() && *seconds > 0.0),
            argument: field("argument").map(Value::String),
        },
        payload,
    ))
}

/// A script placed as every format's is, or one its provider carries in the text written out
/// under the name its content gives.
fn locate(
    reader: &mut Reader<'_>,
    mut def: ScriptDef,
    payload: Option<String>,
    number: u32,
) -> Result<Option<Out>, Refusal> {
    if def.pattern.is_none() && def.kind != ScriptKind::Cron {
        return Err(unreadable("a script needs match"));
    }
    if def.kind == ScriptKind::Cron && def.cronexp.is_empty() {
        return Err(unreadable("a cron script needs cron"));
    }
    reader.def.declared_scripts.push(number);
    let Some(content) = payload else {
        return Ok(Some(Out::Script(def)));
    };
    let file = stored_name("inline.js", content.as_bytes());
    let inline = &mut reader.def.inline_files;
    if !inline.iter().any(|inline| inline.file == file) {
        inline.push(InlineFile {
            file: file.clone(),
            content,
        });
    }
    def.path = file;
    reader.def.lists.script.push(ModuleLine {
        line: number,
        def: Ok(def),
    });
    Ok(None)
}
