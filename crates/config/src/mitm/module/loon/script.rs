//! A new-syntax script line (Script/script_v2): a trigger, `script(path[, argument])`, and
//! `with` options.

use std::path::Path;

use serde_json::{Map, Value};

use super::lexer::{Part, Token};
use super::{Cursor, Refusal, Scope, condition, unreadable};
use crate::mitm::script::EVENT_NETWORK_CHANGED;
use crate::mitm::{HeadConditionsDef, ScriptDef, ScriptKind};

/// `None` when the line's arguments turn it off.
pub(super) fn read(
    cursor: &mut Cursor,
    scope: &mut Scope<'_>,
) -> Result<Option<ScriptDef>, Refusal> {
    let Some(Token::Word(trigger)) = cursor.next() else {
        return Err(unreadable("expected a trigger"));
    };
    let mut def = blank();
    match trigger.as_str() {
        "request" | "response" => {
            let response = trigger == "response";
            cursor.word("if");
            let Some(matched) = condition::read(cursor, scope, response)? else {
                return Ok(None);
            };
            if !scope.captures.is_empty() {
                return Err(unreadable("a script's condition captures nothing"));
            }
            if response && !matched.url_guard {
                return Err(unreadable("a response script tests the URL on every match"));
            }
            def.kind = if response {
                ScriptKind::HttpResponse
            } else {
                ScriptKind::HttpRequest
            };
            def.pattern = Some(matched.url);
            def.conditions = HeadConditionsDef {
                request: matched.request,
                response: matched.response,
            };
        }
        "cron" => {
            def.kind = ScriptKind::Cron;
            let expression = cursor
                .next()
                .ok_or_else(|| unreadable("cron needs an expression"))?;
            def.cronexp = scope.string(&expression)?;
        }
        "network-changed" => {
            def.kind = ScriptKind::Event;
            def.event = EVENT_NETWORK_CHANGED.to_string();
        }
        "generic" => def.kind = ScriptKind::Generic,
        other => return Err(unreadable(format!("unknown trigger {other}"))),
    }
    if !cursor.word("then") || !cursor.word("script") {
        return Err(unreadable("expected then script(...)"));
    }
    cursor.expect("(")?;
    def.path = match cursor.next() {
        Some(Token::Template(parts)) => fixed(&parts)?,
        Some(Token::Raw(path)) => path,
        _ => return Err(unreadable("a script path is a fixed string")),
    };
    if def.path.is_empty() {
        return Err(unreadable("a script path is a fixed string"));
    }
    if cursor.symbol(",") {
        def.argument = Some(match cursor.next() {
            Some(Token::Object(names)) => object(scope, &names)?,
            Some(token @ (Token::Template(_) | Token::Raw(_))) => {
                Value::String(scope.string(&token)?)
            }
            _ => return Err(unreadable("a script argument is a string or an object")),
        });
    }
    cursor.expect(")")?;
    let http = !def.kind.is_task();
    // Loon's defaults (its script docs, on the fields a script takes).
    def.timeout = Some(if http { 20.0 } else { 300.0 });
    if cursor.word("with") && !options(cursor, scope, &mut def, http)? {
        return Ok(None);
    }
    if !cursor.done() {
        return Err(unreadable("unexpected text after the script"));
    }
    if def.name.is_empty() {
        def.name = Path::new(&def.path).file_name().map_or_else(
            || def.path.clone(),
            |name| name.to_string_lossy().into_owned(),
        );
    }
    Ok(Some(def))
}

fn blank() -> ScriptDef {
    ScriptDef {
        name: String::new(),
        path: String::new(),
        kind: ScriptKind::Generic,
        pattern: None,
        conditions: HeadConditionsDef::default(),
        requires_body: false,
        binary_body: false,
        full_header: false,
        max_size: 0,
        cronexp: String::new(),
        event: String::new(),
        timeout: None,
        argument: None,
    }
}

fn fixed(parts: &[Part]) -> Result<String, Refusal> {
    match parts {
        [Part::Text(text)] => Ok(text.clone()),
        _ => Err(unreadable("expected a fixed string")),
    }
}

/// `{${a}, ${b}}`: each declared argument by name, keeping its type; one with no value
/// is `null`.
fn object(scope: &Scope<'_>, names: &[String]) -> Result<Value, Refusal> {
    let mut object = Map::new();
    for name in names {
        let argument = scope
            .declared(name)
            .ok_or_else(|| unreadable(format!("${{{name}}} is not declared")))?;
        let value = argument.typed(scope.values).unwrap_or(Value::Null);
        if object.insert(name.clone(), value).is_some() {
            return Err(unreadable(format!("${{{name}}} is listed twice")));
        }
    }
    Ok(Value::Object(object))
}

/// The `with` options; `false` when `enable` turns the script off.
fn options(
    cursor: &mut Cursor,
    scope: &Scope<'_>,
    def: &mut ScriptDef,
    http: bool,
) -> Result<bool, Refusal> {
    let mut seen: Vec<String> = Vec::new();
    let mut enable = true;
    loop {
        let Some(Token::Word(key)) = cursor.next() else {
            return Err(unreadable("expected an option"));
        };
        cursor.expect("=")?;
        let value = cursor
            .next()
            .ok_or_else(|| unreadable(format!("{key} needs a value")))?;
        if seen.contains(&key) {
            return Err(unreadable(format!("{key} is given twice")));
        }
        match key.as_str() {
            "enable" => enable = boolean(scope, &value, true)?,
            "debug" => {
                boolean(scope, &value, false)?;
            }
            "tag" => def.name = literal(&value)?,
            "img_url" => {
                literal(&value)?;
            }
            "timeout" => {
                if let Some(seconds) = timeout(scope, &value)? {
                    def.timeout = Some(seconds);
                }
            }
            "requires_body" | "binary_body_mode" if http => {
                let on = match &value {
                    Token::Word(word) if word == "true" || word == "false" => word == "true",
                    _ => return Err(unreadable(format!("{key} is true or false"))),
                };
                if key == "requires_body" {
                    def.requires_body = on;
                } else {
                    def.binary_body = on;
                }
            }
            _ => return Err(unreadable(format!("unknown option {key}"))),
        }
        seen.push(key);
        if !cursor.symbol(",") {
            return Ok(enable);
        }
    }
}

/// A boolean option: `true`, `false`, or a switch argument, `fallback` when it has no
/// value (Loon's script docs, on a dynamic option with no value).
fn boolean(scope: &Scope<'_>, value: &Token, fallback: bool) -> Result<bool, Refusal> {
    match value {
        Token::Word(word) if word == "true" || word == "false" => Ok(word == "true"),
        Token::Var(name) => {
            let argument = scope
                .declared(name)
                .ok_or_else(|| unreadable(format!("${{{name}}} is not declared")))?;
            match argument.typed(scope.values) {
                Some(Value::Bool(on)) => Ok(on),
                None => Ok(fallback),
                Some(_) => Err(unreadable(format!("${{{name}}} is not a switch"))),
            }
        }
        _ => Err(unreadable("expected true or false")),
    }
}

fn literal(value: &Token) -> Result<String, Refusal> {
    match value {
        Token::Template(parts) => fixed(parts),
        Token::Raw(text) => Ok(text.clone()),
        _ => Err(unreadable("expected a string")),
    }
}

/// Seconds, positive and finite: a number, or an argument holding one or a numeric string;
/// `None` for an argument with no value, which leaves the default.
fn timeout(scope: &Scope<'_>, value: &Token) -> Result<Option<f64>, Refusal> {
    let seconds = match value {
        Token::Number(text) => text.parse::<f64>().ok(),
        Token::Var(name) => {
            let argument = scope
                .declared(name)
                .ok_or_else(|| unreadable(format!("${{{name}}} is not declared")))?;
            match argument.typed(scope.values) {
                None => return Ok(None),
                Some(Value::Number(number)) => number.as_f64(),
                Some(Value::String(text)) => text.trim().parse::<f64>().ok(),
                Some(_) => None,
            }
        }
        _ => None,
    };
    seconds
        .filter(|seconds| *seconds > 0.0 && seconds.is_finite())
        .map(Some)
        .ok_or_else(|| unreadable("timeout is a positive number of seconds"))
}
