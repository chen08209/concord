//! Loon's plugin lines that differ from Surge's: the new Rewrite and Script syntax
//! (Rewrite/rewrite_v2, Script/script_v2) and the legacy Rewrite one (Rewrite/).

mod action;
mod condition;
mod legacy;
mod lexer;
mod script;

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde_json::Value;

use self::lexer::{Part, Token, lex};
use super::IgnoreReason;
use super::arguments::ArgumentDef;
use super::rule::Refusal;
use crate::mitm::{BodyRewriteDef, HeaderRewriteDef, MapLocalDef, Read, ScriptDef, UrlRewriteDef};

pub(super) use legacy::{legacy_script, read_legacy};

/// What a line gives Concord's lists; a line may give several.
#[derive(Debug)]
pub(super) enum Out {
    Url(Read<UrlRewriteDef>),
    Header(Read<HeaderRewriteDef>),
    Body(Read<BodyRewriteDef>),
    MapLocal(Read<MapLocalDef>),
    RequestBodyMock(Read<MapLocalDef>),
    Script(ScriptDef),
}

/// A line of the new syntax: `request if`, `response if`, or a trigger before `then`.
pub(super) fn is_new(line: &str) -> bool {
    let mut words = line.split_whitespace();
    match words.next() {
        Some("request" | "response") => words.next() == Some("if"),
        Some("generic" | "network-changed") => words.next() == Some("then"),
        Some("cron") => line.contains(" then "),
        _ => false,
    }
}

pub(super) fn is_new_script(line: &str) -> bool {
    is_new(line) && line.contains("script(")
}

/// A new-syntax line; `Ok(None)` when its arguments turn it off.
pub(super) fn read_new(
    line: &str,
    arguments: &[ArgumentDef],
    values: &BTreeMap<String, String>,
) -> Result<Option<Vec<Out>>, Refusal> {
    let tokens = lex(line).map_err(|err| unreadable(err.0))?;
    let mut cursor = Cursor { tokens, at: 0 };
    let mut scope = Scope {
        arguments,
        values,
        captures: Vec::new(),
    };
    if is_new_script(line) {
        return Ok(script::read(&mut cursor, &mut scope)?.map(|def| vec![Out::Script(def)]));
    }
    let response = match cursor.next() {
        Some(Token::Word(phase)) if phase == "request" => false,
        Some(Token::Word(phase)) if phase == "response" => true,
        _ => return Err(unreadable("a rewrite starts with request or response")),
    };
    cursor.word("if");
    let Some(matched) = condition::read(&mut cursor, &mut scope, response)? else {
        return Ok(None);
    };
    if !cursor.word("then") {
        return Err(unreadable("expected then"));
    }
    action::read(&mut cursor, &scope, &matched, response).map(Some)
}

pub(super) fn unreadable(detail: impl Into<String>) -> Refusal {
    (IgnoreReason::Unreadable, Some(detail.into()))
}

pub(super) fn condition(detail: impl Into<String>) -> Refusal {
    (IgnoreReason::Condition, Some(detail.into()))
}

pub(super) fn runtime(detail: impl Into<String>) -> Refusal {
    (IgnoreReason::RuntimeValue, Some(detail.into()))
}

pub(super) struct Cursor {
    tokens: Vec<Token>,
    at: usize,
}

impl Cursor {
    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.at).cloned();
        self.at += usize::from(token.is_some());
        token
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn done(&self) -> bool {
        self.at >= self.tokens.len()
    }

    fn symbol(&mut self, symbol: &str) -> bool {
        let found = matches!(self.peek(), Some(Token::Symbol(s)) if *s == symbol);
        self.at += usize::from(found);
        found
    }

    fn word(&mut self, word: &str) -> bool {
        let found = matches!(self.peek(), Some(Token::Word(w)) if w == word);
        self.at += usize::from(found);
        found
    }

    fn expect(&mut self, symbol: &str) -> Result<(), Refusal> {
        if self.symbol(symbol) {
            Ok(())
        } else {
            Err(unreadable(format!("expected {symbol}")))
        }
    }
}

/// The plugin's arguments with their values, and the captures the line's condition names.
pub(super) struct Scope<'a> {
    arguments: &'a [ArgumentDef],
    values: &'a BTreeMap<String, String>,
    /// By name, the groups a URL rewrite's replacement can name; `None` for a capture only
    /// the rule's run knows.
    captures: Vec<(String, Option<usize>)>,
}

impl Scope<'_> {
    fn declared(&self, name: &str) -> Option<&ArgumentDef> {
        self.arguments.iter().find(|argument| argument.name == name)
    }

    /// An argument's value as its type has it.
    fn argument(&self, name: &str) -> Result<Value, Refusal> {
        let argument = self
            .declared(name)
            .ok_or_else(|| unreadable(format!("${{{name}}} is not declared")))?;
        argument
            .typed(self.values)
            .ok_or_else(|| unreadable(format!("${{{name}}} has no value")))
    }

    fn capture(&mut self, name: &str, groups: Option<usize>) -> Result<(), Refusal> {
        if self.declared(name).is_some() || self.captures.iter().any(|(each, _)| each == name) {
            return Err(unreadable(format!("capture {name} is named twice")));
        }
        self.captures.push((name.to_string(), groups));
        Ok(())
    }

    /// A string value: a template filled in, a raw string, or a string argument.
    fn string(&self, token: &Token) -> Result<String, Refusal> {
        match token {
            Token::Template(parts) => self.text(parts, false),
            Token::Raw(text) => Ok(text.clone()),
            Token::Var(name) => match self.argument(name)? {
                Value::String(text) => Ok(text),
                _ => Err(unreadable(format!("${{{name}}} is not a string"))),
            },
            _ => Err(unreadable("expected a string")),
        }
    }

    /// A template's text. With `url` it is a URL rewrite's replacement, where a capture of
    /// the URL regex is its group and a `$` of the text is escaped.
    fn text(&self, parts: &[Part], url: bool) -> Result<String, Refusal> {
        let mut out = String::new();
        for part in parts {
            match part {
                Part::Text(text) if url => out.push_str(&text.replace('$', "$$")),
                Part::Text(text) => out.push_str(text),
                Part::Var(name) => out.push_str(&self.fill(name, url)?),
            }
        }
        Ok(out)
    }

    fn fill(&self, name: &str, url: bool) -> Result<Cow<'static, str>, Refusal> {
        if let Some((capture, index)) = name.rsplit_once('.')
            && let Some((_, groups)) = self.captures.iter().find(|(each, _)| each == capture)
        {
            let index: usize = index
                .parse()
                .map_err(|_| unreadable(format!("${{{name}}} names no group")))?;
            return match groups {
                Some(groups) if url && index <= *groups => Ok(Cow::Owned(format!("${{{index}}}"))),
                Some(_) if url => Err(unreadable(format!("${{{name}}} names no group"))),
                _ => Err(runtime(format!("${{{name}}}"))),
            };
        }
        if name == "url" || name.starts_with("request.") || name.starts_with("response.") {
            return Err(runtime(format!("${{{name}}}")));
        }
        Ok(Cow::Owned(match self.argument(name)? {
            Value::String(text) => text,
            other => other.to_string(),
        }))
    }
}

#[cfg(test)]
mod tests;
