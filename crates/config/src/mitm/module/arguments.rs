//! A module's arguments: Surge's `#!arguments`, and the values the user set for them.

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde::Serialize;

use super::source::{split_commas, unquote};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ArgumentKind {
    Text,
    /// `true` or `false`.
    Switch,
    Select {
        options: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArgumentDef {
    pub name: String,
    pub kind: ArgumentKind,
    /// A number, which a typed use hands over as one.
    pub number: bool,
    pub default: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    pub line: u32,
}

impl ArgumentDef {
    /// The user's value, or the default.
    pub fn value<'a>(&'a self, values: &'a BTreeMap<String, String>) -> &'a str {
        values.get(&self.name).map_or(&self.default, String::as_str)
    }
}

/// Surge's `#!arguments=name:default,...`: the default after the first colon, quotes
/// taken off; `true` or `false` makes a switch.
pub(super) fn read_surge(text: &str, line: u32, out: &mut Vec<ArgumentDef>) {
    for item in split_commas(text) {
        let (name, default) = match item.split_once(':') {
            Some((name, default)) => (name.trim(), unquote(default.trim())),
            None => (item, ""),
        };
        if name.is_empty() {
            continue;
        }
        let kind = if matches!(default, "true" | "false") {
            ArgumentKind::Switch
        } else {
            ArgumentKind::Text
        };
        out.push(ArgumentDef {
            name: name.to_string(),
            kind,
            number: false,
            default: default.to_string(),
            label: None,
            desc: None,
            line,
        });
    }
}

/// `line` with each `{{{name}}}` of a declared argument replaced by its value, as Surge does
/// before it reads the line; an undeclared one stays as written.
pub(super) fn substitute_surge<'a>(
    line: &'a str,
    arguments: &[ArgumentDef],
    values: &BTreeMap<String, String>,
) -> Cow<'a, str> {
    if arguments.is_empty() || !line.contains("{{{") {
        return Cow::Borrowed(line);
    }
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(start) = rest.find("{{{") {
        let (head, tail) = rest.split_at(start);
        out.push_str(head);
        let inner = tail.get(3..).unwrap_or_default();
        let declared = inner.find("}}}").and_then(|end| {
            let name = inner.get(..end)?;
            let argument = arguments.iter().find(|argument| argument.name == name)?;
            Some((argument.value(values), inner.get(end + 3..)?))
        });
        match declared {
            Some((value, after)) => {
                out.push_str(value);
                rest = after;
            }
            None => {
                out.push_str("{{{");
                rest = inner;
            }
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surge_arguments_take_their_defaults_and_values() {
        let mut arguments = Vec::new();
        read_surge(
            r#"host:a.test,on:true,"quoted":"x, y",bare"#,
            3,
            &mut arguments,
        );
        let summary: Vec<_> = arguments
            .iter()
            .map(|argument| {
                (
                    argument.name.as_str(),
                    &argument.kind,
                    argument.default.as_str(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("host", &ArgumentKind::Text, "a.test"),
                ("on", &ArgumentKind::Switch, "true"),
                (r#""quoted""#, &ArgumentKind::Text, "x, y"),
                ("bare", &ArgumentKind::Text, ""),
            ]
        );
        let values = BTreeMap::from([("host".to_string(), "b.test".to_string())]);
        assert_eq!(
            substitute_surge("{{{host}}}/{{{on}}}/{{{none}}}/{{{", &arguments, &values),
            "b.test/true/{{{none}}}/{{{"
        );
    }
}
