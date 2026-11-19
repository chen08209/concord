//! A module's arguments: Surge's `#!arguments` and Loon's `[Argument]`, and the values the
//! user set for them.

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use super::Unreadable;
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

    /// The value as its type has it, as Loon hands it on; `None` when the user left an input
    /// or a select with no default empty, or the value does not read as its type.
    pub fn typed(&self, values: &BTreeMap<String, String>) -> Option<Value> {
        let text = self.value(values);
        match &self.kind {
            ArgumentKind::Switch => match text {
                "true" => Some(Value::Bool(true)),
                "false" => Some(Value::Bool(false)),
                _ => None,
            },
            _ if text.is_empty() && !values.contains_key(&self.name) => None,
            _ if self.number => serde_json::from_str::<Value>(text.trim())
                .ok()
                .filter(Value::is_number),
            _ => Some(Value::String(text.to_string())),
        }
    }
}

/// Loon's `name = input|select|switch,values,type=,tag=,desc=` (Plugin, `[Argument]`): a
/// select's first value is its default, and `type=number` makes every value a number.
pub(super) fn read_loon(line: &str, number_line: u32) -> Result<ArgumentDef, Unreadable> {
    let (name, rest) = line
        .split_once('=')
        .ok_or("expected name = control,values")?;
    let name = name.trim();
    let parts = split_commas(rest);
    let (control, rest) = parts.split_first().ok_or("expected a control")?;
    if name.is_empty() {
        return Err("expected a name".into());
    }
    let (mut options, mut label, mut desc, mut kind_type) = (Vec::new(), None, None, None);
    let mut last: Option<&str> = None;
    for part in rest {
        let named = part
            .split_once('=')
            .map(|(key, value)| (key.trim().to_ascii_lowercase(), unquote(value.trim())))
            .filter(|(key, _)| ["tag", "desc", "type"].contains(&key.as_str()));
        let mut other = None;
        let slot = match named.as_ref().map(|(key, _)| key.as_str()).or(last) {
            Some("tag") => &mut label,
            Some("desc") => &mut desc,
            _ => &mut other,
        };
        match named {
            Some((key, value)) if key == "type" => kind_type = Some(value.to_ascii_lowercase()),
            Some((key, value)) => {
                *slot = Some(value.to_string());
                last = Some(if key == "tag" { "tag" } else { "desc" });
            }
            None if last.is_some() => {
                if let Some(text) = slot {
                    text.push(',');
                    text.push_str(part);
                }
            }
            None if part.is_empty() => {}
            None => options.push(unquote(part).to_string()),
        }
    }
    let control = control.to_ascii_lowercase();
    let number = match (control.as_str(), kind_type.as_deref()) {
        ("input" | "select", None | Some("string")) | ("switch", None | Some("boolean")) => false,
        ("input" | "select", Some("number")) => true,
        (_, Some(other)) if !["string", "number", "boolean"].contains(&other) => {
            return Err(format!("unknown type {other}").into());
        }
        ("input" | "select" | "switch", Some(other)) => {
            return Err(format!("{control} takes no {other} values").into());
        }
        _ => return Err(format!("unknown control {control}").into()),
    };
    if number
        && options
            .iter()
            .any(|option| option.trim().parse::<f64>().is_err())
    {
        return Err("a number argument takes numbers".into());
    }
    let kind = match control.as_str() {
        "switch" => {
            if options
                .iter()
                .any(|option| option != "true" && option != "false")
            {
                return Err("a switch takes true or false".into());
            }
            ArgumentKind::Switch
        }
        "select" if options.is_empty() => return Err("a select needs options".into()),
        "select" => ArgumentKind::Select {
            options: options.clone(),
        },
        _ => ArgumentKind::Text,
    };
    let default = match (&kind, options.first()) {
        (ArgumentKind::Switch, None) => "false".to_string(),
        (_, first) => first.cloned().unwrap_or_default(),
    };
    Ok(ArgumentDef {
        name: name.to_string(),
        kind,
        number,
        default,
        label: label.filter(|label| !label.is_empty()),
        desc: desc.filter(|desc| !desc.is_empty()),
        line: number_line,
    })
}

/// `line` with each `${name}` and `{name}` of a declared argument replaced by its value, as
/// Loon fills a legacy line in before it reads it.
pub(super) fn substitute_loon<'a>(
    line: &'a str,
    arguments: &[ArgumentDef],
    values: &BTreeMap<String, String>,
) -> Cow<'a, str> {
    if arguments.is_empty() || !line.contains('{') {
        return Cow::Borrowed(line);
    }
    let mut out = line.to_string();
    for argument in arguments {
        let value = argument.value(values);
        for marker in [
            format!("${{{}}}", argument.name),
            format!("{{{}}}", argument.name),
        ] {
            if out.contains(&marker) {
                out = out.replace(&marker, value);
            }
        }
    }
    Cow::Owned(out)
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
    fn loon_arguments_read_with_their_types() {
        let read = |line| read_loon(line, 1);
        let price = read("price = input,9.99,type=number,tag=价格").unwrap();
        assert!(price.number);
        assert_eq!(price.label.as_deref(), Some("价格"));
        let switch = read("on = switch,true,false,tag=a,b,desc=c").unwrap();
        assert_eq!(
            (switch.label.as_deref(), switch.desc.as_deref()),
            (Some("a,b"), Some("c"))
        );
        let region = read(r#"region = select,"CN","US",tag=地区"#).unwrap();
        assert_eq!(region.default, "CN");
        assert_eq!(
            region.kind,
            ArgumentKind::Select {
                options: vec!["CN".into(), "US".into()]
            }
        );
        let values = BTreeMap::from([("price".to_string(), "2".to_string())]);
        assert_eq!(price.typed(&values), Some(serde_json::json!(2)));
        assert_eq!(
            read("on = switch,true").unwrap().typed(&values),
            Some(Value::Bool(true))
        );
        assert_eq!(read("name = input").unwrap().typed(&values), None);
        assert!(read("n = input,abc,type=number").is_err());
        assert!(read("n = input,1,type=integer").is_err());
        assert!(read("n = switch,true,type=number").is_err());
        let arguments = [price, region];
        assert_eq!(
            substitute_loon("a={price}&b=${region}&c={other}", &arguments, &values),
            "a=2&b=CN&c={other}"
        );
    }

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
