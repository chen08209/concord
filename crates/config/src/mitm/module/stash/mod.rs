//! A Stash override (its wiki's override, HTTP engine and script pages): YAML whose `http`,
//! `cron`, `rules`, `rule-providers`, `script-providers`, `dns` and `hosts` a module
//! carries. Every value but the shown ones has its `${args.name}` filled in first.

mod http;

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::arguments::{ArgumentDef, ArgumentKind};
use super::network::{Refused, dns_server};
use super::rule::RuleReader;
use super::surge::Reader;
use super::{IgnoreReason, ModuleDef, ModuleFormat, ModuleInput, ModuleMeta, Unreadable};
use crate::mitm::module::{DomainEntry, InlineRule, ListEdit, RuleSetSource};
use crate::yaml::{ParsedDocument, SourceLines, parse_override};

/// Keys at the top of an override that no Surge module or Quantumult X snippet read as YAML has.
const KEYS: [&str; 7] = [
    "http",
    "script-providers",
    "cron",
    "rules",
    "tiles",
    "dns",
    "hosts",
];
/// Keys shown as written, which Stash fills no argument into.
const SHOWN: [&str; 10] = [
    "name", "desc", "icon", "category", "author", "homepage", "openUrl", "manual", "date",
    "version",
];

/// The override `text` is, when it is one.
pub(super) fn document(text: &str) -> Option<ParsedDocument> {
    let sectioned = text.lines().any(|line| {
        let line = line.trim();
        line.starts_with('[') && line.ends_with(']')
    });
    if sectioned {
        return None;
    }
    let document = parse_override(text).ok()?;
    KEYS.iter()
        .any(|key| document.root.contains_key(*key))
        .then_some(document)
}

pub(super) fn read(document: &ParsedDocument, text: &str, input: &ModuleInput<'_>) -> ModuleDef {
    let lines = &document.lines;
    let mut def = ModuleDef {
        format: ModuleFormat::Stash,
        meta: meta(&document.root),
        ..ModuleDef::default()
    };
    if let Some(Value::Object(arguments)) = document.root.get("arguments") {
        def.arguments = read_arguments(arguments, &lines.keys);
    }
    let filled: Map<String, Value> = document
        .root
        .iter()
        .filter(|(key, _)| !SHOWN.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), fill(value, &def.arguments, input.arguments)))
        .collect();
    let mut reader = Reader::new(input, Vec::new(), def);
    if let Some(Value::Object(providers)) = filled.get("rule-providers") {
        rule_providers(&mut reader, providers, lines);
    }
    let scripts = match filled.get("script-providers") {
        Some(Value::Object(providers)) => providers.clone(),
        _ => Map::new(),
    };
    let mut dns = None;
    for (key, value) in &filled {
        let line = lines.keys.get(key).copied().unwrap_or(1);
        match (key.as_str(), value) {
            ("http", Value::Object(map)) => http::read(&mut reader, map, &scripts, lines),
            ("cron", Value::Object(map)) => http::cron(&mut reader, map, &scripts, lines),
            ("rules", Value::Array(rules)) => {
                for (at, rule) in rules.iter().enumerate() {
                    let read = reader.rules.read(&text_of(rule));
                    reader.read_rule(read, item_line(&lines.rules, at, line));
                }
            }
            ("dns", Value::Object(map)) => dns = Some(read_dns(&mut reader, map, lines, text)),
            ("hosts", Value::Object(map)) => read_hosts(&mut reader, map, lines),
            ("proxies" | "proxy-groups" | "proxy-providers", _) => {
                reader.ignore(line, IgnoreReason::Proxies, None)
            }
            ("tiles", _) => reader.ignore(line, IgnoreReason::AppOnly, None),
            ("arguments" | "arguments-version" | "rule-providers" | "script-providers", _) => {}
            _ => reader.ignore(line, IgnoreReason::Section, Some(key.clone())),
        }
    }
    let mut def = reader.finish();
    def.declared_scripts.sort_unstable();
    if let Some(dns) = dns {
        dns.apply(&mut def);
    }
    def
}

fn meta(root: &Map<String, Value>) -> ModuleMeta {
    let shown = |key: &str| {
        root.get(key)
            .map(text_of)
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty())
    };
    ModuleMeta {
        name: shown("name"),
        desc: shown("desc"),
        author: shown("author"),
        icon: shown("icon"),
        homepage: shown("homepage"),
        category: shown("category"),
        ..ModuleMeta::default()
    }
}

/// A scalar as text, a list or map as JSON.
pub(super) fn text_of(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// The line of a list's item; `fallback`, the list's own, when the reader kept none.
pub(super) fn item_line(lines: &[u32], at: usize, fallback: u32) -> u32 {
    lines.get(at).copied().unwrap_or(fallback)
}

/// `arguments`: `type` input, select or switch, `title`, `description`, `default`,
/// `options` of `value` and `label`, and `value-type: integer`.
fn read_arguments(
    arguments: &Map<String, Value>,
    keys: &BTreeMap<String, u32>,
) -> Vec<ArgumentDef> {
    arguments
        .iter()
        .filter_map(|(name, value)| {
            let Value::Object(spec) = value else {
                return None;
            };
            let field = |key: &str| spec.get(key).map(text_of).filter(|text| !text.is_empty());
            let choices: Vec<&Value> = match spec.get("options") {
                Some(Value::Array(options)) => options
                    .iter()
                    .map(|option| option.get("value").unwrap_or(option))
                    .collect(),
                _ => Vec::new(),
            };
            let kind = match field("type").as_deref() {
                Some("switch") => ArgumentKind::Switch,
                Some("select") => ArgumentKind::Select {
                    options: choices.iter().map(|choice| text_of(choice)).collect(),
                },
                _ => ArgumentKind::Text,
            };
            let number = field("value-type").as_deref() == Some("integer")
                || !choices.is_empty() && choices.iter().all(|choice| choice.is_i64());
            let default = match (spec.get("default"), &kind) {
                (Some(value), _) if !value.is_null() => text_of(value),
                (_, ArgumentKind::Switch) => "false".to_string(),
                _ => String::new(),
            };
            Some(ArgumentDef {
                name: name.clone(),
                kind,
                number,
                default,
                label: field("title"),
                desc: field("description"),
                line: keys.get(&format!("arguments.{name}")).copied().unwrap_or(1),
            })
        })
        .collect()
}

/// `value` with each `${args.name}` filled in: a string that is one reference alone takes
/// the argument's type, `|json` writes the value as JSON, and `$${args.name}` is the text.
fn fill(value: &Value, arguments: &[ArgumentDef], values: &BTreeMap<String, String>) -> Value {
    match value {
        Value::String(text) if text.contains("${args.") => {
            let lone = text
                .strip_prefix("${args.")
                .and_then(|rest| rest.strip_suffix('}'))
                .and_then(|name| arguments.iter().find(|argument| argument.name == name));
            if let Some(argument) = lone {
                return argument
                    .typed(values)
                    .unwrap_or_else(|| Value::String(argument.value(values).to_string()));
            }
            Value::String(fill_text(text, arguments, values))
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| fill(item, arguments, values))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), fill(value, arguments, values)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn fill_text(text: &str, arguments: &[ArgumentDef], values: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${args.") {
        let escaped = rest
            .get(..start)
            .is_some_and(|before| before.ends_with('$'));
        let Some(end) = rest.get(start..).and_then(|tail| tail.find('}')) else {
            break;
        };
        let reference = rest.get(start + 7..start + end).unwrap_or_default();
        let (name, json) = match reference.strip_suffix("|json") {
            Some(name) => (name, true),
            None => (reference, false),
        };
        let argument = arguments.iter().find(|argument| argument.name == name);
        let before = rest.get(..start).unwrap_or_default();
        let whole = rest.get(start..=start + end).unwrap_or_default();
        match argument {
            _ if escaped => {
                out.push_str(before.strip_suffix('$').unwrap_or(before));
                out.push_str(whole);
            }
            Some(argument) if json => {
                out.push_str(before);
                let value = argument
                    .typed(values)
                    .unwrap_or_else(|| Value::String(argument.value(values).to_string()));
                out.push_str(&value.to_string());
            }
            Some(argument) => {
                out.push_str(before);
                out.push_str(argument.value(values));
            }
            None => {
                out.push_str(before);
                out.push_str(whole);
            }
        }
        rest = rest.get(start + end + 1..).unwrap_or_default();
    }
    out.push_str(rest);
    out
}

/// `rule-providers`: a classical list fetched as text, or an inline one; Concord's rule sets
/// hold neither the domain and CIDR behaviors nor the YAML and MRS formats.
fn rule_providers(reader: &mut Reader<'_>, providers: &Map<String, Value>, lines: &SourceLines) {
    for (name, provider) in providers {
        let line = lines
            .keys
            .get(&format!("rule-providers.{name}"))
            .copied()
            .unwrap_or(1);
        let field = |key: &str| provider.get(key).map(text_of).unwrap_or_default();
        let kind = field("type");
        let behavior = field("behavior");
        let format = field("format");
        let source = match kind.as_str() {
            _ if behavior != "classical" => Err(Unreadable(format!("behavior {behavior}"))),
            "inline" => inline_provider(provider.get("payload"), line),
            "http" | "" if format == "text" && !field("url").is_empty() => Ok(RuleSetSource::Url {
                url: field("url"),
                interval: provider.get("interval").and_then(Value::as_u64),
            }),
            "http" | "" => Err(Unreadable(format!("format {format}"))),
            other => Err(Unreadable(format!("type {other}"))),
        };
        match source {
            Ok(source) => reader.rules.provider(name, source),
            Err(Unreadable(detail)) => reader.ignore(line, IgnoreReason::RuleType, Some(detail)),
        }
    }
}

fn inline_provider(payload: Option<&Value>, line: u32) -> Result<RuleSetSource, Unreadable> {
    let Some(Value::Array(items)) = payload else {
        return Err("an inline provider needs a payload".into());
    };
    let rules = items
        .iter()
        .map(|item| {
            RuleReader::inline_rule(&text_of(item))
                .map(|rule| InlineRule { line, rule })
                .map_err(|(_, detail)| Unreadable(detail.unwrap_or_else(|| text_of(item))))
        })
        .collect::<Result<Vec<_>, Unreadable>>()?;
    Ok(RuleSetSource::Inline { rules })
}

fn read_hosts(reader: &mut Reader<'_>, hosts: &Map<String, Value>, lines: &SourceLines) {
    for (host, value) in hosts {
        let line = lines
            .keys
            .get(&format!("hosts.{host}"))
            .copied()
            .unwrap_or(1);
        let targets = match value {
            Value::Array(items) => items.iter().map(text_of).collect::<Vec<_>>().join(", "),
            other => text_of(other),
        };
        match reader
            .network
            .read_host(&format!("{host} = {targets}"), line)
        {
            Ok(()) => {}
            Err(Refused::Setting) => reader.ignore(line, IgnoreReason::Setting, None),
            Err(Refused::Unreadable(detail)) => {
                reader.ignore(line, IgnoreReason::Unreadable, Some(detail))
            }
        }
    }
}

/// The DNS lists an override sets, each going before the profile's, after it with
/// `#!append`, or in its place with `#!replace`.
#[derive(Default)]
struct Dns {
    nameserver: Option<ListEdit>,
    default_nameserver: Option<ListEdit>,
    fake_ip_filter: Option<ListEdit>,
    policy: Vec<DomainEntry>,
    lines: Vec<u32>,
}

impl Dns {
    fn apply(self, def: &mut ModuleDef) {
        let network = &mut def.network;
        network.nameserver = self.nameserver.or(network.nameserver.take());
        network.default_nameserver = self
            .default_nameserver
            .or(network.default_nameserver.take());
        network.fake_ip_filter = self.fake_ip_filter.or(network.fake_ip_filter.take());
        network.nameserver_policy.extend(self.policy);
        network.lines.extend(self.lines);
        network.lines.sort_unstable();
    }
}

fn read_dns(
    reader: &mut Reader<'_>,
    dns: &Map<String, Value>,
    lines: &SourceLines,
    text: &str,
) -> Dns {
    let mut out = Dns::default();
    let source: Vec<&str> = text.lines().collect();
    for (key, value) in dns {
        let line = lines.keys.get(&format!("dns.{key}")).copied().unwrap_or(1);
        let written = source
            .get(line.saturating_sub(1) as usize)
            .copied()
            .unwrap_or_default();
        let items: Vec<String> = match value {
            Value::Array(items) => items.iter().map(text_of).collect(),
            Value::Object(_) => Vec::new(),
            other => vec![text_of(other)],
        };
        let edit = |values: Vec<String>| {
            if written.contains("#!replace") {
                ListEdit {
                    replace: true,
                    before: values,
                    after: Vec::new(),
                }
            } else if written.contains("#!append") {
                ListEdit {
                    replace: false,
                    before: Vec::new(),
                    after: values,
                }
            } else {
                ListEdit {
                    replace: false,
                    before: values,
                    after: Vec::new(),
                }
            }
        };
        let servers = |items: &[String]| -> Result<Vec<String>, Unreadable> {
            items
                .iter()
                .map(|item| dns_server(item.trim()).ok_or_else(|| Unreadable(item.clone())))
                .collect()
        };
        let read = match (key.as_str(), value) {
            ("nameserver", _) => servers(&items).map(|list| out.nameserver = Some(edit(list))),
            ("default-nameserver", _) => {
                servers(&items).map(|list| out.default_nameserver = Some(edit(list)))
            }
            ("fake-ip-filter", _) => {
                out.fake_ip_filter = Some(edit(items));
                Ok(())
            }
            ("nameserver-policy", Value::Object(policy)) => {
                policy.iter().try_for_each(|(domain, value)| {
                    let listed = match value {
                        Value::Array(items) => items.iter().map(text_of).collect(),
                        other => vec![text_of(other)],
                    };
                    let values = servers(&listed)?;
                    out.policy.push(DomainEntry {
                        domain: domain.clone(),
                        values,
                    });
                    Ok(())
                })
            }
            _ => {
                reader.ignore(line, IgnoreReason::Setting, Some(format!("dns.{key}")));
                continue;
            }
        };
        match read {
            Ok(()) => out.lines.push(line),
            Err(Unreadable(detail)) => reader.ignore(line, IgnoreReason::Unreadable, Some(detail)),
        }
    }
    out
}
