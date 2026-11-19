//! The sectioned text Surge and Loon write, a section's lines read the way that section is.

use super::arguments::{read_surge, substitute_surge};
use super::network::{NetworkEdits, Refused};
use super::requirement::evaluate;
use super::resource::{ResourceKind, is_url, locate};
use super::rule::{RuleReader, ip_rewrite};
use super::source::{
    LineRequirement, ListMark, is_comment, key_value, list_mark, numbered, section_name,
    split_requirement, unquote,
};
use super::{
    HostLine, IgnoreReason, IgnoredLine, ModuleDef, ModuleFormat, ModuleInput, ModuleLine,
    ModuleMeta, ModuleOff,
};
use crate::mitm::rules::mime_by_extension;
use crate::mitm::script::{
    EVENT_ENGINE_STARTED, EVENT_NETWORK_CHANGED, EVENT_PROFILE_RELOADED, split_script_line,
};
use crate::mitm::{
    MapLocalBody, host_items, parse_body_rewrite, parse_header_rewrite, parse_map_local,
    parse_script, parse_url_rewrite, source_items,
};

const LOON_SECTIONS: [&str; 4] = ["rewrite", "argument", "remote rule", "plugin"];
const PROXY_SECTIONS: [&str; 4] = ["proxy", "proxy group", "proxy-groups", "proxies"];
const APP_ONLY_SECTIONS: [&str; 10] = [
    "panel",
    "ponte",
    "dhcp",
    "ssid setting",
    "mtproto",
    "snell server",
    "replica",
    "tiles",
    "keystore",
    "wireguard",
];
const RUNNABLE_SCRIPTS: [&str; 5] = ["http-request", "http-response", "cron", "event", "generic"];

/// What the `#!` lines and section headers say, read before any line, so a line may use an
/// argument or a rule set declared after it.
struct Declarations {
    meta: ModuleMeta,
    format: ModuleFormat,
    inline_sets: Vec<String>,
}

fn declarations(text: &str, def: &mut ModuleDef) -> Declarations {
    let mut meta = ModuleMeta::default();
    let mut inline_sets = Vec::new();
    let mut format = ModuleFormat::Surge;
    for (number, raw) in numbered(text) {
        let line = raw.trim();
        if let Some(name) = section_name(line) {
            let lower = name.to_ascii_lowercase();
            if let Some(set) = lower.strip_prefix("ruleset ").and(name.get(8..)) {
                inline_sets.push(set.trim().to_string());
            }
            if LOON_SECTIONS.contains(&lower.as_str()) {
                format = ModuleFormat::Loon;
            }
            continue;
        }
        let Some((key, value)) = line.strip_prefix("#!").and_then(key_value) else {
            continue;
        };
        let value = value.replace("\\n", "\n");
        let value = value.trim();
        let slot = match key.as_str() {
            "name" => &mut meta.name,
            "desc" => &mut meta.desc,
            "author" => &mut meta.author,
            "icon" => &mut meta.icon,
            "homepage" => &mut meta.homepage,
            "category" => &mut meta.category,
            "system" => &mut meta.system,
            "requirement" => &mut meta.requirement,
            "arguments-desc" => &mut meta.arguments_desc,
            "arguments" => {
                read_surge(value, number, &mut def.arguments);
                continue;
            }
            _ => continue,
        };
        if slot.is_none() && !value.is_empty() {
            *slot = Some(value.to_string());
        }
    }
    Declarations {
        meta,
        format,
        inline_sets,
    }
}

pub(super) fn read(text: &str, input: &ModuleInput<'_>) -> ModuleDef {
    let mut def = ModuleDef::default();
    let Declarations {
        meta,
        format,
        inline_sets,
    } = declarations(text, &mut def);
    let mut reader = Reader {
        input,
        rules: RuleReader::new(inline_sets, input.attachments),
        network: NetworkEdits::default(),
        skip_verify: None,
        def,
    };
    reader.def.format = format;
    let mut section: Option<&str> = None;
    for (number, raw) in numbered(text) {
        let trimmed = raw.trim();
        if let Some(name) = section_name(trimmed) {
            section = Some(name);
            continue;
        }
        let (line, requirement) = split_requirement(trimmed);
        if line.is_empty() || is_comment(line) {
            continue;
        }
        if let Some(requirement) = requirement
            && let Some(reason) = unmet(requirement, input)
        {
            reader.ignore(number, reason, None);
            continue;
        }
        let Some(section) = section else {
            reader.ignore(number, IgnoreReason::Section, None);
            continue;
        };
        let lower = section.to_ascii_lowercase();
        if lower == "script" {
            reader.declare_script(line, number);
        }
        let line = substitute_surge(line, &reader.def.arguments, input.arguments);
        let line = line.trim();
        if line.is_empty() || is_comment(line) {
            continue;
        }
        reader.read_line(&lower, section, line, number);
    }
    reader.def.meta = meta;
    reader.finish()
}

fn unmet(requirement: LineRequirement<'_>, input: &ModuleInput<'_>) -> Option<IgnoreReason> {
    let holds = match requirement {
        LineRequirement::Expression(expression) => evaluate(expression, input.environment),
        LineRequirement::System(system) => Some(input.environment.system == system),
    };
    match holds {
        Some(true) => None,
        Some(false) => Some(IgnoreReason::Requirement),
        None => Some(IgnoreReason::RequirementUnreadable),
    }
}

struct Reader<'a> {
    input: &'a ModuleInput<'a>,
    rules: RuleReader<'a>,
    network: NetworkEdits,
    skip_verify: Option<u32>,
    def: ModuleDef,
}

impl Reader<'_> {
    fn ignore(&mut self, line: u32, reason: IgnoreReason, detail: Option<String>) {
        self.def.ignored.push(IgnoredLine {
            line,
            reason,
            detail,
        });
    }

    fn read_line(&mut self, lower: &str, section: &str, line: &str, number: u32) {
        let lists = &mut self.def.lists;
        match lower {
            "general" => self.read_general(line, number),
            "host" => match self.network.read_host(line, number) {
                Ok(()) => {}
                Err(Refused::Setting) => self.ignore(number, IgnoreReason::Setting, None),
                Err(Refused::Unreadable(detail)) => {
                    self.ignore(number, IgnoreReason::Unreadable, Some(detail));
                }
            },
            "rule" => {
                let read = self.rules.read(line);
                self.read_rule(read, number);
            }
            "ip rewrite" => self.read_rule(ip_rewrite(line), number),
            "url rewrite" => lists.url_rewrite.push(at(number, parse_url_rewrite(line))),
            "header rewrite" => lists
                .header_rewrite
                .push(at(number, parse_header_rewrite(line))),
            "body rewrite" => lists
                .body_rewrite
                .push(at(number, parse_body_rewrite(line))),
            "map local" => self.read_map_local(line, number),
            "mitm" => self.read_mitm(line, number),
            "script" => self.read_script(line, number),
            _ if lower.starts_with("ruleset ") => {
                let set = section.get(8..).unwrap_or_default().trim();
                if let Err((reason, detail)) = self.rules.read_inline(set, line, number) {
                    self.ignore(number, reason, detail);
                }
            }
            _ if PROXY_SECTIONS.contains(&lower) => {
                self.ignore(number, IgnoreReason::Proxies, None)
            }
            _ if APP_ONLY_SECTIONS.contains(&lower)
                || lower.starts_with("wireguard ")
                || lower.starts_with("tailscale ") =>
            {
                self.ignore(number, IgnoreReason::AppOnly, None)
            }
            _ => self.ignore(number, IgnoreReason::Section, Some(section.to_string())),
        }
    }

    fn read_rule(&mut self, read: Result<super::ModuleRule, super::rule::Refusal>, line: u32) {
        match read {
            Ok(def) => self.def.rules.push(ModuleLine { line, def }),
            Err((reason, detail)) => self.ignore(line, reason, detail),
        }
    }

    fn read_general(&mut self, line: &str, number: u32) {
        let Some((key, value)) = key_value(line) else {
            self.ignore(number, IgnoreReason::Unreadable, None);
            return;
        };
        if key == "force-http-engine-hosts" {
            let (_, value) = list_mark(value);
            self.def.lists.force_http_hostname.push(ModuleLine {
                line: number,
                def: host_items(value),
            });
            return;
        }
        match self.network.read_general(&key, value, number) {
            Ok(()) => {}
            Err(Refused::Setting) => self.ignore(number, IgnoreReason::Setting, Some(key)),
            Err(Refused::Unreadable(detail)) => {
                self.ignore(number, IgnoreReason::Unreadable, Some(detail))
            }
        }
    }

    fn read_mitm(&mut self, line: &str, number: u32) {
        let Some((key, value)) = key_value(line) else {
            self.ignore(number, IgnoreReason::Unreadable, None);
            return;
        };
        let on = value.eq_ignore_ascii_case("true");
        let lists = &mut self.def.lists;
        match key.as_str() {
            "hostname" => {
                let (mark, value) = list_mark(value);
                lists.hostname.push(ModuleLine {
                    line: number,
                    def: HostLine {
                        insert: mark == ListMark::Insert,
                        items: host_items(value),
                    },
                });
            }
            "h2" if on => lists.h2 = lists.h2.or(Some(number)),
            "h2" => {}
            "skip-server-cert-verify" if on => self.skip_verify = Some(number),
            "skip-server-cert-verify" => {}
            "client-source-address" => {
                let (_, value) = list_mark(value);
                if !value.is_empty() {
                    lists.client_source_address.push(ModuleLine {
                        line: number,
                        def: source_items(value),
                    });
                }
            }
            "ca-p12" | "ca-passphrase" | "ca-keystore-name" | "keystore" => {
                self.ignore(number, IgnoreReason::ManagedCa, None)
            }
            _ => self.ignore(number, IgnoreReason::Setting, Some(key)),
        }
    }

    fn read_map_local(&mut self, line: &str, number: u32) {
        let mut read = parse_map_local(line, false);
        if let Ok(local) = &mut read
            && local.body == MapLocalBody::File
        {
            match locate(
                &local.data,
                ResourceKind::MapLocal,
                number,
                self.input.attachments,
                &mut self.def.resources,
            ) {
                Ok(path) => {
                    if is_url(&path) {
                        let without_query = path.split(['?', '#']).next().unwrap_or_default();
                        local.content_type =
                            mime_by_extension(without_query).unwrap_or("application/octet-stream");
                    }
                    local.data = path;
                }
                Err(reason) => {
                    self.ignore(number, reason, Some(local.data.clone()));
                    return;
                }
            }
        }
        self.def.lists.map_local.push(at(number, read));
    }

    /// Counted before the arguments are filled in, so a script an argument turns off still
    /// asks for consent.
    fn declare_script(&mut self, line: &str, number: u32) {
        let kind = split_script_line(line)
            .map(|(_, kind, _)| kind)
            .unwrap_or_default();
        if RUNNABLE_SCRIPTS.contains(&kind.as_str()) || kind.contains('{') {
            self.def.declared_scripts.push(number);
        }
    }

    fn read_script(&mut self, line: &str, number: u32) {
        if let Ok((_, kind, params)) = split_script_line(line) {
            let param = |key: &str| params.get(key).map(String::as_str);
            let refused = match kind.as_str() {
                "dns" | "rule" => Some(IgnoreReason::ScriptType),
                "event"
                    if !matches!(
                        param("event-name"),
                        Some(EVENT_NETWORK_CHANGED | EVENT_ENGINE_STARTED | EVENT_PROFILE_RELOADED)
                    ) =>
                {
                    Some(IgnoreReason::Event)
                }
                _ if param("enable").is_some_and(|on| on.eq_ignore_ascii_case("false")) => {
                    Some(IgnoreReason::Disabled)
                }
                _ => None,
            };
            if let Some(reason) = refused {
                self.ignore(number, reason, None);
                return;
            }
        }
        let mut read = parse_script(line);
        if let Ok(script) = &mut read {
            match locate(
                unquote(&script.path),
                ResourceKind::Script,
                number,
                self.input.attachments,
                &mut self.def.resources,
            ) {
                Ok(path) => script.path = path,
                Err(reason) => {
                    self.ignore(number, reason, Some(script.path.clone()));
                    return;
                }
            }
        }
        self.def.lists.script.push(at(number, read));
    }

    fn finish(mut self) -> ModuleDef {
        self.finish_skip_verify();
        let loon = self.def.format == ModuleFormat::Loon;
        self.def.network = std::mem::take(&mut self.network).finish(loon);
        self.def.rule_sets = std::mem::take(&mut self.rules.sets);
        self.def.off = module_off(&self.def.meta, self.input);
        self.def.ignored.sort_by_key(|ignored| ignored.line);
        self.def
    }

    /// A module may skip verifying its own hostnames' servers, never every server.
    fn finish_skip_verify(&mut self) {
        let Some(line) = self.skip_verify else {
            return;
        };
        let mut hosts = Vec::new();
        let mut covers_all = false;
        for entry in self
            .def
            .lists
            .hostname
            .iter()
            .flat_map(|host| &host.def.items.items)
            .filter(|entry| !entry.exclude)
        {
            if entry.pattern.chars().all(|c| c == '*') {
                covers_all = true;
            } else {
                hosts.push(entry.clone());
            }
        }
        if covers_all {
            self.ignore(line, IgnoreReason::SkipVerifyAll, None);
        }
        self.def.lists.skip_server_cert_verify = Some(ModuleLine { line, def: hosts });
    }
}

fn at<T>(line: u32, def: T) -> ModuleLine<T> {
    ModuleLine { line, def }
}

/// `#!system` gates a module only on a system Surge runs on, as it names those alone; a
/// module written for one runs everywhere else.
/// `#!system` names the systems Surge runs the module on, not where Concord does, so only
/// `#!requirement` turns a module off.
fn module_off(meta: &ModuleMeta, input: &ModuleInput<'_>) -> Option<ModuleOff> {
    let requirement = meta.requirement.as_deref()?;
    match evaluate(requirement, input.environment) {
        Some(true) => None,
        Some(false) => Some(ModuleOff::Requirement),
        None => Some(ModuleOff::RequirementUnreadable),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::mitm::module::{Environment, read_module};

    fn off(text: &str, system: &str) -> Option<ModuleOff> {
        let none = BTreeMap::new();
        let environment = Environment {
            system: system.to_string(),
            language: String::new(),
        };
        let input = ModuleInput {
            arguments: &none,
            attachments: &none,
            environment: &environment,
        };
        read_module(text, &input).off
    }

    #[test]
    fn only_the_requirement_turns_a_module_off() {
        assert_eq!(off("#!system=ios", "macOS"), None);
        assert_eq!(off("#!system=ios", ""), None);
        assert_eq!(
            off("#!system=mac\n#!requirement=SYSTEM = 'iOS'", "macOS"),
            Some(ModuleOff::Requirement)
        );
        assert_eq!(off("#!requirement=CORE_VERSION >= 20", ""), None);
        assert_eq!(
            off("#!requirement=(", ""),
            Some(ModuleOff::RequirementUnreadable)
        );
    }
}
