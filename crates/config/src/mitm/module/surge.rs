//! The sectioned text Surge and Loon write, a section's lines read the way that section is.

use std::borrow::Cow;

use super::arguments::{read_loon, read_surge, substitute_loon, substitute_surge};
use super::loon::{self, Out};
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
    ModuleMeta, ModuleOff, Unreadable,
};
use crate::mitm::rules::mime_by_extension;
use crate::mitm::script::{
    EVENT_ENGINE_STARTED, EVENT_NETWORK_CHANGED, EVENT_PROFILE_RELOADED, split_script_line,
};
use crate::mitm::{
    BodyActionDef, MapLocalBody, MapLocalDef, Read, host_items, parse_body_rewrite,
    parse_header_rewrite, parse_map_local, parse_script, parse_url_rewrite, source_items,
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
    let mut tag = None;
    let mut in_arguments = false;
    for (number, raw) in numbered(text) {
        let line = raw.trim();
        if in_arguments && !line.is_empty() && !is_comment(line) && section_name(line).is_none() {
            match read_loon(line, number) {
                Ok(argument) => def.arguments.push(argument),
                Err(Unreadable(detail)) => def.ignored.push(IgnoredLine {
                    line: number,
                    reason: IgnoreReason::Unreadable,
                    detail: Some(detail),
                }),
            }
            continue;
        }
        if let Some(name) = section_name(line) {
            let lower = name.to_ascii_lowercase();
            in_arguments = lower == "argument";
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
            "tag" => {
                if tag.is_none() && !value.is_empty() {
                    tag = Some(value.to_string());
                }
                continue;
            }
            _ => continue,
        };
        if slot.is_none() && !value.is_empty() {
            *slot = Some(value.to_string());
        }
    }
    if format == ModuleFormat::Loon && meta.category.is_none() {
        meta.category = tag;
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
        if lower == "argument" {
            continue;
        }
        if lower == "script" || loon::is_new_script(line) {
            reader.declare_script(line, number);
        }
        if matches!(lower.as_str(), "rewrite" | "script") && loon::is_new(line) {
            reader.read_new(line, number);
            continue;
        }
        let raw = line;
        let line = substitute_surge(line, &reader.def.arguments, input.arguments);
        let line = match reader.def.format {
            ModuleFormat::Loon => Cow::Owned(
                substitute_loon(&line, &reader.def.arguments, input.arguments).into_owned(),
            ),
            _ => line,
        };
        let line = line.trim();
        if line.is_empty() || is_comment(line) {
            continue;
        }
        reader.read_line(&lower, section, line, raw, number);
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

    fn read_line(&mut self, lower: &str, section: &str, line: &str, raw: &str, number: u32) {
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
            "map local" => {
                let mut read = parse_map_local(line, false);
                if self.place_file(&mut read, number) {
                    self.def.lists.map_local.push(at(number, read));
                }
            }
            "mitm" => self.read_mitm(line, number),
            "script" => self.read_script(line, raw, number),
            "rewrite" => match loon::read_legacy(line) {
                Ok(outs) => outs.into_iter().for_each(|out| self.place(number, out)),
                Err((reason, detail)) => self.ignore(number, reason, detail),
            },
            "remote rule" => match self.rules.remote(line) {
                Ok(Some(def)) => self.def.rules.push(ModuleLine { line: number, def }),
                Ok(None) => self.ignore(number, IgnoreReason::Disabled, None),
                Err((reason, detail)) => self.ignore(number, reason, detail),
            },
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

    /// A new-syntax Loon line, read with the arguments as typed values.
    fn read_new(&mut self, line: &str, number: u32) {
        match loon::read_new(line, &self.def.arguments, self.input.arguments) {
            Ok(Some(outs)) => outs.into_iter().for_each(|out| self.place(number, out)),
            Ok(None) => self.ignore(number, IgnoreReason::Disabled, None),
            Err((reason, detail)) => self.ignore(number, reason, detail),
        }
    }

    fn place(&mut self, number: u32, out: Out) {
        match out {
            Out::Url(read) => self.def.lists.url_rewrite.push(at(number, read)),
            Out::Header(read) => self.def.lists.header_rewrite.push(at(number, read)),
            Out::Body(mut read) => {
                if let Ok(def) = &mut read
                    && let BodyActionDef::JqFile(path) = &mut def.action
                {
                    match self.locate(path, ResourceKind::Jq, number) {
                        Some(file) => *path = file,
                        None => return,
                    }
                }
                self.def.lists.body_rewrite.push(at(number, read));
            }
            Out::MapLocal(mut read) => {
                if self.place_file(&mut read, number) {
                    self.def.lists.map_local.push(at(number, read));
                }
            }
            Out::RequestBodyMock(mut read) => {
                if self.place_file(&mut read, number) {
                    self.def.lists.request_body_mock.push(at(number, read));
                }
            }
            Out::Script(mut def) => {
                if let Some(file) = self.locate(&def.path, ResourceKind::Script, number) {
                    def.path = file;
                    self.def.lists.script.push(at(number, Ok(def)));
                }
            }
        }
    }

    /// The file a line names: a URL stays as the resource it is, a relative path becomes its
    /// attachment; `None` once the line is ignored for want of one.
    fn locate(&mut self, path: &str, kind: ResourceKind, number: u32) -> Option<String> {
        let path = unquote(path);
        match locate(
            path,
            kind,
            number,
            self.input.attachments,
            &mut self.def.resources,
        ) {
            Ok(file) => Some(file),
            Err(reason) => {
                self.ignore(number, reason, Some(path.to_string()));
                None
            }
        }
    }

    /// Places a map local's file; `false` once the line is ignored for want of one.
    fn place_file(&mut self, read: &mut Read<MapLocalDef>, number: u32) -> bool {
        let Ok(local) = read else {
            return true;
        };
        if !matches!(local.body, MapLocalBody::File { .. }) {
            return true;
        }
        let Some(path) = self.locate(&local.data.clone(), ResourceKind::MapLocal, number) else {
            return false;
        };
        if is_url(&path) {
            let without_query = path.split(['?', '#']).next().unwrap_or_default();
            local.content_type =
                mime_by_extension(without_query).unwrap_or("application/octet-stream");
        }
        local.data = path;
        true
    }

    /// Counted before the arguments are filled in, so a script an argument turns off still
    /// asks for consent.
    fn declare_script(&mut self, line: &str, number: u32) {
        if loon::is_new_script(line) {
            self.def.declared_scripts.push(number);
            return;
        }
        let kind = split_script_line(line)
            .map(|(_, kind, _)| kind)
            .unwrap_or_default();
        if RUNNABLE_SCRIPTS.contains(&kind.as_str()) || kind.contains('{') {
            self.def.declared_scripts.push(number);
        }
    }

    fn read_script(&mut self, line: &str, raw: &str, number: u32) {
        let mut legacy = false;
        if let Ok((_, kind, params)) = split_script_line(line) {
            legacy = !params.contains_key("type");
            let param = |key: &str| params.get(key).map(String::as_str);
            let off = |key: &str| param(key).is_some_and(|on| on.eq_ignore_ascii_case("false"));
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
                _ if off("enable") || off("enabled") => Some(IgnoreReason::Disabled),
                _ => None,
            };
            if let Some(reason) = refused {
                self.ignore(number, reason, None);
                return;
            }
        }
        let mut read = parse_script(line);
        if let Ok(script) = &mut read {
            if legacy {
                self.read_legacy_script(script, raw);
            }
            match self.locate(&script.path.clone(), ResourceKind::Script, number) {
                Some(file) => script.path = file,
                None => return,
            }
        }
        self.def.lists.script.push(at(number, read));
    }

    /// Loon's legacy script: its URL regex ignores case (Script/script_v2), and its plugin
    /// arguments may be handed on as an object.
    fn read_legacy_script(&self, script: &mut crate::mitm::ScriptDef, raw: &str) {
        if let Some(pattern) = &mut script.pattern {
            pattern.insert_str(0, "(?i)");
        }
        if let Some(argument) = loon::legacy_script(raw, &self.def.arguments, self.input.arguments)
        {
            script.argument = Some(argument);
        }
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
