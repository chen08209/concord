//! Modules in force: the `modules` the section names, read from the text the engine hands in
//! and merged into the profile. Their rules go ahead of the profile's, their rule sets become
//! rule providers, their DNS and hosts entries edit the profile's own, and their section lines
//! follow the profile's, each remote file a line reads named by the file it is stored in.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::module::{
    Environment, ListEdit, ModuleDef, ModuleInput, NetworkDef, Policy, RuleSetDef, RuleSetSource,
    is_url, read_module,
};
use super::{BodyActionDef, MapLocalBody, MitmDef, MitmLine, Read, ScriptKind};
use crate::hosts::HostsConfig;
use crate::raw::RawConfig;
use crate::rule::{EXTENDED_MATCHING, REQUIRES_RESOLVE, RuleLines};
use crate::{LoadReport, Map};

/// The MITM engine's directory under the home directory, and its resources directory: the
/// engine's `AUTHORITY_DIR` and the `resources` it keeps there.
pub const MITM_DIR: &str = "mitm";
pub const RESOURCES_DIR: &str = "mitm/resources";

/// The file a remote file's content is stored in: the first 32 hex digits of the content's
/// SHA-256, then the extension the URL's path ends in when it is 1 to 8 letters or digits, so a
/// script keeps the type its loader goes by.
pub fn stored_name(url: &str, bytes: &[u8]) -> String {
    let digest = hex::encode(Sha256::digest(bytes));
    let hash = digest.get(..32).unwrap_or(&digest);
    let path = url.split(['?', '#']).next().unwrap_or_default();
    let last = path.rsplit('/').next().unwrap_or_default();
    match last.rsplit_once('.') {
        Some((_, extension))
            if (1..=8).contains(&extension.len())
                && extension.bytes().all(|byte| byte.is_ascii_alphanumeric()) =>
        {
            format!("{hash}.{extension}")
        }
        _ => hash.to_string(),
    }
}

/// Why the engine could not read a module the section names by `path`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unreadable(pub String);

/// By name, the text of each module the section names by `path`, as the engine read it.
pub type ModuleTexts = BTreeMap<String, Result<String, Unreadable>>;

/// A module the host has installed, as the section names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct ModuleSpec {
    /// The host's name for it, unique among the modules.
    pub name: String,
    /// Relative to the MITM directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(
        deserialize_with = "scalars",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub arguments: BTreeMap<String, String>,
    /// By the relative path the module names, the file in the resources directory.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub attachments: BTreeMap<String, String>,
    /// Remote files the host stored before Concord did, by URL: the file in the resources
    /// directory, which Concord takes over while it is still there.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub adopt_resources: BTreeMap<String, String>,
    /// Off, it is read so that the files it reads are kept, and takes no effect.
    pub enabled: bool,
}

impl Default for ModuleSpec {
    fn default() -> ModuleSpec {
        ModuleSpec {
            name: String::new(),
            path: None,
            text: None,
            arguments: BTreeMap::new(),
            attachments: BTreeMap::new(),
            adopt_resources: BTreeMap::new(),
            enabled: true,
        }
    }
}

/// Argument values as text whatever YAML made of them; a module's declaration types them.
fn scalars<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    let values = Option::<BTreeMap<String, Value>>::deserialize(deserializer)?.unwrap_or_default();
    Ok(values
        .into_iter()
        .map(|(name, value)| {
            let text = match value {
                Value::String(text) => text,
                Value::Null => String::new(),
                other => other.to_string(),
            };
            (name, text)
        })
        .collect())
}

/// The section's keys for modules, read ahead of the rest of the profile.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
struct Settings {
    modules: Vec<ModuleSpec>,
    module_policy: BTreeMap<String, String>,
    module_language: String,
}

/// The modules the raw `mitm` section names by `path` alone, by name: what the engine reads
/// before the profile is loaded.
pub fn module_paths(section: &Map) -> Vec<(String, String)> {
    let settings: Settings =
        serde_json::from_value(Value::Object(section.clone())).unwrap_or_default();
    settings
        .modules
        .into_iter()
        .filter(|spec| spec.text.is_none())
        .filter_map(|spec| Some((spec.name, spec.path?)))
        .collect()
}

/// Why a module named in the section takes no effect at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "camelCase")]
pub enum ModuleProblem {
    /// Neither its `path` nor its `text` gives a module.
    Unreadable { detail: String },
    /// An earlier module has its name.
    Duplicate,
}

/// A module rule left out of the profile's rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RefusedRule {
    pub line: u32,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub struct AppliedModule {
    pub spec: ModuleSpec,
    pub text: String,
    pub def: ModuleDef,
    pub problem: Option<ModuleProblem>,
    pub refused_rules: Vec<RefusedRule>,
}

impl AppliedModule {
    /// How logs name it: its own name, with the host's after it when they differ.
    pub fn origin(&self) -> Arc<str> {
        match &self.def.meta.name {
            Some(name) if *name != self.spec.name => format!("{name} ({})", self.spec.name).into(),
            _ => self.spec.name.as_str().into(),
        }
    }

    /// On, read, and not turned off by its own requirement.
    pub fn in_force(&self) -> bool {
        self.spec.enabled && self.problem.is_none() && self.def.off.is_none()
    }
}

/// The modules of a profile being loaded, and the host's mapping of their policy names.
pub(crate) struct Modules {
    pub list: Vec<AppliedModule>,
    policy: BTreeMap<String, String>,
}

/// Reads the modules the raw `mitm` section names and writes their DNS and hosts entries and
/// rule sets into `raw`; `texts` holds by name what the engine read from each `path`, or why
/// it could not.
pub(crate) fn read(raw: &mut RawConfig, texts: &ModuleTexts) -> Modules {
    let settings: Settings =
        serde_json::from_value(Value::Object(raw.mitm.clone())).unwrap_or_default();
    let environment = Environment::current(settings.module_language);
    let mut names = HashSet::new();
    let list = settings
        .modules
        .into_iter()
        .map(|spec| {
            let source = match (&spec.text, &spec.path) {
                (Some(text), _) => Ok(text.clone()),
                (None, Some(_)) => texts
                    .get(&spec.name)
                    .cloned()
                    .unwrap_or_else(|| Err(Unreadable("not read".to_string()))),
                (None, None) => Err(Unreadable("neither path nor text is given".to_string())),
            };
            let problem = if names.insert(spec.name.clone()) {
                source.as_ref().err().map(|why| ModuleProblem::Unreadable {
                    detail: why.0.clone(),
                })
            } else {
                Some(ModuleProblem::Duplicate)
            };
            let text = source.unwrap_or_default();
            let def = match problem {
                None => read_module(
                    &text,
                    &ModuleInput {
                        arguments: &spec.arguments,
                        attachments: &spec.attachments,
                        environment: &environment,
                    },
                ),
                Some(_) => ModuleDef::default(),
            };
            AppliedModule {
                spec,
                text,
                def,
                problem,
                refused_rules: Vec::new(),
            }
        })
        .collect();
    let modules = Modules {
        list,
        policy: settings.module_policy,
    };
    modules.edit_raw(raw);
    modules
}

impl Modules {
    fn in_force(&self) -> impl Iterator<Item = &AppliedModule> {
        self.list.iter().filter(|module| module.in_force())
    }

    fn edit_raw(&self, raw: &mut RawConfig) {
        let network = merged_network(self.in_force());
        for (key, edit) in [
            ("nameserver", &network.nameserver),
            ("default-nameserver", &network.default_nameserver),
            ("fake-ip-filter", &network.fake_ip_filter),
        ] {
            if let Some(edit) = edit {
                edit_list(&mut raw.dns, key, edit);
            }
        }
        if !network.nameserver_policy.is_empty() {
            let mut policy = match raw.dns.remove("nameserver-policy") {
                Some(Value::Object(policy)) => policy,
                _ => Map::new(),
            };
            for entry in &network.nameserver_policy {
                policy.insert(entry.domain.clone(), json!(entry.values));
            }
            raw.dns
                .insert("nameserver-policy".to_string(), Value::Object(policy));
        }
        for entry in &network.hosts {
            raw.hosts.insert(entry.domain.clone(), json!(entry.values));
        }
        for set in rule_sets(self.in_force()) {
            if !raw.rule_providers.contains_key(&set.name) {
                let provider = provider_map(&set);
                raw.rule_providers.insert(set.name, provider);
            }
        }
    }

    /// Every module's rules in module order ahead of `rules`, each with its policy mapped to an
    /// outbound and kept when `check` passes it as a profile line; the others are noted on
    /// their module.
    pub fn ahead(
        &mut self,
        rules: RuleLines,
        mut check: impl FnMut(&str) -> crate::Result<()>,
    ) -> RuleLines {
        let mut lines = Vec::new();
        for module in self.list.iter_mut().filter(|module| module.in_force()) {
            for rule in &module.def.rules {
                let target = match &rule.def.policy {
                    Policy::Builtin(name) => (*name).to_string(),
                    Policy::Named(name) => self
                        .policy
                        .get(name)
                        .cloned()
                        .unwrap_or_else(|| name.clone()),
                };
                let mut line = format!("{},{target}", rule.def.rule);
                if rule.def.no_resolve {
                    line.push_str(",no-resolve");
                }
                if rule.def.extended_matching {
                    line.push(',');
                    line.push_str(EXTENDED_MATCHING);
                }
                if rule.def.requires_resolve {
                    line.push(',');
                    line.push_str(REQUIRES_RESOLVE);
                }
                match check(&line) {
                    Ok(()) => lines.push(line),
                    Err(err) => module.refused_rules.push(RefusedRule {
                        line: rule.line,
                        detail: err.to_string(),
                    }),
                }
            }
        }
        if lines.is_empty() {
            return rules;
        }
        let bytes = lines.iter().map(String::len).sum::<usize>()
            + rules.iter().map(str::len).sum::<usize>();
        let mut joined = RuleLines::with_text_capacity(bytes);
        for line in lines.iter().map(String::as_str).chain(rules.iter()) {
            joined.push(line);
        }
        joined
    }
}

/// `hosts` without the entries naming no `dns` script the profile or a module declares, each
/// `[Host]` line of those noted on its module.
pub(crate) fn hosts_with_scripts(
    hosts: HostsConfig,
    own: &MitmDef,
    modules: &mut [AppliedModule],
    report: &mut LoadReport,
) -> HostsConfig {
    let declared = script_names(own, modules, ScriptKind::Dns);
    for module in modules.iter_mut().filter(|module| module.in_force()) {
        for entry in &module.def.network.hosts {
            let unknown = entry.values.iter().find_map(|value| {
                value
                    .strip_prefix(crate::hosts::SCRIPT_PREFIX)
                    .filter(|name| !declared.contains(name.trim()))
            });
            if let Some(name) = unknown {
                module.refused_rules.push(RefusedRule {
                    line: entry.line,
                    detail: format!("dns script [{name}] not found"),
                });
            }
        }
    }
    hosts.with_scripts(&declared, report)
}

/// The names of the scripts of `kind` the profile's own section and the modules in force declare.
pub fn script_names(own: &MitmDef, modules: &[AppliedModule], kind: ScriptKind) -> HashSet<String> {
    let modules = modules
        .iter()
        .filter(|module| module.in_force())
        .flat_map(|module| module.def.lists.script.iter().map(|line| &line.def));
    own.script
        .iter()
        .map(|line| &line.read)
        .chain(modules)
        .filter_map(|read| read.as_ref().ok())
        .filter(|def| def.kind == kind)
        .map(|def| def.name.clone())
        .collect()
}

fn joined<T: Clone>(a: &[T], b: &[T]) -> Vec<T> {
    [a, b].concat()
}

fn merged_network<'a>(modules: impl Iterator<Item = &'a AppliedModule>) -> NetworkDef {
    let edit = |a: &Option<ListEdit>, b: &Option<ListEdit>| match (a, b) {
        (Some(a), Some(b)) => Some(a.clone().then(b.clone())),
        (a, b) => a.clone().or_else(|| b.clone()),
    };
    modules.fold(NetworkDef::default(), |merged, module| {
        let next = &module.def.network;
        NetworkDef {
            nameserver: edit(&merged.nameserver, &next.nameserver),
            default_nameserver: edit(&merged.default_nameserver, &next.default_nameserver),
            fake_ip_filter: edit(&merged.fake_ip_filter, &next.fake_ip_filter),
            nameserver_policy: joined(&merged.nameserver_policy, &next.nameserver_policy),
            hosts: joined(&merged.hosts, &next.hosts),
            route_address: joined(&merged.route_address, &next.route_address),
            route_exclude_address: edit(&merged.route_exclude_address, &next.route_exclude_address),
            bypass_domain: edit(&merged.bypass_domain, &next.bypass_domain),
            lines: Vec::new(),
        }
    })
}

/// What of the modules' network requests the host carries out: TUN routes and the system
/// proxy's bypass list.
pub fn host_network(modules: &[AppliedModule]) -> NetworkDef {
    let merged = merged_network(modules.iter().filter(|module| module.in_force()));
    NetworkDef {
        route_address: merged.route_address,
        route_exclude_address: merged.route_exclude_address,
        bypass_domain: merged.bypass_domain,
        ..NetworkDef::default()
    }
}

fn edit_list(map: &mut Map, key: &str, edit: &ListEdit) {
    let own: Vec<Value> = match map.get(key) {
        Some(Value::Array(items)) if !edit.replace => items.clone(),
        _ => Vec::new(),
    };
    let items = edit
        .before
        .iter()
        .map(|item| Value::String(item.clone()))
        .chain(own)
        .chain(edit.after.iter().map(|item| Value::String(item.clone())))
        .collect();
    map.insert(key.to_string(), Value::Array(items));
}

/// The modules' rule sets, an inline set of one name gathering its lines from every module
/// that writes it, as Surge adds up `[Ruleset]` sections of one name.
fn rule_sets<'a>(modules: impl Iterator<Item = &'a AppliedModule>) -> Vec<RuleSetDef> {
    let mut sets: Vec<RuleSetDef> = Vec::new();
    for set in modules.flat_map(|module| &module.def.rule_sets) {
        match sets.iter_mut().find(|known| known.name == set.name) {
            Some(known) => {
                if let (RuleSetSource::Inline { rules }, RuleSetSource::Inline { rules: more }) =
                    (&mut known.source, &set.source)
                {
                    rules.extend(more.iter().cloned());
                }
            }
            None => sets.push(set.clone()),
        }
    }
    sets
}

fn provider_map(set: &RuleSetDef) -> Map {
    let mut provider = Map::new();
    let mut put = |key: &str, value: Value| {
        provider.insert(key.to_string(), value);
    };
    put(
        "behavior",
        json!(if set.domain { "domain" } else { "classical" }),
    );
    match &set.source {
        RuleSetSource::Url { url, interval } => {
            put("type", json!("http"));
            put("url", json!(url));
            put("format", json!("text"));
            if let Some(interval) = interval {
                put("interval", json!(interval));
            }
        }
        RuleSetSource::Inline { rules } => {
            put("type", json!("inline"));
            let payload: Vec<&str> = rules.iter().map(|rule| rule.rule.as_str()).collect();
            put("payload", json!(payload));
        }
        RuleSetSource::Builtin { rules } => {
            put("type", json!("inline"));
            put("payload", json!(rules));
        }
        RuleSetSource::File { file } => {
            put("type", json!("file"));
            put("format", json!("text"));
            put("path", json!(format!("{RESOURCES_DIR}/{file}")));
        }
    }
    provider
}

/// The section in force: the profile's own lines, then each module's in module order, with
/// each remote file a line reads named by the file `stored` keeps it in. A file not stored
/// leaves its URL, which the line then reports as missing. Hostnames go the profile's first,
/// then every module's `%INSERT%` lines, then the rest.
pub fn compose(
    own: &MitmDef,
    modules: &[AppliedModule],
    stored: impl Fn(&str) -> Option<String>,
) -> MitmDef {
    let mut section = own.clone();
    let mut appended = Vec::new();
    for module in modules.iter().filter(|module| module.in_force()) {
        let mut lines = module.def.section(&module.text);
        lines.mark_origin(&module.origin());
        let inserts = module.def.lists.hostname.iter().map(|line| line.def.insert);
        for (line, insert) in lines.hostname.into_iter().zip(inserts) {
            if insert {
                section.hostname.push(line);
            } else {
                appended.push(line);
            }
        }
        section.hostname_disabled.extend(lines.hostname_disabled);
        section.h2 |= lines.h2;
        section
            .skip_server_cert_verify_hostname
            .extend(lines.skip_server_cert_verify_hostname);
        section
            .client_source_address
            .extend(lines.client_source_address);
        section.url_rewrite.extend(lines.url_rewrite);
        section.header_rewrite.extend(lines.header_rewrite);
        section
            .body_rewrite
            .extend(stored_in(
                lines.body_rewrite,
                &stored,
                |def| match &mut def.action {
                    BodyActionDef::JqFile(path) => Some(path),
                    _ => None,
                },
            ));
        section
            .map_local
            .extend(stored_in(lines.map_local, &stored, local_file));
        section
            .request_body_mock
            .extend(stored_in(lines.request_body_mock, &stored, local_file));
        section
            .script
            .extend(stored_in(lines.script, &stored, |def| Some(&mut def.path)));
    }
    section.hostname.extend(appended);
    section
}

fn local_file(def: &mut super::MapLocalDef) -> Option<&mut String> {
    matches!(def.body, MapLocalBody::File { .. }).then_some(&mut def.data)
}

fn stored_in<T>(
    mut lines: Vec<MitmLine<Read<T>>>,
    stored: &impl Fn(&str) -> Option<String>,
    path: impl Fn(&mut T) -> Option<&mut String>,
) -> Vec<MitmLine<Read<T>>> {
    for line in &mut lines {
        if let Ok(def) = &mut line.read
            && let Some(path) = path(def)
            && is_url(path)
            && let Some(file) = stored(path)
        {
            *path = file;
        }
    }
    lines
}

#[cfg(test)]
#[path = "modules_tests.rs"]
mod tests;
