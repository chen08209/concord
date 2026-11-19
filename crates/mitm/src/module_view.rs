//! How a module reads, for a host that shows it before and after it is added: the module's
//! own definitions, and each of its lines in force compiled as the engine compiles them.

use std::collections::BTreeMap;

use concord_config::mitm::module::{
    ArgumentDef, IgnoreReason, ModuleFormat, ModuleInput, ModuleMeta, ModuleOff, ModuleRule,
    NetworkDef, ResourceDef, RuleSetDef, lines, read_module,
};
use serde::Serialize;

use crate::config::{Issue, LineEntry, ParseEnv, check_def};

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleView {
    pub format: ModuleFormat,
    pub meta: ModuleMeta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub off: Option<ModuleOff>,
    pub arguments: Vec<ArgumentDef>,
    pub resources: Vec<ResourceDef>,
    pub declared_scripts: Vec<u32>,
    pub asks_consent: bool,
    /// By list, as `mitm.validate` keys them, plus `force-http-hostname`; an index is the
    /// module line.
    pub issues: BTreeMap<String, Vec<Issue>>,
    pub views: BTreeMap<String, Vec<LineEntry>>,
    pub rules: Vec<RuleView>,
    pub rule_sets: Vec<RuleSetDef>,
    pub network: NetworkDef,
    pub ignored: Vec<IgnoredView>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RuleView {
    pub line: u32,
    #[serde(flatten)]
    pub rule: ModuleRule,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct IgnoredView {
    pub line: u32,
    pub text: String,
    pub reason: IgnoreReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

const FORCE_HTTP: &str = "force-http-hostname";

pub(crate) fn view_module(text: &str, input: &ModuleInput<'_>, env: &ParseEnv) -> ModuleView {
    let def = read_module(text, input);
    let mut validation = check_def(&def.section(text), env);
    let force_http = check_def(&def.force_http_section(text), env);
    if let Some(issues) = force_http.issues.into_values().next() {
        validation.issues.insert(FORCE_HTTP.to_string(), issues);
    }
    if let Some(views) = force_http.views.into_values().next() {
        validation.views.insert(FORCE_HTTP.to_string(), views);
    }
    let lines = lines(text);
    let line_text = |line: u32| {
        lines
            .get((line as usize).saturating_sub(1))
            .copied()
            .unwrap_or_default()
            .to_string()
    };
    let asks_consent = def.asks_consent();
    ModuleView {
        format: def.format,
        meta: def.meta,
        off: def.off,
        arguments: def.arguments,
        resources: def.resources,
        declared_scripts: def.declared_scripts,
        asks_consent,
        issues: validation.issues,
        views: validation.views,
        rules: def
            .rules
            .into_iter()
            .map(|line| RuleView {
                line: line.line,
                rule: line.def,
            })
            .collect(),
        rule_sets: def.rule_sets,
        network: def.network,
        ignored: def
            .ignored
            .into_iter()
            .map(|ignored| IgnoredView {
                text: line_text(ignored.line),
                line: ignored.line,
                reason: ignored.reason,
                detail: ignored.detail,
            })
            .collect(),
    }
}
