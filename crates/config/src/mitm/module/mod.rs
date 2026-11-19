//! Reads a module, as Surge, Loon, Quantumult X and Stash write one, into the typed definitions
//! the `mitm` section and the rule table take. Nothing here touches a file or the network: the
//! caller hands in the text, the values the user set for its arguments and the files attached
//! to it, and downloads what [ModuleDef::resources] names.
//!
//! Every definition carries the line of the module it came from, counted from 1. A line that
//! does not take effect is either kept in its list with its error, as the profile's own lines
//! are, or listed in [ModuleDef::ignored] with the reason.

/// A line that does not parse, and what in it does not.
#[derive(Debug)]
pub(super) struct Unreadable(pub(super) String);

impl From<String> for Unreadable {
    fn from(detail: String) -> Self {
        Self(detail)
    }
}

impl From<&str> for Unreadable {
    fn from(detail: &str) -> Self {
        Self(detail.to_string())
    }
}

mod arguments;
mod loon;
mod network;
mod qx;
#[cfg(test)]
mod qx_stash_tests;
mod requirement;
mod resource;
mod rule;
mod source;
mod stash;
mod surge;
#[cfg(test)]
mod surge_tests;

use std::collections::BTreeMap;

use serde::Serialize;

use super::hosts::{HostEntryDef, SourceEntryDef};
use super::rules::{BodyRewriteDef, HeaderRewriteDef, MapLocalDef, UrlRewriteDef};
use super::script::ScriptDef;
use super::{Items, MitmDef, MitmLine, Read};

pub use arguments::{ArgumentDef, ArgumentKind};
pub use network::{DomainEntry, ListEdit, NetworkDef};
pub use requirement::{Environment, evaluate};
pub(crate) use resource::is_url;
pub use resource::{InlineFile, ResourceDef, ResourceKind};
pub use rule::{InlineRule, ModuleRule, Policy, RuleSetDef, RuleSetSource};

/// What [read_module] reads besides the text.
#[derive(Clone, Copy, Debug)]
pub struct ModuleInput<'a> {
    /// By argument name, as the user set it; a declared argument missing here takes its default.
    pub arguments: &'a BTreeMap<String, String>,
    /// By the relative path the module names, the file in the resources directory the host
    /// stored it as.
    pub attachments: &'a BTreeMap<String, String>,
    pub environment: &'a Environment,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleFormat {
    #[default]
    Surge,
    Loon,
    QuantumultX,
    Stash,
}

/// The `#!` lines a host shows; each is the first one of its key, trimmed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleMeta {
    pub name: Option<String>,
    pub desc: Option<String>,
    pub author: Option<String>,
    pub icon: Option<String>,
    pub homepage: Option<String>,
    pub category: Option<String>,
    /// Shown only: it names the systems Surge runs the module on, so it never turns it off.
    pub system: Option<String>,
    pub requirement: Option<String>,
    pub arguments_desc: Option<String>,
}

/// Why a module takes no effect as a whole, though its lines are still read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "camelCase")]
pub enum ModuleOff {
    /// `#!requirement` does not hold.
    Requirement,
    /// `#!requirement` cannot be read.
    RequirementUnreadable,
}

/// A definition and the module line it came from. One line may give several, as a hostname line
/// of many items does.
#[derive(Clone, Debug, PartialEq)]
pub struct ModuleLine<T> {
    pub line: u32,
    pub def: T,
}

/// A `hostname` line: `%INSERT%` puts its items ahead of what every module appends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostLine {
    pub insert: bool,
    pub items: Items<HostEntryDef>,
}

/// The module's part of each of the section's lists, in module order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ModuleLists {
    pub hostname: Vec<ModuleLine<HostLine>>,
    /// Surge's `force-http-engine-hosts`: plain HTTP these hosts carry goes through the HTTP
    /// engine, and their TLS is never decrypted.
    pub force_http_hostname: Vec<ModuleLine<Items<HostEntryDef>>>,
    /// The module's own hostnames, when it asks not to verify their servers.
    pub skip_server_cert_verify: Option<ModuleLine<Vec<HostEntryDef>>>,
    pub client_source_address: Vec<ModuleLine<Items<SourceEntryDef>>>,
    /// The line that turns on HTTP/2 towards clients.
    pub h2: Option<u32>,
    pub url_rewrite: Vec<ModuleLine<Read<UrlRewriteDef>>>,
    pub header_rewrite: Vec<ModuleLine<Read<HeaderRewriteDef>>>,
    pub body_rewrite: Vec<ModuleLine<Read<BodyRewriteDef>>>,
    pub map_local: Vec<ModuleLine<Read<MapLocalDef>>>,
    pub request_body_mock: Vec<ModuleLine<Read<MapLocalDef>>>,
    pub script: Vec<ModuleLine<Read<ScriptDef>>>,
}

/// Why a line takes no effect. A host shows each reason in its own words.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IgnoreReason {
    /// A section no format has, or one Concord does not read.
    Section,
    /// A section for a feature of the app the module was written for (a panel, a DHCP server).
    AppOnly,
    /// `[Proxy]` and `[Proxy Group]`, which a module may not change.
    Proxies,
    /// A key of `[General]` or `[MITM]` Concord does not take from a module.
    Setting,
    /// The CA, which the host manages.
    ManagedCa,
    /// A line requirement that does not hold.
    Requirement,
    /// A line requirement that cannot be read.
    RequirementUnreadable,
    /// A `dns` or `rule` script.
    ScriptType,
    /// An event script for an event Concord does not raise.
    Event,
    /// `enable=false` and the like.
    Disabled,
    /// `FINAL`: module rules go before the profile's, which ends with its own.
    FinalRule,
    /// A rule on what only an Apple device knows of itself or its network.
    DeviceRule,
    /// A rule of a type Concord has no counterpart for.
    RuleType,
    /// A policy that names nothing, as an argument left unexpanded.
    Policy,
    /// `RULE-SET` or `DOMAIN-SET` inside a `[Ruleset]` section.
    NestedRuleSet,
    /// `reflect` in `[IP Rewrite]`.
    Reflect,
    /// `skip-server-cert-verify` while a hostname entry covers every host.
    SkipVerifyAll,
    /// A relative path no attachment provides.
    NoAttachment,
    /// A line of a section Concord reads that does not parse.
    Unreadable,
    /// A condition Concord cannot test, as `||` across the URL and a header.
    Condition,
    /// A value only the request at hand fills in, as the condition's capture inside a header
    /// value; a URL rewrite's replacement may name the URL's.
    RuntimeValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IgnoredLine {
    pub line: u32,
    pub reason: IgnoreReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ModuleDef {
    pub format: ModuleFormat,
    pub meta: ModuleMeta,
    pub arguments: Vec<ArgumentDef>,
    pub off: Option<ModuleOff>,
    pub lists: ModuleLists,
    /// In module order, ahead of the profile's own rules.
    pub rules: Vec<ModuleLine<ModuleRule>>,
    /// The rule sets the rules name, under names no profile uses.
    pub rule_sets: Vec<RuleSetDef>,
    pub resources: Vec<ResourceDef>,
    pub inline_files: Vec<InlineFile>,
    pub network: NetworkDef,
    /// The lines that declare a script Concord runs, whatever the arguments turn off: what the
    /// user consents to.
    pub declared_scripts: Vec<u32>,
    pub ignored: Vec<IgnoredLine>,
}

impl ModuleDef {
    /// Whether turning it on changes what the user set for traffic it does not itself
    /// rewrite, which they confirm first.
    pub fn asks_consent(&self) -> bool {
        !self.network.is_empty()
            || self.lists.skip_server_cert_verify.is_some()
            || !self.lists.client_source_address.is_empty()
    }
}

impl ModuleDef {
    /// The module's lists as a section in force, each line as the module wrote it, numbered
    /// by its module line: what the engine compiles and views. `text` is the module read.
    pub fn section(&self, text: &str) -> MitmDef {
        let lines = lines(text);
        let at = |line: u32| -> (usize, String) {
            let index = line as usize;
            let text = lines
                .get(index.saturating_sub(1))
                .copied()
                .unwrap_or_default();
            (index, text.to_string())
        };
        fn each<T: Clone, U>(
            list: &[ModuleLine<T>],
            at: &impl Fn(u32) -> (usize, String),
            map: impl Fn(&T) -> U,
        ) -> Vec<MitmLine<U>> {
            list.iter()
                .map(|line| {
                    let (index, text) = at(line.line);
                    MitmLine {
                        index,
                        text,
                        read: map(&line.def),
                    }
                })
                .collect()
        }
        let lists = &self.lists;
        let skip = lists.skip_server_cert_verify.as_ref().map(|line| {
            let (index, text) = at(line.line);
            MitmLine {
                index,
                text,
                read: Items {
                    items: line.def.clone(),
                    error: None,
                },
            }
        });
        MitmDef {
            enable: true,
            h2: lists.h2.is_some(),
            hostname: each(&lists.hostname, &at, |line| line.items.clone()),
            skip_server_cert_verify_hostname: skip.into_iter().collect(),
            client_source_address: each(&lists.client_source_address, &at, Clone::clone),
            url_rewrite: each(&lists.url_rewrite, &at, Clone::clone),
            header_rewrite: each(&lists.header_rewrite, &at, Clone::clone),
            body_rewrite: each(&lists.body_rewrite, &at, Clone::clone),
            map_local: each(&lists.map_local, &at, Clone::clone),
            request_body_mock: each(&lists.request_body_mock, &at, Clone::clone),
            script: each(&lists.script, &at, Clone::clone),
            ..MitmDef::default()
        }
    }

    /// `force-http-engine-hosts` as a section's `hostname` list, for viewing.
    pub fn force_http_section(&self, text: &str) -> MitmDef {
        let module = ModuleDef {
            lists: ModuleLists {
                hostname: self
                    .lists
                    .force_http_hostname
                    .iter()
                    .map(|line| ModuleLine {
                        line: line.line,
                        def: HostLine {
                            insert: false,
                            items: line.def.clone(),
                        },
                    })
                    .collect(),
                ..ModuleLists::default()
            },
            ..ModuleDef::default()
        };
        module.section(text)
    }
}

/// The lines of `text` trimmed, the first at index 0 for line 1, as definitions count them.
pub fn lines(text: &str) -> Vec<&str> {
    source::numbered(text)
        .map(|(_, line)| line.trim())
        .collect()
}

/// Reads `text` in the format it is written in.
pub fn read_module(text: &str, input: &ModuleInput<'_>) -> ModuleDef {
    match stash::document(text) {
        Some(document) => stash::read(&document, text, input),
        None => surge::read(text, input),
    }
}
