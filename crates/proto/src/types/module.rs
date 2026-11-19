use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{MitmIssue, MitmLineEntry};

dto! {
    pub struct MitmModuleReadParams {
        /// The module as its author wrote it: a Surge module, a Loon plugin, a Quantumult X
        /// snippet or a Stash override.
        pub text: String,
        /// By argument name, as the user set it; an argument left out takes its default.
        #[serde(default)]
        pub arguments: BTreeMap<String, String>,
        /// By the relative path the module names, the file in the MITM resources directory.
        #[serde(default)]
        pub attachments: BTreeMap<String, String>,
        /// The language requirement expressions read, as `zh-Hans`.
        #[serde(default)]
        pub language: String,
    }

    /// Every line of a module that takes effect is in `views`, `rules`, `ruleSets`,
    /// `network` or `hostname`-like views; one that cannot be read is in `issues`; one
    /// Concord does not take is in `ignored`. Lines are counted from 1.
    pub struct MitmModuleView {
        pub format: MitmModuleFormat,
        pub meta: MitmModuleMeta,
        /// Why the module takes no effect as a whole, though its lines still read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub off: Option<MitmModuleOff>,
        pub arguments: Vec<MitmModuleArgument>,
        /// The remote files its lines read; until stored, the lines name them by URL.
        pub resources: Vec<MitmModuleResource>,
        /// The lines that declare a script, whatever the arguments turn off.
        pub declared_scripts: Vec<u32>,
        /// Whether it changes what the user set for traffic it does not itself rewrite: DNS,
        /// hosts, routes, verifying servers or the clients decrypted for.
        pub asks_consent: bool,
        /// As `mitm.validate`'s, plus `force-http-hostname`; an `index` is the module line.
        pub issues: BTreeMap<String, Vec<MitmIssue>>,
        pub views: BTreeMap<String, Vec<MitmLineEntry>>,
        pub rules: Vec<MitmModuleRule>,
        pub rule_sets: Vec<MitmModuleRuleSet>,
        pub network: MitmModuleNetwork,
        pub ignored: Vec<MitmModuleIgnored>,
    }

    pub struct MitmModuleMeta {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub desc: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub author: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub icon: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub homepage: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub category: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        /// Shown only: it names the systems Surge runs the module on, so it never turns it off.
        pub system: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requirement: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub arguments_desc: Option<String>,
    }

    pub struct MitmModuleArgument {
        pub name: String,
        pub kind: MitmArgumentKind,
        /// A number, which a typed use hands over as one.
        pub number: bool,
        pub default: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub desc: Option<String>,
        pub line: u32,
    }

    pub struct MitmModuleResource {
        pub url: String,
        pub kind: MitmResourceKind,
        pub lines: Vec<u32>,
    }

    /// `rule` is what goes before the policy in a profile's rule line.
    pub struct MitmModuleRule {
        pub line: u32,
        pub rule: String,
        pub policy: MitmModulePolicy,
        pub no_resolve: bool,
        /// Surge's `extended-matching`. A DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD or
        /// DOMAIN-WILDCARD rule also matches the name the flow was dialed by and the Host
        /// header of a request the MITM engine routes, and sees the SNI only when sniffing is
        /// on; on any other rule it is not applied.
        pub extended_matching: bool,
    }

    pub struct MitmModuleRuleSet {
        pub name: String,
        /// One domain per line, as Surge's `DOMAIN-SET`.
        pub domain: bool,
        pub source: MitmRuleSetSource,
    }

    pub struct MitmModuleInlineRule {
        pub line: u32,
        pub rule: String,
    }

    /// In mihomo's keys; each list edit puts `before` ahead of the profile's list and
    /// `after` behind it, and with `replace` drops the profile's own entries.
    pub struct MitmModuleNetwork {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nameserver: Option<MitmListEdit>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub default_nameserver: Option<MitmListEdit>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fake_ip_filter: Option<MitmListEdit>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub nameserver_policy: Vec<MitmDomainEntry>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub hosts: Vec<MitmDomainEntry>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub route_address: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub route_exclude_address: Option<MitmListEdit>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub bypass_domain: Option<MitmListEdit>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub lines: Vec<u32>,
    }

    pub struct MitmListEdit {
        pub replace: bool,
        pub before: Vec<String>,
        pub after: Vec<String>,
    }

    pub struct MitmDomainEntry {
        pub domain: String,
        pub values: Vec<String>,
    }

    pub struct MitmModuleIgnored {
        pub line: u32,
        pub text: String,
        pub reason: MitmIgnoreReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MitmModuleFormat {
    Surge,
    Loon,
    QuantumultX,
    Stash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "reason", rename_all = "camelCase")]
pub enum MitmModuleOff {
    /// `#!requirement` does not hold.
    Requirement,
    /// `#!requirement` cannot be read.
    RequirementUnreadable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum MitmArgumentKind {
    Text,
    /// `true` or `false`.
    Switch,
    Select {
        options: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MitmResourceKind {
    Script,
    MapLocal,
    Jq,
}

/// A built-in policy (`DIRECT`, `REJECT`, `REJECT-DROP`, `REJECT-NO-DROP`,
/// `REJECT-TINYGIF`, `REJECT-DICT`, `REJECT-ARRAY`, `REJECT-200`), or a name the host maps to
/// one of its outbounds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum MitmModulePolicy {
    Builtin(String),
    Named(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum MitmRuleSetSource {
    /// Downloaded every `interval` seconds, 0 for never; absent, the host's default.
    Url {
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interval: Option<u64>,
    },
    /// `[Ruleset <name>]` lines; sets of one name add up across modules.
    Inline { rules: Vec<MitmModuleInlineRule> },
    /// Surge's internal `LAN` and `SYSTEM` sets.
    Builtin { rules: Vec<String> },
    /// An attached file.
    File { file: String },
}

/// Why a line takes no effect; a host shows each in its own words.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum MitmIgnoreReason {
    /// A section no format has, or one Concord does not read.
    Section,
    /// A section for a feature of the app the module was written for.
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
    /// Turned off on the line itself.
    Disabled,
    /// `FINAL`: module rules go before the profile's.
    FinalRule,
    /// A rule on what only an Apple device knows of itself or its network.
    DeviceRule,
    /// A rule type Concord has no counterpart for.
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
    /// value or Surge's `{{{GATEWAY_ADDRESS}}}`; a URL rewrite's replacement may name the URL's.
    RuntimeValue,
}
