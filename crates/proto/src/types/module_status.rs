use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{MitmModuleNetwork, MitmModuleOff, MitmResourceKind};

dto! {
    pub struct MitmFetchModuleParams {
        /// The module whose remote files are fetched again; absent, every module's.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
    }

    /// The modules the `mitm` section of the profile in force names, in its order.
    pub struct MitmModuleStatusList {
        pub modules: Vec<MitmModuleStatus>,
    }

    pub struct MitmModuleStatus {
        pub name: String,
        /// Read, and not turned off by its own requirement: its lines take effect.
        pub in_force: bool,
        /// Why it could not be taken at all.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub problem: Option<MitmModuleProblem>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub off: Option<MitmModuleOff>,
        pub resources: Vec<MitmModuleResourceStatus>,
        /// Rules left out of the profile, by the module line that wrote them: most often a
        /// policy that `module-policy` maps to no outbound.
        pub refused_rules: Vec<MitmRefusedRule>,
        /// The routes and proxy bypass entries the module asks for, which the host applies.
        pub host_network: MitmModuleNetwork,
    }

    pub struct MitmModuleResourceStatus {
        pub url: String,
        pub kind: MitmResourceKind,
        pub lines: Vec<u32>,
        /// The file in the MITM resources directory the lines read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub file: Option<String>,
        pub state: MitmResourceState,
        /// Why the last fetch failed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<MitmFetchFailure>,
    }

    pub struct MitmRefusedRule {
        pub line: u32,
        pub detail: String,
    }

    pub struct MitmFetchFailure {
        pub reason: MitmFetchFailureReason,
        /// The HTTP status of an `http` failure.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub status: Option<u16>,
        pub detail: String,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "reason", rename_all = "camelCase")]
pub enum MitmModuleProblem {
    /// Neither its `path` nor its `text` gives a module.
    Unreadable { detail: String },
    /// An earlier module has its name.
    Duplicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum MitmResourceState {
    Ok,
    /// The last fetch failed; a file an earlier fetch stored stays in use.
    Failed,
    /// Never stored: the lines that read it take no effect.
    Missing,
    Fetching,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum MitmFetchFailureReason {
    /// The server answered with a status other than 2xx.
    Http,
    Dns,
    Tls,
    Timeout,
    Connection,
    Other,
}
