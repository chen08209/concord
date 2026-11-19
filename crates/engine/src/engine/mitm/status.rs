//! What `mitm.moduleStatus` answers: each module the profile names and how it stands.

use concord_config::mitm::module::{ModuleOff, NetworkDef, ResourceKind};
use concord_config::mitm::modules::{AppliedModule, ModuleProblem, RefusedRule, host_network};
use serde::Serialize;

use super::store::{FetchFailure, ModuleResources, ResourceState};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ModuleStatus<'a> {
    name: &'a str,
    enabled: bool,
    in_force: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    problem: Option<&'a ModuleProblem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    off: Option<&'a ModuleOff>,
    resources: Vec<ResourceStatus<'a>>,
    /// Rules left out of the profile, by the module line that wrote them.
    refused_rules: &'a [RefusedRule],
    /// What of the module's network requests the host carries out.
    host_network: NetworkDef,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceStatus<'a> {
    url: &'a str,
    kind: ResourceKind,
    lines: &'a [u32],
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    state: ResourceState,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<FetchFailure>,
}

pub(super) fn module_status<'a>(
    module: &'a AppliedModule,
    resources: &ModuleResources,
) -> ModuleStatus<'a> {
    ModuleStatus {
        name: &module.spec.name,
        enabled: module.spec.enabled,
        in_force: module.in_force(),
        problem: module.problem.as_ref(),
        off: module.def.off.as_ref(),
        resources: module
            .def
            .resources
            .iter()
            .map(|resource| {
                let (state, error) = resources.state(&resource.url);
                ResourceStatus {
                    url: &resource.url,
                    kind: resource.kind,
                    lines: &resource.lines,
                    file: resources.stored(&resource.url),
                    state,
                    error,
                }
            })
            .collect(),
        refused_rules: &module.refused_rules,
        host_network: host_network(std::slice::from_ref(module)),
    }
}
