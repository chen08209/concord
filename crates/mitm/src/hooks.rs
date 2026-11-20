use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use concord_common::scripts::{DnsScriptAnswer, RuleScriptRequest, ScriptHooks};
use concord_config::mitm::ScriptKind;
use serde_json::{Value, json};

use crate::engine::MitmEngine;
use crate::script::{ScriptError, ScriptInvocation};
use crate::task::TaskDial;

const DNS_PORT: u16 = 53;

/// The `rule` and `dns` scripts of the engine in force; with none, each is missing.
pub(crate) struct Hooks {
    pub(crate) current: Arc<ArcSwapOption<MitmEngine>>,
}

impl Hooks {
    async fn run(
        &self,
        name: &str,
        kind: ScriptKind,
        fill: impl FnOnce(&mut ScriptInvocation),
    ) -> Result<Value, ScriptError> {
        let engine = self
            .current
            .load_full()
            .ok_or_else(|| ScriptError("MITM is off".to_string()))?;
        let core = &engine.core;
        let script = core
            .config
            .rules
            .scripts
            .iter()
            .find(|script| script.kind == kind && script.name == name)
            .ok_or_else(|| ScriptError("no such script".to_string()))?;
        let dial = Arc::new(TaskDial { core: core.clone() });
        let mut invocation = ScriptInvocation::base(dial.clone());
        fill(&mut invocation);
        let result = core
            .invoke(&core.hook_gate, script, invocation, dial)
            .await?;
        serde_json::from_slice(&result.value)
            .map_err(|_| ScriptError("$done was given nothing readable".to_string()))
    }
}

#[async_trait]
impl ScriptHooks for Hooks {
    async fn rule(&self, name: &str, request: &RuleScriptRequest) -> bool {
        let input = rule_input(request);
        let verdict = self
            .run(name, ScriptKind::Rule, |invocation| {
                invocation.rule = Some(input);
            })
            .await
            .and_then(|done| {
                done.get("matched")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| ScriptError("$done has no matched boolean".to_string()))
            });
        verdict.unwrap_or_else(|err| {
            tracing::warn!("[MITM] rule script {name}: {err}; the rule does not match");
            false
        })
    }

    async fn dns(&self, name: &str, domain: &str) -> DnsScriptAnswer {
        let answer = self
            .run(name, ScriptKind::Dns, |invocation| {
                invocation.domain = Some(domain.to_string());
            })
            .await
            .and_then(|done| dns_answer(&done));
        answer.unwrap_or_else(|err| {
            tracing::warn!("[MITM] dns script {name} for {domain}: {err}; it is resolved as usual");
            DnsScriptAnswer::Resolve
        })
    }

    fn generation(&self) -> u64 {
        self.current
            .load()
            .as_ref()
            .map_or(0, |engine| engine.generation)
    }
}

fn rule_input(request: &RuleScriptRequest) -> Value {
    let dns = request.dns_result.as_ref().map(|ips| {
        let text = |v4: bool| -> Vec<String> {
            ips.iter()
                .filter(|ip| ip.is_ipv4() == v4)
                .map(IpAddr::to_string)
                .collect()
        };
        json!({"v4Addresses": text(true), "v6Addresses": text(false)})
    });
    json!({
        "hostname": request.hostname,
        "destPort": request.dest_port,
        "protocol": request.protocol,
        "sourceIP": request.source_ip.map(|ip| ip.to_string()),
        "sourcePort": request.source_port,
        "listenPort": request.listen_port,
        "processPath": request.process_path,
        "userAgent": request.user_agent,
        "url": request.url,
        "dnsResult": dns,
    })
}

/// Surge's `dns` script answers with one of `address`, `addresses`, `server` and
/// `servers`; an object with none of them leaves the domain to the resolver.
fn dns_answer(done: &Value) -> Result<DnsScriptAnswer, ScriptError> {
    let list = |one: &str, many: &str| -> Option<Vec<String>> {
        match (done.get(one), done.get(many)) {
            (Some(Value::String(item)), _) => Some(vec![item.clone()]),
            (_, Some(Value::Array(items))) => Some(
                items
                    .iter()
                    .map(|item| item.as_str().unwrap_or_default().to_string())
                    .collect(),
            ),
            _ => None,
        }
    };
    let unreadable = |item: &str| ScriptError(format!("{item:?} is not an address"));
    if let Some(items) = list("address", "addresses") {
        let ips = items
            .iter()
            .map(|item| item.parse::<IpAddr>().map_err(|_| unreadable(item)))
            .collect::<Result<Vec<_>, _>>()?;
        let ttl = done
            .get("ttl")
            .and_then(Value::as_f64)
            .filter(|seconds| *seconds > 0.0 && seconds.is_finite())
            .map(Duration::from_secs_f64);
        return Ok(match ips.is_empty() {
            true => DnsScriptAnswer::Resolve,
            false => DnsScriptAnswer::Addresses { ips, ttl },
        });
    }
    if let Some(items) = list("server", "servers") {
        let servers = items
            .iter()
            .map(|item| {
                item.parse::<SocketAddr>()
                    .or_else(|_| {
                        item.parse::<IpAddr>()
                            .map(|ip| SocketAddr::new(ip, DNS_PORT))
                    })
                    .map_err(|_| unreadable(item))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !servers.is_empty() {
            return Ok(DnsScriptAnswer::Servers(servers));
        }
    }
    Ok(DnsScriptAnswer::Resolve)
}
