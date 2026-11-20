use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

/// Surge's `$request` for a `rule` script: what a connection shows before it is routed,
/// `None` where it shows nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleScriptRequest {
    pub hostname: Option<String>,
    pub dest_port: u16,
    pub protocol: &'static str,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub listen_port: Option<u16>,
    pub process_path: Option<String>,
    pub user_agent: Option<String>,
    pub url: Option<String>,
    /// The addresses the hostname resolved to, looked up only for a `requires-resolve` rule.
    pub dns_result: Option<Vec<IpAddr>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsScriptAnswer {
    Addresses {
        ips: Vec<IpAddr>,
        ttl: Option<Duration>,
    },
    Servers(Vec<SocketAddr>),
    /// `$done({})`, or a run that failed: the domain resolves as if no script named it.
    Resolve,
}

/// Runs the `rule` and `dns` scripts the profile declares. A script that is missing, fails
/// or runs out of time is logged with its name and does not match, or leaves the domain to
/// the resolver.
#[async_trait]
pub trait ScriptHooks: Send + Sync {
    async fn rule(&self, name: &str, request: &RuleScriptRequest) -> bool;

    async fn dns(&self, name: &str, domain: &str) -> DnsScriptAnswer;

    /// Changes whenever the scripts in force change, so an answer kept under one value is not
    /// given under another.
    fn generation(&self) -> u64 {
        0
    }
}

/// The hooks the MITM engine set last, for runtimes built before it started and after; with
/// none, every script is missing.
#[derive(Default)]
pub struct ScriptSlot(Mutex<Option<Arc<dyn ScriptHooks>>>);

impl ScriptSlot {
    pub fn set(&self, hooks: Arc<dyn ScriptHooks>) {
        *crate::sync::lock(&self.0) = Some(hooks);
    }

    fn get(&self) -> Option<Arc<dyn ScriptHooks>> {
        crate::sync::lock(&self.0).clone()
    }
}

#[async_trait]
impl ScriptHooks for ScriptSlot {
    async fn rule(&self, name: &str, request: &RuleScriptRequest) -> bool {
        match self.get() {
            Some(hooks) => hooks.rule(name, request).await,
            None => false,
        }
    }

    async fn dns(&self, name: &str, domain: &str) -> DnsScriptAnswer {
        match self.get() {
            Some(hooks) => hooks.dns(name, domain).await,
            None => DnsScriptAnswer::Resolve,
        }
    }

    fn generation(&self) -> u64 {
        self.get().map_or(0, |hooks| hooks.generation())
    }
}
