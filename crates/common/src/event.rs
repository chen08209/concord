use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use crate::conn::ConnRecord;
use crate::options::{FindProcessMode, LogLevel, TunnelMode};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Initiator {
    App,
    Rule,
    Direct,
    Proxy,
    #[default]
    Other,
}

impl Initiator {
    pub fn as_str(self) -> &'static str {
        match self {
            Initiator::App => "app",
            Initiator::Rule => "rule",
            Initiator::Direct => "direct",
            Initiator::Proxy => "proxy",
            Initiator::Other => "other",
        }
    }
}

#[derive(Clone, Debug)]
pub struct LogRecord {
    pub level: LogLevel,
    pub payload: String,
}

/// `value` is milliseconds when positive, -1 for a timeout, -2 for a failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelayResult {
    pub url: String,
    pub name: String,
    pub value: i32,
}

#[derive(Clone, Debug)]
pub struct DnsRecord {
    pub domain: String,
    pub qtype: String,
    pub initiator: Initiator,
    pub upstream: String,
    pub cached: bool,
    pub answers: Vec<String>,
    pub rcode: String,
    pub error: String,
    pub delay_ms: i64,
    pub time: SystemTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind {
    ProxyProvider,
    RuleProvider,
    Geo,
    /// The remote files of the MITM module of that name.
    MitmModule,
}

/// What a finished fetch did to the content in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refresh {
    Updated,
    Unchanged,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourcePhase {
    Updating,
    Updated,
    Unchanged,
    Failed(String),
}

impl ResourcePhase {
    pub fn of<E: std::fmt::Display>(outcome: &Result<Refresh, E>) -> Self {
        match outcome {
            Ok(Refresh::Updated) => ResourcePhase::Updated,
            Ok(Refresh::Unchanged) => ResourcePhase::Unchanged,
            Err(err) => ResourcePhase::Failed(err.to_string()),
        }
    }
}

/// The error of a fetch cut short because its config was replaced or the core
/// stopped.
pub const SUPERSEDED: &str = "superseded";

/// One fetch as a host hears of it: `updating` when it starts, then its
/// outcome, or `failed` with `SUPERSEDED` when it is dropped unfinished, so
/// every fetch a host saw start also ends.
pub struct Fetch<R: Fn(ResourcePhase)> {
    report: R,
    open: bool,
}

impl<R: Fn(ResourcePhase)> Fetch<R> {
    pub fn start(report: R) -> Self {
        report(ResourcePhase::Updating);
        Fetch { report, open: true }
    }

    pub fn finish(mut self, phase: ResourcePhase) {
        self.open = false;
        (self.report)(phase);
    }
}

impl<R: Fn(ResourcePhase)> Drop for Fetch<R> {
    fn drop(&mut self) {
        if self.open {
            (self.report)(ResourcePhase::Failed(SUPERSEDED.to_string()));
        }
    }
}

/// One step of a provider or geo database fetch, whatever started it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceUpdate {
    pub kind: ResourceKind,
    pub name: Arc<str>,
    pub phase: ResourcePhase,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RouteStamp {
    pub epoch: u64,
    pub version: u64,
}

/// What a route watcher is told. `running` is read only as the epoch moves, so a
/// host never pairs the listeners' state with an epoch from before they changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RouteView {
    pub stamp: RouteStamp,
    pub running: bool,
}

/// Who asked for a change of state a host keeps: the host over its own
/// connection, a dashboard through the external controller, or the core
/// itself, as when a fallback group drops a pick whose node died.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Host,
    Controller,
    Core,
}

/// The fields of a general patch that changed, with their new values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GeneralChange {
    pub mode: Option<TunnelMode>,
    pub log_level: Option<LogLevel>,
    pub allow_lan: Option<bool>,
    pub ipv6: Option<bool>,
    pub mixed_port: Option<u16>,
    pub tcp_concurrent: Option<bool>,
    pub find_process_mode: Option<FindProcessMode>,
    pub unified_delay: Option<bool>,
    /// User names only.
    pub authentication: Option<Vec<String>>,
    pub geo_auto_update: Option<bool>,
    pub geo_update_interval: Option<u32>,
    pub geox_url: Option<BTreeMap<String, String>>,
    pub tun_enable: Option<bool>,
    pub tun_device: Option<String>,
    pub tun_stack: Option<String>,
    pub tun_auto_route: Option<bool>,
}

impl GeneralChange {
    pub fn is_empty(&self) -> bool {
        *self == GeneralChange::default()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// An empty `proxy` clears the pick.
    Selected {
        group: String,
        proxy: String,
    },
    General(GeneralChange),
    /// A config apply replaced the picks with the ones it was given.
    Applied,
}

/// `seq` orders every change across origins in the order it took effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateChange {
    pub seq: u64,
    pub origin: Origin,
    pub change: Change,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficDelta {
    pub seq: u64,
    pub id: String,
    pub upload: u64,
    pub download: u64,
}

#[derive(Clone, Debug)]
pub enum CoreEvent {
    Log(LogRecord),
    Delay(DelayResult),
    Request(Arc<ConnRecord>),
    RequestTraffic(Vec<TrafficDelta>),
    Dns(DnsRecord),
    Resource(ResourceUpdate),
    RouteChanged(RouteView),
    DialerLoop(Arc<str>),
    State(StateChange),
}

/// Check `enabled` before building an event: Android runs without a listener for
/// as long as the Flutter engine is gone.
pub trait EventSink: Send + Sync {
    fn enabled(&self) -> bool;
    fn publish(&self, event: CoreEvent);

    /// Whether the event was queued. A report of cumulative totals retries when it
    /// was not, and so must not count itself as delivered.
    fn offer(&self, event: CoreEvent) -> bool {
        self.publish(event);
        true
    }

    /// A listed connection ended. `seq` is the record's.
    fn closed(&self, _seq: u64) {}
}

pub struct NullSink;

impl EventSink for NullSink {
    fn enabled(&self) -> bool {
        false
    }

    fn publish(&self, _event: CoreEvent) {}
}
