use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use concord_common::packet::PacketSession;
use concord_common::scripts::ScriptHooks;
use concord_common::{
    Address, BoxStream, DialEnv, FindProcessMode, FlowHandler, FlowKey, FlowMeta, HostResolver,
    InboundKind, Initiator, IpVersion, LookupIps, ProcessInfo, Tasks, TunnelMode, UdpFlow,
    UdpPayload, UdpReply,
};
use concord_dns::Resolver;
use concord_group::{Outbounds, Touch};
use concord_net::LoopbackGuard;
use concord_platform::Platform;
use concord_rules::RouteProgram;
use concord_rules::geo::GeoStore;

use crate::flow::FlowState;
use crate::intercept::{ConnInterceptor, UpstreamDialer};
use crate::route::{Decision, route};
use crate::sniff::Dispatcher;
use crate::table::ConnTable;
use crate::tcp;
use crate::udp::UdpNat;
use crate::upstream::TunnelUpstream;

pub const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(60);

/// What one applied config brought. A flow keeps the one it started with.
pub struct Runtime {
    pub program: RouteProgram,
    pub outbounds: Arc<Outbounds>,
    pub dns: Arc<Resolver>,
    pub sniffer: Arc<Dispatcher>,
    pub geo: Arc<GeoStore>,
    pub platform: Arc<dyn Platform>,
    pub scripts: Arc<dyn ScriptHooks>,
    /// What the core's own connections resolve with: `dns` without its scripts.
    inner_dns: Arc<dyn HostResolver>,
    pub(crate) owner_cache: OwnerCache,
}

impl Runtime {
    pub fn new(
        program: RouteProgram,
        outbounds: Arc<Outbounds>,
        dns: Arc<Resolver>,
        sniffer: Arc<Dispatcher>,
        geo: Arc<GeoStore>,
        platform: Arc<dyn Platform>,
        scripts: Arc<dyn ScriptHooks>,
    ) -> Self {
        Runtime {
            program,
            outbounds,
            inner_dns: dns.unscripted(),
            dns,
            sniffer,
            geo,
            platform,
            scripts,
            owner_cache: OwnerCache::default(),
        }
    }

    pub(crate) fn dns_lookup<'a>(
        &'a self,
        flow: &FlowState,
        host: &'a str,
        version: IpVersion,
        initiator: Initiator,
    ) -> impl Future<Output = io::Result<LookupIps>> + Send + 'a {
        if flow.is_inner() {
            self.inner_dns.lookup(host, version, initiator)
        } else {
            self.dns.lookup(host, version, initiator)
        }
    }

    /// The outbounds' dial environment, resolving without `dns` scripts for the core's own flows.
    pub(crate) fn env_for(&self, flow: &FlowState) -> Arc<DialEnv> {
        let env = self.outbounds.env();
        if !flow.is_inner() {
            return env;
        }
        Arc::new(DialEnv {
            resolver: Arc::clone(&self.inner_dns),
            ..(*env).clone()
        })
    }
}

const OWNER_CACHE_CAPACITY: usize = 256;
const OWNER_LIFETIME: Duration = Duration::from_millis(200);

struct Owned {
    owner: Option<Arc<ProcessInfo>>,
    added: Instant,
    used: u64,
}

/// sing-box's process cache: answers, misses included, keyed by the flow and kept briefly, so
/// a burst of flows from one socket costs one platform lookup.
#[derive(Default)]
pub(crate) struct OwnerCache {
    entries: Mutex<OwnerEntries>,
}

#[derive(Default)]
struct OwnerEntries {
    map: HashMap<FlowKey, Owned>,
    clock: u64,
}

impl OwnerCache {
    pub fn get(&self, key: &FlowKey, now: Instant) -> Option<Option<Arc<ProcessInfo>>> {
        let mut entries = concord_common::sync::lock(&self.entries);
        entries.clock += 1;
        let clock = entries.clock;
        let entry = entries.map.get_mut(key)?;
        if now.duration_since(entry.added) >= OWNER_LIFETIME {
            entries.map.remove(key);
            return None;
        }
        entry.used = clock;
        Some(entry.owner.clone())
    }

    pub fn put(&self, key: FlowKey, owner: Option<Arc<ProcessInfo>>, now: Instant) {
        let mut entries = concord_common::sync::lock(&self.entries);
        if entries.map.len() >= OWNER_CACHE_CAPACITY && !entries.map.contains_key(&key) {
            entries
                .map
                .retain(|_, entry| now.duration_since(entry.added) < OWNER_LIFETIME);
            if entries.map.len() >= OWNER_CACHE_CAPACITY
                && let Some(oldest) = entries
                    .map
                    .iter()
                    .min_by_key(|(_, entry)| entry.used)
                    .map(|(key, _)| *key)
            {
                entries.map.remove(&oldest);
            }
        }
        entries.clock += 1;
        let used = entries.clock;
        entries.map.insert(
            key,
            Owned {
                owner,
                added: now,
                used,
            },
        );
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LiveOptions {
    pub mode: TunnelMode,
    pub find_process_mode: FindProcessMode,
    pub udp_timeout: Duration,
}

impl Default for LiveOptions {
    fn default() -> Self {
        LiveOptions {
            mode: TunnelMode::Rule,
            find_process_mode: FindProcessMode::Off,
            udp_timeout: DEFAULT_UDP_TIMEOUT,
        }
    }
}

/// mihomo's tunnel status. `Inner` lets the core's own traffic through before the
/// listeners are open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TunnelStatus {
    Suspended = 0,
    Inner = 1,
    Running = 2,
}

/// `ArcSwap` holds thin pointers only.
pub(crate) struct InterceptorSlot(pub Arc<dyn ConnInterceptor>);

pub(crate) struct Inner {
    pub table: Arc<ConnTable>,
    pub loopback: Arc<LoopbackGuard>,
    pub nat: UdpNat,
    pub tasks: Tasks,
    pub interceptor: ArcSwapOption<InterceptorSlot>,
    runtime: ArcSwapOption<Runtime>,
    live: ArcSwap<LiveOptions>,
    status: AtomicU8,
}

impl Inner {
    pub fn live(&self) -> LiveOptions {
        **self.live.load()
    }

    pub fn runtime_for(&self, kind: InboundKind) -> Option<Arc<Runtime>> {
        if self.handles(kind) {
            self.runtime.load_full()
        } else {
            None
        }
    }

    pub(crate) fn handles(&self, kind: InboundKind) -> bool {
        let status = self.status.load(Ordering::Acquire);
        status == TunnelStatus::Running as u8
            || (status == TunnelStatus::Inner as u8 && kind == InboundKind::Inner)
    }
}

#[derive(Clone)]
pub struct Tunnel {
    inner: Arc<Inner>,
}

impl Tunnel {
    /// Flows run on `tasks`; they end when the connection table closes them, not when the engine
    /// stops.
    pub fn new(table: Arc<ConnTable>, loopback: Arc<LoopbackGuard>, tasks: Tasks) -> Self {
        Tunnel {
            inner: Arc::new(Inner {
                table,
                loopback,
                nat: UdpNat::default(),
                tasks,
                interceptor: ArcSwapOption::empty(),
                runtime: ArcSwapOption::empty(),
                live: ArcSwap::from_pointee(LiveOptions::default()),
                status: AtomicU8::new(TunnelStatus::Suspended as u8),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }

    pub fn set_interceptor(&self, interceptor: Arc<dyn ConnInterceptor>) {
        self.inner
            .interceptor
            .store(Some(Arc::new(InterceptorSlot(interceptor))));
    }

    /// What an interceptor dials its upstream connections with.
    pub fn upstream_dialer(&self) -> Arc<dyn UpstreamDialer> {
        Arc::new(TunnelUpstream {
            inner: Arc::downgrade(&self.inner),
        })
    }

    pub fn install(&self, runtime: Arc<Runtime>) {
        self.inner.runtime.store(Some(runtime));
    }

    pub fn clear(&self) {
        self.inner.runtime.store(None);
    }

    pub fn runtime(&self) -> Option<Arc<Runtime>> {
        self.inner.runtime.load_full()
    }

    pub fn set_status(&self, status: TunnelStatus) {
        self.inner.status.store(status as u8, Ordering::Release);
    }

    pub fn is_suspended(&self) -> bool {
        self.inner.status.load(Ordering::Acquire) == TunnelStatus::Suspended as u8
    }

    pub fn live(&self) -> LiveOptions {
        self.inner.live()
    }

    pub fn set_live(&self, live: LiveOptions) {
        self.inner.live.store(Arc::new(live));
    }

    pub fn tasks(&self) -> &Tasks {
        &self.inner.tasks
    }

    pub fn table(&self) -> &Arc<ConnTable> {
        &self.inner.table
    }

    pub async fn dial_inner(&self, target: &Address, proxy: Option<&str>) -> io::Result<BoxStream> {
        tcp::dial_inner(&self.inner, target, proxy)
            .await
            .map(|(stream, _)| stream)
    }

    /// As `dial_inner`, with the chains the connection took: exit first, then the
    /// groups above it.
    pub async fn dial_inner_routed(
        &self,
        target: &Address,
        proxy: Option<&str>,
    ) -> io::Result<(BoxStream, Box<[Arc<str>]>)> {
        tcp::dial_inner(&self.inner, target, proxy).await
    }

    pub async fn associate_inner(
        &self,
        target: &Address,
        proxy: Option<&str>,
    ) -> io::Result<Arc<dyn PacketSession>> {
        tcp::associate_inner(&self.inner, target, proxy).await
    }

    /// `route.check`: the route the rules give a name right now, with nothing
    /// dialled, no `lazy` group woken, and no name resolved beyond what rules need.
    pub async fn explain(&self, host: &Address, proxy: Option<&str>) -> Option<RouteExplanation> {
        let runtime = self.inner.runtime.load_full()?;
        let mut flow = tcp::inner_flow(host, concord_common::Network::Tcp, proxy);
        crate::flow::pre_handle(&mut flow, &runtime.dns).ok()?;
        let live = self.inner.live();
        let decision = route(&mut flow, &runtime, &live, Touch::No).await.ok()?;
        Some(RouteExplanation::from_decision(&flow, decision))
    }

    /// `route.explain`: the decision for a flow whose metadata the caller spells out.
    pub async fn explain_flow(&self, request: ExplainFlow) -> Result<RouteExplanation, String> {
        let runtime = self
            .inner
            .runtime
            .load_full()
            .ok_or_else(|| "no config applied".to_string())?;
        let mut flow = FlowState::new(request.meta);
        if flow.host.is_some() {
            flow.dst_ip = request.dst_ip.map(concord_common::addr::unmap);
        }
        flow.sniff_host = request.sniff_host;
        flow.dscp = request.dscp;
        if let Some(process) = request.process {
            flow.process = Some(Arc::new(process));
        }
        crate::flow::pre_handle(&mut flow, &runtime.dns)?;
        let live = self.inner.live();
        let decision = route(&mut flow, &runtime, &live, Touch::No)
            .await
            .map_err(|err| err.to_string())?;
        Ok(RouteExplanation::from_decision(&flow, decision))
    }

    /// `resolveExit`: where a connection to `host` would leave now.
    pub async fn exit_of(&self, host: &Address, proxy: Option<&str>) -> Option<String> {
        let runtime = self.inner.runtime.load_full()?;
        let mut flow = tcp::inner_flow(host, concord_common::Network::Tcp, proxy);
        crate::flow::pre_handle(&mut flow, &runtime.dns).ok()?;
        let live = self.inner.live();
        let decision = route(&mut flow, &runtime, &live, Touch::No).await.ok()?;
        Some(decision.exit_name())
    }
}

#[derive(Clone, Debug)]
pub struct ExplainFlow {
    pub meta: FlowMeta,
    pub dst_ip: Option<std::net::IpAddr>,
    pub sniff_host: Option<concord_common::Host>,
    pub dscp: u8,
    pub process: Option<concord_common::ProcessInfo>,
}

#[derive(Clone, Debug)]
pub struct RouteExplanation {
    pub target: String,
    pub chain: Box<[Arc<str>]>,
    pub rule: String,
    pub payload: String,
    pub remote: String,
}

impl RouteExplanation {
    fn from_decision(flow: &FlowState, decision: Decision) -> Self {
        let (rule, payload) = match &decision.rule {
            Some(rule) => (rule.type_name.to_string(), rule.payload.to_string()),
            None => (String::new(), String::new()),
        };
        RouteExplanation {
            target: decision.target,
            chain: decision.chain,
            rule,
            payload,
            remote: flow.remote_text(),
        }
    }
}

impl FlowHandler for Tunnel {
    fn handle_tcp(&self, meta: FlowMeta, stream: BoxStream) {
        self.inner
            .tasks
            .spawn_to_end(tcp::handle(self.inner.clone(), meta, stream));
    }

    fn handle_udp(&self, flow: UdpFlow<'_>, payload: UdpPayload<'_>, reply: &Arc<dyn UdpReply>) {
        crate::udp::handle(&self.inner, flow, payload, reply);
    }

    fn udp_round(&self, round: &mut dyn FnMut()) {
        let _round = crate::udp::BatchRound::begin(&self.inner);
        round();
    }
}

use std::future::Future;

#[cfg(test)]
mod owner_cache_tests {
    use std::net::SocketAddr;

    use super::*;

    fn owner() -> Arc<ProcessInfo> {
        Arc::new(ProcessInfo {
            uid: None,
            name: "app".to_string(),
            path: String::new(),
        })
    }

    fn key(port: u16) -> FlowKey {
        FlowKey {
            network: concord_common::Network::Udp,
            src: SocketAddr::from(([10, 0, 0, 1], port)),
            dst: SocketAddr::from(([1, 1, 1, 1], 53)),
        }
    }

    #[test]
    fn answers_and_misses_last_their_lifetime() {
        let cache = OwnerCache::default();
        let now = Instant::now();
        cache.put(key(1), Some(owner()), now);
        cache.put(key(2), None, now);
        assert!(matches!(cache.get(&key(1), now), Some(Some(_))));
        assert!(matches!(cache.get(&key(2), now), Some(None)));
        let later = now + OWNER_LIFETIME;
        assert!(cache.get(&key(1), later).is_none());
        assert!(cache.get(&key(2), later).is_none());
    }

    #[test]
    fn a_full_cache_drops_the_least_recently_used() {
        let cache = OwnerCache::default();
        let now = Instant::now();
        for port in 0..OWNER_CACHE_CAPACITY as u16 {
            cache.put(key(port), Some(owner()), now);
        }
        assert!(cache.get(&key(0), now).is_some());
        cache.put(key(u16::MAX), Some(owner()), now);
        assert!(cache.get(&key(0), now).is_some());
        assert!(cache.get(&key(1), now).is_none());
        assert!(cache.get(&key(u16::MAX), now).is_some());
    }
}
