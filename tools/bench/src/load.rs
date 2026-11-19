//! The workloads. Each trial measures over a window that opens after its warmup,
//! and reads every watched process's counters at the window's two edges.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::mitm::{self, Wire};
use crate::origin::{CHUNK, Ports};
use crate::probe::{self, Delta, Window};
use crate::sockets;
use crate::socks::{self, Entry, Udp};
use crate::stats;
use crate::syscalls;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Workload {
    TcpDown,
    TcpUp,
    TcpMulti,
    TcpRr,
    TcpCrr,
    UdpStream,
    UdpRr,
    MitmRr,
    MitmH2Rr,
    MitmCrr,
    HttpRr,
    Idle,
    Startup,
    Large,
}

impl Workload {
    pub const ALL: [Workload; 14] = [
        Workload::TcpDown,
        Workload::TcpUp,
        Workload::TcpMulti,
        Workload::TcpRr,
        Workload::TcpCrr,
        Workload::UdpStream,
        Workload::UdpRr,
        Workload::MitmRr,
        Workload::MitmH2Rr,
        Workload::MitmCrr,
        Workload::HttpRr,
        Workload::Idle,
        Workload::Startup,
        Workload::Large,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Workload::TcpDown => "tcp-down",
            Workload::TcpUp => "tcp-up",
            Workload::TcpMulti => "tcp-multi",
            Workload::TcpRr => "tcp-rr",
            Workload::TcpCrr => "tcp-crr",
            Workload::UdpStream => "udp-stream",
            Workload::UdpRr => "udp-rr",
            Workload::MitmRr => "mitm-rr",
            Workload::MitmH2Rr => "mitm-h2-rr",
            Workload::MitmCrr => "mitm-crr",
            Workload::HttpRr => "http-rr",
            Workload::Idle => "idle",
            Workload::Startup => "startup",
            Workload::Large => "large",
        }
    }

    pub fn about(self) -> &'static str {
        match self {
            Workload::TcpDown => "one TCP flow, origin to client",
            Workload::TcpUp => "one TCP flow, client to origin, rate as the origin saw it",
            Workload::TcpMulti => "parallel TCP downloads: aggregate rate and fairness",
            Workload::TcpRr => "64-byte request and response on one connection: per-packet latency",
            Workload::TcpCrr => "connect, one byte each way, close: handshake latency and rate",
            Workload::UdpStream => "windowed UDP echo: goodput, loss and RTT",
            Workload::UdpRr => "one UDP ping in flight: RTT and loss",
            Workload::MitmRr => {
                "mitm cases: 64-byte HTTP/1.1 POST and answer over one TLS connection"
            }
            Workload::MitmH2Rr => {
                "mitm cases: 64-byte HTTP/2 POST and answer over one TLS connection"
            }
            Workload::MitmCrr => "mitm cases: TLS connect, one HTTP/1.1 exchange, close",
            Workload::HttpRr => {
                "mitm cases: 64-byte plain HTTP/1.1 POST and answer over one connection"
            }
            Workload::Idle => {
                "memory per held connection, and what stays after they close; on mitm cases each holds a TLS session after one exchange"
            }
            Workload::Startup => "spawn to first proxied byte, idle memory, threads, exit time",
            Workload::Large => "a large generated profile: time to ready and peak memory",
        }
    }

    pub fn parse(text: &str) -> Option<Workload> {
        Workload::ALL.into_iter().find(|w| w.name() == text)
    }

    pub fn needs_udp(self) -> bool {
        matches!(self, Workload::UdpStream | Workload::UdpRr)
    }

    /// Speaks HTTP to the origin's HTTPS or HTTP port, so it runs on the mitm cases only.
    pub fn needs_mitm(self) -> bool {
        matches!(
            self,
            Workload::MitmRr | Workload::MitmH2Rr | Workload::MitmCrr | Workload::HttpRr
        )
    }

    /// Runs against a fresh core each trial rather than the case's shared one.
    pub fn fresh_core(self) -> bool {
        matches!(self, Workload::Idle | Workload::Startup | Workload::Large)
    }

    pub fn per_case(self) -> bool {
        self != Workload::Large
    }
}

pub type Metrics = BTreeMap<String, f64>;

#[derive(Clone, Copy)]
pub struct Pids {
    pub core: u32,
    pub server: Option<u32>,
    pub origin: Option<u32>,
}

#[derive(Clone)]
pub struct Ctx {
    pub entry: Entry,
    pub origin: std::net::IpAddr,
    pub ports: Ports,
    pub warmup: Duration,
    pub duration: Duration,
    pub pids: Pids,
    pub flows: usize,
    pub crr_conns: usize,
    pub crr_concurrency: usize,
    pub udp_size: usize,
    pub udp_window: usize,
    pub idle_conns: usize,
    pub net_counters: bool,
    pub far_netns: Option<String>,
    /// Set on the mitm cases, whose origin gave the CA.
    pub tls: Option<crate::mitm::Clients>,
}

impl Ctx {
    fn at(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.origin, port)
    }
}

/// Windows on every process of the trial, the harness included.
pub(crate) struct Windows {
    core: Window,
    server: Option<Window>,
    origin: Option<Window>,
    client: Window,
    core_pid: u32,
    sampler: probe::Sampler,
}

pub(crate) struct Closed {
    core: Delta,
    server: Option<Delta>,
    origin: Option<Delta>,
    client: Delta,
    core_peak: probe::Memory,
}

impl Windows {
    pub(crate) fn open(pids: Pids) -> Windows {
        Windows {
            sampler: probe::Sampler::start(pids.core, Duration::from_millis(50)),
            core: Window::open_counting_syscalls(pids.core),
            server: pids.server.map(Window::open_counting_syscalls),
            origin: pids.origin.map(Window::open),
            client: Window::open(std::process::id()),
            core_pid: pids.core,
        }
    }

    pub(crate) fn close(self) -> Closed {
        let core = self.core.close();
        let server = self.server.map(Window::close);
        let origin = self.origin.map(Window::close);
        let client = self.client.close();
        let mut peak = probe::peak(&self.sampler.finish());
        if let Some(now) = probe::memory(self.core_pid, false) {
            peak.footprint = peak.footprint.max(now.footprint);
        }
        Closed {
            core,
            server,
            origin,
            client,
            core_peak: peak,
        }
    }
}

const MIB: f64 = 1024.0 * 1024.0;

/// Cost of the window per `unit_count` units of work, named `per`.
fn costs(m: &mut Metrics, closed: &Closed, bytes: Option<u64>, per: Option<(&str, f64, f64)>) {
    let core = &closed.core;
    let cpu = core.cpu_ns() as f64;
    m.insert("cores".into(), core.cores());
    if cpu > 0.0 {
        m.insert("sys_share".into(), core.sys_ns as f64 / cpu);
        if let Some(wait) = core.wait_ns {
            m.insert("wait_share".into(), wait as f64 / cpu);
        }
    }
    if let (Some(instructions), Some(cycles)) = (core.instructions, core.cycles)
        && cycles > 0
    {
        m.insert("ipc".into(), instructions as f64 / cycles as f64);
    }
    m.insert("peak_mib".into(), closed.core_peak.footprint as f64 / MIB);
    if let Some(server) = closed.server {
        m.insert("server_cores".into(), server.cores());
    }
    if let Some(origin) = closed.origin {
        m.insert("origin_cores".into(), origin.cores());
    }
    m.insert("client_cores".into(), closed.client.cores());
    if let Some(bytes) = bytes.filter(|b| *b > 0) {
        let gb = bytes as f64 / 1e9;
        let mb = bytes as f64 / 1e6;
        m.insert("cpu_s_per_gb".into(), cpu / 1e9 / gb);
        if let Some(server) = closed.server {
            m.insert(
                "server_cpu_s_per_gb".into(),
                server.cpu_ns() as f64 / 1e9 / gb,
            );
        }
        if let Some(cycles) = core.cycles {
            m.insert("cycles_per_byte".into(), cycles as f64 / bytes as f64);
        }
        if let Some(instructions) = core.instructions {
            m.insert(
                "instructions_per_byte".into(),
                instructions as f64 / bytes as f64,
            );
        }
        if let Some(switches) = core.context_switches {
            m.insert("ctx_per_mb".into(), switches as f64 / mb);
        }
        syscall_metrics(m, closed, "mb", mb);
        if let Some(io) = core.io {
            m.insert("vfs_reads_per_mb".into(), io.read_calls as f64 / mb);
            m.insert("vfs_writes_per_mb".into(), io.write_calls as f64 / mb);
            if io.read_calls > 0 {
                m.insert(
                    "vfs_read_bytes_per_call".into(),
                    io.read_bytes as f64 / io.read_calls as f64,
                );
            }
            if io.write_calls > 0 {
                m.insert(
                    "vfs_write_bytes_per_call".into(),
                    io.write_bytes as f64 / io.write_calls as f64,
                );
            }
        }
    }
    if let Some((name, count, scale)) = per.filter(|p| p.1 > 0.0) {
        m.insert(name.into(), cpu / scale / count);
        if let Some(cycles) = core.cycles {
            m.insert(
                format!("k{}", name.replace("cpu_us", "cycles")),
                cycles as f64 / 1e3 / count,
            );
        }
        if let Some(unit) = name.strip_prefix("cpu_us_per_") {
            syscall_metrics(m, closed, unit, count);
        }
    }
}

/// System calls of the core and the server per `count` units of work, named `unit`.
fn syscall_metrics(m: &mut Metrics, closed: &Closed, unit: &str, count: f64) {
    if let Some(calls) = closed.core.syscalls {
        m.insert(format!("syscalls_per_{unit}"), calls as f64 / count);
    }
    for (prefix, delta) in [
        ("", Some(&closed.core)),
        ("server_", closed.server.as_ref()),
    ] {
        let Some(counts) = delta.and_then(|d| d.syscall_counts) else {
            continue;
        };
        if !prefix.is_empty() {
            m.insert(
                format!("{prefix}syscalls_per_{unit}"),
                counts.total as f64 / count,
            );
        }
        for (name, calls) in syscalls::NAMES.iter().zip(counts.by_name) {
            if calls > 0 {
                m.insert(
                    format!("{prefix}sys_{name}_per_{unit}"),
                    calls as f64 / count,
                );
            }
        }
        m.insert(
            format!("{prefix}recv_calls_per_{unit}"),
            counts.sum(&syscalls::RECV) as f64 / count,
        );
        m.insert(
            format!("{prefix}send_calls_per_{unit}"),
            counts.sum(&syscalls::SEND) as f64 / count,
        );
    }
}

fn latency_metrics(m: &mut Metrics, prefix: &str, samples: &mut [u64], unit_ns: f64, unit: &str) {
    if samples.is_empty() {
        return;
    }
    samples.sort_unstable();
    let as_f64: Vec<f64> = samples.iter().map(|&v| v as f64 / unit_ns).collect();
    for (label, q) in [("p50", 0.5), ("p90", 0.9), ("p99", 0.99), ("p999", 0.999)] {
        m.insert(
            format!("{prefix}{label}_{unit}"),
            stats::quantile(&as_f64, q),
        );
    }
    m.insert(
        format!("{prefix}max_{unit}"),
        *as_f64.last().unwrap_or(&0.0),
    );
}

type Io<T> = Result<T, String>;

fn io(what: &str) -> impl FnOnce(std::io::Error) -> String + '_ {
    move |e| format!("{what}: {e}")
}

pub async fn run(workload: Workload, ctx: &Ctx) -> Io<Metrics> {
    match workload {
        Workload::TcpDown => stream(ctx, Direction::Down, 1).await,
        Workload::TcpUp => stream(ctx, Direction::Up, 1).await,
        Workload::TcpMulti => stream(ctx, Direction::Down, ctx.flows).await,
        Workload::TcpRr => rr(ctx).await,
        Workload::TcpCrr => crr(ctx).await,
        Workload::UdpStream => udp(ctx, ctx.udp_size, ctx.udp_window).await,
        Workload::UdpRr => udp(ctx, 64, 1).await,
        Workload::MitmRr => mitm::rr(ctx, Wire::H1).await,
        Workload::MitmH2Rr => mitm::rr(ctx, Wire::H2).await,
        Workload::MitmCrr => {
            let ctx_ = ctx.clone();
            crr_with(ctx, "mitm-crr", move || mitm::crr_once(ctx_.clone())).await
        }
        Workload::HttpRr => mitm::rr(ctx, Wire::Plain).await,
        Workload::Idle | Workload::Startup | Workload::Large => {
            Err(format!("{} runs on a fresh core", workload.name()))
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Down,
    Up,
}

/// Bulk transfer over `flows` connections. Down counts what the client reads, up
/// what the origin reports it received, so neither side's buffering inflates a rate.
async fn stream(ctx: &Ctx, direction: Direction, flows: usize) -> Io<Metrics> {
    let counters: Arc<Vec<AtomicU64>> = Arc::new((0..flows).map(|_| AtomicU64::new(0)).collect());
    let stop = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(std::sync::Mutex::new(None::<String>));
    let target = ctx.at(match direction {
        Direction::Down => ctx.ports.source,
        Direction::Up => ctx.ports.sink,
    });
    let mut tasks = Vec::new();
    for flow in 0..flows {
        let stream = socks::connect(ctx.entry, target)
            .await
            .map_err(io("connect"))?;
        let (counters, stop, failed) = (counters.clone(), stop.clone(), failed.clone());
        tasks.push(tokio::spawn(async move {
            let result = match direction {
                Direction::Down => drain(stream, &counters[flow], &stop).await,
                Direction::Up => fill(stream, &counters[flow], &stop).await,
            };
            if let Err(err) = result
                && !stop.load(Ordering::Relaxed)
            {
                *failed.lock().unwrap_or_else(|e| e.into_inner()) = Some(err.to_string());
            }
        }));
    }
    let total = || {
        counters
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum::<u64>()
    };
    tokio::time::sleep(ctx.warmup).await;
    let mixed_port = match ctx.entry {
        Entry::Socks(proxy) => Some(proxy.port()),
        Entry::Tun => None,
    };
    let tcp_before = sockets::snapshot(ctx.pids.core, mixed_port);
    let net_before = ctx.net_counters.then(|| NetEdge::read(ctx));
    let per_flow_start: Vec<u64> = counters.iter().map(|c| c.load(Ordering::Relaxed)).collect();
    let windows = Windows::open(ctx.pids);
    let started = Instant::now();
    let start_bytes = total();
    let mut intervals = Vec::new();
    let mut last = (started, start_bytes);
    let mut tick = tokio::time::interval_at(
        tokio::time::Instant::now() + crate::origin::REPORT_EVERY,
        crate::origin::REPORT_EVERY,
    );
    while started.elapsed() < ctx.duration {
        tick.tick().await;
        let now = (Instant::now(), total());
        intervals
            .push((now.1 - last.1) as f64 * 8.0 / 1e9 / now.0.duration_since(last.0).as_secs_f64());
        last = now;
    }
    let elapsed = started.elapsed().as_secs_f64();
    let bytes = total() - start_bytes;
    let per_flow: Vec<f64> = counters
        .iter()
        .zip(&per_flow_start)
        .map(|(c, s)| (c.load(Ordering::Relaxed) - s) as f64 * 8.0 / 1e9 / elapsed)
        .collect();
    let closed = windows.close();
    let tcp_after = sockets::snapshot(ctx.pids.core, mixed_port);
    let net_after = ctx.net_counters.then(|| NetEdge::read(ctx));
    stop.store(true, Ordering::Relaxed);
    for task in tasks {
        task.abort();
    }
    if let Some(err) = failed.lock().unwrap_or_else(|e| e.into_inner()).take() {
        return Err(err);
    }
    if bytes == 0 {
        return Err("no bytes moved".into());
    }
    let mut m = Metrics::new();
    m.insert("gbps".into(), bytes as f64 * 8.0 / 1e9 / elapsed);
    m.insert("interval_cv".into(), stats::cv(&intervals));
    let mut sorted = intervals.clone();
    sorted.sort_by(f64::total_cmp);
    m.insert("interval_p10_gbps".into(), stats::quantile(&sorted, 0.1));
    if flows > 1 {
        m.insert("jain".into(), stats::jain(&per_flow));
        m.insert(
            "min_flow_gbps".into(),
            per_flow.iter().copied().fold(f64::INFINITY, f64::min),
        );
        if ctx.net_counters {
            for (flow, rate) in per_flow.iter().enumerate() {
                m.insert(format!("flow_{flow}_gbps"), *rate);
            }
        }
    }
    costs(&mut m, &closed, Some(bytes), None);
    if let (Some(before), Some(after)) = (&tcp_before, &tcp_after) {
        let (received, sent) = sockets::metrics(before, after, &mut m);
        if let Some(counts) = closed.core.syscall_counts.filter(|c| c.get("splice") == 0) {
            let per_call =
                |bytes: u64, calls: u64| (calls > 0).then(|| bytes as f64 / calls as f64);
            if let Some(v) = per_call(received, counts.sum(&syscalls::RECV)) {
                m.insert("socket_bytes_per_recv_call".into(), v);
            }
            if let Some(v) = per_call(sent, counts.sum(&syscalls::SEND)) {
                m.insert("socket_bytes_per_send_call".into(), v);
            }
        }
        if net_after.is_some() {
            sockets::receive_state(before, after, &mut m);
        }
    }
    if let (Some(before), Some(after)) = (&net_before, &net_after) {
        crate::netstat::metrics(&before.counters, &after.counters, bytes, &mut m);
        if let (Some(before), Some(after)) = (&before.server, &after.server) {
            sockets::link_metrics(before, after, elapsed, &mut m);
        }
    }
    Ok(m)
}

/// What `--net-counters` reads at one edge of a window.
struct NetEdge {
    counters: crate::netstat::Edge,
    server: Option<sockets::Snapshot>,
}

impl NetEdge {
    fn read(ctx: &Ctx) -> NetEdge {
        let far = ctx.far_netns.as_deref();
        NetEdge {
            counters: crate::netstat::edge(far),
            server: far
                .zip(ctx.pids.server)
                .and_then(|(netns, server)| sockets::snapshot_link(server, netns)),
        }
    }
}

async fn drain(
    mut stream: tokio::net::TcpStream,
    counter: &AtomicU64,
    stop: &AtomicBool,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 4 * CHUNK];
    while !stop.load(Ordering::Relaxed) {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::Error::other("origin closed the download"));
        }
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
    socks::abort(stream);
    Ok(())
}

async fn fill(
    stream: tokio::net::TcpStream,
    counter: &AtomicU64,
    stop: &AtomicBool,
) -> std::io::Result<()> {
    let (mut read, mut write) = stream.into_split();
    let writer = async {
        let chunk = vec![0xa5u8; CHUNK];
        loop {
            write.write_all(&chunk).await?;
        }
    };
    let reports = async {
        let mut report = [0u8; 8];
        while !stop.load(Ordering::Relaxed) {
            read.read_exact(&mut report).await?;
            counter.store(u64::from_le_bytes(report), Ordering::Relaxed);
        }
        Ok::<(), std::io::Error>(())
    };
    tokio::select! {
        result = writer => result,
        result = reports => result,
    }
}

const RR_SIZE: usize = 64;

async fn rr(ctx: &Ctx) -> Io<Metrics> {
    let mut stream = socks::connect(ctx.entry, ctx.at(ctx.ports.echo))
        .await
        .map_err(io("connect"))?;
    let request = [0x42u8; RR_SIZE];
    let mut reply = [0u8; RR_SIZE];
    let warm_until = Instant::now() + ctx.warmup;
    while Instant::now() < warm_until {
        stream.write_all(&request).await.map_err(io("rr"))?;
        stream.read_exact(&mut reply).await.map_err(io("rr"))?;
    }
    let windows = Windows::open(ctx.pids);
    let started = Instant::now();
    let mut samples = Vec::with_capacity(1 << 16);
    while started.elapsed() < ctx.duration {
        let sent = Instant::now();
        stream.write_all(&request).await.map_err(io("rr"))?;
        stream.read_exact(&mut reply).await.map_err(io("rr"))?;
        samples.push(sent.elapsed().as_nanos() as u64);
    }
    let metrics = rr_metrics(started, windows.close(), &mut samples);
    socks::abort(stream);
    Ok(metrics)
}

pub(crate) fn rr_metrics(started: Instant, closed: Closed, samples: &mut [u64]) -> Metrics {
    let elapsed = started.elapsed().as_secs_f64();
    let mut m = Metrics::new();
    let count = samples.len() as f64;
    m.insert("tps".into(), count / elapsed);
    latency_metrics(&mut m, "", samples, 1e3, "us");
    costs(&mut m, &closed, None, Some(("cpu_us_per_tx", count, 1e3)));
    m
}

async fn crr(ctx: &Ctx) -> Io<Metrics> {
    let (entry, target) = (ctx.entry, ctx.at(ctx.ports.crr));
    crr_with(ctx, "tcp-crr", move || crr_once(entry, target)).await
}

/// `crr_conns` connections, `crr_concurrency` at a time, each made and timed by `once`.
async fn crr_with<F, Fut>(ctx: &Ctx, name: &str, once: F) -> Io<Metrics>
where
    F: Fn() -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<u64, String>> + Send,
{
    let run = |count: usize| {
        let next = Arc::new(AtomicU64::new(0));
        let workers: Vec<_> = (0..ctx.crr_concurrency)
            .map(|_| {
                let next = next.clone();
                let once = once.clone();
                tokio::spawn(async move {
                    let mut ok = Vec::new();
                    let mut errors = Vec::new();
                    while (next.fetch_add(1, Ordering::Relaxed) as usize) < count {
                        match once().await {
                            Ok(ns) => ok.push(ns),
                            Err(e) => errors.push(e),
                        }
                    }
                    (ok, errors)
                })
            })
            .collect();
        async move {
            let mut ok = Vec::new();
            let mut errors = Vec::new();
            for worker in workers {
                if let Ok((o, e)) = worker.await {
                    ok.extend(o);
                    errors.extend(e);
                }
            }
            (ok, errors)
        }
    };
    let warm = (ctx.crr_conns / 10).max(ctx.crr_concurrency);
    let _ = run(warm).await;
    let windows = Windows::open(ctx.pids);
    let started = Instant::now();
    let (mut ok, errors) = run(ctx.crr_conns).await;
    let elapsed = started.elapsed().as_secs_f64();
    let closed = windows.close();
    if ok.is_empty() {
        return Err(format!("every connection failed: {}", error_kinds(&errors)));
    }
    if !errors.is_empty() {
        eprintln!(
            "  {name}: {} of {} connections failed: {}",
            errors.len(),
            ctx.crr_conns,
            error_kinds(&errors)
        );
    }
    let mut m = Metrics::new();
    let count = ok.len() as f64;
    m.insert("cps".into(), count / elapsed);
    m.insert(
        "error_pct".into(),
        errors.len() as f64 * 100.0 / ctx.crr_conns as f64,
    );
    latency_metrics(&mut m, "", &mut ok, 1e6, "ms");
    costs(&mut m, &closed, None, Some(("cpu_us_per_conn", count, 1e3)));
    if let Some(fds) = probe::open_fds(ctx.pids.core) {
        m.insert("fds_after".into(), fds as f64);
    }
    Ok(m)
}

/// The three most common failures with their counts, so an exhausted resource (an OS error code) shows apart
/// from a refused or timed-out connection.
fn error_kinds(errors: &[String]) -> String {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for error in errors {
        *counts.entry(error).or_default() += 1;
    }
    let mut kinds: Vec<_> = counts.into_iter().collect();
    kinds.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    kinds
        .iter()
        .take(3)
        .map(|(error, n)| format!("{n} x {error}"))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn crr_once(entry: Entry, target: SocketAddr) -> Result<u64, String> {
    let started = Instant::now();
    let work = async {
        let mut stream = socks::connect(entry, target).await?;
        stream.write_all(b"c").await?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        socks::abort(stream);
        Ok::<_, std::io::Error>(())
    };
    match tokio::time::timeout(Duration::from_secs(5), work).await {
        Ok(Ok(())) => Ok(started.elapsed().as_nanos() as u64),
        Ok(Err(err)) => Err(err.to_string()),
        Err(_) => Err("timed out".into()),
    }
}

const LOSS_AFTER: Duration = Duration::from_millis(250);

/// `window` packets of `size` bytes in flight; one missing for `LOSS_AFTER` counts
/// as lost and frees its slot.
async fn udp(ctx: &Ctx, size: usize, window: usize) -> Io<Metrics> {
    let flow = Udp::open(ctx.entry, ctx.at(ctx.ports.udp))
        .await
        .map_err(io("udp associate"))?;
    let header = flow.header_len();
    let size = size.max(16);
    let mut packet = vec![0u8; header + size];
    let mut buf = vec![0u8; 65_536];
    let mut inflight: HashMap<u64, Instant> = HashMap::with_capacity(window * 2);
    let mut seq = 0u64;
    let begun = Instant::now();
    let measure_from = begun + ctx.warmup;
    let mut windows = None;
    let mut window_start = None;
    let (mut sent, mut received, mut lost) = (0u64, 0u64, 0u64);
    let mut rtts = Vec::new();
    loop {
        let now = Instant::now();
        if windows.is_none() && now >= measure_from {
            windows = Some(Windows::open(ctx.pids));
            window_start = Some(now);
        }
        if let Some(start) = window_start
            && now.duration_since(start) >= ctx.duration
        {
            break;
        }
        if now.duration_since(begun) > ctx.warmup + ctx.duration + Duration::from_secs(5) {
            break;
        }
        while inflight.len() < window {
            seq += 1;
            packet[header..header + 8].copy_from_slice(&seq.to_le_bytes());
            flow.send(&mut packet).await.map_err(io("udp send"))?;
            inflight.insert(seq, Instant::now());
            if window_start.is_some() {
                sent += 1;
            }
        }
        match tokio::time::timeout(Duration::from_millis(20), flow.recv(&mut buf)).await {
            Ok(Ok(payload)) if payload.len() >= 8 => {
                let id = u64::from_le_bytes(payload[..8].try_into().unwrap_or_default());
                if let Some(at) = inflight.remove(&id)
                    && window_start.is_some_and(|s| at >= s)
                {
                    received += 1;
                    rtts.push(at.elapsed().as_nanos() as u64);
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(err)) => return Err(format!("udp recv: {err}")),
            Err(_) => {}
        }
        let now = Instant::now();
        inflight.retain(|_, at| {
            let keep = now.duration_since(*at) < LOSS_AFTER;
            if !keep && window_start.is_some_and(|s| *at >= s) {
                lost += 1;
            }
            keep
        });
    }
    let elapsed = window_start.map_or(0.0, |s| s.elapsed().as_secs_f64());
    let closed = windows.ok_or("udp window never opened")?.close();
    if received == 0 {
        return Err("no UDP packet came back".into());
    }
    let mut m = Metrics::new();
    let bytes = received * size as u64;
    m.insert("mbps".into(), bytes as f64 * 8.0 / 1e6 / elapsed);
    m.insert("pps".into(), received as f64 / elapsed);
    m.insert("loss_pct".into(), lost as f64 * 100.0 / sent.max(1) as f64);
    latency_metrics(&mut m, "rtt_", &mut rtts, 1e3, "us");
    costs(&mut m, &closed, Some(bytes * 2), None);
    Ok(m)
}

/// Holds `ctx.idle_conns` connections, each proven end to end, and reads the core
/// before, while they are held, and after they are closed.
pub async fn idle(ctx: &Ctx) -> Io<Metrics> {
    if ctx.tls.is_some() {
        let held = ctx.clone();
        return hold(ctx, move || mitm::held(held.clone()), drop).await;
    }
    let (entry, target) = (ctx.entry, ctx.at(ctx.ports.echo));
    let open = move || async move {
        let mut stream = socks::connect(entry, target)
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(b"i").await.map_err(|e| e.to_string())?;
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| e.to_string())?;
        Ok(stream)
    };
    hold(ctx, open, socks::abort).await
}

/// Opens `idle_conns` connections with `open`, 64 at a time, and reads what holding them costs.
async fn hold<T, F, Fut>(ctx: &Ctx, open: F, close: fn(T)) -> Io<Metrics>
where
    T: Send + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, String>> + Send + 'static,
{
    let pid = ctx.pids.core;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let before = probe::memory(pid, true).ok_or("read core memory")?;
    let server_before = ctx.pids.server.and_then(|p| probe::memory(p, true));
    let fds_before = probe::open_fds(pid);
    let started = Instant::now();
    let mut held = Vec::with_capacity(ctx.idle_conns);
    let mut pending = tokio::task::JoinSet::new();
    let mut failures = 0usize;
    let mut first_error = None;
    for _ in 0..ctx.idle_conns {
        if pending.len() >= 64
            && let Some(done) = pending.join_next().await
        {
            match done {
                Ok(Ok(stream)) => held.push(stream),
                Ok(Err(e)) => {
                    failures += 1;
                    first_error.get_or_insert(e);
                }
                Err(_) => failures += 1,
            }
        }
        let opening = open();
        pending.spawn(async move {
            tokio::time::timeout(Duration::from_secs(10), opening)
                .await
                .map_err(|_| "held connection not proven within 10 s".to_string())?
        });
    }
    while let Some(done) = pending.join_next().await {
        match done {
            Ok(Ok(stream)) => held.push(stream),
            Ok(Err(e)) => {
                failures += 1;
                first_error.get_or_insert(e);
            }
            Err(_) => failures += 1,
        }
    }
    let open_ms = started.elapsed().as_secs_f64() * 1e3;
    if held.is_empty() {
        return Err(format!(
            "no connection opened: {}",
            first_error.unwrap_or_default()
        ));
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let loaded = probe::memory(pid, true).ok_or("read core memory")?;
    let server_loaded = ctx.pids.server.and_then(|p| probe::memory(p, true));
    let fds_loaded = probe::open_fds(pid);
    let count = held.len() as f64;
    for item in held.drain(..) {
        close(item);
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after = probe::memory(pid, true).ok_or("read core memory")?;
    let mut m = Metrics::new();
    let kib = |a: u64, b: u64| (a as f64 - b as f64) / 1024.0 / count;
    m.insert(
        "kib_per_conn".into(),
        kib(loaded.footprint, before.footprint),
    );
    m.insert(
        "retained_kib_per_conn".into(),
        kib(after.footprint, before.footprint),
    );
    m.insert("open_ms".into(), open_ms);
    m.insert("failed".into(), failures as f64);
    m.insert("threads_loaded".into(), loaded.threads as f64);
    if let (Some(b), Some(l)) = (server_before, server_loaded) {
        m.insert("server_kib_per_conn".into(), kib(l.footprint, b.footprint));
    }
    if let (Some(b), Some(l)) = (fds_before, fds_loaded) {
        m.insert("fds_per_conn".into(), (l as f64 - b as f64) / count);
    }
    Ok(m)
}

/// After `ready`: settle, then read what an idle core holds.
pub async fn settled(pid: u32, ready: Duration, settle: Duration) -> Metrics {
    let ready_usage = probe::usage(pid);
    tokio::time::sleep(settle).await;
    let mut m = Metrics::new();
    m.insert("ready_ms".into(), ready.as_secs_f64() * 1e3);
    if let Some(usage) = ready_usage {
        m.insert("ready_cpu_ms".into(), usage.cpu_ns() as f64 / 1e6);
    }
    if let Some(mem) = probe::memory(pid, true) {
        m.insert("footprint_mib".into(), mem.footprint as f64 / MIB);
        m.insert("rss_mib".into(), mem.rss as f64 / MIB);
        m.insert("peak_mib".into(), mem.peak as f64 / MIB);
        m.insert("threads".into(), mem.threads as f64);
    }
    if let Some(fds) = probe::open_fds(pid) {
        m.insert("fds".into(), fds as f64);
    }
    if let Some(usage) = probe::usage(pid) {
        m.insert("startup_cpu_ms".into(), usage.cpu_ns() as f64 / 1e6);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::error_kinds;

    #[test]
    fn error_kinds_lists_the_commonest_failures_first() {
        let errors: Vec<String> = [
            "refused",
            "in use",
            "timed out",
            "in use",
            "reset",
            "in use",
            "refused",
        ]
        .map(String::from)
        .into();
        assert_eq!(error_kinds(&errors), "3 x in use; 2 x refused; 1 x reset");
    }
}
