//! What SCRIPT rules and DNS scripts cost, arm against arm in one process. A measurement, run
//! by hand on the Linux VM:
//! `cargo test -p concord-engine --release --test e2e script_cost -- --ignored --nocapture --test-threads 1`.
//! `MM_ROUNDS` (10) rounds alternate the arms' order; each runs `MM_PER` (200) samples per arm.
//! Lines read: each arm's median over rounds of its per-round p50 and p95, then the median of
//! the per-round difference with its distribution-free 95% interval.

use std::future::Future;
use std::time::Instant;

use super::*;

fn env_or(name: &str, default: usize) -> usize {
    std::env::var(name).map_or(default, |n| n.parse().unwrap())
}

/// The median and a distribution-free 95% interval for it, from order statistics.
fn median_ci(mut values: Vec<f64>) -> (f64, f64, f64) {
    values.sort_by(f64::total_cmp);
    let n = values.len();
    let (mut j, mut below, mut ways) = (1, 0.0, 1.0);
    for i in 0..n {
        if i > 0 {
            ways *= (n - i + 1) as f64 / i as f64;
        }
        below += ways / 2f64.powi(n as i32);
        if 2.0 * below > 0.05 {
            break;
        }
        j = i + 1;
    }
    let j = j.clamp(1, n.div_ceil(2));
    let middle = if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    };
    (middle, values[j - 1], values[n - j])
}

fn quantile(sorted: &[f64], q: f64) -> f64 {
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

/// `count` timings in microseconds, `concurrency` at a time; `op` is given the sample's index.
async fn sample<F, Fut>(count: usize, concurrency: usize, op: F) -> Vec<f64>
where
    F: Fn(usize) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = f64> + Send,
{
    let next = Arc::new(AtomicUsize::new(0));
    let workers: Vec<_> = (0..concurrency)
        .map(|_| {
            let (next, op) = (next.clone(), op.clone());
            tokio::spawn(async move {
                let mut out = Vec::new();
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= count {
                        return out;
                    }
                    out.push(op(index).await);
                }
            })
        })
        .collect();
    let mut all = Vec::with_capacity(count);
    for worker in workers {
        all.extend(worker.await.unwrap());
    }
    all.sort_by(f64::total_cmp);
    all
}

/// Runs both arms `MM_ROUNDS` times in alternating order and prints the comparison.
async fn compare<A, B, FA, FB>(cell: &str, names: [&str; 2], concurrency: usize, a: A, b: B)
where
    A: Fn(usize) -> FA + Clone + Send + 'static,
    B: Fn(usize) -> FB + Clone + Send + 'static,
    FA: Future<Output = f64> + Send,
    FB: Future<Output = f64> + Send,
{
    let (rounds, per) = (env_or("MM_ROUNDS", 10), env_or("MM_PER", 200));
    let _ = sample(per / 4, concurrency, a.clone()).await;
    let _ = sample(per / 4, concurrency, b.clone()).await;
    let mut stats = [[Vec::new(), Vec::new()], [Vec::new(), Vec::new()]];
    for round in 0..rounds {
        let offset = (round + 1) * per;
        let (a, b) = (a.clone(), b.clone());
        let a = move |i| a(offset + i);
        let b = move |i| b(offset + i);
        let (first, second) = if round % 2 == 0 {
            let x = sample(per, concurrency, a).await;
            (x, sample(per, concurrency, b).await)
        } else {
            let y = sample(per, concurrency, b).await;
            (sample(per, concurrency, a).await, y)
        };
        for (arm, samples) in [first, second].iter().enumerate() {
            stats[0][arm].push(quantile(samples, 0.5));
            stats[1][arm].push(quantile(samples, 0.95));
        }
    }
    let mut line = format!("MM-COST {cell}");
    for (arm, name) in names.iter().enumerate() {
        let (p50, p95) = (
            median_ci(stats[0][arm].clone()).0,
            median_ci(stats[1][arm].clone()).0,
        );
        line.push_str(&format!(" | {name}: p50 {p50:.1} us, p95 {p95:.1} us"));
    }
    for (label, at) in [("p50", 0), ("p95", 1)] {
        let deltas = stats[at][1]
            .iter()
            .zip(&stats[at][0])
            .map(|(b, a)| b - a)
            .collect();
        let (mid, lo, hi) = median_ci(deltas);
        line.push_str(&format!(
            " | {label} added {mid:+.1} us [{lo:+.1}, {hi:+.1}]"
        ));
    }
    println!("{line}");
}

async fn connect_ip(mixed: u16, target: SocketAddr) -> f64 {
    let started = Instant::now();
    let mut stream = socks_connect(mixed, target).await.unwrap();
    round_trip(&mut stream).await;
    started.elapsed().as_secs_f64() * 1e6
}

async fn connect_name(mixed: u16, name: &str, port: u16) -> f64 {
    let started = Instant::now();
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, mixed))
        .await
        .unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    let mut request = vec![5, 1, 0, 3, name.len() as u8];
    request.extend_from_slice(name.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "socks reply");
    round_trip(&mut stream).await;
    started.elapsed().as_secs_f64() * 1e6
}

async fn query(port: u16, name: String) -> f64 {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let started = Instant::now();
    socket
        .send_to(&dns_query(&name), (Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no answer")
        .unwrap();
    let elapsed = started.elapsed().as_secs_f64() * 1e6;
    assert_ne!(last_a_record(&buf[..len]), [0; 4], "{name} has no answer");
    elapsed
}

/// A core whose `never` rule script matches nothing, `pick` answers names by their suffix,
/// and `cost.test` is the loopback address.
async fn rig(rules: &str, dns_port: u16) -> Rig {
    let nameserver = super::mitm::nameserver_answering([127, 0, 0, 1]).await;
    let named = super::mitm::nameserver_answering([10, 0, 0, 2]).await;
    let rig = Rig::new();
    let resources = rig.home.path().join("mitm/resources");
    std::fs::create_dir_all(&resources).unwrap();
    std::fs::write(resources.join("never.js"), "$done({matched: false})").unwrap();
    let pick = format!(
        "if ($domain.endsWith('.a.test')) $done({{addresses: ['192.0.2.1'], ttl: 600}});\n\
         else if ($domain.endsWith('.v.test')) $done({{server: '{named}'}});\n\
         else $done({{}});"
    );
    std::fs::write(resources.join("pick.js"), pick).unwrap();
    let config = format!(
        "hosts:\n  cost.test: 127.0.0.1\n  +.a.test: script:pick\n  +.v.test: script:pick\n  \
         +.f.test: script:pick\n\
         dns:\n  enable: true\n  listen: 127.0.0.1:{dns_port}\n  enhanced-mode: redir-host\n  \
         nameserver:\n    - {nameserver}\n\
         mitm:\n  enable: true\n  script:\n    - never = type=rule,script-path=never.js\n    \
         - pick = type=dns,script-path=pick.js\n\
         rules:\n{rules}"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    rig
}

fn filler(range: std::ops::Range<usize>) -> String {
    range
        .map(|i| format!("  - DOMAIN,n{i}.invalid,REJECT\n"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, run by hand on the Linux VM"]
async fn script_cost() {
    let echo = tcp_echo().await;
    let ordinary = "  - DOMAIN,never.invalid,REJECT\n";
    let script = "  - SCRIPT,never,REJECT\n";
    let last = "  - MATCH,DIRECT\n";
    let cells: [(&str, String, String, bool, usize); 6] = [
        (
            "route, SCRIPT first",
            format!("{ordinary}{last}"),
            format!("{script}{last}"),
            false,
            1,
        ),
        (
            "route, SCRIPT 50th of 100",
            format!("{}{ordinary}{}{last}", filler(0..49), filler(49..99)),
            format!("{}{script}{}{last}", filler(0..49), filler(49..99)),
            false,
            1,
        ),
        (
            "route, a second rule naming the script",
            format!("{script}{last}"),
            format!("{script}{script}{last}"),
            false,
            1,
        ),
        (
            "route, requires-resolve, by name",
            format!("{script}{last}"),
            format!("  - SCRIPT,never,REJECT,requires-resolve\n{last}"),
            true,
            1,
        ),
        (
            "route, SCRIPT first, 2 at once",
            format!("{ordinary}{last}"),
            format!("{script}{last}"),
            false,
            2,
        ),
        (
            "route, SCRIPT first, 8 at once",
            format!("{ordinary}{last}"),
            format!("{script}{last}"),
            false,
            8,
        ),
    ];
    for (cell, base, with, by_name, concurrency) in cells {
        let (a, b) = (rig(&base, free_port()).await, rig(&with, free_port()).await);
        let names = if by_name {
            ["without", "with"]
        } else {
            ["ordinary rule", "SCRIPT"]
        };
        let names = if cell.contains("second") {
            ["one rule", "two rules"]
        } else {
            names
        };
        let (ma, mb, port) = (a.mixed, b.mixed, echo.port());
        if by_name {
            compare(
                cell,
                names,
                concurrency,
                move |_| connect_name(ma, "cost.test", port),
                move |_| connect_name(mb, "cost.test", port),
            )
            .await;
        } else {
            compare(
                cell,
                names,
                concurrency,
                move |_| connect_ip(ma, echo),
                move |_| connect_ip(mb, echo),
            )
            .await;
        }
        a.engine.shutdown().await;
        b.engine.shutdown().await;
    }

    let port = free_port();
    let dns = rig(last, port).await;
    let fresh = |suffix: &'static str| move |i: usize| query(port, format!("q{i}.{suffix}"));
    let again = |name: &'static str| move |_| query(port, name.to_string());
    let plain = ["plain", "scripted"];
    compare(
        "dns, address and ttl, first query",
        plain,
        1,
        fresh("p.test"),
        fresh("a.test"),
    )
    .await;
    compare(
        "dns, address and ttl, cache hit",
        plain,
        1,
        again("hit.p.test"),
        again("hit.a.test"),
    )
    .await;
    compare(
        "dns, $done({}) falls back",
        plain,
        1,
        fresh("p2.test"),
        fresh("f.test"),
    )
    .await;
    compare(
        "dns, server, first query",
        plain,
        1,
        fresh("p3.test"),
        fresh("v.test"),
    )
    .await;
    compare(
        "dns, server, the same name again",
        plain,
        1,
        again("hit.p3.test"),
        again("hit.v.test"),
    )
    .await;
    dns.engine.shutdown().await;

    footprint(echo).await;
}

/// Threads and resident memory while 8 connections at a time each run a rule script.
async fn footprint(echo: SocketAddr) {
    fn status() -> Option<(f64, f64)> {
        let text = std::fs::read_to_string("/proc/self/status").ok()?;
        let field = |key: &str| -> Option<f64> {
            text.lines()
                .find_map(|line| line.strip_prefix(key))?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        };
        Some((field("Threads:")?, field("VmRSS:")? / 1024.0))
    }
    let Some(idle) = status() else {
        println!("MM-COST footprint: /proc only, skipped");
        return;
    };
    let rig = rig("  - SCRIPT,never,REJECT\n  - MATCH,DIRECT\n", free_port()).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = status().unwrap();
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watcher = {
        let done = done.clone();
        std::thread::spawn(move || {
            let mut peak = (0.0f64, 0.0f64);
            while !done.load(Ordering::Relaxed) {
                if let Some((threads, rss)) = status() {
                    peak = (peak.0.max(threads), peak.1.max(rss));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            peak
        })
    };
    let runs = env_or("MM_PER", 200) * 5;
    let mixed = rig.mixed;
    let started = Instant::now();
    let _ = sample(runs, 8, move |_| connect_ip(mixed, echo)).await;
    let elapsed = started.elapsed();
    done.store(true, Ordering::Relaxed);
    let peak = watcher.join().unwrap();
    println!(
        "MM-COST footprint, {runs} script runs 8 at a time in {elapsed:.2?} | threads: idle {} then {}, peak {} | RSS MiB: idle {:.1} then {:.1}, peak {:.1}",
        idle.0, before.0, peak.0, idle.1, before.1, peak.1
    );
    rig.engine.shutdown().await;
}
