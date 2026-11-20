use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use concord_common::scripts::{DnsScriptAnswer, RuleScriptRequest, ScriptHooks};
use concord_common::{HostResolver, Initiator, IpVersion};
use concord_config::hosts::{HostEntry, HostValue, HostsConfig};
use hickory_proto::rr::RecordType;

use super::support::*;
use crate::Resolver;

struct Answers {
    runs: AtomicUsize,
    answer: DnsScriptAnswer,
    generation: AtomicU64,
}

#[async_trait]
impl ScriptHooks for Answers {
    async fn rule(&self, _name: &str, _request: &RuleScriptRequest) -> bool {
        false
    }

    async fn dns(&self, name: &str, _domain: &str) -> DnsScriptAnswer {
        assert_eq!(name, "pick");
        self.runs.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(50)).await;
        self.answer.clone()
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn scripted(upstream: &str, answer: DnsScriptAnswer) -> (Arc<Resolver>, Arc<Answers>) {
    let hooks = Arc::new(Answers {
        runs: AtomicUsize::new(0),
        answer,
        generation: AtomicU64::new(0),
    });
    let hosts = HostsConfig {
        entries: vec![HostEntry {
            domain: "+.picked.test".into(),
            value: HostValue::Script("pick".into()),
        }],
    };
    let mut deps = deps(&Arc::new(Sink::default()));
    deps.scripts = hooks.clone();
    let mut config = config(&[upstream.to_string()]);
    config.use_hosts = true;
    let resolver = Resolver::new(&config, &hosts, deps).unwrap();
    (resolver, hooks)
}

async fn v4(resolver: &Resolver, host: &str) -> Vec<IpAddr> {
    resolver
        .lookup(host, IpVersion::Ipv4, Initiator::App)
        .await
        .unwrap()
        .v4
}

#[tokio::test]
async fn a_script_s_addresses_answer_and_are_kept_for_their_ttl_with_one_run_for_concurrent_asks() {
    let upstream = serve_udp(answer_with(Ipv4Addr::new(10, 0, 0, 1)), Duration::ZERO).await;
    let answer = DnsScriptAnswer::Addresses {
        ips: vec![ip("192.0.2.7"), ip("2001:db8::7")],
        ttl: Some(Duration::from_secs(60)),
    };
    let (resolver, hooks) = scripted(&upstream.udp_url(), answer);
    let (one, two) = tokio::join!(
        v4(&resolver, "a.picked.test"),
        v4(&resolver, "a.picked.test")
    );
    assert_eq!((one, two), (vec![ip("192.0.2.7")], vec![ip("192.0.2.7")]));
    assert_eq!(v4(&resolver, "a.picked.test").await, vec![ip("192.0.2.7")]);
    assert_eq!(hooks.runs.load(Ordering::SeqCst), 1);
    let reply = parse(
        &resolver
            .handle_query(&query_bytes("a.picked.test", RecordType::A), Initiator::App)
            .await
            .unwrap(),
    );
    assert_eq!(crate::msg::answer_ips(&reply), vec![ip("192.0.2.7")]);
    assert_eq!(reply.answers.first().map(|record| record.ttl), Some(60));
    assert_eq!(upstream.hits(), 0);
}

#[tokio::test]
async fn an_answer_without_a_ttl_is_asked_again() {
    let upstream = serve_udp(answer_with(Ipv4Addr::new(10, 0, 0, 1)), Duration::ZERO).await;
    let answer = DnsScriptAnswer::Addresses {
        ips: vec![ip("192.0.2.8")],
        ttl: None,
    };
    let (resolver, hooks) = scripted(&upstream.udp_url(), answer);
    v4(&resolver, "picked.test").await;
    v4(&resolver, "picked.test").await;
    assert_eq!(hooks.runs.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_script_leaving_the_domain_to_the_resolver_falls_through_to_the_nameservers() {
    let upstream = serve_udp(answer_with(Ipv4Addr::new(10, 0, 0, 1)), Duration::ZERO).await;
    let (resolver, hooks) = scripted(&upstream.udp_url(), DnsScriptAnswer::Resolve);
    assert_eq!(v4(&resolver, "picked.test").await, vec![ip("10.0.0.1")]);
    let reply = parse(
        &resolver
            .handle_query(&query_bytes("picked.test", RecordType::A), Initiator::App)
            .await
            .unwrap(),
    );
    assert_eq!(crate::msg::answer_ips(&reply), vec![ip("10.0.0.1")]);
    assert_eq!(hooks.runs.load(Ordering::SeqCst), 2);
    assert_eq!(v4(&resolver, "other.test").await, vec![ip("10.0.0.1")]);
    assert_eq!(hooks.runs.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_servers_a_script_names_answer_in_place_of_the_nameservers() {
    let upstream = serve_udp(answer_with(Ipv4Addr::new(10, 0, 0, 1)), Duration::ZERO).await;
    let named = serve_udp(answer_with(Ipv4Addr::new(10, 0, 0, 2)), Duration::ZERO).await;
    let servers: Vec<SocketAddr> = vec![named.addr];
    let (resolver, _) = scripted(&upstream.udp_url(), DnsScriptAnswer::Servers(servers));
    assert_eq!(v4(&resolver, "picked.test").await, vec![ip("10.0.0.2")]);
    let reply = parse(
        &resolver
            .handle_query(&query_bytes("picked.test", RecordType::A), Initiator::App)
            .await
            .unwrap(),
    );
    assert_eq!(crate::msg::answer_ips(&reply), vec![ip("10.0.0.2")]);
    assert_eq!(upstream.hits(), 0);
}

async fn ask_a(resolver: &Resolver, host: &str) -> hickory_proto::op::Message {
    parse(
        &resolver
            .handle_query(&query_bytes(host, RecordType::A), Initiator::App)
            .await
            .unwrap(),
    )
}

#[tokio::test]
async fn the_reply_of_a_script_s_servers_is_kept_for_its_ttl_until_the_scripts_change() {
    let upstream = serve_udp(answer_with(Ipv4Addr::new(10, 0, 0, 1)), Duration::ZERO).await;
    let named = serve_udp(answer_with(Ipv4Addr::new(10, 0, 0, 2)), Duration::ZERO).await;
    let (resolver, hooks) = scripted(
        &upstream.udp_url(),
        DnsScriptAnswer::Servers(vec![named.addr]),
    );
    ask_a(&resolver, "picked.test").await;
    let again = ask_a(&resolver, "Picked.test").await;
    assert_eq!(crate::msg::answer_ips(&again), vec![ip("10.0.0.2")]);
    assert!(again.answers.iter().all(|record| record.ttl <= 60));
    assert_eq!(v4(&resolver, "picked.test").await, vec![ip("10.0.0.2")]);
    assert_eq!((hooks.runs.load(Ordering::SeqCst), named.hits()), (1, 1));

    hooks.generation.store(1, Ordering::SeqCst);
    ask_a(&resolver, "picked.test").await;
    assert_eq!((hooks.runs.load(Ordering::SeqCst), named.hits()), (2, 2));
    assert_eq!(upstream.hits(), 0);
}

#[tokio::test]
async fn a_reply_with_no_ttl_to_keep_it_by_is_asked_again() {
    let upstream = serve_udp(answer_with(Ipv4Addr::new(10, 0, 0, 1)), Duration::ZERO).await;
    let zero: Handler = Arc::new(|req| {
        let query = req.queries.first()?;
        let mut resp = crate::msg::empty_answer(req);
        resp.answers.push(crate::msg::a_record(
            &query.name,
            0,
            Ipv4Addr::new(10, 0, 0, 3),
        ));
        Some(resp)
    });
    let named = serve_udp(zero, Duration::ZERO).await;
    let (resolver, hooks) = scripted(
        &upstream.udp_url(),
        DnsScriptAnswer::Servers(vec![named.addr]),
    );
    ask_a(&resolver, "picked.test").await;
    ask_a(&resolver, "picked.test").await;
    assert_eq!((hooks.runs.load(Ordering::SeqCst), named.hits()), (2, 2));
}

#[tokio::test]
async fn addresses_kept_from_a_script_go_when_the_scripts_change() {
    let upstream = serve_udp(answer_with(Ipv4Addr::new(10, 0, 0, 1)), Duration::ZERO).await;
    let answer = DnsScriptAnswer::Addresses {
        ips: vec![ip("192.0.2.9")],
        ttl: Some(Duration::from_secs(60)),
    };
    let (resolver, hooks) = scripted(&upstream.udp_url(), answer);
    v4(&resolver, "picked.test").await;
    hooks.generation.store(1, Ordering::SeqCst);
    v4(&resolver, "picked.test").await;
    assert_eq!(hooks.runs.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_kept_answer_past_its_ttl_is_asked_again() {
    let upstream = serve_udp(answer_with(Ipv4Addr::new(10, 0, 0, 1)), Duration::ZERO).await;
    let answer = DnsScriptAnswer::Addresses {
        ips: vec![ip("192.0.2.9")],
        ttl: Some(Duration::from_millis(100)),
    };
    let (resolver, hooks) = scripted(&upstream.udp_url(), answer);
    v4(&resolver, "picked.test").await;
    v4(&resolver, "picked.test").await;
    assert_eq!(hooks.runs.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(150)).await;
    v4(&resolver, "picked.test").await;
    assert_eq!(hooks.runs.load(Ordering::SeqCst), 2);
}

/// A kept answer's lookup with 5000 other domains kept, run by hand:
/// `cargo test -p concord-dns --release --lib kept_answer_lookup -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "a measurement, run by hand"]
async fn kept_answer_lookup_time_among_5000_others() {
    let upstream = serve_udp(answer_with(Ipv4Addr::new(10, 0, 0, 1)), Duration::ZERO).await;
    let answer = DnsScriptAnswer::Addresses {
        ips: vec![ip("192.0.2.7")],
        ttl: Some(Duration::from_secs(600)),
    };
    let (resolver, _hooks) = scripted(&upstream.udp_url(), answer);
    let mut fill = tokio::task::JoinSet::new();
    for n in 0..5000 {
        let resolver = resolver.clone();
        fill.spawn(async move {
            let other = query_bytes(&format!("n{n}.picked.test"), RecordType::A);
            resolver.handle_query(&other, Initiator::App).await.unwrap();
        });
    }
    fill.join_all().await;
    let query = query_bytes("a.picked.test", RecordType::A);
    resolver.handle_query(&query, Initiator::App).await.unwrap();
    let mut times: Vec<f64> = Vec::new();
    for _ in 0..20_000 {
        let started = std::time::Instant::now();
        std::hint::black_box(resolver.handle_query(&query, Initiator::App).await.unwrap());
        times.push(started.elapsed().as_secs_f64() * 1e6);
    }
    times.sort_by(f64::total_cmp);
    println!(
        "MM-KEPT median {:.2} us, p90 {:.2} us",
        times[10_000], times[18_000]
    );
}
