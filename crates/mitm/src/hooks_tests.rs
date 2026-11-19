use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use concord_common::scripts::{DnsScriptAnswer, RuleScriptRequest, ScriptHooks};
use serde_json::json;

use crate::testing::{Reply, Rig, TestServer, rig_for, start_server};

async fn scripts(
    files: &[(&str, &str)],
    lines: &[&str],
) -> (TestServer, Rig, Arc<dyn ScriptHooks>) {
    let server = start_server(false, &["http/1.1"], Arc::new(|_| Reply::ok(""))).await;
    let rig = rig_for(&server, None);
    std::fs::create_dir_all(rig.resources()).unwrap();
    for (name, source) in files {
        std::fs::write(rig.resources().join(name), source).unwrap();
    }
    let errors = rig.config(json!({"enable": true, "script": lines}));
    assert!(errors.is_empty(), "{errors:?}");
    let hooks = rig.mitm.script_hooks();
    (server, rig, hooks)
}

fn request() -> RuleScriptRequest {
    RuleScriptRequest {
        hostname: Some("a.test".into()),
        dest_port: 443,
        protocol: "HTTPS",
        source_ip: Some("10.0.0.2".parse().unwrap()),
        dns_result: Some(vec!["203.0.113.9".parse().unwrap()]),
        ..RuleScriptRequest::default()
    }
}

#[tokio::test]
async fn a_rule_script_reads_the_connection_and_a_failure_does_not_match() {
    let (_server, _rig, hooks) = scripts(
        &[
            (
                "match.js",
                "$done({matched: $request.hostname === 'a.test' && $request.destPort === 443 \
                 && $request.sourceIP === '10.0.0.2' && $request.url === null \
                 && $request.dnsResult.v4Addresses[0] === '203.0.113.9'})",
            ),
            ("throws.js", "throw new Error('no')"),
            ("silent.js", "setTimeout(() => {}, 60000)"),
            ("vague.js", "$done({matched: 'yes'})"),
        ],
        &[
            "match = type=rule,script-path=match.js",
            "throws = type=rule,script-path=throws.js",
            "silent = type=rule,script-path=silent.js,timeout=1",
            "vague = type=rule,script-path=vague.js",
        ],
    )
    .await;
    assert!(hooks.rule("match", &request()).await);
    let other = RuleScriptRequest {
        dest_port: 80,
        ..request()
    };
    assert!(!hooks.rule("match", &other).await);
    assert!(!hooks.rule("throws", &request()).await);
    assert!(!hooks.rule("vague", &request()).await);
    assert!(!hooks.rule("missing", &request()).await);
    let started = Instant::now();
    assert!(!hooks.rule("silent", &request()).await);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the script's own timeout ends the run"
    );
}

#[tokio::test]
async fn a_dns_script_answers_or_leaves_the_domain_to_the_resolver() {
    let (_server, rig, hooks) = scripts(
        &[(
            "dns.js",
            "const answers = {\
               'one.test': {address: '203.0.113.1', ttl: 60},\
               'many.test': {addresses: ['203.0.113.2', '2001:db8::2']},\
               'server.test': {server: '192.0.2.53'},\
               'bad.test': {address: 'nowhere'},\
             };\
             $done(answers[$domain] || {})",
        )],
        &["dns = type=dns,script-path=dns.js"],
    )
    .await;
    let ip = |text: &str| text.parse::<IpAddr>().unwrap();
    assert_eq!(
        hooks.dns("dns", "one.test").await,
        DnsScriptAnswer::Addresses {
            ips: vec![ip("203.0.113.1")],
            ttl: Some(Duration::from_secs(60))
        }
    );
    assert_eq!(
        hooks.dns("dns", "many.test").await,
        DnsScriptAnswer::Addresses {
            ips: vec![ip("203.0.113.2"), ip("2001:db8::2")],
            ttl: None
        }
    );
    assert_eq!(
        hooks.dns("dns", "server.test").await,
        DnsScriptAnswer::Servers(vec![SocketAddr::new(ip("192.0.2.53"), 53)])
    );
    assert_eq!(hooks.dns("dns", "bad.test").await, DnsScriptAnswer::Resolve);
    assert_eq!(
        hooks.dns("dns", "other.test").await,
        DnsScriptAnswer::Resolve
    );

    rig.config(json!({"enable": false}));
    assert_eq!(hooks.dns("dns", "one.test").await, DnsScriptAnswer::Resolve);
}
