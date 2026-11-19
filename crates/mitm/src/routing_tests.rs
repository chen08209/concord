use std::sync::atomic::Ordering;

use concord_common::sync::lock;
use http::Request;
use http_body_util::Full;
use serde_json::json;

use crate::testing::{Client, Handler, Reply, Rig, flow, rig_for, start_server};

fn named(name: &'static str) -> Handler {
    std::sync::Arc::new(move |seen| Reply::ok(&format!("{name}|{}", seen.path)))
}

fn listed(rig: &Rig, host: &str) {
    let errors = rig.config(json!({
        "enable": true,
        "hostname": [host],
        "skip-server-cert-verify": true,
        "h2": true,
    }));
    assert!(errors.is_empty(), "{errors:?}");
}

fn routed(rig: &Rig) -> Vec<Option<String>> {
    lock(&rig.dialer.routed).clone()
}

#[tokio::test]
async fn a_direct_exception_ahead_of_a_reject_is_reached_once_the_request_is_read() {
    let server = start_server(true, &["http/1.1"], named("origin")).await;
    let rig = rig_for(&server, None);
    listed(&rig, "a.test");
    rig.mitm.set_capture(true);
    rig.dialer.reject("a.test");
    rig.dialer
        .route_url("https://a.test/ok", "DIRECT", Some(server.addr));
    let mut client = Client::tls(&rig, "a.test", 443, &["http/1.1"])
        .await
        .expect("a host rejected only until its requests are read is still decrypted");
    let answer = client.get("/ok?x=1").await;
    assert_eq!(answer.text(), "origin|/ok?x=1");
    let answer = client.get("/ad").await;
    assert_eq!((answer.status.as_u16(), answer.body.len()), (404, 0));
    assert_eq!(server.requests().len(), 1);
    assert_eq!(
        routed(&rig),
        [
            None,
            Some("https://a.test/ok?x=1".to_string()),
            Some("https://a.test/ad".to_string()),
        ]
    );
    assert_eq!(
        lock(&rig.dialer.closed).last().cloned(),
        Some(("a.test".to_string(), vec!["REJECT".to_string()]))
    );
    assert_eq!(
        lock(&rig.dialer.closed_rules)
            .last()
            .cloned()
            .flatten()
            .as_deref(),
        Some("DOMAIN,a.test")
    );
}

async fn each_request_leaves_through_its_own_route(alpn: &'static str) {
    let a = start_server(true, &[alpn], named("a")).await;
    let b = start_server(true, &[alpn], named("b")).await;
    let rig = rig_for(&a, None);
    listed(&rig, "b.test");
    rig.dialer.route_url("/x", "A", Some(a.addr));
    rig.dialer.route_url("/y", "B", Some(b.addr));
    let mut client = Client::tls(&rig, "b.test", 443, &[alpn]).await.unwrap();
    for (path, from) in [("/x", "a"), ("/y", "b"), ("/x", "a"), ("/y", "b")] {
        assert_eq!(
            client.get(path).await.text(),
            format!("{from}|{path}"),
            "{alpn}"
        );
    }
    let paths = |server: &crate::testing::TestServer| -> Vec<String> {
        server
            .requests()
            .into_iter()
            .map(|seen| seen.path)
            .collect()
    };
    assert_eq!(paths(&a), ["/x", "/x"], "{alpn}");
    assert_eq!(paths(&b), ["/y", "/y"], "{alpn}");
    assert_eq!(
        a.connections.load(Ordering::SeqCst),
        2,
        "the dial made before the handshake is DIRECT's, so A has one of its own: {alpn}"
    );
    assert_eq!(b.connections.load(Ordering::SeqCst), 1, "{alpn}");
}

#[tokio::test]
async fn each_request_leaves_through_its_own_route_over_http1() {
    each_request_leaves_through_its_own_route("http/1.1").await;
}

#[tokio::test]
async fn each_request_leaves_through_its_own_route_over_http2() {
    each_request_leaves_through_its_own_route("h2").await;
}

#[tokio::test]
async fn a_request_routed_to_the_pre_dialed_chain_uses_that_connection() {
    let server = start_server(true, &["http/1.1"], named("origin")).await;
    let rig = rig_for(&server, None);
    listed(&rig, "c.test");
    rig.dialer.route_url("/elsewhere", "B", Some(server.addr));
    let mut client = Client::tls(&rig, "c.test", 443, &["http/1.1"])
        .await
        .unwrap();
    assert_eq!(client.get("/").await.text(), "origin|/");
    assert_eq!(client.get("/again").await.text(), "origin|/again");
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    assert_eq!(routed(&rig).len(), 3);
}

#[tokio::test]
async fn a_request_rejected_by_a_variant_gets_its_reply() {
    let server = start_server(true, &["http/1.1"], named("origin")).await;
    let rig = rig_for(&server, None);
    listed(&rig, "ads.test");
    rig.dialer.route_url("/gif", "REJECT-TINYGIF", None);
    rig.dialer.route_url("/dict", "REJECT-DICT", None);
    rig.dialer.route_url("/array", "REJECT-ARRAY", None);
    rig.dialer.route_url("/200", "REJECT-200", None);
    rig.dialer.route_url("/plain", "REJECT", None);
    rig.dialer.route_url("/drop", "REJECT-DROP", None);
    let mut client = Client::tls(&rig, "ads.test", 443, &["http/1.1"])
        .await
        .unwrap();
    let answer = client.get("/gif").await;
    assert_eq!(
        (
            answer.status.as_u16(),
            answer.header("content-type").as_str()
        ),
        (200, "image/gif")
    );
    assert_eq!(client.get("/dict").await.text(), "{}");
    assert_eq!(client.get("/array").await.text(), "[]");
    let answer = client.get("/200").await;
    assert_eq!((answer.status.as_u16(), answer.body.len()), (200, 0));
    assert_eq!(client.get("/plain").await.status.as_u16(), 404);
    assert!(server.requests().is_empty());
    let request = Request::get("/drop")
        .header("host", "ads.test")
        .body(Full::default())
        .unwrap();
    assert!(
        client.send(request).await.is_err(),
        "REJECT-DROP answers nothing"
    );
}

#[tokio::test]
async fn plain_http_is_read_while_the_rules_read_requests() {
    let server = start_server(false, &[], named("origin")).await;
    let other = start_server(false, &[], named("other")).await;
    let rig = rig_for(&server, None);
    rig.config(json!({"enable": true, "hostname": ["listed.test"]}));
    let engine = rig.mitm.engine().unwrap();
    assert!(!engine.match_tcp(&flow("anywhere.test", 80)));
    rig.dialer.route_url("/to-other", "B", Some(other.addr));
    assert!(engine.match_tcp(&flow("anywhere.test", 80)));
    assert!(!engine.match_tcp(&flow("anywhere.test", 8080)));
    let mut client = Client::plain(&rig, "anywhere.test", 80).await;
    assert_eq!(client.get("/to-other").await.text(), "other|/to-other");
    assert_eq!(client.get("/home").await.text(), "origin|/home");
}

#[tokio::test]
async fn without_http_rules_a_session_routes_once() {
    let server = start_server(true, &["http/1.1"], named("origin")).await;
    let rig = rig_for(&server, None);
    listed(&rig, "d.test");
    let mut client = Client::tls(&rig, "d.test", 443, &["http/1.1"])
        .await
        .unwrap();
    client.get("/1").await;
    client.get("/2").await;
    assert_eq!(routed(&rig), [None]);
}

#[tokio::test]
async fn each_captured_request_names_its_rule_and_chain() {
    let a = start_server(true, &["http/1.1"], named("a")).await;
    let rig = rig_for(&a, None);
    let errors = rig.config(json!({
        "enable": true,
        "hostname": ["e.test"],
        "skip-server-cert-verify": true,
        "url-rewrite": [r"^https://e\.test/ad _ reject-dict"],
    }));
    assert!(errors.is_empty(), "{errors:?}");
    rig.mitm.set_capture(true);
    rig.dialer.route_url("/x", "A", Some(a.addr));
    rig.dialer.route_url("/gif", "REJECT-TINYGIF", None);
    let mut client = Client::tls(&rig, "e.test", 443, &["http/1.1"])
        .await
        .unwrap();
    client.get("/x").await;
    client.get("/gif").await;
    client.get("/ad").await;
    let routes: Vec<_> = (1..=3)
        .map(|id| {
            let route = rig.mitm.exchange(id).unwrap().route.unwrap();
            (route.rule, route.rule_payload, route.chains)
        })
        .collect();
    let row = |rule: &str, payload: &str, chain: &str| {
        (
            rule.to_string(),
            payload.to_string(),
            vec![chain.to_string()],
        )
    };
    assert_eq!(
        routes,
        [
            row("URLRegex", "/x", "A"),
            row("URLRegex", "/gif", "REJECT-TINYGIF"),
            row("URL-REWRITE", r"^https://e\.test/ad", "REJECT"),
        ]
    );
}
