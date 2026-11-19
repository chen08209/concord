mod common;

use common::*;
use concord_common::sync::lock;
use concord_common::{Address, InboundKind};
use concord_inbound::{ListenSpec, ListenerKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn http_only() -> ListenSpec {
    ListenSpec {
        http_port: Some(0),
        ..Default::default()
    }
}

async fn read_response(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let head = String::from_utf8(read_until(stream, b"\r\n\r\n").await).unwrap();
    let length = head
        .to_ascii_lowercase()
        .lines()
        .find_map(|line| line.strip_prefix("content-length: ").map(str::to_owned))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);
    let body = read_exact(stream, length).await;
    (head, body)
}

fn request(target: &str, host: &str, extra: &str) -> String {
    format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n{extra}\r\n")
}

const KEEP: &str = "Proxy-Connection: keep-alive\r\n";

#[tokio::test]
async fn connect_replies_200_and_hands_over_the_stream_with_early_bytes() {
    let run = start(http_only(), Fake::echo()).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    stream
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nearly")
        .await
        .unwrap();
    let head = read_until(&mut stream, b"\r\n\r\n").await;
    assert_eq!(head, b"HTTP/1.1 200 Connection established\r\n\r\n");
    assert_eq!(read_exact(&mut stream, 5).await, b"early");
    stream.write_all(b"later").await.unwrap();
    assert_eq!(read_exact(&mut stream, 5).await, b"later");

    let meta = run.fake.flow(0);
    assert_eq!(meta.inbound.kind, InboundKind::Https);
    assert_eq!(&*meta.inbound.name, "DEFAULT-HTTP");
    assert_eq!(meta.dst, Address::new("example.com", 443));
    assert_eq!(meta.src, stream.local_addr().unwrap());
    assert_eq!(meta.inbound.user_agent, None);
}

#[tokio::test]
async fn connect_follows_the_request_version_and_defaults_to_port_80() {
    let run = start(http_only(), Fake::echo()).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    stream
        .write_all(b"CONNECT bare.test HTTP/1.0\r\n\r\n")
        .await
        .unwrap();
    let head = read_until(&mut stream, b"\r\n\r\n").await;
    assert_eq!(head, b"HTTP/1.0 200 Connection established\r\n\r\n");
    wait_for(|| run.fake.flow_count() == 1).await;
    assert_eq!(run.fake.flow(0).dst, Address::new("bare.test", 80));
}

#[tokio::test]
async fn connect_keeps_its_user_agent_for_the_rules() {
    let run = start(http_only(), Fake::echo()).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    stream
        .write_all(b"CONNECT a.test:443 HTTP/1.1\r\nUser-Agent: Foo/1.0 (x)\r\n\r\n")
        .await
        .unwrap();
    read_until(&mut stream, b"\r\n\r\n").await;
    wait_for(|| run.fake.flow_count() == 1).await;
    assert_eq!(
        run.fake.flow(0).inbound.user_agent.as_deref(),
        Some("Foo/1.0 (x)")
    );
}

#[tokio::test]
async fn the_handshake_timeout_spares_an_idle_kept_alive_connection() {
    let (fake, _) = origin(|_, _| ok("x"));
    let run = start(http_only(), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    let get = request("http://origin.test/", "origin.test", KEEP);
    stream.write_all(get.as_bytes()).await.unwrap();
    assert_eq!(read_response(&mut stream).await.1, b"x");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    tokio::time::pause();
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    // A paused clock jumps to the read timeout whenever the runtime waits on loopback I/O.
    tokio::time::resume();
    stream.write_all(get.as_bytes()).await.unwrap();
    assert_eq!(read_response(&mut stream).await.1, b"x");
}

#[tokio::test]
async fn a_plain_request_is_rewritten_and_the_response_relayed() {
    let (fake, seen) = origin(|_, _| ok("hello"));
    let run = start(http_only(), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    let extra = format!(
        "{KEEP}Proxy-Authorization: Basic eDp5\r\nConnection: X-Secret\r\nX-Secret: 1\r\nAccept: */*\r\n"
    );
    stream
        .write_all(request("http://origin.test/a?b=1", "ignored", &extra).as_bytes())
        .await
        .unwrap();
    let (head, body) = read_response(&mut stream).await;
    assert_eq!(body, b"hello");
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    assert!(head.contains("Proxy-Connection: keep-alive\r\n"), "{head}");
    assert!(head.contains("Connection: keep-alive\r\n"));
    assert!(head.contains("Keep-Alive: timeout=4\r\n"));

    let upstream = lock(&seen)[0].clone();
    assert!(
        upstream.starts_with("GET /a?b=1 HTTP/1.1\r\nHost: origin.test\r\n"),
        "{upstream}"
    );
    assert!(upstream.contains("Accept: */*\r\n"));
    for gone in ["Proxy-", "X-Secret", "Connection"] {
        assert!(!upstream.contains(gone), "{gone} leaked: {upstream}");
    }
    let meta = run.fake.flow(0);
    assert_eq!(meta.inbound.kind, InboundKind::Http);
    assert_eq!(meta.dst, Address::new("origin.test", 80));
}

#[tokio::test]
async fn keep_alive_reuses_a_flow_per_host_and_dials_each_new_host() {
    let (fake, seen) = origin(|head, _| {
        ok(if head.contains("host: b.test") {
            "b"
        } else {
            "a"
        })
    });
    let run = start(http_only(), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    for (url, host, want) in [
        ("http://a.test/1", "a.test", "a"),
        ("http://a.test/2", "a.test", "a"),
        ("http://b.test/3", "b.test", "b"),
        ("http://a.test/4", "a.test", "a"),
    ] {
        stream
            .write_all(request(url, host, KEEP).as_bytes())
            .await
            .unwrap();
        let (_, body) = read_response(&mut stream).await;
        assert_eq!(body, want.as_bytes());
    }
    assert_eq!(lock(&seen).len(), 4);
    assert_eq!(run.fake.flow_count(), 2);
    assert_eq!(run.fake.flow(0).dst, Address::new("a.test", 80));
    assert_eq!(run.fake.flow(1).dst, Address::new("b.test", 80));
}

#[tokio::test]
async fn without_proxy_connection_keep_alive_the_client_connection_closes() {
    let (fake, _) = origin(|_, _| ok("x"));
    let run = start(http_only(), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    stream
        .write_all(request("http://a.test/", "a.test", "").as_bytes())
        .await
        .unwrap();
    let mut all = String::from_utf8(read_to_close(&mut stream).await).unwrap();
    assert!(all.contains("Connection: close\r\n"), "{all}");
    assert!(all.ends_with("\r\n\r\nx"));
    all.clear();
}

#[tokio::test]
async fn port_80_is_dropped_from_the_host_header_and_other_ports_stay() {
    let (fake, seen) = origin(|_, _| ok("x"));
    let run = start(http_only(), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    for url in ["http://p.test:80/", "http://p.test:8080/"] {
        stream
            .write_all(request(url, "p.test", KEEP).as_bytes())
            .await
            .unwrap();
        read_response(&mut stream).await;
    }
    let seen = lock(&seen).clone();
    assert!(seen[0].contains("Host: p.test\r\n"), "{}", seen[0]);
    assert!(seen[1].contains("Host: p.test:8080\r\n"), "{}", seen[1]);
    assert_eq!(run.fake.flow(0).dst, Address::new("p.test", 80));
    assert_eq!(run.fake.flow(1).dst, Address::new("p.test", 8080));
}

#[tokio::test]
async fn a_request_for_the_proxys_own_origin_form_path_is_a_400() {
    let run = start(http_only(), Fake::echo()).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    stream
        .write_all(request("/", "127.0.0.1:7890", KEEP).as_bytes())
        .await
        .unwrap();
    let (head, body) = read_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{head}");
    assert!(body.is_empty());
    assert_eq!(run.fake.flow_count(), 0);
}

#[tokio::test]
async fn https_urls_are_not_proxied_in_clear() {
    let run = start(http_only(), Fake::echo()).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    stream
        .write_all(request("https://a.test/", "a.test", KEEP).as_bytes())
        .await
        .unwrap();
    let (head, _) = read_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{head}");
}

#[tokio::test]
async fn a_failed_dial_is_a_502() {
    let fake = Fake::new(|_, stream| drop(stream));
    let run = start(http_only(), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    stream
        .write_all(request("http://down.test/", "down.test", KEEP).as_bytes())
        .await
        .unwrap();
    let (head, _) = read_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{head}");
    stream
        .write_all(request("http://down.test/", "down.test", KEEP).as_bytes())
        .await
        .unwrap();
    let (head, _) = read_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 502 Bad Gateway\r\n"), "{head}");
}

fn with_auth(mut spec: ListenSpec) -> ListenSpec {
    spec.authentication = vec![("alice".into(), "secret".into())];
    spec
}

#[tokio::test]
async fn proxy_authorization_gates_requests_with_407_and_403() {
    let (fake, _) = origin(|_, _| ok("fine"));
    let run = start(with_auth(http_only()), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;

    stream
        .write_all(request("http://a.test/", "a.test", KEEP).as_bytes())
        .await
        .unwrap();
    let (head, _) = read_response(&mut stream).await;
    assert!(
        head.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"),
        "{head}"
    );
    assert!(head.contains("Proxy-Authenticate: Basic\r\n"));
    assert!(head.contains("Content-Length: 0\r\n"));

    let bad = format!("{KEEP}Proxy-Authorization: Basic YWxpY2U6bm9wZQ==\r\n");
    stream
        .write_all(request("http://a.test/", "a.test", &bad).as_bytes())
        .await
        .unwrap();
    let (head, _) = read_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{head}");
    assert_eq!(run.fake.flow_count(), 0);

    let good = format!("{KEEP}Proxy-Authorization: bAsIc YWxpY2U6c2VjcmV0\r\n");
    stream
        .write_all(request("http://a.test/", "a.test", &good).as_bytes())
        .await
        .unwrap();
    let (_, body) = read_response(&mut stream).await;
    assert_eq!(body, b"fine");
    assert_eq!(run.fake.flow(0).inbound.user.as_deref(), Some("alice"));
}

#[tokio::test]
async fn connect_requires_credentials_and_records_the_user() {
    let run = start(with_auth(http_only()), Fake::echo()).await;
    let addr = run.addr(ListenerKind::Http).await;
    let mut denied = connect(addr).await;
    denied
        .write_all(b"CONNECT a.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert!(
        read_to_close(&mut denied)
            .await
            .starts_with(b"HTTP/1.1 407")
    );
    assert_eq!(run.fake.flow_count(), 0);

    let mut stream = connect(addr).await;
    stream
        .write_all(
            b"CONNECT a.test:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n",
        )
        .await
        .unwrap();
    read_until(&mut stream, b"\r\n\r\n").await;
    stream.write_all(b"z").await.unwrap();
    assert_eq!(read_exact(&mut stream, 1).await, b"z");
    assert_eq!(run.fake.flow(0).inbound.user.as_deref(), Some("alice"));
}

#[tokio::test]
async fn a_connection_stays_trusted_after_one_good_credential() {
    let (fake, _) = origin(|_, _| ok("ok"));
    let run = start(with_auth(http_only()), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    let good = format!("{KEEP}Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n");
    stream
        .write_all(request("http://a.test/", "a.test", &good).as_bytes())
        .await
        .unwrap();
    read_response(&mut stream).await;
    stream
        .write_all(request("http://a.test/", "a.test", KEEP).as_bytes())
        .await
        .unwrap();
    let (head, body) = read_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"ok");
}

fn with_host(spec: ListenSpec) -> ListenSpec {
    ListenSpec {
        host_credential: Some(("flclash".into(), "s3cret".into())),
        ..spec
    }
}

const HOST_AUTH: &str = "Proxy-Authorization: Basic ZmxjbGFzaDpzM2NyZXQ=\r\n";
const WRONG_HOST_AUTH: &str = "Proxy-Authorization: Basic ZmxjbGFzaDpndWVzcw==\r\n";

#[tokio::test]
async fn the_host_credential_passes_authentication_and_never_reaches_the_origin() {
    for spec in [with_host(http_only()), with_host(with_auth(http_only()))] {
        let (fake, seen) = origin(|_, _| ok("fine"));
        let run = start(spec, fake).await;
        let addr = run.addr(ListenerKind::Http).await;
        let mut stream = connect(addr).await;
        let extra = format!("{KEEP}{HOST_AUTH}");
        stream
            .write_all(request("http://a.test/", "a.test", &extra).as_bytes())
            .await
            .unwrap();
        assert_eq!(read_response(&mut stream).await.1, b"fine");
        let upstream = lock(&seen)[0].clone();
        for gone in ["Proxy-", "ZmxjbGFzaDpzM2NyZXQ="] {
            assert!(!upstream.contains(gone), "{gone} leaked: {upstream}");
        }
        let meta = run.fake.flow(0);
        assert!(meta.inbound.host);
        assert_eq!(meta.inbound.user, None);

        let mut tunnel = connect(addr).await;
        tunnel
            .write_all(format!("CONNECT b.test:443 HTTP/1.1\r\n{HOST_AUTH}\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_until(&mut tunnel, b"\r\n\r\n").await;
        assert!(head.starts_with(b"HTTP/1.1 200"));
        wait_for(|| run.fake.flow_count() == 2).await;
        let meta = run.fake.flow(1);
        assert!(meta.inbound.host);
        assert_eq!(meta.inbound.user, None);
    }
}

#[tokio::test]
async fn a_wrong_host_credential_is_an_ordinary_credential() {
    let (fake, _) = origin(|_, _| ok("fine"));
    let run = start(with_host(http_only()), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    let extra = format!("{KEEP}{WRONG_HOST_AUTH}");
    stream
        .write_all(request("http://a.test/", "a.test", &extra).as_bytes())
        .await
        .unwrap();
    assert_eq!(read_response(&mut stream).await.1, b"fine");
    let meta = run.fake.flow(0);
    assert!(!meta.inbound.host);
    assert_eq!(meta.inbound.user.as_deref(), Some("flclash"));

    let (fake, _) = origin(|_, _| ok("fine"));
    let run = start(with_host(with_auth(http_only())), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    stream
        .write_all(request("http://a.test/", "a.test", &extra).as_bytes())
        .await
        .unwrap();
    let (head, _) = read_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{head}");
    assert_eq!(run.fake.flow_count(), 0);
}

#[tokio::test]
async fn request_bodies_pass_with_length_and_with_chunked_framing() {
    let (fake, seen) = origin(|_, body| ok(&String::from_utf8_lossy(body)));
    let run = start(http_only(), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    stream
        .write_all(
            format!("POST http://a.test/up HTTP/1.1\r\nHost: a.test\r\n{KEEP}Content-Length: 5\r\n\r\nhello")
                .as_bytes(),
        )
        .await
        .unwrap();
    let (_, body) = read_response(&mut stream).await;
    assert_eq!(body, b"hello");

    stream
        .write_all(
            format!(
                "POST http://a.test/up HTTP/1.1\r\nHost: a.test\r\n{KEEP}Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let (_, body) = read_response(&mut stream).await;
    assert_eq!(body, b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
    let second = lock(&seen)[1].clone();
    assert!(
        second.contains("Transfer-Encoding: chunked\r\n"),
        "{second}"
    );
    assert_eq!(run.fake.flow_count(), 1);
}

#[tokio::test]
async fn chunked_responses_keep_their_framing_and_the_connection_is_reusable() {
    let (fake, _) = origin(|_, _| {
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
            .to_vec()
    });
    let run = start(http_only(), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    for _ in 0..2 {
        stream
            .write_all(request("http://a.test/", "a.test", KEEP).as_bytes())
            .await
            .unwrap();
        let head = read_until(&mut stream, b"\r\n\r\n").await;
        let head = String::from_utf8(head).unwrap();
        assert!(head.contains("Transfer-Encoding: chunked\r\n"), "{head}");
        assert!(head.contains("Connection: keep-alive\r\n"));
        let body = read_until(&mut stream, b"0\r\n\r\n").await;
        assert_eq!(body, b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n");
    }
    assert_eq!(run.fake.flow_count(), 1);
}

#[tokio::test]
async fn a_response_that_runs_to_eof_closes_the_client_connection() {
    let fake = Fake::new(|_, stream| {
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(stream);
            let mut buf = [0u8; 1024];
            let _ = rd.read(&mut buf).await;
            let _ = wr.write_all(b"HTTP/1.1 200 OK\r\n\r\nstreamed body").await;
        });
    });
    let run = start(http_only(), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    stream
        .write_all(request("http://a.test/", "a.test", KEEP).as_bytes())
        .await
        .unwrap();
    let all = String::from_utf8(read_to_close(&mut stream).await).unwrap();
    assert!(all.contains("Connection: close\r\n"), "{all}");
    assert!(all.ends_with("\r\n\r\nstreamed body"), "{all}");
}

#[tokio::test]
async fn head_responses_carry_a_length_but_no_body_and_keep_the_connection() {
    let (fake, _) = origin(|head, _| {
        if head.starts_with("head ") {
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".to_vec()
        } else {
            ok("next")
        }
    });
    let run = start(http_only(), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    stream
        .write_all(format!("HEAD http://a.test/ HTTP/1.1\r\nHost: a.test\r\n{KEEP}\r\n").as_bytes())
        .await
        .unwrap();
    let head = String::from_utf8(read_until(&mut stream, b"\r\n\r\n").await).unwrap();
    assert!(head.contains("Content-Length: 5\r\n"), "{head}");
    stream
        .write_all(request("http://a.test/", "a.test", KEEP).as_bytes())
        .await
        .unwrap();
    let (_, body) = read_response(&mut stream).await;
    assert_eq!(body, b"next");
}

#[tokio::test]
async fn an_idle_flow_the_origin_closed_is_redialed() {
    let fake = Fake::new(|_, stream| {
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(stream);
            let mut buf = [0u8; 1024];
            let _ = rd.read(&mut buf).await;
            let _ = wr.write_all(&ok("once")).await;
        });
    });
    let run = start(http_only(), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    for _ in 0..2 {
        stream
            .write_all(request("http://a.test/", "a.test", KEEP).as_bytes())
            .await
            .unwrap();
        let (head, body) = read_response(&mut stream).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(body, b"once");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(run.fake.flow_count(), 2);
}

#[tokio::test]
async fn expect_continue_lets_the_origin_ask_for_the_body_first() {
    let fake = Fake::new(|_, stream| {
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(stream);
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = rd.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            wr.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .unwrap();
            let mut body = [0u8; 4];
            rd.read_exact(&mut body).await.unwrap();
            wr.write_all(&ok(&String::from_utf8_lossy(&body)))
                .await
                .unwrap();
        });
    });
    let run = start(http_only(), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    stream
        .write_all(
            format!("POST http://a.test/ HTTP/1.1\r\nHost: a.test\r\n{KEEP}Expect: 100-continue\r\nContent-Length: 4\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let interim = read_until(&mut stream, b"\r\n\r\n").await;
    assert!(interim.starts_with(b"HTTP/1.1 100 Continue"));
    stream.write_all(b"body").await.unwrap();
    let (_, body) = read_response(&mut stream).await;
    assert_eq!(body, b"body");
}

#[tokio::test]
async fn upgrade_requests_are_forwarded_and_the_connection_switches_protocols() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let record = seen.clone();
    let fake = Fake::new(move |_, stream| {
        let record = record.clone();
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(stream);
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = rd.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            *lock(&record) = String::from_utf8_lossy(&buf).into_owned();
            wr.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nProxy-Connection: x\r\n\r\nwelcome",
            )
            .await
            .unwrap();
            let _ = tokio::io::copy(&mut rd, &mut wr).await;
        });
    });
    let run = start(http_only(), fake).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    stream
        .write_all(
            b"GET http://ws.test/chat HTTP/1.1\r\nHost: ws.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nProxy-Connection: keep-alive\r\n\r\nearly-frame",
        )
        .await
        .unwrap();
    let head = String::from_utf8(read_until(&mut stream, b"\r\n\r\n").await).unwrap();
    assert!(
        head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "{head}"
    );
    assert!(!head.contains("Proxy-Connection"), "{head}");
    assert_eq!(read_exact(&mut stream, 7).await, b"welcome");
    assert_eq!(read_exact(&mut stream, 11).await, b"early-frame");
    stream.write_all(b"more").await.unwrap();
    assert_eq!(read_exact(&mut stream, 4).await, b"more");

    let upstream = lock(&seen).clone();
    assert!(
        upstream.starts_with("GET /chat HTTP/1.1\r\nHost: ws.test\r\n"),
        "{upstream}"
    );
    assert!(upstream.contains("Upgrade: websocket\r\n"));
    assert!(upstream.contains("Connection: Upgrade\r\n"));
    assert!(!upstream.contains("Proxy-"));
    assert_eq!(run.fake.flow(0).dst, Address::new("ws.test", 80));
}

#[tokio::test]
async fn garbage_closes_the_connection_without_touching_the_handler() {
    let run = start(http_only(), Fake::echo()).await;
    let mut stream = connect(run.addr(ListenerKind::Http).await).await;
    stream
        .write_all(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\r\n\r\n")
        .await
        .unwrap();
    assert!(read_to_close(&mut stream).await.is_empty());
    assert_eq!(run.fake.flow_count(), 0);
}
