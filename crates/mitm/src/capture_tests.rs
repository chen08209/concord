use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use concord_common::sync::lock;
use http_body_util::{BodyExt, StreamBody};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use concord_config::mitm::MitmDef;

use crate::capture::{Action, ExchangeSummary};
use crate::limits::PRESSURE_NO_BODIES;
use crate::script::testkit::{FakeRuntime, sync_program};
use crate::script::{ScriptProgram, ScriptResponse, ScriptResult, ScriptRuntime};
use crate::testing::{
    Client, Handler, Reply, Rig, Service, TestServer, Wire, flow, offer_on, rig_for, start_server,
    start_service,
};

fn echo() -> Handler {
    Arc::new(|seen| {
        let added = seen
            .headers
            .get("x-added")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        Reply::ok(&format!(
            "{}|{}|{added}|{}",
            seen.host,
            seen.path,
            String::from_utf8_lossy(&seen.body)
        ))
        .with("X-Upstream", "yes")
    })
}

fn capture(rig: &Rig, section: serde_json::Value) {
    let errors = rig.config(section);
    assert!(errors.is_empty(), "{errors:?}");
    rig.mitm.set_capture(true);
}

/// Waits for the handlers to finish what their clients already read.
async fn settled(rig: &Rig, connection: &str, count: usize) -> Vec<ExchangeSummary> {
    for _ in 0..400 {
        let list = rig.mitm.exchanges(connection);
        if list.exchanges.len() == count && list.exchanges.iter().all(|e| !e.pending) {
            return list.exchanges;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "{connection} holds {:?}, want {count} settled exchanges",
        rig.mitm.exchanges(connection).exchanges
    );
}

fn header(list: Option<&crate::script::HeaderList>, name: &str) -> String {
    list.and_then(|list| {
        list.iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .and_then(|(_, values)| values.first().cloned())
    })
    .unwrap_or_default()
}

fn action(kind: &str, phase: &str, detail: &str) -> Action {
    Action {
        kind: kind.into(),
        phase: phase.into(),
        detail: detail.into(),
        module: String::new(),
    }
}

async fn tls_rig(handler: Handler, alpn: &[&str]) -> (TestServer, Rig) {
    let server = start_server(true, alpn, handler).await;
    let rig = rig_for(&server, None);
    (server, rig)
}

#[tokio::test]
async fn exchanges_are_filed_under_the_connection_they_went_out_on() {
    let (_server, rig) = tls_rig(echo(), &["http/1.1"]).await;
    capture(
        &rig,
        json!({
            "enable": true,
            "hostname": ["example.test"],
            "skip-server-cert-verify": true,
            "url-rewrite": [
                r"^https://example\.test/ad _ reject-img",
                r"^https://example\.test/old/(.*) https://example.test/new/$1",
            ],
            "header-rewrite": [r"http-request ^https://example\.test header-add X-Added yes"],
        }),
    );
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    client.get("/ad").await;
    client.get("/old/x").await;
    let request = client.request("POST", "/echo", &[], "payload");
    client.send(request).await.unwrap();

    assert_eq!(rig.dialer.dialed().len(), 1);
    assert_eq!(
        rig.dialer.marks(),
        vec![Some(concord_common::intercept::ConnMark::Decrypted)]
    );
    let exchanges = settled(&rig, "conn-1", 2).await;
    let rewritten = rig.mitm.exchange(exchanges[0].id).unwrap();
    assert_eq!(
        (
            rewritten.summary.url.as_str(),
            rewritten.original_url.as_str(),
            rewritten.summary.status,
            rewritten.proto.as_str(),
            rewritten.connection.as_str()
        ),
        (
            "https://example.test/new/x",
            "https://example.test/old/x",
            200,
            "HTTP/1.1",
            "conn-1"
        )
    );
    assert_eq!(header(Some(&rewritten.request_header), "x-added"), "yes");
    assert_eq!(
        header(Some(&rewritten.request_header), "host"),
        "example.test"
    );
    assert_eq!(
        header(rewritten.response_header.as_ref(), "x-upstream"),
        "yes"
    );
    assert!(
        rewritten
            .actions
            .contains(&action("url-rewrite", "", "header"))
            && rewritten
                .actions
                .contains(&action("header-rewrite", "request", "")),
        "{:?}",
        rewritten.actions
    );
    let posted = &exchanges[1];
    assert_eq!(
        (
            posted.method.as_str(),
            posted.request_size,
            posted.response_size
        ),
        (
            "POST",
            "payload".len() as i64,
            "example.test|/echo|yes|payload".len() as i64
        )
    );

    let rejected = rig.mitm.exchange(exchanges[0].id - 1).unwrap();
    assert!(
        rejected.connection.starts_with("closed-"),
        "{}",
        rejected.connection
    );
    assert_eq!(rejected.summary.status, 200);
    assert_eq!(
        header(rejected.response_header.as_ref(), "content-type"),
        "image/gif"
    );
    assert!(
        rejected
            .actions
            .contains(&action("url-rewrite", "", "reject-img"))
    );
}

#[tokio::test]
async fn a_request_answered_in_place_is_listed_as_a_connection() {
    let server = start_server(true, &["http/1.1"], echo()).await;
    let mut runtime = FakeRuntime::default();
    let answer: Arc<dyn ScriptProgram> = sync_program(|_| {
        Ok(ScriptResult {
            response: Some(ScriptResponse {
                status: 203,
                header: Default::default(),
                body: None,
                trailers: None,
            }),
            ..ScriptResult::default()
        })
    });
    let abort: Arc<dyn ScriptProgram> = sync_program(|_| {
        Ok(ScriptResult {
            abort: true,
            ..ScriptResult::default()
        })
    });
    runtime.0.insert("answer".into(), answer);
    runtime.0.insert("abort".into(), abort);
    let rig = rig_for(&server, Some(Arc::new(runtime) as Arc<dyn ScriptRuntime>));
    std::fs::create_dir_all(rig.resources()).unwrap();
    for name in ["answer", "abort"] {
        std::fs::write(rig.resources().join(format!("{name}.js")), name).unwrap();
    }
    capture(
        &rig,
        json!({
            "enable": true,
            "hostname": ["example.test"],
            "skip-server-cert-verify": true,
            "url-rewrite": [
                r"^https://example\.test/ad _ reject",
                r"^https://example\.test/moved https://example.test:8443/new 302",
            ],
            "map-local": [r#"^https://example\.test/local data-type=text data="{}""#],
            "script": [
                r"answer = type=http-request,pattern=^https://example\.test/answer,script-path=answer.js",
                r"abort = type=http-request,pattern=^https://example\.test/abort,script-path=abort.js",
            ],
        }),
    );
    let want = [
        ("/ad", "REJECT"),
        ("/moved", "REDIRECT"),
        ("/local", "MAP-LOCAL"),
        ("/answer", "SCRIPT"),
        ("/abort", "SCRIPT"),
    ];
    for (path, _) in want {
        let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
            .await
            .unwrap();
        let request = client.request("POST", path, &[], "");
        let _ = client.send(request).await;
    }

    let closed = lock(&rig.dialer.closed).clone();
    let ids = lock(&rig.dialer.closed_ids).clone();
    assert_eq!(closed.len(), want.len(), "{closed:?}");
    for ((host, chain), id) in closed.iter().zip(&ids) {
        let list = rig.mitm.exchanges(id).exchanges;
        assert_eq!(list.len(), 1, "{id} holds {list:?}");
        let path = list[0].url.trim_start_matches("https://example.test");
        let expected = want.iter().find(|(p, _)| *p == path).unwrap().1;
        assert_eq!(
            (host.as_str(), chain.as_slice()),
            ("example.test", &[expected.to_string()][..]),
            "{path}"
        );
    }

    rig.mitm.set_capture(false);
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    client.get("/ad").await;
    assert_eq!(
        lock(&rig.dialer.closed).len(),
        want.len(),
        "a request answered while capture was off joined the connections"
    );
}

#[tokio::test]
#[allow(
    clippy::disallowed_methods,
    reason = "a loopback server that closes every connection"
)]
async fn a_request_whose_server_was_not_reached_is_listed_with_its_error() {
    let (_server, rig) = tls_rig(echo(), &["http/1.1"]).await;
    let broken = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let broken_addr = broken.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = broken.accept().await {
            drop(stream);
        }
    });
    rig.dialer.reject("blocked.test");
    rig.dialer.route("broken.test", broken_addr);
    capture(
        &rig,
        json!({
            "enable": true,
            "hostname": ["example.test"],
            "skip-server-cert-verify": true,
            "url-rewrite": [
                r"^https://example\.test/blocked https://blocked.test/",
                r"^https://example\.test/broken https://broken.test/",
            ],
        }),
    );
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    for path in ["/blocked", "/broken"] {
        assert_eq!(client.get(path).await.status.as_u16(), 502, "{path}");
    }

    let closed = lock(&rig.dialer.closed).clone();
    assert_eq!(
        closed,
        vec![("blocked.test".to_string(), vec!["REJECT".to_string()])]
    );
    let blocked_id = lock(&rig.dialer.closed_ids)[0].clone();
    let broken_id = format!(
        "conn-{}",
        blocked_id
            .trim_start_matches("closed-")
            .parse::<u32>()
            .unwrap()
            + 1
    );
    assert_eq!(
        rig.dialer.dialed()[2],
        ("broken.test".to_string(), 443),
        "{broken_id} is the dial to the broken server"
    );
    for (connection, url) in [
        (blocked_id.as_str(), "https://blocked.test/"),
        (broken_id.as_str(), "https://broken.test/"),
    ] {
        let exchanges = settled(&rig, connection, 1).await;
        assert_eq!(exchanges[0].url, url);
        assert!(!exchanges[0].error.is_empty(), "{connection}: no error");
    }
}

#[tokio::test]
async fn http2_streams_are_kept_on_their_connection() {
    let handler: Handler =
        Arc::new(|seen| Reply::ok(seen.path.split("n=").nth(1).unwrap_or_default()));
    let (_server, rig) = tls_rig(handler, &["h2"]).await;
    capture(
        &rig,
        json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true, "h2": true}),
    );
    let mut client = Client::tls(&rig, "example.test", 443, &["h2"])
        .await
        .unwrap();
    client.get("/?n=warm").await;
    let Wire::H2(sender) = &client.wire else {
        panic!("not h2")
    };
    let streams = (0..10).map(|n| {
        let mut sender = sender.clone();
        let request = client.request("GET", &format!("/?n={n}"), &[], "");
        async move {
            let response = sender.send_request(request).await.unwrap();
            response.into_body().collect().await.unwrap();
        }
    });
    futures_util::future::join_all(streams).await;

    assert_eq!(rig.dialer.dialed().len(), 1);
    for summary in settled(&rig, "conn-1", 11).await {
        let exchange = rig.mitm.exchange(summary.id).unwrap();
        assert_eq!(
            (exchange.proto.as_str(), exchange.summary.status),
            ("HTTP/2.0", 200)
        );
    }
}

#[tokio::test]
async fn the_handshake_of_a_websocket_is_recorded() {
    let (_server, rig) = tls_rig(echo(), &["http/1.1"]).await;
    capture(
        &rig,
        json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true}),
    );
    let (near, _offer) = offer_on(rig.mitm.interceptor(), flow("example.test", 443));
    let name = rustls::pki_types::ServerName::try_from("example.test").unwrap();
    let connector =
        tokio_rustls::TlsConnector::from(crate::testing::client_config(&rig.root, &["http/1.1"]));
    let mut tls = connector.connect(name, near).await.unwrap();
    tls.write_all(b"GET /socket HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tls.read_u8().await.unwrap());
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"));

    let exchanges = settled(&rig, "conn-1", 1).await;
    let handshake = rig.mitm.exchange(exchanges[0].id).unwrap();
    assert_eq!(handshake.summary.status, 101);
    assert_eq!(
        header(handshake.response_header.as_ref(), "upgrade"),
        "websocket"
    );
    assert_eq!(
        header(Some(&handshake.request_header), "upgrade"),
        "websocket"
    );
}

const BODY_TEXT: &str = "the body of a test of a test of a test of a test of a test of a test of a test of a test of a test of a test of a test";

fn brotli_body() -> Vec<u8> {
    let mut brotli = vec![0xa0, 0x00, 0x10];
    brotli.extend_from_slice(b"brotli body");
    brotli.push(0x03);
    brotli
}

fn zstd_body() -> Vec<u8> {
    let mut zstd = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x09, 0x49, 0x00, 0x00];
    zstd.extend_from_slice(b"zstd body");
    zstd
}

fn encoding_handler() -> Handler {
    Arc::new(|seen| {
        let coding = seen.path.trim_start_matches('/');
        let body = match coding {
            "gzip" => {
                let mut w =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                w.write_all(BODY_TEXT.as_bytes()).unwrap();
                w.finish().unwrap()
            }
            "deflate" => {
                let mut w =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                w.write_all(BODY_TEXT.as_bytes()).unwrap();
                w.finish().unwrap()
            }
            "br" => brotli_body(),
            "zstd" => zstd_body(),
            "compress" => b"raw bytes".to_vec(),
            _ => BODY_TEXT.as_bytes().to_vec(),
        };
        let reply = Reply {
            status: 200,
            headers: Vec::new(),
            body,
        };
        if coding == "plain" {
            reply
        } else {
            reply.with("Content-Encoding", coding)
        }
    })
}

/// Sends each request on one decrypted connection and answers the ids of
/// their records by path.
async fn captured_paths(rig: &Rig, paths: &[&str]) -> Vec<(String, i64)> {
    let mut client = Client::tls(rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    for path in paths {
        client.get(path).await;
    }
    settled(rig, "conn-1", paths.len())
        .await
        .into_iter()
        .map(|e| {
            (
                e.url.trim_start_matches("https://example.test").to_string(),
                e.id,
            )
        })
        .collect()
}

fn section(limits: serde_json::Value) -> serde_json::Value {
    json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true, "limits": limits})
}

#[tokio::test]
async fn the_body_of_each_side_is_kept() {
    let (_server, rig) = tls_rig(echo(), &["http/1.1"]).await;
    capture(&rig, section(json!({})));
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    let request = client.request("POST", "/echo", &[], "payload");
    client.send(request).await.unwrap();
    let id = settled(&rig, "conn-1", 1).await[0].id;
    let request = rig.mitm.body(id, false).unwrap();
    assert_eq!(
        (request.data.as_slice(), request.truncated),
        (&b"payload"[..], false)
    );
    assert_eq!(
        rig.mitm.body(id, true).unwrap().data,
        b"example.test|/echo||payload"
    );
    assert!(rig.mitm.body(id + 1, true).is_none(), "a body of no record");
}

#[tokio::test]
async fn bodies_are_decoded_from_their_content_encoding() {
    let (_server, rig) = tls_rig(encoding_handler(), &["http/1.1"]).await;
    capture(&rig, section(json!({})));
    let ids = captured_paths(
        &rig,
        &["/plain", "/gzip", "/deflate", "/br", "/zstd", "/compress"],
    )
    .await;
    for (path, id) in ids {
        let body = rig.mitm.body(id, true).unwrap();
        let (data, encoding): (&[u8], &str) = match path.as_str() {
            "/br" => (b"brotli body", ""),
            "/zstd" => (b"zstd body", ""),
            "/compress" => (b"raw bytes", "compress"),
            _ => (BODY_TEXT.as_bytes(), ""),
        };
        assert_eq!(
            (body.data.as_slice(), body.encoding.as_str(), body.truncated),
            (data, encoding, false),
            "{path}"
        );
    }
}

#[tokio::test]
async fn a_body_is_kept_up_to_the_size_limit() {
    let (_server, rig) = tls_rig(encoding_handler(), &["http/1.1"]).await;
    capture(&rig, section(json!({"max-body-size": 16})));
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    assert_eq!(client.get("/plain").await.text(), BODY_TEXT);
    let id = settled(&rig, "conn-1", 1).await[0].id;
    let body = rig.mitm.body(id, true).unwrap();
    assert_eq!(
        (body.data.as_slice(), body.truncated),
        (&BODY_TEXT.as_bytes()[..16], true)
    );
}

#[tokio::test]
async fn bodies_are_left_out_and_let_go_under_memory_pressure() {
    let (_server, rig) = tls_rig(encoding_handler(), &["http/1.1"]).await;
    capture(&rig, section(json!({})));
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    client.get("/plain").await;
    let kept = settled(&rig, "conn-1", 1).await[0].id;
    assert_eq!(
        rig.mitm.body(kept, true).unwrap().data,
        BODY_TEXT.as_bytes()
    );
    let captures = rig.mitm.engine().unwrap().core.shared.captures.clone();
    let held = captures.tracked_bytes();

    rig.mitm.set_pressure(PRESSURE_NO_BODIES);
    let body = rig.mitm.body(kept, true).unwrap();
    assert!(body.data.is_empty() && body.truncated);
    assert!(captures.tracked_bytes() <= held - BODY_TEXT.len() as i64);

    client.get("/plain").await;
    let summaries = settled(&rig, "conn-1", 2).await;
    let body = rig.mitm.body(summaries[1].id, true).unwrap();
    assert!(body.data.is_empty() && body.truncated, "{body:?}");
}

#[tokio::test]
async fn the_memory_a_body_holds_is_counted() {
    const SIZE: usize = 100_000;
    let service: Service = Arc::new(|request| {
        Box::pin(async move {
            let chunks = (0..SIZE / 1000).map(|_| {
                Ok::<_, std::io::Error>(hyper::body::Frame::data(Bytes::from(vec![b'x'; 1000])))
            });
            match request.uri().path() {
                "/declared" => http::Response::builder()
                    .header("Content-Length", SIZE)
                    .body(BodyExt::boxed(StreamBody::new(futures_util::stream::iter(
                        chunks,
                    ))))
                    .unwrap(),
                _ => http::Response::builder()
                    .body(BodyExt::boxed(StreamBody::new(futures_util::stream::iter(
                        chunks,
                    ))))
                    .unwrap(),
            }
        })
    });
    let server = start_service(&["http/1.1"], service).await;
    let rig = rig_for(&server, None);
    capture(&rig, section(json!({})));
    let captures = rig.mitm.engine().unwrap().core.shared.captures.clone();
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    let mut before = captures.tracked_bytes();
    for (index, path) in ["/declared", "/chunked"].into_iter().enumerate() {
        assert_eq!(client.get(path).await.body.len(), SIZE);
        let id = settled(&rig, "conn-1", index + 1).await[index].id;
        assert_eq!(rig.mitm.body(id, true).unwrap().data.len(), SIZE);
        let grew = captures.tracked_bytes() - before;
        assert!(grew >= SIZE as i64, "{path} counted {grew}");
        if path == "/declared" {
            assert!(
                grew < SIZE as i64 + 4096,
                "a declared body took {grew} bytes for {SIZE}"
            );
        }
        before = captures.tracked_bytes();
    }
}

#[tokio::test]
async fn bodies_count_against_the_byte_limit() {
    let handler: Handler = Arc::new(|seen| match seen.path.as_str() {
        "/large" => Reply::ok(&"x".repeat(4096)),
        _ => Reply::ok(""),
    });
    let (_server, rig) = tls_rig(handler, &["http/1.1"]).await;
    capture(&rig, section(json!({"capture-bytes": 2048})));
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    client.get("/small").await;
    settled(&rig, "conn-1", 1).await;
    client.get("/large").await;
    crate::testing::eventually(|| rig.mitm.exchanges("conn-1").exchanges.is_empty()).await;
}

#[tokio::test]
async fn each_action_names_the_module_whose_line_it_was() {
    let (_server, rig) = tls_rig(echo(), &["http/1.1"]).await;
    let section = |value| MitmDef::read(&serde_json::from_value(value).unwrap());
    let mut def = section(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "header-rewrite": [r"http-request ^https://example\.test header-add X-Added yes"],
    }));
    let mut module = section(json!({
        "url-rewrite": [r"^https://example\.test/old/(.*) https://example.test/new/$1"],
        "header-rewrite": [
            r"http-request ^https://example\.test header-add X-Ads 1",
            r"http-request ^https://example\.test header-add X-Ads-Too 1",
        ],
    }));
    module.mark_origin(&Arc::from("Ads"));
    def.url_rewrite.append(&mut module.url_rewrite);
    def.header_rewrite.append(&mut module.header_rewrite);
    assert!(
        rig.mitm
            .apply_section(Some(def), concord_common::Tasks::default())
            .is_empty()
    );
    rig.mitm.set_capture(true);
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    client.get("/old/x").await;

    let exchanges = settled(&rig, "conn-1", 1).await;
    let actions = rig.mitm.exchange(exchanges[0].id).unwrap().actions;
    let from = |kind: &str, phase: &str, detail: &str, module: &str| Action {
        module: module.into(),
        ..action(kind, phase, detail)
    };
    assert_eq!(
        actions,
        [
            from("url-rewrite", "", "header", "Ads"),
            from("header-rewrite", "request", "", ""),
            from("header-rewrite", "request", "", "Ads"),
        ]
    );
}
