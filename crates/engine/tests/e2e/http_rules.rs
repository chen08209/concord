use super::mitm::tls_echo_server;
use super::*;

trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

/// A plain HTTP/1.1 server that keeps connections open and answers `<path>|<user-agent>`.
async fn plain_echo_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                loop {
                    let Some(head) = read_head(&mut stream).await else {
                        return;
                    };
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let body = format!("{path}|");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

async fn read_head(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.ok()?;
        head.push(byte[0]);
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

struct Setup {
    rig: Rig,
    ca: String,
    tls: u16,
    plain: u16,
    a: Arc<Mutex<Vec<String>>>,
    b: Arc<Mutex<Vec<String>>>,
}

/// Nodes A and B and a select group G over them, with the HTTPS and the plain origin listed
/// for decryption under `rules`.
async fn setup(rules: &[&str]) -> Setup {
    let tls = tls_echo_server().await.port();
    let plain = plain_echo_server().await.port();
    let (a_port, a) = upstream_socks().await;
    let (b_port, b) = upstream_socks().await;
    let rig = Rig::new();
    let info = rig.engine.mitm().generate_certificate().unwrap();
    let rules: String = rules.iter().map(|rule| format!("  - '{rule}'\n")).collect();
    let config = format!(
        "proxies:\n  - {{name: A, type: socks5, server: 127.0.0.1, port: {a_port}}}\n  \
         - {{name: B, type: socks5, server: 127.0.0.1, port: {b_port}}}\n\
         proxy-groups:\n  - {{name: G, type: select, proxies: [A, B]}}\n\
         mitm:\n  enable: true\n  hostname: ['localhost:{tls}', 'localhost:{plain}']\n  \
         ca-fingerprint: {}\n  skip-server-cert-verify: true\n\
         rules:\n{rules}",
        info["fingerprint"].as_str().unwrap()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    Setup {
        rig,
        ca: info["pem"].as_str().unwrap().to_string(),
        tls,
        plain,
        a,
        b,
    }
}

impl Setup {
    /// A client connection through the core over SOCKS to the HTTPS origin, trusting the
    /// MITM CA, or to the plain one.
    async fn open(&self, https: bool) -> (Box<dyn Io>, u16) {
        use rustls_pki_types::pem::PemObject;
        use rustls_pki_types::{CertificateDer, ServerName};

        let port = if https { self.tls } else { self.plain };
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, self.rig.mixed))
            .await
            .unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await.unwrap();
        let mut request = vec![5, 1, 0, 3, 9];
        request.extend_from_slice(b"localhost");
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.unwrap();
        if !https {
            return (Box::new(stream), port);
        }
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(self.ca.as_bytes()) {
            roots.add(certificate.unwrap()).unwrap();
        }
        let tls = tokio_rustls::TlsConnector::from(Arc::new(
            tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let secured = timeout(
            PATIENCE,
            tls.connect(ServerName::try_from("localhost").unwrap(), stream),
        )
        .await
        .expect("the handshake stalled")
        .expect("the MITM engine declined the connection");
        (Box::new(secured), port)
    }

    fn seen(&self) -> (usize, usize) {
        (lock(&self.a).len(), lock(&self.b).len())
    }
}

/// One request on a kept connection: its status, content type and body, or `None` when the
/// connection closed instead.
async fn ask(
    stream: &mut Box<dyn Io>,
    port: u16,
    path: &str,
    agent: Option<&str>,
) -> Option<(u16, String, String)> {
    let agent = agent.map_or_else(String::new, |agent| format!("User-Agent: {agent}\r\n"));
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\n{agent}\r\n").as_bytes(),
        )
        .await
        .ok()?;
    let head = timeout(PATIENCE, read_head(stream))
        .await
        .expect("no answer")?;
    let status = head.split_whitespace().nth(1)?.parse().ok()?;
    let header = |wanted: &str| {
        head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(wanted)
                .then(|| value.trim().to_string())
        })
    };
    let length: usize = header("content-length").map_or(0, |length| length.parse().unwrap());
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.ok()?;
    Some((
        status,
        header("content-type").unwrap_or_default(),
        String::from_utf8_lossy(&body).into_owned(),
    ))
}

async fn body_of(stream: &mut Box<dyn Io>, port: u16, path: &str) -> (u16, String) {
    let (status, _, body) = ask(stream, port, path, None)
        .await
        .unwrap_or_else(|| panic!("{path} got no answer"));
    (status, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_exception_ahead_of_a_reject_is_reached() {
    let setup = setup(&[
        r"URL-REGEX,^https?://localhost:\d+/ok,DIRECT",
        "DOMAIN,localhost,REJECT",
        "MATCH,A",
    ])
    .await;
    for https in [true, false] {
        let (mut stream, port) = setup.open(https).await;
        assert_eq!(
            body_of(&mut stream, port, "/ok?x=1").await,
            (200, "/ok?x=1|".to_string()),
            "https: {https}"
        );
        assert_eq!(
            body_of(&mut stream, port, "/ad").await,
            (404, String::new())
        );
    }
    assert_eq!(setup.seen(), (0, 0));
    let rejected = lock(&setup.rig.events.seen)
        .iter()
        .filter(|event| {
            matches!(event, CoreEvent::Request(record)
                if record.chains.iter().map(|c| c.as_ref()).eq(["REJECT"])
                    && record.rule_payload.as_ref() == "localhost")
        })
        .count();
    assert_eq!(rejected, 2, "each /ad is listed as a rejected connection");
    setup.rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_on_one_connection_leave_through_their_own_nodes() {
    let setup = setup(&["URL-REGEX,/x,A", "URL-REGEX,/y,B", "MATCH,DIRECT"]).await;
    for (round, https) in [true, false].into_iter().enumerate() {
        let (mut stream, port) = setup.open(https).await;
        for path in ["/x", "/y", "/x", "/y"] {
            assert_eq!(body_of(&mut stream, port, path).await.1, format!("{path}|"));
        }
        assert_eq!(
            setup.seen(),
            (round + 1, round + 1),
            "one upstream connection per node, kept for its own requests: https {https}"
        );
    }
    setup.rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_group_switch_moves_the_next_request() {
    let setup = setup(&["URL-REGEX,/g,G", "MATCH,DIRECT"]).await;
    for https in [true, false] {
        setup.rig.engine.select("G", "A").await;
        let before = setup.seen();
        let (mut stream, port) = setup.open(https).await;
        body_of(&mut stream, port, "/g").await;
        assert_eq!(setup.seen(), (before.0 + 1, before.1));
        assert!(setup.rig.engine.select("G", "B").await.changed);
        assert_eq!(body_of(&mut stream, port, "/g").await.1, "/g|");
        assert_eq!(
            setup.seen(),
            (before.0 + 1, before.1 + 1),
            "A's pooled connection is not reused for B: https {https}"
        );
    }
    setup.rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reject_variant_answers_with_its_reply() {
    let setup = setup(&[
        "URL-REGEX,/gif,REJECT-TINYGIF",
        "URL-REGEX,/dict,REJECT-DICT",
        "URL-REGEX,/array,REJECT-ARRAY",
        "URL-REGEX,/empty,REJECT-200",
        "URL-REGEX,/drop,REJECT-DROP",
        "MATCH,DIRECT",
    ])
    .await;
    for https in [true, false] {
        let (mut stream, port) = setup.open(https).await;
        let gif = ask(&mut stream, port, "/gif", None).await.unwrap();
        assert_eq!((gif.0, gif.1.as_str()), (200, "image/gif"));
        assert_eq!(
            body_of(&mut stream, port, "/dict").await,
            (200, "{}".to_string())
        );
        assert_eq!(
            body_of(&mut stream, port, "/array").await,
            (200, "[]".to_string())
        );
        assert_eq!(
            body_of(&mut stream, port, "/empty").await,
            (200, String::new())
        );
        assert_eq!(
            body_of(&mut stream, port, "/kept").await,
            (200, "/kept|".to_string())
        );
        assert!(
            ask(&mut stream, port, "/drop", None).await.is_none(),
            "REJECT-DROP answers nothing: https {https}"
        );
    }
    setup.rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logic_over_a_user_agent_decides_each_request() {
    let setup = setup(&[
        "AND,((DOMAIN,localhost),(USER-AGENT,Foo*)),REJECT",
        "NOT,((URL-REGEX,/keep)),B",
        "MATCH,A",
    ])
    .await;
    for https in [true, false] {
        let before = setup.seen();
        let (mut stream, port) = setup.open(https).await;
        let rejected = ask(&mut stream, port, "/keep", Some("Foo/1"))
            .await
            .unwrap();
        assert_eq!(rejected.0, 404, "https {https}");
        let kept = ask(&mut stream, port, "/keep", Some("Bar/1"))
            .await
            .unwrap();
        assert_eq!((kept.0, kept.2.as_str()), (200, "/keep|"));
        let other = ask(&mut stream, port, "/other", None).await.unwrap();
        assert_eq!((other.0, other.2.as_str()), (200, "/other|"));
        assert_eq!(
            setup.seen(),
            (before.0 + 1, before.1 + 1),
            "/keep through A, on the connection dialed before the handshake when there is one, \
             the rest through B: https {https}"
        );
    }
    setup.rig.engine.shutdown().await;
}

/// A CONNECT through the mixed port's HTTP proxy, with `agent` as its User-Agent.
async fn connect_with(mixed: u16, port: u16, agent: &str) -> TcpStream {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, mixed))
        .await
        .unwrap();
    stream
        .write_all(
            format!(
                "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\nUser-Agent: {agent}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let head = timeout(PATIENCE, read_head(&mut stream))
        .await
        .unwrap()
        .unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    stream
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undecrypted_connect_is_routed_by_its_user_agent() {
    let setup = setup(&[
        r"URL-REGEX,^https://localhost,B",
        "USER-AGENT,Bot*,A",
        "MATCH,DIRECT",
    ])
    .await;
    let unlisted = tls_echo_server().await.port();
    let _bot = connect_with(setup.rig.mixed, unlisted, "Bot/2").await;
    assert!(
        eventually(|| setup.seen() == (1, 0)).await,
        "{:?}",
        setup.seen()
    );
    let _other = connect_with(setup.rig.mixed, unlisted, "Browser/1").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        setup.seen(),
        (1, 0),
        "neither the agent nor the unread URL took it"
    );
    setup.rig.engine.shutdown().await;
}
