use std::time::Instant;

use super::*;

const SCRIPTS: [(&str, &str); 3] = [
    (
        "pick.js",
        "$done({matched: $request.hostname === '127.0.0.1' && $request.protocol === 'TCP' \
         && $request.url === null})",
    ),
    ("throws.js", "throw new Error('no')"),
    ("silent.js", "setTimeout(() => {}, 60000)"),
];

async fn scripted(rules: &str) -> (Rig, Arc<Mutex<Vec<String>>>, Arc<Mutex<Vec<String>>>) {
    let (a_port, a) = upstream_socks().await;
    let (b_port, b) = upstream_socks().await;
    let rig = Rig::new();
    let resources = rig.home.path().join("mitm/resources");
    std::fs::create_dir_all(&resources).unwrap();
    for (name, source) in SCRIPTS {
        std::fs::write(resources.join(name), source).unwrap();
    }
    let config = format!(
        "proxies:\n  - {{name: A, type: socks5, server: 127.0.0.1, port: {a_port}}}\n  \
         - {{name: B, type: socks5, server: 127.0.0.1, port: {b_port}}}\n\
         mitm:\n  enable: true\n  script:\n    - pick = type=rule,script-path=pick.js\n    \
         - throws = type=rule,script-path=throws.js\n    \
         - silent = type=rule,script-path=silent.js,timeout=1\n\
         rules:\n{rules}"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    (rig, a, b)
}

async fn echoes(rig: &Rig) {
    let echo = tcp_echo().await;
    let mut stream = timeout(PATIENCE, socks_connect(rig.mixed, echo))
        .await
        .unwrap()
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    timeout(PATIENCE, stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"ping");
}

#[tokio::test]
async fn a_script_rule_routes_by_its_verdict_and_a_failing_one_does_not_match() {
    let (rig, a, b) =
        scripted("  - SCRIPT,throws,B\n  - SCRIPT,silent,B\n  - SCRIPT,pick,A\n  - MATCH,B\n")
            .await;
    let started = Instant::now();
    echoes(&rig).await;
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(1) && waited < Duration::from_secs(5),
        "the silent script's own timeout ended its wait: {waited:?}"
    );
    assert_eq!((lock(&a).len(), lock(&b).len()), (1, 0));
}

#[tokio::test]
async fn a_rule_naming_no_script_loads_and_never_matches() {
    let (rig, a, b) = scripted("  - SCRIPT,missing,A\n  - MATCH,B\n").await;
    echoes(&rig).await;
    assert_eq!((lock(&a).len(), lock(&b).len()), (0, 1));
}

async fn ask(port: u16, name: &str) -> [u8; 4] {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket
        .send_to(&dns_query(name), (Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no answer")
        .unwrap();
    last_a_record(&buf[..len])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dns_script_answers_and_one_that_fails_or_runs_out_of_time_leaves_the_name_to_dns() {
    let nameserver = super::mitm::nameserver_answering([10, 0, 0, 1]).await;
    let named = super::mitm::nameserver_answering([10, 0, 0, 2]).await;
    let port = free_port();
    let rig = Rig::new();
    let resources = rig.home.path().join("mitm/resources");
    std::fs::create_dir_all(&resources).unwrap();
    let pick = format!(
        "if ($domain === 'hit.test') $done({{addresses: ['192.0.2.1'], ttl: 60}});\n\
         else if ($domain === 'served.test') $done({{server: '{named}'}});\n\
         else if ($domain === 'throws.test') throw new Error('no');\n\
         else $done({{}});"
    );
    std::fs::write(resources.join("pick.js"), pick).unwrap();
    std::fs::write(resources.join("slow.js"), "setTimeout(() => {}, 60000)").unwrap();
    let config = format!(
        "hosts:\n  hit.test: script:pick\n  served.test: script:pick\n  throws.test: script:pick\n  \
         pass.test: script:pick\n  slow.test: script:slow\n\
         dns:\n  enable: true\n  listen: 127.0.0.1:{port}\n  enhanced-mode: redir-host\n  \
         nameserver:\n    - {nameserver}\n\
         mitm:\n  enable: true\n  script:\n    - pick = type=dns,script-path=pick.js\n    \
         - slow = type=dns,script-path=slow.js,timeout=1\n\
         rules:\n  - MATCH,DIRECT\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    assert_eq!(ask(port, "hit.test").await, [192, 0, 2, 1]);
    assert_eq!(ask(port, "served.test").await, [10, 0, 0, 2]);
    assert_eq!(ask(port, "pass.test").await, [10, 0, 0, 1]);
    assert_eq!(ask(port, "throws.test").await, [10, 0, 0, 1]);
    let started = Instant::now();
    assert_eq!(ask(port, "slow.test").await, [10, 0, 0, 1]);
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(1) && waited < Duration::from_secs(5),
        "the script's own timeout ended its wait: {waited:?}"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dns_script_reaching_its_own_domain_does_not_wait_on_itself() {
    let nameserver = super::mitm::nameserver_answering([127, 0, 0, 1]).await;
    let (server, hits) = http_server(HashMap::from([("/ip", "192.0.2.9".to_string())])).await;
    let port = free_port();
    let rig = Rig::new();
    let resources = rig.home.path().join("mitm/resources");
    std::fs::create_dir_all(&resources).unwrap();
    let own = format!(
        "$httpClient.get('http://own.test:{}/ip', (error, response, body) => \
         $done(error ? {{}} : {{addresses: [body]}}))",
        server.port()
    );
    std::fs::write(resources.join("own.js"), own).unwrap();
    let config = format!(
        "hosts:\n  own.test: script:own\n\
         dns:\n  enable: true\n  listen: 127.0.0.1:{port}\n  enhanced-mode: redir-host\n  \
         nameserver:\n    - {nameserver}\n\
         mitm:\n  enable: true\n  script:\n    - own = type=dns,script-path=own.js\n\
         rules:\n  - MATCH,DIRECT\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    let started = Instant::now();
    assert_eq!(ask(port, "own.test").await, [192, 0, 2, 9]);
    let waited = started.elapsed();
    assert!(
        waited < Duration::from_secs(2),
        "the script's own request waited on the script: {waited:?}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    rig.engine.shutdown().await;
}
