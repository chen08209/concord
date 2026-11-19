use concord_common::ResourceKind;
use concord_config::mitm::modules::{RESOURCES_DIR, stored_name};
use serde_json::{Value, json};
use tokio::time::{Instant, sleep};

use super::http_rules::{Io, ask, body_of, plain_echo_server, read_head};
use super::*;

/// Serves `/body.json` with the status the test sets, counting the requests.
struct Files {
    status: Arc<AtomicU16>,
    asked: Arc<AtomicUsize>,
    port: u16,
}

async fn file_server(status: u16) -> Files {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let files = Files {
        status: Arc::new(AtomicU16::new(status)),
        asked: Arc::new(AtomicUsize::new(0)),
        port,
    };
    let (answer, asked) = (files.status.clone(), files.asked.clone());
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let (answer, asked) = (answer.clone(), asked.clone());
            tokio::spawn(async move {
                if read_head(&mut stream).await.is_none() {
                    return;
                }
                asked.fetch_add(1, Ordering::SeqCst);
                let status = answer.load(Ordering::SeqCst);
                let body = if status == 200 { "{\"local\":1}" } else { "" };
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    files
}

/// Through the core over SOCKS to the plain origin at `port`.
async fn open(rig: &Rig, port: u16) -> Box<dyn Io> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
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
    Box::new(stream)
}

fn config(origin: u16, files: u16, a_port: u16, b_port: u16) -> String {
    let module = format!(
        "#!name=Local\n\
         [Rule]\n\
         URL-REGEX,^http://localhost:\\d+/viaproxy,PROXY\n\
         DOMAIN,never.test,Nowhere\n\
         [Map Local]\n\
         ^http://localhost:\\d+/local data-type=file data=\"http://127.0.0.1:{files}/body.json\"\n\
         [MITM]\n\
         hostname = %APPEND% localhost:{origin}\n"
    );
    let indented: String = module
        .lines()
        .map(|line| format!("        {line}\n"))
        .collect();
    format!(
        "proxies:\n  - {{name: A, type: socks5, server: 127.0.0.1, port: {a_port}}}\n  \
         - {{name: B, type: socks5, server: 127.0.0.1, port: {b_port}}}\n\
         mitm:\n  enable: true\n  module-policy: {{PROXY: B}}\n  modules:\n    \
         - name: local\n      text: |\n{indented}\
         rules:\n  - MATCH,A\n"
    )
}

/// Asks for `/local` on fresh connections until the map-local file answers it: the section is
/// composed again just after the file is stored, which winds the connections down.
async fn answered_locally(rig: &Rig, origin: u16) {
    let deadline = Instant::now() + PATIENCE;
    loop {
        let mut stream = open(rig, origin).await;
        let answer = ask(&mut stream, origin, "/local", None).await;
        if matches!(&answer, Some((200, _, body)) if body == "{\"local\":1}") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "/local never answered locally: {answer:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn module(rig: &Rig) -> Value {
    rig.engine.mitm().module_status().unwrap()["modules"][0].clone()
}

/// Waits until the module's file reaches `state`.
async fn until(rig: &Rig, state: &str) -> Value {
    let deadline = Instant::now() + PATIENCE;
    loop {
        let status = module(rig).await;
        if status["resources"][0]["state"] == state {
            return status;
        }
        assert!(Instant::now() < deadline, "never {state}: {status}");
        sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_module_rule_goes_ahead_of_the_profiles_through_the_mapped_policy() {
    let origin = plain_echo_server().await.port();
    let files = file_server(200).await;
    let (a_port, a) = upstream_socks().await;
    let (b_port, b) = upstream_socks().await;
    let rig = Rig::new();
    rig.apply(&config(origin, files.port, a_port, b_port))
        .await
        .unwrap();
    rig.engine.start_listeners().await;
    until(&rig, "ok").await;
    let mut stream = open(&rig, origin).await;
    assert_eq!(
        body_of(&mut stream, origin, "/viaproxy").await,
        (200, "/viaproxy|".to_string())
    );
    assert_eq!(body_of(&mut stream, origin, "/other").await.0, 200);
    assert_eq!(lock(&b).len(), 1);
    assert!(!lock(&a).is_empty());
    let status = module(&rig).await;
    assert_eq!(status["refusedRules"][0]["line"], 4, "{status}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_never_fetched_is_fetched_on_apply_and_takes_effect() {
    let origin = plain_echo_server().await.port();
    let files = file_server(200).await;
    let (a_port, _) = upstream_socks().await;
    let rig = Rig::new();
    let config = config(origin, files.port, a_port, a_port);
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await;
    let status = until(&rig, "ok").await;
    let file = status["resources"][0]["file"].as_str().unwrap().to_string();
    let stored = rig.home.path().join("mitm/resources").join(&file);
    assert_eq!(std::fs::read_to_string(stored).unwrap(), "{\"local\":1}");
    answered_locally(&rig, origin).await;
    let updates: Vec<ResourcePhase> = lock(&rig.events.seen)
        .iter()
        .filter_map(|event| match event {
            CoreEvent::Resource(update)
                if update.kind == ResourceKind::MitmModule && &*update.name == "local" =>
            {
                Some(update.phase.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(updates, [ResourcePhase::Updating, ResourcePhase::Updated]);

    rig.apply(&config).await.unwrap();
    sleep(Duration::from_millis(200)).await;
    assert_eq!(files.asked.load(Ordering::SeqCst), 1);
    assert_eq!(module(&rig).await["resources"][0]["state"], "ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_that_failed_to_fetch_takes_effect_once_fetched_again() {
    let origin = plain_echo_server().await.port();
    let files = file_server(404).await;
    let (a_port, _) = upstream_socks().await;
    let rig = Rig::new();
    rig.apply(&config(origin, files.port, a_port, a_port))
        .await
        .unwrap();
    rig.engine.start_listeners().await;
    let status = until(&rig, "failed").await;
    let error = &status["resources"][0]["error"];
    assert_eq!(
        (&error["reason"], &error["status"]),
        (&json!("http"), &json!(404))
    );
    assert!(status["resources"][0]["file"].is_null());
    let mut stream = open(&rig, origin).await;
    assert_eq!(
        body_of(&mut stream, origin, "/local").await,
        (200, "/local|".to_string())
    );

    files.status.store(200, Ordering::SeqCst);
    rig.engine
        .mitm()
        .fetch_module(Some("local".into()))
        .unwrap();
    until(&rig, "ok").await;
    answered_locally(&rig, origin).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stash_script_carried_in_the_text_is_written_out_on_apply() {
    let text = "name: Inline\n\
                  http:\n  script:\n    - match: ^https://a\\.test/\n      name: inline\n      type: request\n\
                  script-providers:\n  inline:\n    payload: '$done({})'\n";
    let indented: String = text
        .lines()
        .map(|line| format!("        {line}\n"))
        .collect();
    let rig = Rig::new();
    rig.apply(&format!(
        "mitm:\n  enable: true\n  modules:\n    - name: inline\n      text: |\n{indented}\
         rules:\n  - MATCH,DIRECT\n"
    ))
    .await
    .unwrap();
    let status = module(&rig).await;
    assert_eq!(status["inForce"], true, "{status}");
    let file = rig
        .home
        .path()
        .join(RESOURCES_DIR)
        .join(stored_name("inline.js", b"$done({})"));
    assert_eq!(std::fs::read_to_string(file).unwrap(), "$done({})");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_module_turned_off_keeps_its_file_until_the_host_no_longer_lists_it() {
    let origin = plain_echo_server().await.port();
    let files = file_server(200).await;
    let (a_port, _) = upstream_socks().await;
    let rig = Rig::new();
    let on = config(origin, files.port, a_port, a_port);
    let off = on.replacen(
        "- name: local\n",
        "- name: local\n      enabled: false\n",
        1,
    );
    rig.apply(&off).await.unwrap();
    rig.engine.start_listeners().await;
    sleep(Duration::from_millis(200)).await;
    let status = module(&rig).await;
    assert_eq!(status["enabled"], false, "{status}");
    assert_eq!(status["inForce"], false, "{status}");
    assert_eq!(status["resources"][0]["state"], "missing", "{status}");
    assert_eq!(files.asked.load(Ordering::SeqCst), 0);

    rig.apply(&on).await.unwrap();
    let file = until(&rig, "ok").await["resources"][0]["file"]
        .as_str()
        .unwrap()
        .to_string();
    let stored = rig.home.path().join(RESOURCES_DIR).join(file);
    rig.apply(&off).await.unwrap();
    assert!(stored.is_file());

    let without = |mitm: &str| format!("mitm:\n{mitm}rules:\n  - MATCH,DIRECT\n");
    for kept in ["  enable: true\n", "  enable: false\n  modules: []\n"] {
        rig.apply(&without(kept)).await.unwrap();
        assert!(stored.is_file(), "{kept}");
    }
    rig.apply(&without("  enable: true\n  modules: []\n"))
        .await
        .unwrap();
    assert!(!stored.is_file());
}
