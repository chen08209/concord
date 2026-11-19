#![allow(
    clippy::disallowed_methods,
    reason = "clients knocking on the core's ports from outside"
)]

//! What runs in each phase of the core's life: a config applied, the core started, stopped and
//! started again. Only what takes traffic in is the run's: the listeners and `dns.listen` open
//! with `engine.start` and close with `engine.stop`. Health checks and provider updates go on
//! from the apply whether or not the core runs, and a stop leaves established connections alone.
//! A task that comes up with `engine.start` and outlives `engine.stop` fails here.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use concord_common::CoreOptions;
use concord_test_support::tcp_echo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

use super::tests::{bare_engine, running, socks};
use super::*;

const PATIENCE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
struct Ports {
    mixed: u16,
    dns: u16,
}

/// What the config's own background work has fetched so far.
struct Fetched {
    checks: Arc<AtomicUsize>,
    provider: Arc<AtomicUsize>,
}

impl Fetched {
    async fn goes_on(counter: &AtomicUsize) -> bool {
        let before = counter.load(Ordering::SeqCst);
        timeout(PATIENCE, async {
            while counter.load(Ordering::SeqCst) == before {
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .is_ok()
    }

    async fn assert_goes_on(&self, phase: &str) {
        assert!(
            Self::goes_on(&self.checks).await,
            "health checks paused: {phase}"
        );
        assert!(
            Self::goes_on(&self.provider).await,
            "provider updates paused: {phase}"
        );
    }
}

/// An HTTP origin that answers every request with `body` and counts them.
async fn counting_origin(body: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let counted = counted.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0; 1024];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                counted.fetch_add(1, Ordering::SeqCst);
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });
    (addr, count)
}

#[derive(Debug, PartialEq)]
struct Listening {
    mixed: bool,
    dns: bool,
}

impl Listening {
    const ALL: Listening = Listening {
        mixed: true,
        dns: true,
    };
    const NONE: Listening = Listening {
        mixed: false,
        dns: false,
    };
}

fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    probe.local_addr().unwrap().port()
}

/// An initialized engine whose `config.yaml` opens a mixed port and `dns.listen`, health-checks a
/// url-test group and updates a proxy provider every second.
async fn engine_with_every_service() -> (Arc<Engine>, Ports, Fetched, tempfile::TempDir) {
    let (check_url, checks) = counting_origin("ok").await;
    let (provider_url, provider) =
        counting_origin("proxies:\n  - {name: n, type: socks5, server: 127.0.0.1, port: 1}\n")
            .await;
    let ports = Ports {
        mixed: free_port(),
        dns: free_port(),
    };
    let home = tempfile::tempdir().unwrap();
    let config = format!(
        "mixed-port: {}\n\
         dns:\n  enable: true\n  listen: 127.0.0.1:{}\n  nameserver:\n    - 127.0.0.1:1\n\
         proxy-providers:\n  p: {{type: http, url: 'http://{provider_url}/p.yaml', path: ./p.yaml, interval: 1}}\n\
         proxy-groups:\n  - {{name: g, type: url-test, proxies: [DIRECT], url: 'http://{check_url}/', interval: 1, lazy: false}}\n\
         rules:\n  - MATCH,DIRECT\n",
        ports.mixed, ports.dns
    );
    std::fs::write(home.path().join("config.yaml"), config).unwrap();
    let engine = bare_engine();
    engine.init(home.path().to_str().unwrap(), 0).unwrap();
    let fetched = Fetched { checks, provider };
    (engine, ports, fetched, home)
}

async fn apply(engine: &Arc<Engine>) {
    let request = SetupRequest {
        base: None,
        selected: BTreeMap::new(),
        options: CoreOptions::default(),
    };
    timeout(PATIENCE, engine.setup(request))
        .await
        .expect("apply hung")
        .unwrap();
}

async fn accepts(port: u16) -> bool {
    matches!(
        timeout(PATIENCE, TcpStream::connect((Ipv4Addr::LOCALHOST, port))).await,
        Ok(Ok(_))
    )
}

async fn listening(ports: Ports) -> Listening {
    Listening {
        mixed: accepts(ports.mixed).await,
        dns: accepts(ports.dns).await,
    }
}

/// The engine's task count once it has held still for a while, so a task that only answers a
/// knock or frees memory after an apply is not counted.
async fn settled_tasks(engine: &Engine) -> usize {
    let settle = async {
        let (mut last, mut still) = (engine.tasks.len(), 0);
        loop {
            sleep(Duration::from_millis(20)).await;
            let now = engine.tasks.len();
            if now == last {
                still += 1;
                if still == 10 {
                    return now;
                }
            } else {
                (last, still) = (now, 0);
            }
        }
    };
    timeout(PATIENCE, settle)
        .await
        .expect("the engine's tasks never settled")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_stop_ends_everything_engine_start_began() {
    let (engine, ports, fetched, _home) = engine_with_every_service().await;
    apply(&engine).await;
    fetched.assert_goes_on("applied, never started").await;
    let applied = settled_tasks(&engine).await;
    assert_eq!(
        listening(ports).await,
        Listening::NONE,
        "applied, never started"
    );

    timeout(PATIENCE, engine.start_listeners()).await.unwrap();
    assert_eq!(listening(ports).await, Listening::ALL, "started");
    let started = settled_tasks(&engine).await;

    timeout(PATIENCE, engine.stop_listeners()).await.unwrap();
    assert_eq!(listening(ports).await, Listening::NONE, "stopped");
    fetched.assert_goes_on("stopped").await;
    assert_eq!(
        settled_tasks(&engine).await,
        applied,
        "a task engine.start began outlived engine.stop"
    );

    timeout(PATIENCE, engine.start_listeners()).await.unwrap();
    assert_eq!(listening(ports).await, Listening::ALL, "started again");
    assert_eq!(
        settled_tasks(&engine).await,
        started,
        "a second start ran a different set of tasks"
    );
    timeout(PATIENCE, engine.shutdown()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_before_the_first_apply_opens_what_the_apply_brings() {
    let (engine, ports, _fetched, _home) = engine_with_every_service().await;
    timeout(PATIENCE, engine.start_listeners()).await.unwrap();
    apply(&engine).await;
    assert_eq!(listening(ports).await, Listening::ALL);

    timeout(PATIENCE, engine.stop_listeners()).await.unwrap();
    assert_eq!(listening(ports).await, Listening::NONE);
    timeout(PATIENCE, engine.shutdown()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_stop_leaves_an_established_connection_relaying() {
    let echo = tcp_echo().await;
    let (engine, port, _home) = running("rules:\n  - MATCH,DIRECT\n").await;
    let (mut client, _) = socks(port, 1, echo).await;
    timeout(PATIENCE, engine.stop_listeners()).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0; 4];
    timeout(PATIENCE, client.read_exact(&mut echoed))
        .await
        .expect("the connection stopped relaying")
        .unwrap();
    assert_eq!(&echoed, b"ping");
    timeout(PATIENCE, engine.shutdown()).await.unwrap();
}
