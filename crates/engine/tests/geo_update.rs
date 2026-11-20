#![allow(
    clippy::disallowed_methods,
    reason = "the peers here stand for the outside world, not the core's own sockets"
)]

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{
    CoreEvent, CoreOptions, EventSink, ResourceKind, ResourcePhase, ResourceUpdate, RouteStamp,
};
use concord_engine::{Engine, EngineConfig, SetupRequest};
use concord_platform::NativePlatform;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct Events {
    geo: std::sync::Mutex<Vec<(String, ResourcePhase)>>,
    routes: std::sync::Mutex<Vec<RouteStamp>>,
}

impl EventSink for Events {
    fn enabled(&self) -> bool {
        true
    }

    fn publish(&self, event: CoreEvent) {
        match event {
            CoreEvent::Resource(ResourceUpdate {
                kind: ResourceKind::Geo,
                name,
                phase,
            }) => lock(&self.geo).push((name.to_string(), phase)),
            CoreEvent::RouteChanged(view) => lock(&self.routes).push(view.stamp),
            _ => {}
        }
    }
}

struct Rig {
    engine: Arc<Engine>,
    events: Arc<Events>,
    home: tempfile::TempDir,
}

impl Rig {
    fn new() -> Rig {
        let events = Arc::new(Events::default());
        let engine = Engine::new(EngineConfig {
            sink: events.clone(),
            android: false,
            platform: Arc::new(NativePlatform::new()),
        });
        let home = tempfile::tempdir().unwrap();
        engine.init(home.path().to_str().unwrap(), 0).unwrap();
        Rig {
            engine,
            events,
            home,
        }
    }

    async fn apply(&self, config: &str) {
        std::fs::write(self.home.path().join("config.yaml"), config).unwrap();
        self.engine
            .setup(SetupRequest {
                base: None,
                selected: BTreeMap::new(),
                options: CoreOptions::default(),
            })
            .await
            .unwrap();
    }

    fn geo_events(&self, kind: &str) -> Vec<ResourcePhase> {
        lock(&self.events.geo)
            .iter()
            .filter(|(seen, _)| seen == kind)
            .map(|(_, phase)| phase.clone())
            .collect()
    }
}

async fn serve(body: Option<&'static [u8]>) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((mut stream, _)) = listener.accept().await {
            let Some(body) = body else {
                held.push(stream);
                continue;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

async fn eventually(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    check()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_resource_is_refused() {
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await;

    let failure = rig.engine.geo_update("GEOFOO").unwrap_err();

    assert!(failure.message.contains("unknown geo resource"));
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_update_per_resource_runs_at_a_time() {
    let stuck = serve(None).await;
    let rig = Rig::new();
    rig.apply(&format!(
        "geox-url:\n  mmdb: http://{stuck}/m\n  asn: http://{stuck}/a\nrules:\n  - MATCH,DIRECT\n"
    ))
    .await;

    rig.engine.geo_update("MMDB").unwrap();
    let second = rig.engine.geo_update("MMDB").unwrap_err();

    assert!(second.message.contains("already in progress"), "{second:?}");
    rig.engine.geo_update("ASN").unwrap();
    assert!(eventually(|| rig.geo_events("MMDB").first() == Some(&ResourcePhase::Updating)).await);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_download_ends_the_update_with_an_error_and_frees_the_resource() {
    let server = serve(Some(b"")).await;
    let rig = Rig::new();
    rig.apply(&format!(
        "geox-url:\n  mmdb: http://{server}/m\nrules:\n  - MATCH,DIRECT\n"
    ))
    .await;

    rig.engine.geo_update("MMDB").unwrap();

    assert!(
        eventually(|| rig.geo_events("MMDB").iter().any(
            |phase| matches!(phase, ResourcePhase::Failed(error) if error.contains("no data"))
        ))
        .await,
        "{:?}",
        rig.geo_events("MMDB")
    );
    assert!(rig.engine.geo_update("MMDB").is_ok());
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_download_equal_to_the_file_on_disk_is_skipped_and_does_not_move_the_route() {
    let server = serve(Some(b"same bytes")).await;
    let rig = Rig::new();
    std::fs::write(rig.home.path().join("geoip.metadb"), b"same bytes").unwrap();
    rig.apply(&format!(
        "geox-url:\n  mmdb: http://{server}/m\nrules:\n  - MATCH,DIRECT\n"
    ))
    .await;
    let before = rig.engine.watch_route(false);

    rig.engine.geo_update("MMDB").unwrap();

    assert!(
        eventually(|| rig.geo_events("MMDB").contains(&ResourcePhase::Unchanged)).await,
        "{:?}",
        rig.geo_events("MMDB")
    );
    assert_eq!(rig.engine.watch_route(false), before);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_download_leaves_the_file_on_disk() {
    let server = serve(Some(b"not a database")).await;
    let rig = Rig::new();
    std::fs::write(rig.home.path().join("geoip.metadb"), b"old bytes").unwrap();
    rig.apply(&format!(
        "geox-url:\n  mmdb: http://{server}/m\nrules:\n  - MATCH,DIRECT\n"
    ))
    .await;

    rig.engine.geo_update("MMDB").unwrap();

    assert!(
        eventually(|| rig.geo_events("MMDB").iter().any(
            |phase| matches!(phase, ResourcePhase::Failed(error) if error.contains("invalid MMDB"))
        ))
        .await,
        "{:?}",
        rig.geo_events("MMDB")
    );
    assert_eq!(
        std::fs::read(rig.home.path().join("geoip.metadb")).unwrap(),
        b"old bytes"
    );
    let leftovers = std::fs::read_dir(rig.home.path())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".tmp"))
        .count();
    assert_eq!(leftovers, 0);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_database_the_profile_needs_and_lacks_is_fetched_and_reported() {
    let server = serve(Some(b"not a database")).await;
    let rig = Rig::new();
    std::fs::write(
        rig.home.path().join("config.yaml"),
        format!(
            "geox-url:\n  mmdb: http://{server}/m\nrules:\n  - GEOIP,CN,DIRECT\n  - MATCH,DIRECT\n"
        ),
    )
    .unwrap();
    let _ = rig
        .engine
        .setup(SetupRequest {
            base: None,
            selected: BTreeMap::new(),
            options: CoreOptions::default(),
        })
        .await;

    let seen = rig.geo_events("MMDB");
    assert!(
        matches!(
            seen.as_slice(),
            [ResourcePhase::Updating, ResourcePhase::Failed(_), ..]
        ),
        "{seen:?}"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_asn_database_the_rules_lack_is_fetched_after_the_apply() {
    let server = serve(Some(b"not a database")).await;
    let rig = Rig::new();
    std::fs::write(
        rig.home.path().join("config.yaml"),
        format!("geox-url:\n  asn: http://{server}/a\nrules:\n  - IP-ASN,13335,DIRECT\n  - MATCH,DIRECT\n"),
    )
    .unwrap();
    let applied = rig
        .engine
        .setup(SetupRequest {
            base: None,
            selected: BTreeMap::new(),
            options: CoreOptions::default(),
        })
        .await;

    assert!(applied.is_ok(), "{applied:?}");
    assert!(
        eventually(|| matches!(
            rig.geo_events("ASN").as_slice(),
            [ResourcePhase::Updating, ResourcePhase::Failed(_), ..]
        ))
        .await,
        "{:?}",
        rig.geo_events("ASN")
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_database_dns_needs_and_lacks_is_fetched_and_reported() {
    let server = serve(Some(b"not a database")).await;
    let rig = Rig::new();
    std::fs::write(
        rig.home.path().join("config.yaml"),
        format!(
            "geox-url:\n  mmdb: http://{server}/m\ndns:\n  enable: true\n  nameserver:\n    - 127.0.0.1\n  \
             fallback:\n    - 127.0.0.2\n  fallback-filter:\n    geoip: true\n    geoip-code: CN\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
    )
    .unwrap();
    let _ = rig
        .engine
        .setup(SetupRequest {
            base: None,
            selected: BTreeMap::new(),
            options: CoreOptions::default(),
        })
        .await;

    let seen = rig.geo_events("MMDB");
    assert!(
        matches!(
            seen.as_slice(),
            [ResourcePhase::Updating, ResourcePhase::Failed(_), ..]
        ),
        "{seen:?}"
    );
    rig.engine.shutdown().await;
}

/// VmHWM and VmRSS in MiB.
fn memory() -> Option<(f64, f64)> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    let field = |key: &str| -> Option<f64> {
        text.lines()
            .find_map(|line| line.strip_prefix(key))?
            .split_whitespace()
            .next()?
            .parse::<f64>()
            .ok()
            .map(|kib| kib / 1024.0)
    };
    Some((field("VmHWM:")?, field("VmRSS:")?))
}

/// The memory an update takes above the core's resident set before it, for a download equal
/// to the file on disk and for one that differs by a letter; then what stays once it has
/// settled, and once free memory is handed back.
async fn update_peak(kind: &str, key: &str, name: &str, rule: &str, body: &'static [u8]) {
    let server = serve(Some(body)).await;
    for changed in [false, true] {
        let rig = Rig::new();
        let mut old = body.to_vec();
        if changed {
            let letter = (old.len() / 2..old.len())
                .find(|&at| old[at].is_ascii_lowercase() && old[at] != b'z')
                .unwrap();
            old[letter] += 1;
        }
        std::fs::write(rig.home.path().join(name), &old).unwrap();
        rig.apply(&format!(
            "geox-url:\n  {key}: http://{server}/f\nrules:\n  - {rule}\n  - MATCH,DIRECT\n"
        ))
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        std::fs::write("/proc/self/clear_refs", "5").unwrap();
        let (_, before) = memory().unwrap();
        rig.engine.geo_update(kind).unwrap();
        let done = if changed {
            ResourcePhase::Updated
        } else {
            ResourcePhase::Unchanged
        };
        assert!(
            eventually(|| rig.geo_events(kind).contains(&done)).await,
            "{:?}",
            rig.geo_events(kind)
        );
        let (peak, after) = memory().unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let (_, settled) = memory().unwrap();
        rig.engine.release_memory();
        let (_, released) = memory().unwrap();
        println!(
            "MM-GEO {kind} file_mib {:.1} changed {changed} before_mib {before:.1} peak_mib {peak:.1} \
             peak_over_mib {:.1} after_mib {after:.1} settled_over_mib {:.1} released_over_mib {:.1}",
            body.len() as f64 / 1048576.0,
            peak - before,
            settled - before,
            released - before
        );
        if changed && kind == "GEOSITE" {
            let mut residue = Vec::new();
            for updates in 2..=5 {
                let staged = rig.home.path().join("staged");
                std::fs::write(&staged, &old).unwrap();
                std::fs::rename(&staged, rig.home.path().join(name)).unwrap();
                rig.engine.geo_update(kind).unwrap();
                let updated = || {
                    rig.geo_events(kind)
                        .iter()
                        .filter(|phase| **phase == ResourcePhase::Updated)
                        .count()
                        == updates
                };
                assert!(eventually(updated).await, "{:?}", rig.geo_events(kind));
                tokio::time::sleep(Duration::from_millis(500)).await;
                rig.engine.release_memory();
                residue.push(format!("{:.1}", memory().unwrap().1 - before));
            }
            println!(
                "MM-GEO {kind} repeated released_over_mib {}",
                residue.join(" ")
            );
        }
        rig.engine.shutdown().await;
    }
}

/// The peak memory of a geo update, run by hand on Linux with real databases:
/// `MM_GEO_MMDB=<geoip.metadb> MM_GEO_SITE=<GeoSite.dat> cargo test -p concord-engine --release
/// --test geo_update update_peak -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement, run by hand on Linux"]
async fn geo_update_peak() {
    if memory().is_none() {
        println!("MM-GEO needs /proc");
        return;
    }
    let read = |var: &str| -> Option<&'static [u8]> {
        Some(std::fs::read(std::env::var_os(var)?).unwrap().leak())
    };
    if let Some(body) = read("MM_GEO_MMDB") {
        update_peak("MMDB", "mmdb", "geoip.metadb", "GEOIP,CN,DIRECT", body).await;
    }
    if let Some(body) = read("MM_GEO_SITE") {
        update_peak(
            "GEOSITE",
            "geosite",
            "GeoSite.dat",
            "GEOSITE,cn,DIRECT",
            body,
        )
        .await;
    }
}
