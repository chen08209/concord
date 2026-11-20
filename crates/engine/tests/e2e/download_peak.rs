//! The peak memory of fetching a large module file, run by hand on Linux:
//! `cargo test -p concord-engine --release --test e2e download_peak -- --ignored --nocapture`.

use tokio::time::Instant;

use super::*;

const SIZE: usize = 64 << 20;

/// Serves `SIZE` bytes to every request, in 64 KiB writes.
async fn big_file_server() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                if super::http_rules::read_head(&mut stream).await.is_none() {
                    return;
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {SIZE}\r\nConnection: close\r\n\r\n"
                );
                if stream.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                let chunk = vec![b'x'; 64 << 10];
                for _ in 0..SIZE / chunk.len() {
                    if stream.write_all(&chunk).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement, run by hand on Linux"]
async fn download_peak() {
    if memory().is_none() {
        println!("MM-DOWNLOAD needs /proc");
        return;
    }
    let port = big_file_server().await;
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
    let (_, before) = memory().unwrap();
    let module = format!(
        "        #!name=Big\n        [Map Local]\n        ^http://big\\.test/ data-type=file data=\"http://127.0.0.1:{port}/big.bin\"\n"
    );
    rig.apply(&format!(
        "mitm:\n  enable: true\n  modules:\n    - name: big\n      text: |\n{module}rules:\n  - MATCH,DIRECT\n"
    ))
    .await
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = rig.engine.mitm().module_status().unwrap();
        let state = status["modules"][0]["resources"][0]["state"].clone();
        if state == "ok" {
            break;
        }
        assert!(Instant::now() < deadline, "never fetched: {status}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (peak, after) = memory().unwrap();
    println!(
        "MM-DOWNLOAD {} MiB file: peak +{:.1} MiB, resident afterwards +{:.1} MiB",
        SIZE >> 20,
        peak - before,
        after - before
    );
}
