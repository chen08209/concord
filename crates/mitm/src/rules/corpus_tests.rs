//! What the module corpus asks of every decrypted request: how many rules each list tries
//! for a URL no module names, and how long one request's lookups take. Run by hand:
//! `cargo test -p concord-mitm --release --lib corpus_lookups -- --ignored --nocapture`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use concord_config::mitm::MitmDef;
use concord_config::mitm::module::{Environment, ModuleInput, ResourceKind, read_module};
use concord_config::mitm::modules::{AppliedModule, ModuleSpec, compose};

use crate::config::{Config, ParseEnv};
use crate::heads::Heads;
use crate::rules::Rules;
use crate::rules::index::UrlIndex;
use crate::script::ScriptHost;

fn stored_name(url: &str) -> String {
    let id = url.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    });
    format!("r{id:016x}")
}

fn corpus_rules(resources: &Path) -> Rules {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/tests/data/modules");
    let empty = BTreeMap::new();
    let environment = Environment::current(String::new());
    let input = ModuleInput {
        arguments: &empty,
        attachments: &empty,
        environment: &environment,
    };
    std::fs::create_dir_all(resources).unwrap();
    let mut modules = Vec::new();
    let mut reading = std::time::Duration::ZERO;
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    for path in paths {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.ends_with(".json") || name.ends_with(".md") || name.starts_with("LICENSE") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let started = Instant::now();
        let def = read_module(&text, &input);
        reading += started.elapsed();
        for resource in &def.resources {
            let body = match resource.kind {
                ResourceKind::Script => "$done({});",
                ResourceKind::Jq => ".",
                _ => "x",
            };
            std::fs::write(resources.join(stored_name(&resource.url)), body).unwrap();
        }
        modules.push(AppliedModule {
            spec: ModuleSpec {
                name,
                ..ModuleSpec::default()
            },
            text,
            def,
            problem: None,
            refused_rules: Vec::new(),
        });
    }
    let started = Instant::now();
    let section = compose(&MitmDef::default(), &modules, |url| Some(stored_name(url)));
    let composing = started.elapsed();
    let env = ParseEnv {
        resources: resources.to_path_buf(),
        scripts: Arc::new(ScriptHost::default()),
    };
    let started = Instant::now();
    let (config, _) = Config::compile(section, &env, false);
    println!(
        "MM-READY {} modules read in {:.1} ms, composed in {:.1} ms, compiled and indexed in {:.1} ms",
        modules.len(),
        reading.as_secs_f64() * 1e3,
        composing.as_secs_f64() * 1e3,
        started.elapsed().as_secs_f64() * 1e3
    );
    let Config { rules, .. } = config;
    rules
}

fn per_request(rules: &Rules, url: &str) -> usize {
    let head = || String::from("GET / HTTP/1.1\r\nhost: a\r\n\r\n");
    let heads = Heads::new(Some(&head), Some(&head));
    let mut hits = 0;
    hits += usize::from(rules.rewrite_url(url, &heads).is_some());
    hits += usize::from(rules.map_local(url, &heads).is_some());
    hits += usize::from(rules.request_mock(url, &heads).is_some());
    for response in [false, true] {
        hits += rules.header_rewrites_for(url, response, &heads).len();
        hits += rules.body_rewrites_for(url, response, &heads).len();
        hits += usize::from(rules.script_for(url, response, &heads).is_some());
    }
    hits
}

#[test]
#[ignore = "a measurement, run by hand"]
fn corpus_lookups() {
    let home = tempfile::tempdir().unwrap();
    let rules = corpus_rules(&home.path().join("resources"));
    let started = Instant::now();
    let rebuilt = (
        UrlIndex::new(rules.url_rewrites.iter().map(|rule| Some(&rule.pattern))),
        UrlIndex::new(rules.map_locals.iter().map(|rule| Some(&rule.pattern))),
    );
    println!(
        "MM-INDEX url-rewrite and map-local indexed in {:.1} ms",
        started.elapsed().as_secs_f64() * 1e3
    );
    drop(rebuilt);
    let urls = [
        "https://10.0.0.2:8443/",
        "https://www.example.com/index.html?x=1",
        "https://api.bilibili.com/x/v2/feed/index?build=1",
    ];
    for (name, total, always, bytes) in rules.index_report() {
        println!(
            "MM-INDEX {name}: {total} rules, {always} tried for every URL, index {} KiB",
            bytes >> 10
        );
    }
    for url in urls {
        for (name, tried) in rules.candidate_counts(url) {
            println!("MM-CANDIDATES {url} {name}: {tried}");
        }
    }
    for url in urls {
        let started = Instant::now();
        per_request(&rules, url);
        let first = started.elapsed();
        let rounds = 2000;
        let mut times: Vec<f64> = (0..rounds)
            .map(|_| {
                let started = Instant::now();
                std::hint::black_box(per_request(&rules, url));
                started.elapsed().as_secs_f64() * 1e6
            })
            .collect();
        times.sort_by(f64::total_cmp);
        println!(
            "MM-LOOKUP {url}: first {:.0} us, then median {:.1} us, p99 {:.1} us",
            first.as_secs_f64() * 1e6,
            times[rounds / 2],
            times[rounds * 99 / 100]
        );
    }
}
