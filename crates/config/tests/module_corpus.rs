//! Every module of the corpus in `tests/data/modules` read as a host would read it, against the
//! expectation committed beside it. `remote.json` lists the modules whose licence keeps them
//! out of the repository; `cargo xtask module-corpus` fetches them into the directory
//! `CONCORD_MODULE_CORPUS` names (by default `target/module-corpus`), and the test reads
//! them when they are there. `CONCORD_BLESS=1` rewrites the expectations.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};

use concord_config::mitm::module::{
    Environment, ModuleDef, ModuleInput, ModuleLine, ModuleRule, Policy, read_module,
};
use concord_config::mitm::{HostEntryDef, Items, Read, SourceEntryDef};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn data() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/modules")
}

fn cache() -> PathBuf {
    std::env::var_os("CONCORD_MODULE_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/module-corpus")
        })
}

const EXPECT: &str = ".expect.json";

fn is_module(path: &Path) -> bool {
    let name = path.file_name().unwrap().to_string_lossy();
    !name.ends_with(EXPECT)
        && !name.ends_with(".md")
        && name != "remote.json"
        && !name.starts_with("LICENSE")
}

/// Each module by its name in the corpus, and where its text is; a remote one not fetched
/// has none.
fn modules() -> Vec<(String, Option<PathBuf>)> {
    let mut found: Vec<(String, Option<PathBuf>)> = fs::read_dir(data())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file() && is_module(path))
        .map(|path| {
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                Some(path),
            )
        })
        .collect();
    let remote: Vec<Value> =
        serde_json::from_str(&fs::read_to_string(data().join("remote.json")).unwrap()).unwrap();
    for entry in remote {
        let name = entry["name"].as_str().unwrap().to_string();
        let path = cache().join(&name);
        found.push((name, path.is_file().then_some(path)));
    }
    found.sort();
    found
}

/// Past this many lines a list is pinned by its count and a digest of its lines, so that a
/// large module's expectation stays a fraction of its size; its errors are still listed.
const LISTED: usize = 200;

/// By module line, each definition in its `Debug` form or its error.
fn read<T: Debug>(lines: &[ModuleLine<Read<T>>]) -> Value {
    pinned(
        lines
            .iter()
            .map(|line| match &line.def {
                Ok(def) => (line.line, format!("{def:?}")),
                Err(err) => (line.line, format!("error {:?}: {}", err.kind, err.message)),
            })
            .collect(),
    )
}

fn rules(lines: &[ModuleLine<ModuleRule>]) -> Value {
    pinned(
        lines
            .iter()
            .map(|line| {
                let rule = &line.def;
                let policy = match &rule.policy {
                    Policy::Builtin(name) => (*name).to_string(),
                    Policy::Named(name) => format!("<{name}>"),
                };
                let mut text = format!("{} => {policy}", rule.rule);
                if rule.no_resolve {
                    text.push_str(" no-resolve");
                }
                if rule.extended_matching {
                    text.push_str(" extended-matching");
                }
                (line.line, text)
            })
            .collect(),
    )
}

fn pinned(entries: Vec<(u32, String)>) -> Value {
    if entries.len() <= LISTED {
        return entries
            .into_iter()
            .map(|(line, text)| (line.to_string(), Value::String(text)))
            .collect::<serde_json::Map<_, _>>()
            .into();
    }
    let mut hasher = Sha256::new();
    for (line, text) in &entries {
        hasher.update(format!("{line} {text}\n"));
    }
    let errors: serde_json::Map<String, Value> = entries
        .iter()
        .filter(|(_, text)| text.starts_with("error "))
        .map(|(line, text)| (line.to_string(), Value::String(text.clone())))
        .collect();
    json!({
        "count": entries.len(),
        "sha256": format!("{:x}", hasher.finalize()),
        "errors": errors,
    })
}

fn host(entry: &HostEntryDef) -> String {
    let exclude = if entry.exclude { "-" } else { "" };
    let port = if entry.bare {
        String::new()
    } else {
        format!(":{}", entry.port)
    };
    format!("{exclude}{}{port}", entry.pattern)
}

fn source(entry: &SourceEntryDef) -> String {
    let exclude = if entry.exclude { "-" } else { "" };
    format!("{exclude}{}", entry.network)
}

fn items<T>(line: u32, items: &Items<T>, show: fn(&T) -> String) -> Value {
    let mut value =
        json!({"line": line, "items": items.items.iter().map(show).collect::<Vec<_>>().join(", ")});
    if let Some(err) = &items.error {
        value["error"] = json!(format!("{:?}: {}", err.kind, err.message));
    }
    value
}

fn render(def: &ModuleDef) -> String {
    let lists = &def.lists;
    let value = json!({
        "format": def.format,
        "meta": def.meta,
        "off": def.off,
        "arguments": def.arguments,
        "hostname": lists.hostname.iter().map(|line| {
            let mut value = items(line.line, &line.def.items, host);
            if line.def.insert {
                value["insert"] = json!(true);
            }
            value
        }).collect::<Vec<_>>(),
        "force-http-hostname": lists.force_http_hostname.iter().map(|line| items(line.line, &line.def, host)).collect::<Vec<_>>(),
        "skip-server-cert-verify": lists.skip_server_cert_verify.as_ref().map(|line| json!({
            "line": line.line,
            "hosts": line.def.iter().map(host).collect::<Vec<_>>().join(", "),
        })),
        "client-source-address": lists.client_source_address.iter().map(|line| items(line.line, &line.def, source)).collect::<Vec<_>>(),
        "h2": lists.h2,
        "url-rewrite": read(&lists.url_rewrite),
        "header-rewrite": read(&lists.header_rewrite),
        "body-rewrite": read(&lists.body_rewrite),
        "map-local": read(&lists.map_local),
        "request-body-mock": read(&lists.request_body_mock),
        "script": read(&lists.script),
        "rules": rules(&def.rules),
        "rule-sets": def.rule_sets,
        "resources": def.resources,
        "network": def.network,
        "declared-scripts": def.declared_scripts,
        "ignored": def.ignored,
    });
    let mut text = serde_json::to_string_pretty(&value).unwrap();
    text.push('\n');
    text
}

fn environment() -> Environment {
    Environment {
        system: String::new(),
        language: "zh-Hans".to_string(),
    }
}

#[test]
fn every_module_reads_as_its_expectation_says() {
    let bless = std::env::var_os("CONCORD_BLESS").is_some();
    let (arguments, attachments) = (BTreeMap::new(), BTreeMap::new());
    let environment = environment();
    let input = ModuleInput {
        arguments: &arguments,
        attachments: &attachments,
        environment: &environment,
    };
    let (mut stale, mut missing) = (Vec::new(), Vec::new());
    for (name, path) in modules() {
        let Some(path) = path else {
            missing.push(name);
            continue;
        };
        let text = fs::read_to_string(&path).unwrap();
        let actual = render(&read_module(&text, &input));
        let expected = data().join(format!("{name}{EXPECT}"));
        if bless {
            fs::write(&expected, &actual).unwrap();
        } else if fs::read_to_string(&expected).ok().as_deref() != Some(actual.as_str()) {
            stale.push(name);
        }
    }
    if !missing.is_empty() {
        eprintln!("not fetched, so not read: {missing:?}; run cargo xtask module-corpus");
    }
    assert!(
        stale.is_empty(),
        "{stale:?} differ; run with CONCORD_BLESS=1 after checking the change"
    );
}

#[test]
fn every_expectation_has_its_module() {
    let names: Vec<String> = modules().into_iter().map(|(name, _)| name).collect();
    for entry in fs::read_dir(data()).unwrap() {
        let file = entry.unwrap().file_name().to_string_lossy().into_owned();
        if let Some(name) = file.strip_suffix(EXPECT) {
            assert!(
                names.iter().any(|each| each == name),
                "{file} has no module"
            );
        }
    }
}
