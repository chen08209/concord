//! `xtask module-corpus`: downloads the modules `crates/config/tests/data/modules/remote.json`
//! lists into `target/module-corpus`, or the directory `CONCORD_MODULE_CORPUS` names, and keeps
//! each only when its SHA-256 matches.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Remote {
    name: String,
    url: String,
    sha256: String,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

pub fn run() -> Result<(), String> {
    let list = root().join("crates/config/tests/data/modules/remote.json");
    let text = fs::read_to_string(&list).map_err(|err| format!("{}: {err}", list.display()))?;
    let remote: Vec<Remote> =
        serde_json::from_str(&text).map_err(|err| format!("{}: {err}", list.display()))?;
    let dir = std::env::var_os("CONCORD_MODULE_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| root().join("target/module-corpus"));
    fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    for module in remote {
        let path = dir.join(&module.name);
        if fs::read(&path).is_ok_and(|bytes| digest(&bytes) == module.sha256) {
            continue;
        }
        let output = Command::new("curl")
            .args(["-fsSL", "--retry", "2", &module.url])
            .output()
            .map_err(|err| format!("curl: {err}"))?;
        if !output.status.success() {
            return Err(format!("{}: curl {}", module.url, output.status));
        }
        let got = digest(&output.stdout);
        if got != module.sha256 {
            return Err(format!(
                "{}: sha256 {got}, expected {}",
                module.url, module.sha256
            ));
        }
        fs::write(&path, &output.stdout).map_err(|err| format!("{}: {err}", path.display()))?;
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
