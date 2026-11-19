//! Embeds the config crate's module corpus, so `mitm-modules` runs from a harness copied to
//! another machine.

use std::error::Error;
use std::fmt::Write as _;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?)
        .join("../../crates/config/tests/data/modules")
        .canonicalize()?;
    println!("cargo::rerun-if-changed={}", dir.display());
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if !(name.ends_with(".json") || name.ends_with(".md") || name.starts_with("LICENSE")) {
            paths.push(path);
        }
    }
    paths.sort();
    let mut out = String::from("pub const CORPUS: &[(&str, &str)] = &[\n");
    for path in paths {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        writeln!(
            out,
            "    ({name:?}, include_str!({:?})),",
            path.display().to_string()
        )?;
    }
    out.push_str("];\n");
    std::fs::write(
        PathBuf::from(std::env::var("OUT_DIR")?).join("corpus.rs"),
        out,
    )?;
    Ok(())
}
