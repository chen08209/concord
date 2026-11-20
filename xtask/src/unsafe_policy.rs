//! Holds `unsafe` to the crates `.agents/rules.md` allows it in. The workspace denies
//! `unsafe_code`, but any file can lift that with an attribute, so where the attribute appears
//! is checked from source. Clippy's `undocumented_unsafe_blocks` holds each block to its
//! `// SAFETY:` comment.

use std::path::Path;

use crate::stream_policy::{blank, rust_files};

const SOURCE_ROOTS: &[&str] = &["crates", "bins", "tools"];
const ALLOWED: &[&str] = &[
    "crates/platform/",
    "crates/tun/",
    "crates/ffi/",
    "bins/",
    "tools/",
];
/// Files outside `ALLOWED` that may lift `unsafe_code`, each named in `.agents/rules.md`.
const EXEMPT: &[&str] = &["crates/mitm/src/quickjs/bytecode.rs"];

/// The workspace's `unsafe_code = "deny"` reaches a member only through `[lints] workspace = true`;
/// a member that drops it can allow `unsafe` without any attribute this check would see.
pub(crate) fn check_lints_inherited(root: &Path) -> Result<(), String> {
    let read = |path: &Path| {
        std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))
    };
    let mut problems = Vec::new();
    for member in members(&read(&root.join("Cargo.toml"))?) {
        if !inherits_lints(&read(&root.join(&member).join("Cargo.toml"))?) {
            problems.push(format!(
                "{member}/Cargo.toml: add `[lints] workspace = true`; every member takes the \
                 workspace lints"
            ));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

fn members(manifest: &str) -> Vec<String> {
    let Some(start) = manifest.find("members = [") else {
        return Vec::new();
    };
    let list = manifest
        .get(start + "members = [".len()..)
        .and_then(|rest| rest.split(']').next())
        .unwrap_or_default();
    list.split(',')
        .map(|item| item.trim().trim_matches('"').to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn inherits_lints(manifest: &str) -> bool {
    let compact = |line: &str| line.split('#').next().unwrap_or_default().replace(' ', "");
    let mut in_lints = false;
    for line in manifest.lines().map(compact) {
        if line.starts_with('[') {
            in_lints = line == "[lints]";
            continue;
        }
        if (in_lints && line == "workspace=true")
            || line == "lints.workspace=true"
            || line == "lints={workspace=true}"
        {
            return true;
        }
    }
    false
}

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let mut files = Vec::new();
    for dir in SOURCE_ROOTS {
        rust_files(&root.join(dir), &mut files)?;
    }
    files.sort();
    let mut sources = Vec::new();
    for file in files {
        let source =
            std::fs::read_to_string(&file).map_err(|err| format!("{}: {err}", file.display()))?;
        let name = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        sources.push((name, source));
    }
    let problems = problems(&sources, EXEMPT);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

fn problems(sources: &[(String, String)], exempt: &[&str]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut used = Vec::new();
    for (name, source) in sources {
        let lines = lifts(&blank(source));
        if lines.is_empty() || permitted(name) {
            continue;
        }
        if exempt.contains(&name.as_str()) {
            used.push(name.as_str());
            continue;
        }
        problems.extend(lines.into_iter().map(|line| {
            format!(
                "{name}:{line}: lifts `unsafe_code` outside platform, tun, ffi, bins and tools; \
                 move the call there or add an exemption to `.agents/rules.md` and `EXEMPT`"
            )
        }));
    }
    problems.extend(
        exempt
            .iter()
            .filter(|path| !used.contains(path))
            .map(|path| {
                format!("{path}: exempt but lifts no `unsafe_code`; drop it from `EXEMPT`")
            }),
    );
    problems
}

fn permitted(name: &str) -> bool {
    ALLOWED.iter().any(|prefix| name.starts_with(prefix))
        || name.split('/').any(|part| part == "tests")
}

/// The lines of `allow(...)` and `expect(...)` attribute arguments that name `unsafe_code`,
/// including inside `cfg_attr`.
fn lifts(blanked: &str) -> Vec<usize> {
    let mut lines = Vec::new();
    for keyword in ["allow", "expect"] {
        let mut from = 0;
        while let Some(found) = blanked.get(from..).and_then(|rest| rest.find(keyword)) {
            let start = from + found;
            from = start + keyword.len();
            let preceded = blanked
                .get(..start)
                .and_then(|before| before.chars().next_back())
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
            let rest = blanked.get(from..).unwrap_or_default();
            let Some(args) = rest.trim_start().strip_prefix('(') else {
                continue;
            };
            if preceded {
                continue;
            }
            let args = args.split(')').next().unwrap_or_default();
            if args
                .split(|c: char| c == ',' || c.is_whitespace())
                .any(|word| word == "unsafe_code")
            {
                lines.push(
                    blanked
                        .get(..start)
                        .unwrap_or_default()
                        .matches('\n')
                        .count()
                        + 1,
                );
            }
        }
    }
    lines.sort_unstable();
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(name: &str, text: &str) -> (String, String) {
        (name.to_string(), text.to_string())
    }

    #[test]
    fn the_workspace_keeps_unsafe_where_the_rules_allow_it() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        if let Err(problems) = check(&root) {
            panic!("{problems}");
        }
    }

    #[test]
    fn every_member_inherits_the_workspace_lints() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        if let Err(problems) = check_lints_inherited(&root) {
            panic!("{problems}");
        }
    }

    #[test]
    fn members_and_lint_inheritance_are_read_from_the_manifests() {
        assert_eq!(
            members("[workspace]\nmembers = [\n    \"crates/a\",\n    \"xtask\",\n]\n"),
            ["crates/a", "xtask"]
        );
        assert!(inherits_lints(
            "[package]\nname = \"a\"\n\n[lints]\nworkspace = true\n"
        ));
        assert!(inherits_lints("lints.workspace = true\n"));
        assert!(inherits_lints("lints = { workspace = true }\n"));
        assert!(!inherits_lints("[lints.rust]\nunsafe_code = \"allow\"\n"));
        assert!(!inherits_lints("[package]\nworkspace = true\n"));
        assert!(!inherits_lints("[lints]\n# workspace = true\n"));
    }

    #[test]
    fn an_allow_outside_the_permitted_crates_is_reported() {
        let found = problems(
            &[source(
                "crates/net/src/a.rs",
                "fn a() {}\n#[allow(\n    unsafe_code,\n    reason = \"x\"\n)]\nfn b() {}\n",
            )],
            &[],
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with("crates/net/src/a.rs:2: lifts"),
            "{found:?}"
        );
    }

    #[test]
    fn expect_inner_attributes_and_cfg_attr_count() {
        let text = "#![expect(unsafe_code, reason = \"x\")]\n\
                    #[cfg_attr(unix, allow(dead_code, unsafe_code))]\nfn a() {}\n";
        assert_eq!(lifts(&blank(text)), [1, 2]);
    }

    #[test]
    fn comments_strings_and_other_lints_do_not_count() {
        let text = "// #[allow(unsafe_code)]\nconst A: &str = \"allow(unsafe_code)\";\n\
                    #[allow(unsafe_code_ish, reason = \"x\")]\nfn disallow(unsafe_code: u8) {}\n";
        assert!(lifts(&blank(text)).is_empty());
    }

    #[test]
    fn permitted_crates_tests_and_exemptions_pass() {
        let lift = "#[allow(unsafe_code, reason = \"x\")]\nfn a() {}\n";
        let sources = [
            source("crates/platform/src/a.rs", lift),
            source("bins/desktop/src/main.rs", lift),
            source("crates/engine/tests/alloc.rs", lift),
            source("crates/tls/src/boring_backend.rs", lift),
        ];
        assert_eq!(
            problems(&sources, &["crates/tls/src/boring_backend.rs"]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_stale_exemption_is_reported() {
        let found = problems(
            &[source("crates/tls/src/boring_backend.rs", "fn a() {}\n")],
            &["crates/tls/src/boring_backend.rs"],
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("exempt but lifts no"), "{found:?}");
    }
}
