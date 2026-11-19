//! The files a module's lines read, which the host has Concord download or attaches itself.

use serde::Serialize;

use super::IgnoreReason;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    Script,
    MapLocal,
    Jq,
}

/// A remote file the module's definitions read. Until it is stored they name it by its URL:
/// `ScriptDef::path` and `MapLocalDef::data` hold the URL, which the store maps to its file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResourceDef {
    pub url: String,
    pub kind: ResourceKind,
    /// The lines that read it.
    pub lines: Vec<u32>,
}

/// A script a module carries in its text, which the engine writes into the resources
/// directory under `file`, the name its content gives, before a line reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineFile {
    pub file: String,
    pub content: String,
}

pub(crate) fn is_url(text: &str) -> bool {
    text.get(..8)
        .is_some_and(|head| head.eq_ignore_ascii_case("https://"))
        || text
            .get(..7)
            .is_some_and(|head| head.eq_ignore_ascii_case("http://"))
}

/// Where a path a line names is read from: the URL as it is, or the file the host attached
/// for a relative path.
pub(super) fn locate(
    path: &str,
    kind: ResourceKind,
    line: u32,
    attachments: &std::collections::BTreeMap<String, String>,
    resources: &mut Vec<ResourceDef>,
) -> Result<String, IgnoreReason> {
    if !is_url(path) {
        return attachments
            .get(path)
            .cloned()
            .ok_or(IgnoreReason::NoAttachment);
    }
    match resources.iter_mut().find(|resource| resource.url == path) {
        Some(resource) => {
            if resource.lines.last() != Some(&line) {
                resource.lines.push(line);
            }
        }
        None => resources.push(ResourceDef {
            url: path.to_string(),
            kind,
            lines: vec![line],
        }),
    }
    Ok(path.to_string())
}
