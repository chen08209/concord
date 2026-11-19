//! The remote files modules read, kept in the MITM resources directory under names their
//! content gives, with an index from each URL to its file and the last fetch's outcome.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use concord_common::sync::lock;
use concord_config::mitm::modules::{AppliedModule, MITM_DIR, RESOURCES_DIR, stored_name};
use concord_group::{FetchErrorKind, Fetcher};
use concord_platform::HomeDir;
use serde::{Deserialize, Serialize};

use crate::error::ResourceError;
use crate::resources::{download, rule_set_request};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FailureReason {
    Http,
    Dns,
    Tls,
    Timeout,
    Connection,
    Other,
}

/// Why a remote file could not be fetched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchFailure {
    pub reason: FailureReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub detail: String,
}

impl FetchFailure {
    fn of(err: &ResourceError) -> FetchFailure {
        let (reason, status) = match err {
            ResourceError::Status(code) => (FailureReason::Http, Some(*code)),
            ResourceError::Fetch(fetch) => (
                match fetch.kind {
                    FetchErrorKind::Dns => FailureReason::Dns,
                    FetchErrorKind::Tls => FailureReason::Tls,
                    FetchErrorKind::Timeout => FailureReason::Timeout,
                    FetchErrorKind::Connection => FailureReason::Connection,
                    FetchErrorKind::Other => FailureReason::Other,
                },
                None,
            ),
            ResourceError::Load(_) | ResourceError::Other(_) => (FailureReason::Other, None),
        };
        FetchFailure {
            reason,
            status,
            detail: err.to_string(),
        }
    }

    fn local(err: &std::io::Error) -> FetchFailure {
        FetchFailure {
            reason: FailureReason::Other,
            status: None,
            detail: err.to_string(),
        }
    }
}

impl std::fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<FetchFailure>,
    /// Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fetched_at: Option<u64>,
}

/// The remote files by URL, and the scripts modules carry in their text that the store wrote
/// out, by name: the files it may remove.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Index {
    #[serde(default)]
    urls: BTreeMap<String, Entry>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    inline: BTreeSet<String>,
}

impl Index {
    /// An index written before the store recorded its inline scripts maps URLs alone.
    fn read(bytes: &[u8]) -> Option<Index> {
        serde_json::from_slice(bytes).ok().or_else(|| {
            serde_json::from_slice(bytes).ok().map(|urls| Index {
                urls,
                inline: BTreeSet::new(),
            })
        })
    }

    fn uses(&self, file: &str) -> bool {
        self.inline.contains(file)
            || self
                .urls
                .values()
                .any(|entry| entry.file.as_deref() == Some(file))
    }
}

/// Where a module's remote file stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ResourceState {
    Ok,
    /// The last fetch failed; a file an earlier fetch stored stays in use.
    Failed,
    Missing,
    Fetching,
}

pub(crate) struct ModuleResources {
    home: Arc<HomeDir>,
    fetcher: Arc<dyn Fetcher>,
    index: Mutex<Index>,
    fetching: Mutex<HashSet<String>>,
}

fn index_path() -> String {
    format!("{MITM_DIR}/module-resources.json")
}

fn resource_path(file: &str) -> String {
    format!("{RESOURCES_DIR}/{file}")
}

/// A name the host gives for a file in the resources directory, not a path out of it.
fn plain_name(file: &str) -> bool {
    !file.is_empty() && file != "." && file != ".." && !file.contains(['/', '\\'])
}

/// Takes a URL off the fetching set however its fetch ends, a dropped task included: the
/// engine cancels its tasks on shutdown and keeps the store across a restart in one home.
struct Fetching<'a> {
    set: &'a Mutex<HashSet<String>>,
    url: &'a str,
}

impl Drop for Fetching<'_> {
    fn drop(&mut self) {
        lock(self.set).remove(self.url);
    }
}

impl ModuleResources {
    pub fn open(home: Arc<HomeDir>, fetcher: Arc<dyn Fetcher>) -> ModuleResources {
        let index = std::fs::read(home.join(index_path()))
            .ok()
            .and_then(|bytes| Index::read(&bytes))
            .unwrap_or_default();
        ModuleResources {
            home,
            fetcher,
            index: Mutex::new(index),
            fetching: Mutex::new(HashSet::new()),
        }
    }

    pub fn stored(&self, url: &str) -> Option<String> {
        lock(&self.index)
            .urls
            .get(url)
            .and_then(|entry| entry.file.clone())
    }

    /// Where the file of `url` stands, and why its last fetch failed.
    pub fn state(&self, url: &str) -> (ResourceState, Option<FetchFailure>) {
        let entry = lock(&self.index).urls.get(url).cloned().unwrap_or_default();
        let state = if lock(&self.fetching).contains(url) {
            ResourceState::Fetching
        } else if entry.error.is_some() {
            ResourceState::Failed
        } else if entry.file.is_some() {
            ResourceState::Ok
        } else {
            ResourceState::Missing
        };
        (state, entry.error)
    }

    /// Takes into the index each file the host stored for a URL the index has no file for,
    /// while that file is still there; true when it took any.
    pub fn adopt(&self, modules: &[AppliedModule]) -> bool {
        let mut index = lock(&self.index);
        let mut adopted = false;
        for (url, file) in modules
            .iter()
            .flat_map(|module| &module.spec.adopt_resources)
        {
            let free = index.urls.get(url).is_none_or(|entry| entry.file.is_none());
            if free && plain_name(file) && self.home.join(resource_path(file)).is_file() {
                index.urls.insert(
                    url.clone(),
                    Entry {
                        file: Some(file.clone()),
                        ..Entry::default()
                    },
                );
                adopted = true;
            }
        }
        if adopted {
            self.save(&index);
        }
        adopted
    }

    /// Writes the scripts the modules in force carry in their text that the resources
    /// directory lacks; their names come from their content, so one already there is the same.
    pub fn write_inline(&self, modules: &[AppliedModule]) {
        let mut index = lock(&self.index);
        let mut recorded = false;
        for inline in modules
            .iter()
            .filter(|module| module.in_force())
            .flat_map(|module| &module.def.inline_files)
        {
            if !plain_name(&inline.file) {
                continue;
            }
            let path = resource_path(&inline.file);
            if !self.home.join(&path).is_file()
                && let Err(err) = self.home.write_atomic(&path, inline.content.as_bytes())
            {
                tracing::warn!("[MITM] inline script {}: {err}", inline.file);
                continue;
            }
            recorded |= index.inline.insert(inline.file.clone());
        }
        if recorded {
            self.save(&index);
        }
    }

    /// Removes what the store keeps that none of `modules`, every module the host has, on or
    /// off, reads any longer: the URLs with their files, and the scripts it wrote out. A file a
    /// module attaches is the host's and stays. Nothing goes while a module cannot be read,
    /// since what it reads is unknown, or while a URL is being fetched.
    pub fn collect(&self, modules: &[AppliedModule]) {
        if modules.iter().any(|module| module.problem.is_some()) {
            return;
        }
        let urls: HashSet<&str> = modules
            .iter()
            .flat_map(|module| &module.def.resources)
            .map(|resource| resource.url.as_str())
            .collect();
        let inline: HashSet<&str> = modules
            .iter()
            .flat_map(|module| &module.def.inline_files)
            .map(|inline| inline.file.as_str())
            .collect();
        let attached: HashSet<&str> = modules
            .iter()
            .flat_map(|module| module.spec.attachments.values())
            .map(String::as_str)
            .collect();
        let fetching = lock(&self.fetching).clone();
        let mut index = lock(&self.index);
        let mut dropped = Vec::new();
        let before = (index.urls.len(), index.inline.len());
        index.urls.retain(|url, entry| {
            let keep = urls.contains(url.as_str()) || fetching.contains(url);
            if !keep {
                dropped.extend(entry.file.take());
            }
            keep
        });
        index.inline.retain(|file| {
            let keep = inline.contains(file.as_str());
            if !keep {
                dropped.push(file.clone());
            }
            keep
        });
        if (index.urls.len(), index.inline.len()) == before {
            return;
        }
        for file in dropped {
            if plain_name(&file) && !attached.contains(file.as_str()) && !index.uses(&file) {
                let _ = self.home.remove_file(resource_path(&file));
            }
        }
        self.save(&index);
    }

    /// Fetches `url` and stores what it holds; true when the file in force changed. A URL
    /// already being fetched is left to that fetch.
    pub async fn fetch(&self, url: &str) -> Result<bool, FetchFailure> {
        if !lock(&self.fetching).insert(url.to_string()) {
            return Ok(false);
        }
        let _fetching = Fetching {
            set: &self.fetching,
            url,
        };
        let outcome = self.fetch_and_store(url).await;
        let mut index = lock(&self.index);
        let entry = index.urls.entry(url.to_string()).or_default();
        let result = match outcome {
            Ok(file) => {
                let old = entry.file.replace(file.clone());
                entry.error = None;
                entry.fetched_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .map(|since| since.as_secs());
                let changed = old.as_deref() != Some(file.as_str());
                if let Some(old) = old.filter(|_| changed)
                    && !index.uses(&old)
                {
                    let _ = self.home.remove_file(resource_path(&old));
                }
                Ok(changed)
            }
            Err(failure) => {
                entry.error = Some(failure.clone());
                Err(failure)
            }
        };
        self.save(&index);
        result
    }

    async fn fetch_and_store(&self, url: &str) -> Result<String, FetchFailure> {
        let bytes = download(&*self.fetcher, rule_set_request(url))
            .await
            .map_err(|err| FetchFailure::of(&err))?;
        let file = stored_name(url, &bytes);
        let path = resource_path(&file);
        if !self.home.join(&path).is_file() {
            self.home
                .write_atomic(&path, &bytes)
                .map_err(|err| FetchFailure::local(&err))?;
        }
        Ok(file)
    }

    fn save(&self, index: &Index) {
        let written = serde_json::to_vec_pretty(index)
            .map_err(std::io::Error::other)
            .and_then(|bytes| self.home.write_atomic(index_path(), &bytes));
        if let Err(err) = written {
            tracing::warn!("[MITM] module resources index: {err}");
        }
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
