use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};
use concord_config::mitm::{regex_source, relax};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

use super::Rules;
use crate::pattern::Pattern;

/// Which rules of a list a URL may match. Each pattern is looked up by a few literals one of
/// which every match holds, the set that tells URLs apart best; when they start the pattern
/// after `^`, only at the start of the URL. A pattern with no such set is tried every time.
/// It only narrows the list: each candidate's own pattern still decides.
#[derive(Debug)]
pub(crate) struct UrlIndex {
    literals: Option<AhoCorasick>,
    /// Per literal: the rule it stands for, and whether it has to start the URL.
    owners: Vec<(usize, bool)>,
    always: Vec<usize>,
}

impl UrlIndex {
    pub(crate) fn new<'p>(patterns: impl IntoIterator<Item = Option<&'p Pattern>>) -> UrlIndex {
        let mut literals = Vec::new();
        let mut owners = Vec::new();
        let mut always = Vec::new();
        for (index, pattern) in patterns.into_iter().enumerate() {
            match pattern.and_then(|pattern| lookup(&relax(&regex_source(pattern.source())))) {
                Some(Lookup { found, anchored }) => {
                    owners.extend(std::iter::repeat_n((index, anchored), found.len()));
                    literals.extend(found);
                }
                None => always.push(index),
            }
        }
        let built = if literals.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .match_kind(MatchKind::Standard)
                .build(&literals)
                .ok()
        };
        if built.is_none() {
            always.extend(owners.drain(..).map(|(index, _)| index));
            always.sort_unstable();
            always.dedup();
        }
        UrlIndex {
            literals: built,
            owners,
            always,
        }
    }

    /// In list order.
    pub(crate) fn candidates(&self, url: &str) -> Vec<usize> {
        let mut found = self.always.clone();
        if let Some(literals) = &self.literals {
            found.extend(literals.find_overlapping_iter(url).filter_map(|hit| {
                let (index, anchored) = *self.owners.get(hit.pattern().as_usize())?;
                (!anchored || hit.start() == 0).then_some(index)
            }));
            found.sort_unstable();
            found.dedup();
        }
        found
    }

    #[cfg(test)]
    pub(crate) fn always(&self) -> &[usize] {
        &self.always
    }

    #[cfg(test)]
    pub(crate) fn heap_bytes(&self) -> usize {
        self.literals.as_ref().map_or(0, AhoCorasick::memory_usage)
            + self.owners.capacity() * std::mem::size_of::<(usize, bool)>()
    }
}

#[cfg(test)]
#[path = "index_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "corpus_tests.rs"]
mod corpus_tests;

/// Literals a match must hold, and whether they are prefixes it must start with.
struct Lookup {
    found: Vec<Vec<u8>>,
    anchored: bool,
}

/// More alternatives than this are cheaper to try than to look up.
const MOST: usize = 32;

fn lookup(source: &str) -> Option<Lookup> {
    let hir = regex_syntax::parse(source).ok()?;
    let anchored = hir.properties().look_set_prefix().contains(Look::Start);
    let (found, at_start) = required(&hir)?;
    Some(Lookup {
        found,
        anchored: anchored && at_start,
    })
}

/// The bytes of the weakest literal that tell one URL from another: nearly every URL has a
/// scheme and `://`, so only what follows them counts.
fn strength(found: &[Vec<u8>]) -> usize {
    found
        .iter()
        .map(|literal| {
            let scheme = literal
                .windows(3)
                .rposition(|window| window == b"://")
                .map_or(0, |at| at + 3);
            literal.len() - scheme
        })
        .min()
        .unwrap_or(0)
}

/// Every string `hir` matches, when they are a few.
fn exact(hir: &Hir) -> Option<Vec<Vec<u8>>> {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Some(vec![Vec::new()]),
        HirKind::Literal(literal) => Some(vec![literal.0.to_vec()]),
        HirKind::Class(class) => {
            let mut found = Vec::new();
            match class {
                Class::Unicode(class) => {
                    for range in class.iter() {
                        for c in range.start()..=range.end() {
                            found.push(c.to_string().into_bytes());
                            if found.len() > FEW {
                                return None;
                            }
                        }
                    }
                }
                Class::Bytes(class) => {
                    for range in class.iter() {
                        for b in range.start()..=range.end() {
                            found.push(vec![b]);
                            if found.len() > FEW {
                                return None;
                            }
                        }
                    }
                }
            }
            Some(found)
        }
        HirKind::Capture(capture) => exact(&capture.sub),
        HirKind::Repetition(repetition) if repetition.min == 0 && repetition.max == Some(1) => {
            let mut found = exact(&repetition.sub)?;
            found.push(Vec::new());
            Some(found)
        }
        HirKind::Alternation(branches) => {
            let mut found = Vec::new();
            for branch in branches {
                found.extend(exact(branch)?);
            }
            (found.len() <= MOST).then_some(found)
        }
        HirKind::Concat(parts) => parts.iter().try_fold(vec![Vec::new()], |found, part| {
            product(&found, &exact(part)?)
        }),
        HirKind::Repetition(_) => None,
    }
}

/// Each of `left` followed by each of `right`, while they are at most [MOST].
fn product(left: &[Vec<u8>], right: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    if left.len() * right.len() > MOST {
        return None;
    }
    let mut found = Vec::with_capacity(left.len() * right.len());
    for head in left {
        for tail in right {
            let mut literal = head.clone();
            literal.extend_from_slice(tail);
            found.push(literal);
        }
    }
    found.sort_unstable();
    found.dedup();
    Some(found)
}

/// Literals one of which every match of `hir` contains, the strongest set found, and whether
/// a match starts with them.
fn required(hir: &Hir) -> Option<(Vec<Vec<u8>>, bool)> {
    let usable =
        |found: &[Vec<u8>]| !found.is_empty() && found.iter().all(|literal| !literal.is_empty());
    if let Some(found) = exact(hir).filter(|found| usable(found)) {
        return Some((found, true));
    }
    match hir.kind() {
        HirKind::Capture(capture) => required(&capture.sub),
        HirKind::Repetition(repetition) if repetition.min >= 1 => required(&repetition.sub),
        HirKind::Alternation(branches) => {
            let mut found = Vec::new();
            let mut at_start = true;
            for branch in branches {
                let (branch, start) = required(branch)?;
                found.extend(branch);
                at_start &= start;
            }
            (found.len() <= MOST).then_some((found, at_start))
        }
        HirKind::Concat(parts) => {
            let mut best: Option<(Vec<Vec<u8>>, bool)> = None;
            let mut keep = |found: Vec<Vec<u8>>, at_start: bool| {
                if usable(&found)
                    && best
                        .as_ref()
                        .is_none_or(|(kept, _)| strength(&found) > strength(kept))
                {
                    best = Some((found, at_start));
                }
            };
            let mut run: Vec<Vec<u8>> = vec![Vec::new()];
            let mut run_at_start = true;
            for part in parts {
                if let Some(part_exact) = exact(part) {
                    match product(&run, &part_exact) {
                        Some(longer) => run = longer,
                        None => {
                            keep(std::mem::replace(&mut run, part_exact), run_at_start);
                            run_at_start = false;
                        }
                    }
                    continue;
                }
                keep(std::mem::replace(&mut run, vec![Vec::new()]), run_at_start);
                if let Some((found, _)) = required(part) {
                    keep(found, false);
                }
                run_at_start = false;
            }
            keep(run, run_at_start);
            best
        }
        _ => None,
    }
}

/// A character class of more than this many characters is not spelled out.
const FEW: usize = 10;

#[derive(Debug, Default)]
pub(crate) struct Indexes {
    url_rewrites: OnceLock<UrlIndex>,
    header_rewrites: OnceLock<UrlIndex>,
    body_rewrites: OnceLock<UrlIndex>,
    map_locals: OnceLock<UrlIndex>,
    request_mocks: OnceLock<UrlIndex>,
    scripts: OnceLock<UrlIndex>,
}

fn pick<'r, T>(
    slot: &OnceLock<UrlIndex>,
    rules: &'r [T],
    pattern: impl Fn(&T) -> Option<&Pattern>,
    url: &str,
) -> impl Iterator<Item = &'r T> {
    slot.get_or_init(|| UrlIndex::new(rules.iter().map(pattern)))
        .candidates(url)
        .into_iter()
        .filter_map(|index| rules.get(index))
}

impl Rules {
    #[cfg(test)]
    pub(crate) fn index_of_url_rewrites(&self) -> &UrlIndex {
        let _ = self.url_rewrite_candidates("");
        self.indexes.url_rewrites.get().expect("built above")
    }

    #[cfg(test)]
    fn lists(&self) -> [(&'static str, usize, &UrlIndex); 6] {
        self.index();
        fn get(slot: &OnceLock<UrlIndex>) -> &UrlIndex {
            slot.get().expect("built by index")
        }
        let indexes = &self.indexes;
        [
            (
                "url-rewrite",
                self.url_rewrites.len(),
                get(&indexes.url_rewrites),
            ),
            (
                "header-rewrite",
                self.header_rewrites.len(),
                get(&indexes.header_rewrites),
            ),
            (
                "body-rewrite",
                self.body_rewrites.len(),
                get(&indexes.body_rewrites),
            ),
            ("map-local", self.map_locals.len(), get(&indexes.map_locals)),
            (
                "request-mock",
                self.request_mocks.len(),
                get(&indexes.request_mocks),
            ),
            ("script", self.scripts.len(), get(&indexes.scripts)),
        ]
    }

    #[cfg(test)]
    pub(crate) fn index_report(&self) -> Vec<(&'static str, usize, usize, usize)> {
        self.lists()
            .into_iter()
            .map(|(name, total, index)| (name, total, index.always().len(), index.heap_bytes()))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn candidate_counts(&self, url: &str) -> Vec<(&'static str, usize)> {
        self.lists()
            .into_iter()
            .map(|(name, _, index)| (name, index.candidates(url).len()))
            .collect()
    }

    /// Builds every list's index now, so that the first request does not.
    pub(crate) fn index(&self) {
        let _ = self.url_rewrite_candidates("");
        let _ = self.header_rewrite_candidates("");
        let _ = self.body_rewrite_candidates("");
        let _ = self.map_local_candidates("");
        let _ = self.request_mock_candidates("");
        let _ = self.script_candidates("");
    }

    pub(crate) fn url_rewrite_candidates(
        &self,
        url: &str,
    ) -> impl Iterator<Item = &super::UrlRewrite> {
        pick(
            &self.indexes.url_rewrites,
            &self.url_rewrites,
            |rule| Some(&rule.pattern),
            url,
        )
    }

    pub(crate) fn header_rewrite_candidates(
        &self,
        url: &str,
    ) -> impl Iterator<Item = &super::HeaderRewrite> {
        pick(
            &self.indexes.header_rewrites,
            &self.header_rewrites,
            |rule| Some(&rule.pattern),
            url,
        )
    }

    pub(crate) fn body_rewrite_candidates(
        &self,
        url: &str,
    ) -> impl Iterator<Item = &std::sync::Arc<super::BodyRewrite>> {
        pick(
            &self.indexes.body_rewrites,
            &self.body_rewrites,
            |rule| Some(&rule.pattern),
            url,
        )
    }

    pub(crate) fn map_local_candidates(&self, url: &str) -> impl Iterator<Item = &super::MapLocal> {
        pick(
            &self.indexes.map_locals,
            &self.map_locals,
            |rule| Some(&rule.pattern),
            url,
        )
    }

    pub(crate) fn request_mock_candidates(
        &self,
        url: &str,
    ) -> impl Iterator<Item = &super::MapLocal> {
        pick(
            &self.indexes.request_mocks,
            &self.request_mocks,
            |rule| Some(&rule.pattern),
            url,
        )
    }

    pub(crate) fn script_candidates(
        &self,
        url: &str,
    ) -> impl Iterator<Item = &std::sync::Arc<crate::script::Script>> {
        pick(
            &self.indexes.scripts,
            &self.scripts,
            |script| script.pattern(),
            url,
        )
    }
}
