//! Indexes over a run of adjacent same-family rules. Each answers "the first
//! rule at or after `from` that matches", so a linear scan and the index agree.

use std::net::IpAddr;

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use concord_config::filter::Matcher;

use crate::eval::Ev;
use crate::index::{HashIdx, SuffixHash, hash_key};
use crate::table::{RuleTable, TableBuilder};
use crate::text::wildcard_match;

pub(crate) enum DomainItem {
    Exact,
    Suffix,
    Keyword,
    Wildcard,
    Regex(Matcher),
}

enum Keywords {
    None,
    Few(Vec<(u32, Box<str>)>),
    Many {
        automaton: AhoCorasick,
        rules: Box<[u32]>,
    },
}

pub(crate) struct DomainRun {
    pub(crate) start: u32,
    pub(crate) end: u32,
    /// Its rules ask for `extended-matching`.
    extended: bool,
    exact: HashIdx,
    suffix: HashIdx,
    subdomain: HashIdx,
    keywords: Keywords,
    wildcards: Vec<(u32, Box<[u8]>)>,
    regexes: Vec<(u32, Matcher)>,
}

const KEYWORD_AUTOMATON_FROM: usize = 16;

fn subdomain_literal(pattern: &str) -> Option<&str> {
    let rest = pattern.strip_prefix("*.")?;
    (!rest.is_empty() && !rest.contains(['*', '?'])).then_some(rest)
}

impl DomainRun {
    pub(crate) fn build(
        start: u32,
        end: u32,
        extended: bool,
        items: Vec<(u32, DomainItem)>,
        table: &TableBuilder,
    ) -> DomainRun {
        let mut exact = Vec::new();
        let mut suffix = Vec::new();
        let mut subdomain = Vec::new();
        let mut keywords: Vec<(u32, Box<str>)> = Vec::new();
        let mut wildcards = Vec::new();
        let mut regexes = Vec::new();
        for (idx, item) in items {
            let payload = table.payload(idx).unwrap_or_default();
            match item {
                DomainItem::Exact => exact.push((hash_key(payload), idx)),
                DomainItem::Suffix => suffix.push((hash_key(payload), idx)),
                DomainItem::Keyword => keywords.push((idx, payload.into())),
                DomainItem::Wildcard => match subdomain_literal(payload) {
                    Some(literal) => subdomain.push((hash_key(literal), idx)),
                    None => wildcards.push((idx, payload.as_bytes().into())),
                },
                DomainItem::Regex(matcher) => regexes.push((idx, matcher)),
            }
        }
        let keywords = if keywords.is_empty() {
            Keywords::None
        } else if keywords.len() < KEYWORD_AUTOMATON_FROM {
            Keywords::Few(keywords)
        } else {
            let built = AhoCorasick::builder()
                .match_kind(MatchKind::Standard)
                .kind(Some(AhoCorasickKind::ContiguousNFA))
                .build(keywords.iter().map(|k| k.1.as_bytes()));
            match built {
                Ok(automaton) => Keywords::Many {
                    automaton,
                    rules: keywords.iter().map(|k| k.0).collect(),
                },
                Err(_) => Keywords::Few(keywords),
            }
        };
        DomainRun {
            start,
            end,
            extended,
            exact: HashIdx::build(exact),
            suffix: HashIdx::build(suffix),
            subdomain: HashIdx::build(subdomain),
            keywords,
            wildcards,
            regexes,
        }
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.exact.heap_bytes() + self.suffix.heap_bytes() + self.subdomain.heap_bytes()
    }

    /// As [DomainRun::next_from] for the flow's name, and for its other names when the run's
    /// rules ask for `extended-matching`.
    pub(crate) fn next_in(&self, ev: &Ev<'_>, from: u32, table: &RuleTable) -> Option<u32> {
        let first = self.next_from(ev.host, from, table);
        if !self.extended {
            return first;
        }
        ev.other_hosts()
            .into_iter()
            .flatten()
            .filter_map(|host| self.next_from(host, from, table))
            .chain(first)
            .min()
    }

    /// The smallest rule index in `from..end` whose condition holds for `host`.
    pub(crate) fn next_from(&self, host: &str, from: u32, table: &RuleTable) -> Option<u32> {
        let from = from.max(self.start);
        let mut best = u32::MAX;
        let bytes = host.as_bytes();
        if !self.exact.is_empty() || !self.suffix.is_empty() || !self.subdomain.is_empty() {
            let mut hash = SuffixHash::new();
            for at in (0..bytes.len()).rev() {
                hash.push(bytes.get(at).copied().unwrap_or(0));
                let boundary = at == 0 || bytes.get(at - 1) == Some(&b'.');
                if !boundary {
                    continue;
                }
                let key = hash.finish();
                let tail = host.get(at..).unwrap_or_default();
                if at == 0 {
                    let hit = self
                        .exact
                        .first_from(key, from, |i| table.payload(i) == Some(host));
                    best = best.min(hit.unwrap_or(u32::MAX));
                }
                let hit = self
                    .suffix
                    .first_from(key, from, |i| table.payload(i) == Some(tail));
                best = best.min(hit.unwrap_or(u32::MAX));
                if at > 0 {
                    let hit = self.subdomain.first_from(key, from, |i| {
                        table.payload(i).and_then(|p| p.strip_prefix("*.")) == Some(tail)
                    });
                    best = best.min(hit.unwrap_or(u32::MAX));
                }
            }
        }
        match &self.keywords {
            Keywords::None => {}
            Keywords::Few(list) => {
                for (idx, keyword) in list {
                    if *idx >= from && *idx < best && host.contains(&**keyword) {
                        best = *idx;
                    }
                }
            }
            Keywords::Many { automaton, rules } => {
                for found in automaton.find_overlapping_iter(host) {
                    if let Some(&idx) = rules.get(found.pattern().as_usize())
                        && idx >= from
                        && idx < best
                    {
                        best = idx;
                    }
                }
            }
        }
        let first = self.wildcards.partition_point(|w| w.0 < from);
        for (idx, pattern) in self.wildcards.get(first..).unwrap_or_default() {
            if *idx >= best {
                break;
            }
            if wildcard_match(pattern, bytes, false) {
                best = *idx;
                break;
            }
        }
        let first = self.regexes.partition_point(|r| r.0 < from);
        for (idx, matcher) in self.regexes.get(first..).unwrap_or_default() {
            if *idx >= best {
                break;
            }
            if matcher.is_match(host) {
                best = *idx;
                break;
            }
        }
        (best != u32::MAX).then_some(best)
    }
}

pub(crate) struct IpRun {
    pub(crate) start: u32,
    pub(crate) end: u32,
    pub(crate) src: bool,
    pub(crate) resolves: bool,
    v4: HashIdx,
    lens4: Box<[u8]>,
    v6: Vec<Lane6>,
}

type Lane6 = (u8, Box<[(u128, u32)]>);

fn mask4(len: u8) -> u32 {
    match len {
        0 => 0,
        l => u32::MAX << (32 - u32::from(l.min(32))),
    }
}

fn mask6(len: u8) -> u128 {
    match len {
        0 => 0,
        l => u128::MAX << (128 - u32::from(l.min(128))),
    }
}

impl IpRun {
    pub(crate) fn build(
        start: u32,
        end: u32,
        src: bool,
        resolves: bool,
        nets: &[(u32, IpAddr, u8)],
    ) -> IpRun {
        let mut v4 = Vec::new();
        let mut lens4 = Vec::new();
        let mut v6: Vec<(u8, Vec<(u128, u32)>)> = Vec::new();
        for &(idx, addr, len) in nets {
            match addr {
                IpAddr::V4(addr) => {
                    let net = u32::from(addr) & mask4(len);
                    v4.push(((u64::from(len) << 32) | u64::from(net), idx));
                    if !lens4.contains(&len) {
                        lens4.push(len);
                    }
                }
                IpAddr::V6(addr) => {
                    let net = u128::from(addr) & mask6(len);
                    match v6.iter_mut().find(|(l, _)| *l == len) {
                        Some((_, list)) => list.push((net, idx)),
                        None => v6.push((len, vec![(net, idx)])),
                    }
                }
            }
        }
        let v6 = v6
            .into_iter()
            .map(|(len, mut list)| {
                list.sort_unstable();
                (len, list.into_boxed_slice())
            })
            .collect();
        IpRun {
            start,
            end,
            src,
            resolves,
            v4: HashIdx::build(v4),
            lens4: lens4.into_boxed_slice(),
            v6,
        }
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.v4.heap_bytes() + self.v6.iter().map(|(_, l)| l.len() * 32).sum::<usize>()
    }

    pub(crate) fn next_from(&self, ip: IpAddr, from: u32) -> Option<u32> {
        let from = from.max(self.start);
        let mut best = u32::MAX;
        match ip {
            IpAddr::V4(ip) => {
                let bits = u32::from(ip);
                for &len in self.lens4.iter() {
                    let key = (u64::from(len) << 32) | u64::from(bits & mask4(len));
                    if let Some(idx) = self.v4.first_from(key, from, |_| true) {
                        best = best.min(idx);
                    }
                }
            }
            IpAddr::V6(ip) => {
                let bits = u128::from(ip);
                for (len, list) in &self.v6 {
                    let net = bits & mask6(*len);
                    let at = list.partition_point(|e| *e < (net, from));
                    if let Some(&(found, idx)) = list.get(at)
                        && found == net
                    {
                        best = best.min(idx);
                    }
                }
            }
        }
        (best != u32::MAX).then_some(best)
    }
}
