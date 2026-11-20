//! `GeoSite.dat`: a v2ray protobuf list, read one category at a time.

use std::fs::File;
use std::io::{BufReader, Read, Seek};
use std::path::Path;

use aho_corasick::AhoCorasick;
use prost::Message;
use regex::Regex;

use crate::domain_set::{DomainSet, DomainSetBuilder};

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Attribute {
    #[prost(string, tag = "1")]
    pub key: String,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct Domain {
    #[prost(int32, tag = "1")]
    pub kind: i32,
    #[prost(string, tag = "2")]
    pub value: String,
    #[prost(message, repeated, tag = "3")]
    pub attribute: Vec<Attribute>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GeoSiteEntry {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub domain: Vec<Domain>,
}

const KIND_PLAIN: i32 = 0;
const KIND_REGEX: i32 = 1;
const KIND_DOMAIN: i32 = 2;
const KIND_FULL: i32 = 3;

/// Finds the entry whose country code equals `code` ignoring case and returns
/// its message bytes.
pub(crate) fn find_entry(path: &Path, code: &str) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|err| format!("failed to open file: {err}"))?;
    find_entry_in(BufReader::with_capacity(16 * 1024, file), code)
}

pub(crate) fn find_entry_in<R: Read + Seek>(mut reader: R, code: &str) -> Result<Vec<u8>, String> {
    loop {
        let mut tag = [0u8; 1];
        match reader.read(&mut tag) {
            Ok(0) => return Err("code not found".to_string()),
            Ok(_) => {}
            Err(_) => return Err("failed to read bytes".to_string()),
        }
        if tag[0] != 10 {
            return Err("invalid geodata file".to_string());
        }
        let length = read_varint(&mut reader)?;
        let mut inner_tag = [0u8; 1];
        reader
            .read_exact(&mut inner_tag)
            .map_err(|_| "failed to read expected length of bytes".to_string())?;
        if inner_tag[0] != 10 {
            return Err("invalid geodata file".to_string());
        }
        let (code_len, code_len_bytes) = read_varint_counted(&mut reader)?;
        if code_len > length || code_len > 4096 {
            return Err("invalid geodata file".to_string());
        }
        let mut name = vec![0u8; code_len as usize];
        reader
            .read_exact(&mut name)
            .map_err(|_| "failed to read expected length of bytes".to_string())?;
        let prefix = 1 + code_len_bytes as u64 + code_len;
        let wanted = String::from_utf8_lossy(&name).to_lowercase() == code.to_lowercase();
        let rest = length
            .checked_sub(prefix)
            .ok_or_else(|| "invalid geodata file".to_string())?;
        if wanted {
            if rest > (1 << 30) {
                return Err("invalid geodata file".to_string());
            }
            let mut message = Vec::with_capacity(length as usize);
            message.push(10);
            write_varint(&mut message, code_len);
            message.extend_from_slice(&name);
            let start = message.len();
            message.resize(start + rest as usize, 0);
            reader
                .read_exact(message.get_mut(start..).unwrap_or_default())
                .map_err(|_| "failed to read expected length of bytes".to_string())?;
            return Ok(message);
        }
        reader
            .seek_relative(i64::try_from(rest).map_err(|_| "invalid geodata file".to_string())?)
            .map_err(|_| "failed to read bytes".to_string())?;
        let _ = reader.stream_position();
    }
}

fn read_varint<R: Read>(reader: &mut R) -> Result<u64, String> {
    read_varint_counted(reader).map(|(value, _)| value)
}

fn read_varint_counted<R: Read>(reader: &mut R) -> Result<(u64, usize), String> {
    let mut value = 0u64;
    for count in 0..10usize {
        let mut byte = [0u8; 1];
        reader
            .read_exact(&mut byte)
            .map_err(|_| "failed to read expected length of bytes".to_string())?;
        value |= u64::from(byte[0] & 0x7f) << (7 * count);
        if byte[0] < 128 {
            return Ok((value, count + 1));
        }
    }
    Err("invalid geodata varint length".to_string())
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 128 {
        out.push((value & 0x7f) as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Matches a GeoSite category the way mihomo's succinct matcher group does.
pub struct SiteMatcher {
    set: Option<DomainSet>,
    plain: Vec<Box<str>>,
    plain_index: Option<AhoCorasick>,
    regexes: Vec<Regex>,
    count: usize,
    negate: bool,
}

impl SiteMatcher {
    pub(super) fn from_entry(
        entry: GeoSiteEntry,
        attrs: &[String],
        negate: bool,
    ) -> Result<SiteMatcher, String> {
        let mut builder = DomainSetBuilder::new();
        let mut plain: Vec<Box<str>> = Vec::new();
        let mut regexes = Vec::new();
        let mut count = 0usize;
        for domain in entry.domain {
            if !attrs.iter().all(|want| {
                domain
                    .attribute
                    .iter()
                    .any(|have| have.key.to_lowercase() == *want)
            }) {
                continue;
            }
            count += 1;
            match domain.kind {
                KIND_PLAIN => plain.push(domain.value.into_boxed_str()),
                KIND_REGEX => regexes.push(Regex::new(&domain.value).map_err(|err| {
                    format!("failed to create domain matcher, base error: {err}")
                })?),
                KIND_DOMAIN => builder
                    .insert(&format!("+.{}", domain.value))
                    .map_err(|err| err.to_string())?,
                KIND_FULL => builder
                    .insert(&domain.value)
                    .map_err(|err| err.to_string())?,
                other => return Err(format!("unsupported domain type {other}")),
            }
        }
        let plain_index = (plain.len() > 8)
            .then(|| AhoCorasick::new(plain.iter().map(|p| p.as_bytes())).ok())
            .flatten();
        Ok(SiteMatcher {
            set: builder.build(),
            plain,
            plain_index,
            regexes,
            count,
            negate,
        })
    }

    pub fn matches(&self, host: &str) -> bool {
        if host.is_empty() {
            return false;
        }
        self.raw_match(host) != self.negate
    }

    fn raw_match(&self, host: &str) -> bool {
        if self.set.as_ref().is_some_and(|set| set.has(host)) {
            return true;
        }
        let plain = match &self.plain_index {
            Some(index) => index.is_match(host),
            None => self.plain.iter().any(|p| host.contains(&**p)),
        };
        plain || self.regexes.iter().any(|re| re.is_match(host))
    }

    pub fn count(&self) -> usize {
        self.count
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub(crate) fn site(code: &str, domains: &[(i32, &str, &[&str])]) -> Vec<u8> {
        let entry = GeoSiteEntry {
            country_code: code.to_uppercase(),
            domain: domains
                .iter()
                .map(|(kind, value, attrs)| Domain {
                    kind: *kind,
                    value: (*value).to_string(),
                    attribute: attrs
                        .iter()
                        .map(|key| Attribute {
                            key: (*key).to_string(),
                        })
                        .collect(),
                })
                .collect(),
        };
        let body = entry.encode_to_vec();
        let mut out = vec![10];
        write_varint(&mut out, body.len() as u64);
        out.extend_from_slice(&body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::testing::site;
    use super::*;

    #[test]
    fn find_entry_scans_past_other_categories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("GeoSite.dat");
        let mut data = site("cn", &[(KIND_DOMAIN, "baidu.com", &[])]);
        data.extend(site("google", &[(KIND_FULL, "www.google.com", &[])]));
        data.extend(site("ads", &[(KIND_PLAIN, "adservice", &["ads"])]));
        std::fs::write(&path, &data).unwrap();
        let bytes = find_entry(&path, "GOOGLE").unwrap();
        let entry = GeoSiteEntry::decode(bytes.as_slice()).unwrap();
        assert_eq!(entry.domain.len(), 1);
        assert_eq!(find_entry(&path, "nope").unwrap_err(), "code not found");
    }

    #[test]
    fn site_matcher_group_semantics() {
        let entry = GeoSiteEntry::decode(
            site(
                "x",
                &[
                    (KIND_DOMAIN, "baidu.com", &[]),
                    (KIND_FULL, "exact.example", &[]),
                    (KIND_PLAIN, "adservice", &[]),
                    (KIND_REGEX, r"^ad[0-9]+\.net$", &[]),
                ],
            )
            .get(2..)
            .unwrap(),
        )
        .unwrap();
        let matcher = SiteMatcher::from_entry(entry.clone(), &[], false).unwrap();
        assert!(matcher.matches("baidu.com") && matcher.matches("www.baidu.com"));
        assert!(matcher.matches("exact.example") && !matcher.matches("a.exact.example"));
        assert!(matcher.matches("my-adservice-1.org"));
        assert!(matcher.matches("ad42.net") && !matcher.matches("bad42.net"));
        assert!(!matcher.matches("") && !matcher.matches("google.com"));
        let negated = SiteMatcher::from_entry(entry, &[], true).unwrap();
        assert!(negated.matches("google.com") && !negated.matches("baidu.com"));
        assert!(!negated.matches(""));
    }

    #[test]
    fn attributes_filter_the_category() {
        let bytes = site(
            "x",
            &[
                (KIND_DOMAIN, "a.com", &["ads"]),
                (KIND_DOMAIN, "b.com", &["cn"]),
                (KIND_DOMAIN, "c.com", &["ads", "cn"]),
            ],
        );
        let entry = GeoSiteEntry::decode(bytes.get(2..).unwrap()).unwrap();
        let matcher =
            SiteMatcher::from_entry(entry, &["ads".to_string(), "cn".to_string()], false).unwrap();
        assert!(matcher.matches("c.com") && !matcher.matches("a.com") && !matcher.matches("b.com"));
        assert_eq!(matcher.count(), 1);
    }
}
