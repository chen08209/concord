//! A missing file is [`GeoError::Missing`] from `ensure` and `site_slot`
//! (where mihomo downloads it); until loaded, rules that need it do not match.

pub(crate) mod dat;
mod mmdb;

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use arc_swap::{ArcSwap, ArcSwapOption};
use concord_common::sync::lock;
use prost::Message;

pub use dat::SiteMatcher;
pub use mmdb::AsnRecord;

use mmdb::{AsnDb, IpDb, Source};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GeoFile {
    Mmdb,
    Asn,
    GeoSite,
}

impl GeoFile {
    fn candidates(self) -> &'static [&'static str] {
        match self {
            GeoFile::Mmdb => &["Country.mmdb", "geoip.db", "geoip.metadb", "GEOIP.metadb"],
            GeoFile::Asn => &["ASN.mmdb"],
            GeoFile::GeoSite => &["GeoSite.dat", "GEOSITE.dat"],
        }
    }

    fn default_name(self) -> &'static str {
        match self {
            GeoFile::Mmdb => "geoip.metadb",
            GeoFile::Asn => "ASN.mmdb",
            GeoFile::GeoSite => "GeoSite.dat",
        }
    }
}

impl fmt::Display for GeoFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            GeoFile::Mmdb => "MMDB",
            GeoFile::Asn => "ASN.mmdb",
            GeoFile::GeoSite => "GeoSite.dat",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeoError {
    Missing { file: GeoFile, path: PathBuf },
    Invalid { file: GeoFile, message: String },
    Load(String),
}

impl fmt::Display for GeoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GeoError::Missing { file, path } => {
                write!(f, "can't find {file}: {}", path.display())
            }
            GeoError::Invalid { file, message } => write!(f, "{file} invalid: {message}"),
            GeoError::Load(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for GeoError {}

pub struct SiteSlot {
    matcher: ArcSwap<SiteMatcher>,
}

impl SiteSlot {
    pub fn matches(&self, host: &str) -> bool {
        self.matcher.load().matches(host)
    }

    pub fn count(&self) -> usize {
        self.matcher.load().count()
    }
}

/// Opens a database file's bytes.
pub type Opener = fn(&Path) -> std::io::Result<Box<dyn AsRef<[u8]> + Send + Sync>>;

pub struct GeoStore {
    open: Opener,
    dir: ArcSwap<PathBuf>,
    mmdb: ArcSwapOption<IpDb>,
    asn: ArcSwapOption<AsnDb>,
    sites: Mutex<HashMap<String, Arc<SiteSlot>>>,
}

impl GeoStore {
    pub fn new(dir: impl Into<PathBuf>) -> GeoStore {
        GeoStore {
            open: read_to_heap,
            dir: ArcSwap::from_pointee(dir.into()),
            mmdb: ArcSwapOption::empty(),
            asn: ArcSwapOption::empty(),
            sites: Mutex::default(),
        }
    }

    /// How a database file is opened; the default reads it onto the heap.
    pub fn with_opener(mut self, open: Opener) -> GeoStore {
        self.open = open;
        self
    }

    pub fn dir(&self) -> PathBuf {
        (**self.dir.load()).clone()
    }

    /// The store outlives configs, and the home directory arrives after it exists.
    pub fn set_dir(&self, dir: impl Into<PathBuf>) {
        self.dir.store(Arc::new(dir.into()));
    }

    pub fn path(&self, file: GeoFile) -> PathBuf {
        let dir = self.dir.load_full();
        let mut names: Vec<String> = std::fs::read_dir(dir.as_path())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|kind| !kind.is_dir()))
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        names.sort();
        let found = names.into_iter().find(|name| {
            file.candidates()
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
        });
        dir.join(found.as_deref().unwrap_or(file.default_name()))
    }

    fn existing(&self, file: GeoFile) -> Result<PathBuf, GeoError> {
        let path = self.path(file);
        if path.is_file() {
            Ok(path)
        } else {
            Err(GeoError::Missing { file, path })
        }
    }

    pub fn exists(&self, file: GeoFile) -> bool {
        self.path(file).is_file()
    }

    /// What an update checks before it replaces a file that is in use.
    pub fn validate(file: GeoFile, bytes: &[u8]) -> Result<(), String> {
        match file {
            GeoFile::Mmdb | GeoFile::Asn => IpDb::validate(bytes),
            GeoFile::GeoSite => dat::find_entry_in(std::io::Cursor::new(bytes), "cn").map(|_| ()),
        }
    }

    /// Whether anything has asked for this resource, so it is worth keeping fresh.
    pub fn in_use(&self, file: GeoFile) -> bool {
        match file {
            GeoFile::Mmdb => self.mmdb.load().is_some(),
            GeoFile::Asn => self.asn.load().is_some(),
            GeoFile::GeoSite => !self.lock().is_empty(),
        }
    }

    pub fn reload(&self, file: GeoFile) -> Result<(), GeoError> {
        match file {
            GeoFile::Mmdb => {
                let path = self.existing(file)?;
                let source = self.open_source(&path, file)?;
                let db = IpDb::from_source(source).map_err(|m| mmdb::invalid(file, m))?;
                self.mmdb.store(Some(Arc::new(db)));
                Ok(())
            }
            GeoFile::Asn => {
                let path = self.existing(file)?;
                let source = self.open_source(&path, file)?;
                let db = AsnDb::from_source(source).map_err(|m| mmdb::invalid(file, m))?;
                self.asn.store(Some(Arc::new(db)));
                Ok(())
            }
            GeoFile::GeoSite => self.reload_sites(),
        }
    }

    fn open_source(&self, path: &Path, file: GeoFile) -> Result<Source, GeoError> {
        (self.open)(path)
            .map(Source::new)
            .map_err(|err| mmdb::invalid(file, err.to_string()))
    }

    pub fn ensure(&self, file: GeoFile) -> Result<(), GeoError> {
        let loaded = match file {
            GeoFile::Mmdb => self.mmdb.load().is_some(),
            GeoFile::Asn => self.asn.load().is_some(),
            GeoFile::GeoSite => {
                self.existing(file)?;
                return Ok(());
            }
        };
        if loaded { Ok(()) } else { self.reload(file) }
    }

    fn reload_sites(&self) -> Result<(), GeoError> {
        self.existing(GeoFile::GeoSite)?;
        let sites: Vec<_> = self
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut first_error = None;
        for (spec, slot) in sites {
            match self.load_site(&spec) {
                Ok(matcher) => slot.matcher.store(Arc::new(matcher)),
                Err(err) => first_error = first_error.or(Some(err)),
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub fn has_country(&self, ip: IpAddr, country: &str) -> bool {
        self.mmdb
            .load()
            .as_ref()
            .is_some_and(|db| db.any_code(ip, |code| code == country))
    }

    pub fn country_codes(&self, ip: IpAddr) -> Vec<String> {
        let ip = unmap(ip);
        let mut codes = Vec::new();
        if let Some(db) = self.mmdb.load().as_ref() {
            db.any_code(ip, |code| {
                codes.push(code.to_string());
                false
            });
        }
        codes
    }

    pub fn asn_is(&self, ip: IpAddr, asn: &str) -> bool {
        let ip = unmap(ip);
        self.asn
            .load()
            .as_ref()
            .is_some_and(|db| db.asn_is(ip, asn))
    }

    pub fn has_asn(&self) -> bool {
        self.asn.load().is_some()
    }

    pub fn asn(&self, ip: IpAddr) -> Option<AsnRecord> {
        let ip = unmap(ip);
        self.asn.load().as_ref().and_then(|db| db.lookup(ip))
    }

    pub fn site_slot(&self, code: &str) -> Result<Arc<SiteSlot>, GeoError> {
        let key = code.to_lowercase();
        if let Some(slot) = self.lock().get(&key) {
            return Ok(slot.clone());
        }
        let matcher = self.load_site(&key)?;
        let slot = Arc::new(SiteSlot {
            matcher: ArcSwap::from_pointee(matcher),
        });
        Ok(self.lock().entry(key).or_insert(slot).clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<SiteSlot>>> {
        lock(&self.sites)
    }

    fn load_site(&self, spec: &str) -> Result<SiteMatcher, GeoError> {
        let (negate, spec) = match spec.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, spec),
        };
        if spec.is_empty() {
            return Err(GeoError::Load(
                "country code could not be empty".to_string(),
            ));
        }
        let mut parts = spec.split('@');
        let list = parts.next().unwrap_or_default().trim();
        let attrs: Vec<String> = parts
            .map(|attr| attr.trim().to_lowercase())
            .filter(|attr| !attr.is_empty())
            .collect();
        if list.is_empty() {
            return Err(GeoError::Load(format!("empty listname in rule: {spec}")));
        }
        let path = self.existing(GeoFile::GeoSite)?;
        let bytes = dat::find_entry(&path, list).map_err(|err| decode_error(&path, &err))?;
        let entry = dat::GeoSiteEntry::decode(bytes.as_slice())
            .map_err(|err| decode_error(&path, &err.to_string()))?;
        drop(bytes);
        dat::SiteMatcher::from_entry(entry, &attrs, negate).map_err(GeoError::Load)
    }
}

fn decode_error(path: &Path, base: &str) -> GeoError {
    GeoError::Load(format!(
        "failed to decode geodata file: {}, base error: {base}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
    ))
}

fn read_to_heap(path: &Path) -> std::io::Result<Box<dyn AsRef<[u8]> + Send + Sync>> {
    std::fs::read(path).map(|bytes| Box::new(bytes) as Box<dyn AsRef<[u8]> + Send + Sync>)
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// An IPv4-mapped address is judged as its IPv4 form, except that it is never "unspecified".
pub fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_link_local()
        }
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(v4) => {
                v4.is_private() || v4.is_loopback() || v4.is_multicast() || v4.is_link_local()
            }
            None => {
                let first = ip.segments().first().copied().unwrap_or(0);
                first & 0xfe00 == 0xfc00
                    || ip.is_unspecified()
                    || ip.is_loopback()
                    || ip.is_multicast()
                    || first & 0xffc0 == 0xfe80
            }
        },
    }
}

#[cfg(test)]
pub(crate) mod test_mmdb;
#[cfg(test)]
mod tests;
