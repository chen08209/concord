use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use concord_common::intercept::RuleLabel;
use concord_common::sync::lock;
use serde::{Serialize, Serializer};
use time::OffsetDateTime;

use crate::limits::{
    DEFAULT_CAPTURE_BYTES, DEFAULT_CAPTURE_ENTRIES, DEFAULT_MAX_BODY_SIZE, PRESSURE_NO_BODIES,
    Pressure,
};
use crate::script::HeaderList;

const EXCHANGE_OVERHEAD: i64 = std::mem::size_of::<Capture>() as i64;

pub const PHASE_REQUEST: &str = "request";
pub const PHASE_RESPONSE: &str = "response";

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_empty(value: &str) -> bool {
    value.is_empty()
}

#[derive(Clone, Debug, Serialize)]
pub struct ExchangeSummary {
    pub id: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub start: OffsetDateTime,
    #[serde(skip_serializing_if = "is_false")]
    pub pending: bool,
    pub duration: i64,
    pub method: String,
    pub url: String,
    pub status: i32,
    #[serde(rename = "request-size")]
    pub request_size: i64,
    #[serde(rename = "response-size")]
    pub response_size: i64,
    #[serde(skip_serializing_if = "is_empty")]
    pub error: String,
}

/// One request as the rules left it: the headers sent upstream and those
/// answered to the client. The sizes and the protocol are the client's.
#[derive(Clone, Debug, Serialize)]
pub struct Exchange {
    #[serde(flatten)]
    pub summary: ExchangeSummary,
    #[serde(skip_serializing_if = "is_empty")]
    pub connection: String,
    #[serde(rename = "original-url", skip_serializing_if = "is_empty")]
    pub original_url: String,
    pub proto: String,
    pub ttfb: i64,
    #[serde(rename = "request-header")]
    pub request_header: HeaderList,
    #[serde(rename = "response-header")]
    pub response_header: Option<HeaderList>,
    pub actions: Vec<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<RouteNote>,
}

/// The rule that decided the request and the chain it left through, exit first, as a
/// connection lists them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RouteNote {
    #[serde(skip_serializing_if = "is_empty")]
    pub rule: String,
    #[serde(rename = "rule-payload", skip_serializing_if = "is_empty")]
    pub rule_payload: String,
    pub chains: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Action {
    pub kind: String,
    #[serde(skip_serializing_if = "is_empty")]
    pub phase: String,
    #[serde(skip_serializing_if = "is_empty")]
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExchangeList {
    pub capturing: bool,
    #[serde(skip_serializing_if = "Option::is_none", with = "since_format")]
    pub since: Option<OffsetDateTime>,
    pub exchanges: Vec<ExchangeSummary>,
}

mod since_format {
    use serde::Serializer;
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(
        value: &Option<OffsetDateTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(at) => time::serde::rfc3339::serialize(at, serializer),
            None => serializer.serialize_none(),
        }
    }
}

/// A body as kept, decoded unless `encoding` names a coding left on it.
#[derive(Clone, Debug, Serialize)]
pub struct Body {
    #[serde(serialize_with = "base64_bytes")]
    pub data: Vec<u8>,
    #[serde(skip_serializing_if = "is_false")]
    pub truncated: bool,
    #[serde(skip_serializing_if = "is_empty")]
    pub encoding: String,
}

fn base64_bytes<S: Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    use base64::Engine as _;
    serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(data))
}

#[derive(Default)]
struct KeptBody {
    data: Vec<u8>,
    truncated: bool,
    length: i64,
}

struct Record {
    exchange: Exchange,
    request_body: KeptBody,
    response_body: KeptBody,
    released: bool,
}

pub struct Capture {
    store: Arc<CaptureStore>,
    started: Instant,
    body_limit: i64,
    connection: Mutex<String>,
    size: AtomicI64,
    dropped: AtomicBool,
    request_size: AtomicI64,
    response_size: AtomicI64,
    record: Mutex<Record>,
}

struct StoreInner {
    since: OffsetDateTime,
    last_id: i64,
    records: VecDeque<Arc<Capture>>,
    by_id: HashMap<i64, Arc<Capture>>,
    by_connection: HashMap<String, Vec<Arc<Capture>>>,
    bytes: i64,
    max_entries: usize,
    max_bytes: i64,
    max_body: i64,
}

pub struct CaptureStore {
    on: AtomicBool,
    inner: Mutex<StoreInner>,
    pressure: Arc<Pressure>,
}

impl CaptureStore {
    pub fn new(pressure: Arc<Pressure>) -> Arc<CaptureStore> {
        Arc::new(CaptureStore {
            on: AtomicBool::new(false),
            inner: Mutex::new(StoreInner {
                since: OffsetDateTime::now_utc(),
                last_id: 0,
                records: VecDeque::new(),
                by_id: HashMap::new(),
                by_connection: HashMap::new(),
                bytes: 0,
                max_entries: DEFAULT_CAPTURE_ENTRIES as usize,
                max_bytes: DEFAULT_CAPTURE_BYTES,
                max_body: DEFAULT_MAX_BODY_SIZE,
            }),
            pressure,
        })
    }

    pub fn is_on(&self) -> bool {
        self.on.load(Ordering::Relaxed)
    }

    /// Turning it off drops what was recorded.
    pub fn set_capture(&self, on: bool) {
        let mut inner = lock(&self.inner);
        if self.on.load(Ordering::Relaxed) == on {
            return;
        }
        self.on.store(on, Ordering::Relaxed);
        inner.clear();
    }

    pub fn clear(&self) {
        lock(&self.inner).clear();
    }

    pub fn limit(&self, entries: usize, bytes: i64, body: i64) {
        let mut inner = lock(&self.inner);
        (inner.max_entries, inner.max_bytes, inner.max_body) = (entries, bytes, body);
        inner.evict();
    }

    pub fn max_entries(&self) -> usize {
        lock(&self.inner).max_entries
    }

    pub fn exchanges(&self, connection: &str) -> ExchangeList {
        let inner = lock(&self.inner);
        let capturing = self.is_on();
        let mut exchanges: Vec<ExchangeSummary> = inner
            .by_connection
            .get(connection)
            .map(|list| list.iter().map(|c| c.snapshot().summary).collect())
            .unwrap_or_default();
        exchanges.sort_by_key(|summary| summary.id);
        ExchangeList {
            capturing,
            since: capturing.then_some(inner.since),
            exchanges,
        }
    }

    pub fn find(&self, id: i64) -> Option<Exchange> {
        let inner = lock(&self.inner);
        inner.by_id.get(&id).map(|c| c.snapshot())
    }

    pub fn find_body(&self, id: i64, response: bool) -> Option<Body> {
        let (kept, encoding, limit) = {
            let inner = lock(&self.inner);
            let capture = inner.by_id.get(&id)?;
            let record = lock(&capture.record);
            let (kept, encoding) = if response {
                (
                    (
                        record.response_body.data.clone(),
                        record.response_body.truncated,
                    ),
                    record
                        .exchange
                        .response_header
                        .as_ref()
                        .and_then(|header| header.get("Content-Encoding"))
                        .map(|values| values.join(", "))
                        .unwrap_or_default(),
                )
            } else {
                (
                    (
                        record.request_body.data.clone(),
                        record.request_body.truncated,
                    ),
                    record
                        .exchange
                        .request_header
                        .get("Content-Encoding")
                        .map(|values| values.join(", "))
                        .unwrap_or_default(),
                )
            };
            (kept, encoding, capture.body_limit)
        };
        Some(crate::capture_body::decode_body(
            kept.0, kept.1, &encoding, limit,
        ))
    }

    /// Lets go of the bodies kept so far, which read as cut short.
    pub fn shed(&self) {
        let mut inner = lock(&self.inner);
        let mut freed_total = 0;
        for capture in &inner.records {
            let mut record = lock(&capture.record);
            let freed =
                (record.request_body.data.capacity() + record.response_body.data.capacity()) as i64;
            record.request_body = KeptBody {
                truncated: true,
                ..KeptBody::default()
            };
            record.response_body = KeptBody {
                truncated: true,
                ..KeptBody::default()
            };
            capture.size.fetch_sub(freed, Ordering::Relaxed);
            freed_total += freed;
        }
        inner.bytes -= freed_total;
    }

    pub fn begin(
        self: &Arc<Self>,
        method: &str,
        url: &str,
        proto: &str,
        request_header: HeaderList,
    ) -> Cap {
        if !self.is_on() {
            return Cap(None);
        }
        let mut inner = lock(&self.inner);
        if !self.is_on() {
            return Cap(None);
        }
        inner.last_id += 1;
        let id = inner.last_id;
        let now = OffsetDateTime::now_utc();
        let exchange = Exchange {
            summary: ExchangeSummary {
                id,
                start: now,
                pending: true,
                duration: 0,
                method: method.to_string(),
                url: url.to_string(),
                status: 0,
                request_size: 0,
                response_size: 0,
                error: String::new(),
            },
            connection: String::new(),
            original_url: String::new(),
            proto: proto.to_string(),
            ttfb: 0,
            request_header,
            response_header: None,
            actions: Vec::new(),
            route: None,
        };
        let size = exchange.footprint();
        let capture = Arc::new(Capture {
            store: self.clone(),
            started: Instant::now(),
            body_limit: inner.max_body,
            connection: Mutex::new(String::new()),
            size: AtomicI64::new(size),
            dropped: AtomicBool::new(false),
            request_size: AtomicI64::new(0),
            response_size: AtomicI64::new(0),
            record: Mutex::new(Record {
                exchange,
                request_body: KeptBody::default(),
                response_body: KeptBody::default(),
                released: false,
            }),
        });
        inner.records.push_back(capture.clone());
        inner.by_id.insert(id, capture.clone());
        inner.bytes += size;
        inner.evict();
        Cap(Some(capture))
    }

    fn grow(&self, capture: &Capture, delta: i64) {
        let mut inner = lock(&self.inner);
        if capture.dropped.load(Ordering::Relaxed) {
            return;
        }
        capture.size.fetch_add(delta, Ordering::Relaxed);
        inner.bytes += delta;
        inner.evict();
    }
}

impl StoreInner {
    fn clear(&mut self) {
        for capture in &self.records {
            capture.drop_data();
        }
        self.records.clear();
        self.by_id.clear();
        self.by_connection.clear();
        self.bytes = 0;
        self.since = OffsetDateTime::now_utc();
    }

    /// Drops the oldest records, which also started first.
    fn evict(&mut self) {
        while self.records.len() > self.max_entries || self.bytes > self.max_bytes {
            let Some(capture) = self.records.pop_front() else {
                break;
            };
            capture.drop_data();
            self.bytes -= capture.size.load(Ordering::Relaxed);
            let (id, started) = {
                let record = lock(&capture.record);
                (record.exchange.summary.id, record.exchange.summary.start)
            };
            self.by_id.remove(&id);
            self.unlink(&capture);
            self.since = started;
        }
    }

    fn unlink(&mut self, capture: &Arc<Capture>) {
        let connection = std::mem::take(&mut *lock(&capture.connection));
        if connection.is_empty() {
            return;
        }
        if let Some(list) = self.by_connection.get_mut(&connection) {
            list.retain(|other| !Arc::ptr_eq(other, capture));
            if list.is_empty() {
                self.by_connection.remove(&connection);
            }
        }
    }
}

impl Exchange {
    fn footprint(&self) -> i64 {
        let actions: usize = self
            .actions
            .iter()
            .map(|action| action.kind.len() + action.phase.len() + action.detail.len())
            .sum();
        let route = self.route.as_ref().map_or(0, |route| {
            route.rule.len()
                + route.rule_payload.len()
                + route.chains.iter().map(String::len).sum::<usize>()
        });
        EXCHANGE_OVERHEAD
            + (self.summary.method.len()
                + self.summary.url.len()
                + self.original_url.len()
                + self.summary.error.len()
                + header_size(Some(&self.request_header))
                + header_size(self.response_header.as_ref())
                + actions
                + route) as i64
    }
}

fn header_size(header: Option<&HeaderList>) -> usize {
    header.map_or(0, |header| {
        header
            .iter()
            .map(|(name, values)| name.len() + values.iter().map(String::len).sum::<usize>())
            .sum()
    })
}

impl Capture {
    fn drop_data(&self) {
        self.dropped.store(true, Ordering::Relaxed);
        let mut record = lock(&self.record);
        record.request_body.data = Vec::new();
        record.response_body.data = Vec::new();
        record.released = true;
    }

    fn snapshot(&self) -> Exchange {
        let record = lock(&self.record);
        let mut exchange = record.exchange.clone();
        drop(record);
        exchange.connection = lock(&self.connection).clone();
        exchange.summary.request_size = self.request_size.load(Ordering::Relaxed);
        exchange.summary.response_size = self.response_size.load(Ordering::Relaxed);
        if exchange.summary.pending {
            exchange.summary.duration = millis(self.started);
        }
        exchange
    }

    fn update(&self, change: impl FnOnce(&mut Exchange)) {
        let delta = {
            let mut record = lock(&self.record);
            let before = record.exchange.footprint();
            change(&mut record.exchange);
            record.exchange.footprint() - before
        };
        if delta != 0 {
            self.store.grow(self, delta);
        }
    }

    /// Counts what a body holds, sized from its declared length so that growing it copies nothing.
    fn keep(&self, response: bool, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let grown = {
            let mut record = lock(&self.record);
            let released = record.released;
            let body = if response {
                &mut record.response_body
            } else {
                &mut record.request_body
            };
            let mut take = data.len() as i64;
            if self.store.pressure.level() >= PRESSURE_NO_BODIES || released || body.truncated {
                take = 0;
            } else {
                take = take.min(self.body_limit - body.data.len() as i64);
            }
            take = take.max(0);
            if take < data.len() as i64 {
                body.truncated = true;
            }
            let mut grown = 0;
            if take > 0 {
                let held = body.data.capacity() as i64;
                if body.data.capacity() == 0 && body.length > take {
                    body.data = Vec::with_capacity(body.length.min(self.body_limit) as usize);
                }
                body.data
                    .extend_from_slice(data.get(..take as usize).unwrap_or(data));
                grown = body.data.capacity() as i64 - held;
            }
            grown
        };
        if grown > 0 {
            self.store.grow(self, grown);
        }
    }
}

fn millis(since: Instant) -> i64 {
    i64::try_from(since.elapsed().as_millis()).unwrap_or(i64::MAX)
}

/// A capture that may not exist: every method does nothing while capture is off.
#[derive(Clone, Default)]
pub struct Cap(Option<Arc<Capture>>);

impl Cap {
    pub fn is_some(&self) -> bool {
        self.0.is_some()
    }

    pub fn note(&self, kind: &str, phase: &str, detail: &str) {
        if let Some(c) = &self.0 {
            c.update(|e| {
                e.actions.push(Action {
                    kind: kind.to_string(),
                    phase: phase.to_string(),
                    detail: detail.to_string(),
                })
            });
        }
    }

    pub fn set_request_length(&self, length: i64) {
        if let Some(c) = &self.0 {
            lock(&c.record).request_body.length = length;
        }
    }

    pub fn sent(&self, url: &str, header: HeaderList) {
        if let Some(c) = &self.0 {
            let url = url.to_string();
            c.update(|e| {
                if url != e.summary.url && e.original_url.is_empty() {
                    e.original_url = e.summary.url.clone();
                }
                e.summary.url = url;
                e.request_header = header;
            });
        }
    }

    pub fn routed(&self, chain: &[Arc<str>], rule: Option<&RuleLabel>) {
        if let Some(c) = &self.0 {
            let note = RouteNote {
                rule: rule.map_or_else(String::new, |rule| rule.name.to_string()),
                rule_payload: rule.map_or_else(String::new, |rule| rule.payload.to_string()),
                chains: chain.iter().map(ToString::to_string).collect(),
            };
            c.update(|e| e.route = Some(note));
        }
    }

    pub fn responded(&self, status: u16, header: HeaderList) {
        if let Some(c) = &self.0 {
            let ttfb = millis(c.started);
            if let Some(length) = header
                .get("Content-Length")
                .and_then(|values| values.first())
                .and_then(|text| text.parse::<i64>().ok())
            {
                lock(&c.record).response_body.length = length;
            }
            c.update(|e| {
                e.summary.status = i32::from(status);
                e.response_header = Some(header);
                e.ttfb = ttfb;
            });
        }
    }

    pub fn fail(&self, error: &str) {
        if let Some(c) = &self.0 {
            c.update(|e| {
                if e.summary.error.is_empty() {
                    e.summary.error = error.to_string();
                }
            });
        }
    }

    pub fn finish(&self) {
        if let Some(c) = &self.0 {
            c.update(|e| {
                e.summary.pending = false;
                e.summary.duration = millis(c.started);
            });
        }
    }

    pub fn add_request_size(&self, bytes: usize) {
        if let Some(c) = &self.0 {
            c.request_size.fetch_add(bytes as i64, Ordering::Relaxed);
        }
    }

    pub fn add_response_size(&self, bytes: usize) {
        if let Some(c) = &self.0 {
            c.response_size.fetch_add(bytes as i64, Ordering::Relaxed);
        }
    }

    pub fn keep_request(&self, data: &[u8]) {
        if let Some(c) = &self.0 {
            c.keep(false, data);
        }
    }

    pub fn keep_response(&self, data: &[u8]) {
        if let Some(c) = &self.0 {
            c.keep(true, data);
        }
    }

    /// Files the exchange under the upstream connection it went out on; HTTP/2
    /// may retry it on another.
    pub fn attach(&self, connection: &str) {
        let Some(c) = &self.0 else { return };
        if connection.is_empty() {
            return;
        }
        let mut inner = lock(&c.store.inner);
        if c.dropped.load(Ordering::Relaxed) || *lock(&c.connection) == connection {
            return;
        }
        inner.unlink(c);
        *lock(&c.connection) = connection.to_string();
        inner
            .by_connection
            .entry(connection.to_string())
            .or_default()
            .push(c.clone());
    }

    #[cfg(test)]
    pub(crate) fn id(&self) -> Option<i64> {
        self.0.as_ref().map(|c| lock(&c.record).exchange.summary.id)
    }

    #[cfg(test)]
    pub(crate) fn held_bytes(&self) -> i64 {
        self.0
            .as_ref()
            .map_or(0, |c| c.size.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
impl CaptureStore {
    pub(crate) fn tracked_bytes(&self) -> i64 {
        lock(&self.inner).bytes
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn store() -> (Arc<Pressure>, Arc<CaptureStore>) {
        let pressure = Arc::new(Pressure::with_hold(Duration::from_secs(60)));
        let store = CaptureStore::new(pressure.clone());
        store.set_capture(true);
        (pressure, store)
    }

    fn begin(store: &Arc<CaptureStore>, url: &str) -> Cap {
        store.begin("GET", url, "HTTP/1.1", HeaderList::new())
    }

    #[test]
    fn exchanges_are_filed_under_the_connection_they_went_out_on() {
        let (_, store) = store();
        let a = begin(&store, "https://a.test/1");
        let b = begin(&store, "https://a.test/2");
        a.attach("c1");
        b.attach("c1");
        b.attach("c2");
        a.finish();
        let list = store.exchanges("c1");
        assert!(list.capturing && list.since.is_some());
        assert_eq!(list.exchanges.len(), 1);
        assert_eq!(list.exchanges[0].url, "https://a.test/1");
        assert!(!list.exchanges[0].pending);
        assert_eq!(store.exchanges("c2").exchanges.len(), 1);
        assert_eq!(store.find(b.id().unwrap()).unwrap().connection, "c2");
    }

    #[test]
    fn a_sent_request_keeps_the_original_url() {
        let (_, store) = store();
        let cap = begin(&store, "https://a.test/old");
        cap.sent("https://a.test/new", HeaderList::new());
        let exchange = store.find(cap.id().unwrap()).unwrap();
        assert_eq!(exchange.summary.url, "https://a.test/new");
        assert_eq!(exchange.original_url, "https://a.test/old");
    }

    #[test]
    fn the_oldest_goes_first_past_the_entry_limit() {
        let (_, store) = store();
        store.limit(2, DEFAULT_CAPTURE_BYTES, DEFAULT_MAX_BODY_SIZE);
        let caps: Vec<Cap> = (0..3)
            .map(|i| begin(&store, &format!("https://a.test/{i}")))
            .collect();
        for cap in &caps {
            cap.attach("c");
        }
        let list = store.exchanges("c");
        assert_eq!(list.exchanges.len(), 2);
        assert_eq!(list.exchanges[0].url, "https://a.test/1");
        assert!(store.find(caps[0].id().unwrap()).is_none());
        assert!(list.since.unwrap() <= list.exchanges[0].start);
        store.set_capture(false);
        let off = store.exchanges("c");
        assert!(!off.capturing && off.exchanges.is_empty() && off.since.is_none());
        assert!(begin(&store, "https://a.test/off").id().is_none());
    }

    #[test]
    fn bodies_are_kept_up_to_the_limit_and_never_resume() {
        let (_, store) = store();
        store.limit(10, DEFAULT_CAPTURE_BYTES, 8);
        let cap = begin(&store, "https://a.test/");
        cap.keep_response(b"12345");
        cap.keep_response(b"6789ab");
        cap.keep_response(b"x");
        let body = store.find_body(cap.id().unwrap(), true).unwrap();
        assert_eq!(body.data, b"12345678");
        assert!(body.truncated);
        let request = store.find_body(cap.id().unwrap(), false).unwrap();
        assert!(request.data.is_empty() && !request.truncated);
    }

    #[test]
    fn pressure_leaves_bodies_out_and_sheds_what_was_kept() {
        let (pressure, store) = store();
        let cap = begin(&store, "https://a.test/");
        cap.keep_request(b"kept");
        assert!(pressure.set(PRESSURE_NO_BODIES));
        store.shed();
        let body = store.find_body(cap.id().unwrap(), false).unwrap();
        assert!(body.data.is_empty() && body.truncated);
        cap.keep_request(b"more");
        assert!(
            store
                .find_body(cap.id().unwrap(), false)
                .unwrap()
                .data
                .is_empty()
        );
    }

    #[test]
    fn the_memory_a_body_holds_is_counted() {
        let (_, store) = store();
        let cap = begin(&store, "https://a.test/");
        let before = cap.held_bytes();
        cap.set_request_length(1000);
        cap.keep_request(&[7u8; 100]);
        assert!(cap.held_bytes() - before >= 1000);
        assert_eq!(store.tracked_bytes(), cap.held_bytes());
        store.shed();
        assert_eq!(store.tracked_bytes(), cap.held_bytes());
        assert!(cap.held_bytes() <= before + 1);
    }

    #[test]
    fn the_byte_limit_drops_the_oldest() {
        let (_, store) = store();
        store.limit(100, 3 * EXCHANGE_OVERHEAD, DEFAULT_MAX_BODY_SIZE);
        let first = begin(&store, "https://a.test/1");
        for i in 0..4 {
            begin(&store, &format!("https://a.test/{i}"));
        }
        assert!(store.find(first.id().unwrap()).is_none());
        assert!(store.tracked_bytes() <= 3 * EXCHANGE_OVERHEAD + 100);
    }

    #[test]
    fn json_matches_the_wire_names() {
        let (_, store) = store();
        let cap = begin(&store, "https://a.test/");
        cap.responded(
            200,
            HeaderList::from([("Content-Length".to_string(), vec!["3".to_string()])]),
        );
        cap.note("script", PHASE_RESPONSE, "Ads");
        let json = serde_json::to_value(store.find(cap.id().unwrap()).unwrap()).unwrap();
        for key in [
            "id",
            "start",
            "pending",
            "duration",
            "method",
            "url",
            "status",
            "request-size",
            "response-size",
            "proto",
            "ttfb",
            "request-header",
            "response-header",
            "actions",
        ] {
            assert!(json.get(key).is_some(), "{key} in {json}");
        }
        assert!(json.get("error").is_none() && json.get("connection").is_none());
        assert_eq!(json["actions"][0]["kind"], "script");
    }
}
