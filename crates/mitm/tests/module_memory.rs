//! A module's URL patterns cost memory only once traffic reaches them, and replacing the
//! module keeps one set alive, not one per apply.
#![allow(
    unsafe_code,
    reason = "a counting global allocator wraps the system one"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, Ordering};

use async_trait::async_trait;
use concord_common::intercept::{
    DialFailure, InterceptFlow, Route, RuleLabel, Upstream, UpstreamDialer, UpstreamRequest,
};
use concord_mitm::{Mitm, MitmEnv, RawConfig, UtcClock};
use concord_platform::HomeDir;
use concord_tls::TrustStore;
use serde_json::json;

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

// SAFETY: forwards every call to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size().cast_signed(), Ordering::Relaxed);
        // SAFETY: as above.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size().cast_signed(), Ordering::Relaxed);
        // SAFETY: as above.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        LIVE.fetch_add(
            size.cast_signed() - layout.size().cast_signed(),
            Ordering::Relaxed,
        );
        // SAFETY: as above.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

struct NoDial;

#[async_trait]
impl UpstreamDialer for NoDial {
    async fn route(&self, _: &UpstreamRequest) -> Result<Route, DialFailure> {
        Err(io::Error::other("these tests send no traffic").into())
    }

    async fn dial_routed(&self, _: UpstreamRequest, _: Route) -> Result<Upstream, DialFailure> {
        Err(io::Error::other("these tests send no traffic").into())
    }

    fn record_closed(
        &self,
        _: &InterceptFlow,
        _: &[Arc<str>],
        _: Option<&RuleLabel>,
    ) -> Option<Arc<str>> {
        None
    }
}

const PATTERNS: usize = 1000;

fn module(host: &str) -> RawConfig {
    let rewrites: Vec<String> = (0..PATTERNS)
        .map(|n| {
            format!(r"^https?:\/\/ads{n}\.example\.com\/(\w+\/)?banner\d+\.(jpg|png) _ reject")
        })
        .collect();
    serde_json::from_value(json!({
        "enable": true,
        "hostname": [host],
        "url-rewrite": rewrites,
    }))
    .unwrap()
}

fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

#[tokio::test]
async fn adding_a_module_and_replacing_it_many_times_keeps_its_memory_bounded() {
    let home = tempfile::tempdir().unwrap();
    let mitm = Mitm::new(MitmEnv {
        home: Arc::new(HomeDir::new(home.path())),
        trust: TrustStore::new(&[], Vec::new()),
        dialer: Arc::new(NoDial),
        clock: Arc::new(UtcClock),
        runtime: None,
        events: Arc::new(concord_common::NullSink),
        tasks: concord_common::Tasks::default(),
    });
    mitm.generate_certificate().unwrap();
    mitm.set_running(true);
    let before = live();

    assert!(mitm.apply(Some(module("first.example.com"))).is_empty());
    let added = live() - before;
    assert!(added < 4 << 20, "adding the module kept {added} bytes");

    for round in 0..8 {
        assert!(
            mitm.validate(&module("checked.example.com"))
                .issues
                .is_empty()
        );
        assert!(
            mitm.apply(Some(module(&format!("round{round}.example.com"))))
                .is_empty()
        );
    }
    let replaced = live() - before;
    assert!(
        replaced - added < 64 << 10,
        "replacing it grew {added} bytes to {replaced}"
    );
}
