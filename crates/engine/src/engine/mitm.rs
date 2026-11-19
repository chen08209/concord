use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use arc_swap::ArcSwapOption;
use concord_common::{
    CoreEvent, EventSink, Fetch, ResourceKind, ResourcePhase, ResourceUpdate, Tasks,
};
use concord_config::MitmDef;
use concord_config::mitm::module::{Environment, ModuleInput};
use concord_config::mitm::modules::{AppliedModule, compose};
use concord_group::Fetcher;
use concord_mitm::{
    CaError, EVENT_NETWORK_CHANGED, LocalClock, Mitm, MitmEnv, RawConfig as MitmConfig,
};
use concord_platform::HomeDir;
use concord_tls::TrustStore;
use concord_tunnel::{ConnTable, Tunnel};
use serde_json::Value;

use self::store::ModuleResources;
use super::NOT_INITIALIZED;
use crate::error::Failure;

mod status;
mod store;

/// The MITM engine and the host settings that outlive it.
pub struct MitmService {
    pressure: AtomicI32,
    capture: AtomicBool,
    trusted_ca: ArcSwapOption<String>,
    current: ArcSwapOption<Mitm>,
    table: Arc<ConnTable>,
    fetcher: Arc<dyn Fetcher>,
    events: Arc<dyn EventSink>,
    modules: ArcSwapOption<Modules>,
}

/// What the latest apply put in force, kept to compose again when a module's file arrives.
struct Applied {
    section: MitmDef,
    modules: Vec<AppliedModule>,
    tasks: Tasks,
}

/// The modules' remote files and the section that reads them, shared with the tasks that
/// fetch them.
struct Modules {
    resources: ModuleResources,
    applied: ArcSwapOption<Applied>,
    events: Arc<dyn EventSink>,
    table: Arc<ConnTable>,
}

/// Which of the modules' files a fill fetches.
enum Refetch {
    Missing,
    All,
    Module(String),
}

impl Modules {
    fn install(&self, mitm: &Mitm, applied: &Applied) {
        let section = compose(&applied.section, &applied.modules, |url| {
            self.resources.stored(url)
        });
        for line in mitm.apply_section(Some(section), applied.tasks.clone()) {
            tracing::warn!("[MITM] {line}");
        }
        self.table.set_closed_capacity(mitm.capture_entries());
    }

    fn fill(self: &Arc<Self>, mitm: Arc<Mitm>, applied: Arc<Applied>, which: Refetch) {
        let modules = self.clone();
        let tasks = applied.tasks.clone();
        tasks.spawn(async move { modules.fetch(&mitm, &applied, &which).await });
    }

    /// Fetches each module's files in turn, reporting each module as one fetch, then composes
    /// the section again when a file in force changed and the apply is still the latest.
    async fn fetch(&self, mitm: &Mitm, applied: &Arc<Applied>, which: &Refetch) {
        let mut changed = false;
        for module in applied.modules.iter().filter(|module| module.in_force()) {
            let name = module.spec.name.as_str();
            if matches!(which, Refetch::Module(only) if only != name) {
                continue;
            }
            let urls: Vec<&str> = module
                .def
                .resources
                .iter()
                .map(|resource| resource.url.as_str())
                .filter(|url| {
                    !matches!(which, Refetch::Missing) || self.resources.stored(url).is_none()
                })
                .collect();
            if urls.is_empty() {
                continue;
            }
            let fetch = Fetch::start(|phase| self.report(name, phase));
            let mut updated = false;
            let mut failed = None;
            for url in urls {
                match self.resources.fetch(url).await {
                    Ok(stored) => updated |= stored,
                    Err(failure) => failed = Some(failure),
                }
            }
            changed |= updated;
            fetch.finish(match failed {
                Some(failure) => ResourcePhase::Failed(failure.to_string()),
                None if updated => ResourcePhase::Updated,
                None => ResourcePhase::Unchanged,
            });
        }
        let latest = self
            .applied
            .load()
            .as_ref()
            .is_some_and(|latest| Arc::ptr_eq(latest, applied));
        if changed && latest {
            self.install(mitm, applied);
        }
    }

    fn report(&self, name: &str, phase: ResourcePhase) {
        if self.events.enabled() {
            self.events.publish(CoreEvent::Resource(ResourceUpdate {
                kind: ResourceKind::MitmModule,
                name: Arc::from(name),
                phase,
            }));
        }
    }
}

impl MitmService {
    pub(crate) const ENABLED: bool = true;

    pub(crate) fn new(
        table: Arc<ConnTable>,
        fetcher: Arc<dyn Fetcher>,
        events: Arc<dyn EventSink>,
    ) -> Self {
        MitmService {
            pressure: AtomicI32::new(0),
            capture: AtomicBool::new(false),
            trusted_ca: ArcSwapOption::empty(),
            current: ArcSwapOption::empty(),
            table,
            fetcher,
            events,
            modules: ArcSwapOption::empty(),
        }
    }

    pub(crate) fn is_started(&self) -> bool {
        self.current.load().is_some()
    }

    pub(crate) fn start(&self, home: &Arc<HomeDir>, tunnel: &Tunnel, running: bool, tasks: Tasks) {
        let mitm = Arc::new(Mitm::new(MitmEnv {
            home: home.clone(),
            trust: TrustStore::from_parts(Vec::new(), &[], Vec::new()),
            dialer: tunnel.upstream_dialer(),
            clock: Arc::new(DeviceClock),
            runtime: None,
            events: self.events.clone(),
            tasks,
        }));
        mitm.set_capture(self.capture.load(Ordering::Relaxed));
        mitm.set_trusted_ca(self.trusted_ca.load_full().as_deref().cloned());
        mitm.set_pressure(u8::try_from(self.pressure()).unwrap_or(0));
        mitm.set_running(running);
        tunnel.set_interceptor(mitm.interceptor());
        self.modules.store(Some(Arc::new(Modules {
            resources: ModuleResources::open(home.clone(), self.fetcher.clone()),
            applied: ArcSwapOption::empty(),
            events: self.events.clone(),
            table: self.table.clone(),
        })));
        if let Some(previous) = self.current.swap(Some(mitm)) {
            previous.apply(None);
        }
    }

    fn started(&self) -> Result<Arc<Mitm>, Failure> {
        self.current
            .load_full()
            .ok_or_else(|| Failure::core(NOT_INITIALIZED))
    }

    pub fn certificate(&self) -> Result<Option<Value>, Failure> {
        let certificate = self.started()?.certificate().map_err(ca_failure)?;
        Ok(certificate.map(|info| serde_json::to_value(info).unwrap_or(Value::Null)))
    }

    pub fn generate_certificate(&self) -> Result<Value, Failure> {
        let info = self.started()?.generate_certificate().map_err(ca_failure)?;
        Ok(serde_json::to_value(info).unwrap_or(Value::Null))
    }

    pub fn issue_certificate(&self, host: &str) -> Result<String, Failure> {
        if host.is_empty() {
            return Err(Failure::new("invalid_arguments", "missing host"));
        }
        self.started()?.issue_certificate(host).map_err(ca_failure)
    }

    pub fn validate(&self, raw: Value) -> Result<Value, Failure> {
        let raw: MitmConfig = serde_json::from_value(raw)
            .map_err(|err| Failure::new("invalid_arguments", err.to_string()))?;
        let validation = self.started()?.validate(&raw);
        Ok(serde_json::to_value(validation).unwrap_or(Value::Null))
    }

    /// How `text` reads as a module with these argument values and attachments, on this system
    /// in the host's `language`.
    pub fn read_module(
        &self,
        text: &str,
        arguments: &BTreeMap<String, String>,
        attachments: &BTreeMap<String, String>,
        language: String,
    ) -> Result<Value, Failure> {
        let environment = Environment::current(language);
        let input = ModuleInput {
            arguments,
            attachments,
            environment: &environment,
        };
        let view = self.started()?.read_module(text, &input);
        Ok(serde_json::to_value(view).unwrap_or(Value::Null))
    }

    pub async fn run_script(&self, name: &str) -> Result<Value, Failure> {
        let output = self
            .started()?
            .run_script(name)
            .await
            .map_err(|err| Failure::core(err.to_string()))?;
        Ok(serde_json::to_value(output).unwrap_or(Value::Null))
    }

    /// Closed is read first, so a closed connection's list already holds every request
    /// it carried.
    pub fn exchanges(&self, id: &str) -> Result<Value, Failure> {
        let closed = !self.table.is_open(id);
        let list = self.started()?.exchanges(id);
        let mut value = serde_json::to_value(list).unwrap_or(Value::Null);
        if let Value::Object(map) = &mut value {
            map.insert("closed".into(), Value::Bool(closed));
        }
        Ok(value)
    }

    pub fn exchange(&self, id: i64) -> Result<Value, Failure> {
        let exchange = self.started()?.exchange(id);
        Ok(serde_json::to_value(exchange).unwrap_or(Value::Null))
    }

    pub fn body(&self, id: i64, response: bool) -> Result<Value, Failure> {
        let body = self.started()?.body(id, response);
        Ok(serde_json::to_value(body).unwrap_or(Value::Null))
    }

    /// `tunnel.UpdateMITM`: the profile's section, followed by its modules' lines, each remote
    /// file a line reads named by the file it is stored in. The files not stored yet are
    /// fetched in the background, and the section is composed again when they arrive. The
    /// section outlives a rejected config only as "off". With MITM on and the modules listed,
    /// the files the core stored that none of them reads any longer are removed.
    pub(crate) fn apply(
        &self,
        section: &MitmDef,
        modules: Vec<AppliedModule>,
        trust: Arc<TrustStore>,
        tasks: Tasks,
    ) {
        let (Some(mitm), Some(store)) = (self.current.load_full(), self.modules.load_full()) else {
            return;
        };
        mitm.set_trust(trust);
        store.resources.adopt(&modules);
        store.resources.write_inline(&modules);
        if section.enable && section.modules_listed {
            store.resources.collect(&modules);
        }
        let applied = Arc::new(Applied {
            section: section.clone(),
            modules,
            tasks,
        });
        store.applied.store(Some(applied.clone()));
        store.install(&mitm, &applied);
        store.fill(mitm, applied, Refetch::Missing);
    }

    /// `mitm.moduleStatus`: the modules of the profile in force, in the order it names them.
    pub fn module_status(&self) -> Result<Value, Failure> {
        let store = self
            .modules
            .load_full()
            .ok_or_else(|| Failure::core(NOT_INITIALIZED))?;
        let applied = store.applied.load_full();
        let modules: Vec<_> = applied
            .iter()
            .flat_map(|applied| &applied.modules)
            .map(|module| status::module_status(module, &store.resources))
            .collect();
        Ok(serde_json::json!({ "modules": modules }))
    }

    /// Fetches again the remote files of the module `name`, or of every module.
    pub fn fetch_module(&self, name: Option<String>) -> Result<(), Failure> {
        let mitm = self.started()?;
        let store = self
            .modules
            .load_full()
            .ok_or_else(|| Failure::core(NOT_INITIALIZED))?;
        let Some(applied) = store.applied.load_full() else {
            return Ok(());
        };
        let which = match name {
            Some(name)
                if !applied
                    .modules
                    .iter()
                    .any(|module| module.spec.name == name) =>
            {
                return Err(Failure::new(
                    "invalid_arguments",
                    format!("no module named {name}"),
                ));
            }
            Some(name) => Refetch::Module(name),
            None => Refetch::All,
        };
        store.fill(mitm, applied, which);
        Ok(())
    }

    /// `setMITMRunning`, on every start and stop: scripts run only while started.
    pub(crate) fn set_running(&self, running: bool) {
        if let Some(mitm) = self.current.load_full() {
            mitm.set_running(running);
        }
    }

    /// `mitm.SetPressure`: 0 (none) to 3 (relay), set by the Android service under memory pressure.
    pub fn set_pressure(&self, level: i32) {
        let level = level.clamp(0, 3);
        self.pressure.store(level, Ordering::Relaxed);
        if let Some(mitm) = self.current.load_full() {
            mitm.set_pressure(u8::try_from(level).unwrap_or(0));
        }
    }

    pub fn pressure(&self) -> i32 {
        self.pressure.load(Ordering::Relaxed)
    }

    pub(crate) fn set_capture(&self, on: bool) {
        self.capture.store(on, Ordering::Relaxed);
        if let Some(mitm) = self.current.load_full() {
            mitm.set_capture(on);
        }
    }

    pub(crate) fn set_trusted_ca(&self, fingerprint: Option<String>) {
        self.trusted_ca.store(fingerprint.clone().map(Arc::new));
        if let Some(mitm) = self.current.load_full() {
            mitm.set_trusted_ca(fingerprint);
        }
    }

    pub(crate) fn network_changed(&self) {
        if let Some(mitm) = self.current.load_full() {
            mitm.notify(EVENT_NETWORK_CHANGED);
        }
    }

    pub(crate) fn shutdown(&self) {
        if let Some(mitm) = self.current.load_full() {
            mitm.apply(None);
            mitm.flush_scripts();
        }
    }
}

struct DeviceClock;

impl LocalClock for DeviceClock {
    fn offset_at(&self, unix: i64) -> i32 {
        concord_platform::local_utc_offset(unix)
    }
}

fn ca_failure(err: CaError) -> Failure {
    Failure::core(err.to_string())
}
