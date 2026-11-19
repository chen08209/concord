use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use concord_common::HttpFacts;
use concord_common::intercept::{
    ConnMark, HeldConn, InterceptFlow, Route, RuleLabel, UpstreamRequest,
};
use concord_common::sync::lock;
use concord_common::{BoxStream, Tasks};
use hyper::client::conn::{http1 as client1, http2 as client2};
use hyper::server::conn::{http1 as server1, http2 as server2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::body::Body;
use crate::capture::Cap;
use crate::engine::{ALPN_H2, ALPN_HTTP1, Core, HANDSHAKE_TIMEOUT};
use crate::script::ScriptDial;

const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_IDLE_PER_HOST: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scheme {
    Http,
    Https,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PoolKey {
    pub https: bool,
    pub host: String,
    pub port: u16,
    /// The chain a request routed on its own leaves through; none when the session's
    /// route holds for it.
    pub route: Option<Arc<[Arc<str>]>>,
}

/// A request's own route, still to be dialed, and what it was decided on.
pub(crate) struct Routed {
    pub route: Option<Route>,
    pub http: Arc<HttpFacts>,
}

pub(crate) enum Sender {
    H1(client1::SendRequest<Body>),
    H2(client2::SendRequest<Body>),
}

pub(crate) struct UpConn {
    pub sender: Sender,
    pub id: Option<Arc<str>>,
    pub hop: Arc<Hop>,
}

/// The route a connection was dialed by.
#[derive(Debug)]
pub(crate) struct Hop {
    pub chain: Arc<[Arc<str>]>,
    pub rule: Option<RuleLabel>,
}

impl Hop {
    fn of(route: &Route) -> Arc<Hop> {
        Arc::new(Hop {
            chain: route.chain.clone(),
            rule: route.rule.clone(),
        })
    }
}

impl UpConn {
    fn closed(&self) -> bool {
        match &self.sender {
            Sender::H1(sender) => sender.is_closed(),
            Sender::H2(sender) => sender.is_closed(),
        }
    }

    pub fn is_h2(&self) -> bool {
        matches!(self.sender, Sender::H2(_))
    }

    fn duplicate(&self) -> Option<UpConn> {
        match &self.sender {
            Sender::H2(sender) => Some(UpConn {
                sender: Sender::H2(sender.clone()),
                id: self.id.clone(),
                hop: self.hop.clone(),
            }),
            Sender::H1(_) => None,
        }
    }
}

struct Ready {
    tls: tokio_rustls::client::TlsStream<BoxStream>,
    host: String,
    port: u16,
    id: Option<Arc<str>>,
    hop: Arc<Hop>,
}

#[derive(Default)]
struct Activity {
    inflight: AtomicUsize,
    last: Mutex<Option<Instant>>,
}

pub(crate) struct ActivityGuard(Arc<Activity>);

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::Relaxed);
        {
            let mut last = lock(&self.0.last);
            *last = Some(Instant::now());
        }
    }
}

/// Serves the decrypted requests of one client connection.
pub(crate) struct Session {
    pub core: Arc<Core>,
    pub scheme: Scheme,
    pub host: String,
    pub flow: InterceptFlow,
    pool: Mutex<HashMap<PoolKey, Vec<UpConn>>>,
    key_locks: Mutex<HashMap<PoolKey, Arc<tokio::sync::Mutex<()>>>>,
    ready: Mutex<Option<Ready>>,
    held: Mutex<Option<Arc<dyn HeldConn>>>,
    /// The rules may route this session's requests apart, by their URL or User-Agent.
    per_request: AtomicBool,
    /// The h2 streams, upstream drivers and upgrades of this client connection. They end when
    /// it is served, when the session drops, or when the engine stops.
    tasks: Tasks,
    ended: CancellationToken,
    relays: Mutex<Vec<JoinHandle<()>>>,
    _dropped: DropGuard,
    activity: Arc<Activity>,
}

impl Session {
    pub fn new(core: Arc<Core>, scheme: Scheme, host: String, flow: InterceptFlow) -> Arc<Session> {
        let ended = core.tasks.child_token();
        let tasks = core.tasks.with_stop(ended.clone());
        let per_request = scheme == Scheme::Http && core.shared.dialer.reads_http(&flow);
        Arc::new(Session {
            core,
            scheme,
            host,
            flow,
            pool: Mutex::default(),
            key_locks: Mutex::default(),
            ready: Mutex::new(None),
            held: Mutex::new(None),
            per_request: AtomicBool::new(per_request),
            tasks,
            ended: ended.clone(),
            relays: Mutex::default(),
            _dropped: ended.drop_guard(),
            activity: Arc::default(),
        })
    }

    pub fn https(&self) -> bool {
        self.scheme == Scheme::Https
    }

    pub fn begin_request(&self) -> ActivityGuard {
        self.activity.inflight.fetch_add(1, Ordering::Relaxed);
        ActivityGuard(self.activity.clone())
    }

    pub fn spawn_relay(&self, relay: impl Future<Output = ()> + Send + 'static) {
        lock(&self.relays).push(self.tasks.spawn(relay));
    }

    /// The client connection's flow for the server it came for, so that it is
    /// routed as it would be undecrypted, and a copy pointed at any other
    /// address a rewrite sends a request to.
    pub fn upstream_flow(&self, host: &str, port: u16) -> InterceptFlow {
        if port == self.flow.port && host.eq_ignore_ascii_case(&self.host) {
            return self.flow.clone();
        }
        self.flow.retarget(host, port)
    }

    /// Opens the connection the first request goes out on before the client's
    /// handshake is answered: a server the rules reject, or one that cannot be
    /// reached or verified, leaves the client to the tunnel as if its host were
    /// not listed. A server rejected only until its requests are read is not dialed,
    /// and its requests are routed one by one.
    pub async fn connect(&self) -> io::Result<()> {
        let attempt = async {
            let dialer = &self.core.shared.dialer;
            let request = UpstreamRequest {
                flow: self.flow.clone(),
                hold: true,
                http: None,
            };
            let route = dialer
                .route(&request)
                .await
                .map_err(|failure| failure.error)?;
            self.per_request
                .store(route.http_pending, Ordering::Relaxed);
            if route.reject.is_some() && route.http_pending {
                return Ok(());
            }
            let hop = Hop::of(&route);
            let upstream = dialer
                .dial_routed(request, route)
                .await
                .map_err(|failure| failure.error)?;
            let id = upstream
                .id
                .clone()
                .or_else(|| upstream.held.as_ref().map(|held| Arc::from(held.id())));
            *lock(&self.held) = upstream.held;
            let tls = self
                .tls_connect(
                    upstream.stream,
                    &self.host,
                    self.flow.port,
                    &[ALPN_H2, ALPN_HTTP1],
                )
                .await?;
            *lock(&self.ready) = Some(Ready {
                tls,
                host: self.host.clone(),
                port: self.flow.port,
                id,
                hop,
            });
            Ok(())
        };
        let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, attempt)
            .await
            .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
        if result.is_err() {
            self.release();
        }
        result
    }

    /// Lists the connection `connect` opened as one requests are decrypted on.
    pub fn decrypted(&self) {
        self.mark(ConnMark::Decrypted);
    }

    /// Lists it as one whose client refused the certificate.
    pub fn refused(&self) {
        self.mark(ConnMark::Refused);
    }

    fn mark(&self, mark: ConnMark) {
        if let Some(held) = lock(&self.held).take() {
            held.release(mark);
        }
    }

    pub fn release(&self) {
        *lock(&self.ready) = None;
        self.mark(ConnMark::Plain);
    }

    async fn tls_connect(
        &self,
        stream: BoxStream,
        host: &str,
        port: u16,
        protocols: &[&str],
    ) -> io::Result<tokio_rustls::client::TlsStream<BoxStream>> {
        let config = self.core.client_config(protocols, host, port)?;
        let name = ServerName::try_from(host.to_string()).map_err(io::Error::other)?;
        tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            TlsConnector::from(config).connect(name, stream),
        )
        .await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
    }

    /// Whether a request to `host` and `port` is routed on its own: the session's route
    /// could leave it elsewhere, or it goes to a server a rewrite chose.
    pub fn routes_apart(&self, host: &str, port: u16) -> bool {
        self.per_request.load(Ordering::Relaxed)
            || (port != self.flow.port || !host.eq_ignore_ascii_case(&self.host))
                && self.core.shared.dialer.reads_http(&self.flow)
    }

    /// Dials the server a request goes to, by the route decided for it when it has one,
    /// listing a failed dial under the exchange as a connection of its own.
    async fn dial(
        &self,
        host: &str,
        port: u16,
        cap: &Cap,
        routed: Option<&mut Routed>,
    ) -> io::Result<(BoxStream, Option<Arc<str>>, Arc<Hop>)> {
        let flow = self.upstream_flow(host, port);
        let dialer = &self.core.shared.dialer;
        let request = UpstreamRequest {
            flow: flow.clone(),
            hold: false,
            http: routed.as_ref().map(|routed| routed.http.clone()),
        };
        let route = match routed.and_then(|routed| routed.route.take()) {
            Some(route) => Ok(route),
            None => dialer.route(&request).await,
        };
        let dialed = match route {
            Ok(route) => {
                let hop = Hop::of(&route);
                dialer
                    .dial_routed(request, route)
                    .await
                    .map(|upstream| (upstream, hop))
            }
            Err(failure) => Err(failure),
        };
        match dialed {
            Ok((upstream, hop)) => Ok((upstream.stream, upstream.id, hop)),
            Err(failure) => {
                if !failure.chain.is_empty() {
                    cap.routed(&failure.chain, failure.rule.as_ref());
                    if let Some(id) =
                        dialer.record_closed(&flow, &failure.chain, failure.rule.as_ref())
                    {
                        cap.attach(&id);
                    }
                }
                Err(failure.error)
            }
        }
    }

    fn key_lock(&self, key: &PoolKey) -> Arc<tokio::sync::Mutex<()>> {
        lock(&self.key_locks)
            .entry(key.clone())
            .or_default()
            .clone()
    }

    fn take_ready(&self, key: &PoolKey, http1: bool) -> Option<Ready> {
        let mut slot = lock(&self.ready);
        let ready = slot.as_ref()?;
        let negotiated_h2 = ready.tls.get_ref().1.alpn_protocol() == Some(ALPN_H2.as_bytes());
        let fits = key.https
            && key.port == ready.port
            && key.host.eq_ignore_ascii_case(&ready.host)
            && key
                .route
                .as_ref()
                .is_none_or(|chain| *chain == ready.hop.chain)
            && !(http1 && negotiated_h2);
        if fits { slot.take() } else { None }
    }

    /// A connection to the server of `key`: an idle one, the one dialed ahead,
    /// or a new one. HTTP/2 is offered unless the request that needs it is an upgrade.
    pub async fn connection_for(
        &self,
        key: &PoolKey,
        http1: bool,
        cap: &Cap,
        routed: Option<&mut Routed>,
    ) -> io::Result<(UpConn, bool)> {
        let guard = self.key_lock(key);
        let _serialized = guard.lock().await;
        if let Some(found) = self.pooled(key, http1) {
            cap.attach(found.id.as_deref().unwrap_or_default());
            cap.routed(&found.hop.chain, found.hop.rule.as_ref());
            return Ok((found, true));
        }
        if let Some(ready) = self.take_ready(key, http1) {
            let h2 = ready.tls.get_ref().1.alpn_protocol() == Some(ALPN_H2.as_bytes());
            let conn = self.start(ready.tls, h2, ready.id, ready.hop).await?;
            return Ok(self.register(key, conn, cap));
        }
        let (stream, id, hop) = self.dial(&key.host, key.port, cap, routed).await?;
        cap.attach(id.as_deref().unwrap_or_default());
        let conn = if key.https {
            let protocols: &[&str] = if http1 {
                &[ALPN_HTTP1]
            } else {
                &[ALPN_H2, ALPN_HTTP1]
            };
            let tls = self
                .tls_connect(stream, &key.host, key.port, protocols)
                .await?;
            let h2 = tls.get_ref().1.alpn_protocol() == Some(ALPN_H2.as_bytes());
            self.start(tls, h2, id, hop).await?
        } else {
            self.start(stream, false, id, hop).await?
        };
        Ok(self.register(key, conn, cap))
    }

    fn register(&self, key: &PoolKey, conn: UpConn, cap: &Cap) -> (UpConn, bool) {
        cap.attach(conn.id.as_deref().unwrap_or_default());
        cap.routed(&conn.hop.chain, conn.hop.rule.as_ref());
        if let Some(shared) = conn.duplicate() {
            lock(&self.pool)
                .entry(key.clone())
                .or_default()
                .push(shared);
        }
        (conn, false)
    }

    fn pooled(&self, key: &PoolKey, http1: bool) -> Option<UpConn> {
        let mut pool = lock(&self.pool);
        let entries = pool.get_mut(key)?;
        entries.retain(|conn| !conn.closed());
        if !http1
            && let Some(shared) = entries
                .iter()
                .find(|conn| conn.is_h2())
                .and_then(UpConn::duplicate)
        {
            return Some(shared);
        }
        let at = entries.iter().position(|conn| match &conn.sender {
            Sender::H1(sender) => sender.is_ready(),
            Sender::H2(_) => false,
        })?;
        Some(entries.swap_remove(at))
    }

    /// An HTTP/1 connection goes back once its response head is in.
    pub fn give_back(&self, key: &PoolKey, conn: UpConn) {
        if conn.is_h2() || conn.closed() {
            return;
        }
        let mut pool = lock(&self.pool);
        let entries = pool.entry(key.clone()).or_default();
        entries.retain(|other| !other.closed());
        if entries.iter().filter(|other| !other.is_h2()).count() < MAX_IDLE_PER_HOST {
            entries.push(conn);
        }
    }

    async fn start<S>(
        &self,
        io: S,
        h2: bool,
        id: Option<Arc<str>>,
        hop: Arc<Hop>,
    ) -> io::Result<UpConn>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let sender = if h2 {
            let (sender, conn) = client2::Builder::new(self.tasks.clone())
                .handshake(TokioIo::new(io))
                .await
                .map_err(io::Error::other)?;
            self.tasks.spawn(async move {
                let _ = conn.await;
            });
            Sender::H2(sender)
        } else {
            let (sender, conn) = client1::Builder::new()
                .title_case_headers(true)
                .handshake(TokioIo::new(io))
                .await
                .map_err(io::Error::other)?;
            self.tasks.spawn(async move {
                let _ = conn.with_upgrades().await;
            });
            Sender::H1(sender)
        };
        Ok(UpConn { sender, id, hop })
    }

    /// Serves the client connection until it closes, its CA is retired, it sits idle or its
    /// engine is replaced.
    pub async fn serve<S>(self: &Arc<Self>, io: S, h2: bool, retired: Option<CancellationToken>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let this = self.clone();
        let service = service_fn(move |request| {
            let session = this.clone();
            async move { session.handle(request).await }
        });
        let idle = idle_watch(self.activity.clone());
        let gone = async {
            match &retired {
                Some(token) => token.cancelled().await,
                None => std::future::pending().await,
            }
        };
        let ends = async {
            tokio::select! {
                () = idle => {}
                () = gone => {}
            }
        };
        let replaced = &self.core.replaced;
        if h2 {
            let conn = server2::Builder::new(self.tasks.clone())
                .timer(TokioTimer::new())
                .serve_connection(TokioIo::new(io), service);
            tokio::pin!(conn);
            drive(conn, |conn| conn.graceful_shutdown(), ends, replaced).await;
        } else {
            let conn = server1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(READ_HEADER_TIMEOUT)
                .title_case_headers(true)
                .serve_connection(TokioIo::new(io), service)
                .with_upgrades();
            tokio::pin!(conn);
            drive(conn, |conn| conn.graceful_shutdown(), ends, replaced).await;
        }
        self.finish(retired.as_ref()).await;
    }

    /// A hijacked connection, a WebSocket, is still being relayed; a retired CA cuts it short.
    async fn finish(&self, retired: Option<&CancellationToken>) {
        let relays = std::mem::take(&mut *lock(&self.relays));
        let wait = async {
            for relay in relays {
                let _ = relay.await;
            }
        };
        match retired {
            Some(token) => {
                tokio::select! {
                    () = wait => {}
                    () = token.cancelled() => {}
                }
            }
            None => wait.await,
        }
        self.ended.cancel();
        lock(&self.pool).clear();
        self.release();
    }
}

/// Serves a client connection until it closes or `ends`. Once its engine is replaced, the
/// requests under way finish (an h2 client is sent GOAWAY) and the connection closes.
async fn drive<C>(
    mut conn: Pin<&mut C>,
    shutdown: impl FnOnce(Pin<&mut C>),
    ends: impl Future<Output = ()>,
    replaced: &CancellationToken,
) where
    C: Future<Output = Result<(), hyper::Error>>,
{
    tokio::pin!(ends);
    tokio::select! {
        result = conn.as_mut() => return log_end(result),
        () = &mut ends => return,
        () = replaced.cancelled() => shutdown(conn.as_mut()),
    }
    tokio::select! {
        result = conn => log_end(result),
        () = ends => {}
    }
}

fn log_end(result: Result<(), hyper::Error>) {
    if let Err(err) = result {
        tracing::debug!("[MITM] client connection ended: {err}");
    }
}

async fn idle_watch(activity: Arc<Activity>) {
    loop {
        let since = lock(&activity.last).unwrap_or_else(Instant::now);
        let wait = (since + IDLE_TIMEOUT).saturating_duration_since(Instant::now());
        if wait.is_zero() && activity.inflight.load(Ordering::Relaxed) == 0 {
            return;
        }
        tokio::time::sleep(wait.max(Duration::from_secs(1))).await;
    }
}

pub(crate) struct SessionDial {
    pub session: Arc<Session>,
}

#[async_trait]
impl ScriptDial for SessionDial {
    async fn dial(&self, host: &str, port: u16) -> io::Result<BoxStream> {
        let flow = self.session.upstream_flow(host, port);
        self.session
            .core
            .shared
            .dialer
            .dial(UpstreamRequest {
                flow,
                hold: false,
                http: None,
            })
            .await
            .map(|upstream| upstream.stream)
            .map_err(|failure| failure.error)
    }

    fn tasks(&self) -> Tasks {
        self.session.tasks.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_activity_ends_even_after_a_holder_poisoned_its_clock() {
        let activity = Arc::new(Activity::default());
        activity.inflight.fetch_add(1, Ordering::Relaxed);
        let guard = ActivityGuard(activity.clone());
        concord_test_support::poison(&activity.last);
        drop(guard);
        assert_eq!(activity.inflight.load(Ordering::Relaxed), 0);
        assert!(lock(&activity.last).is_some());
    }
}
