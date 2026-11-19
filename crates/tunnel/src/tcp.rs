use std::io;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use concord_common::packet::{PacketBuf, PacketSession};
use concord_common::stream::PeekedStream;
use concord_common::stream_buffer::{ReadBufferOptions, StreamBuffer};
use concord_common::{
    Address, BoxRead, BoxStream, BoxWrite, ConnRecord, DialCx, FlowMeta, InboundInfo, InboundKind,
    Initiator, Network, Stream,
};
use concord_group::Touch;
use concord_net::{Meter, relay};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::WaitForCancellationFutureOwned;

use crate::flow::{FlowState, pre_handle};
use crate::intercept::Offer;
use crate::route::{Decision, route};
use crate::runtime::{Inner, Runtime};
use crate::table::{Registration, Tracked};

const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// mihomo peeks the client this long after accepting, while it routes and dials.
const FIRST_BYTES_WINDOW: Duration = Duration::from_millis(200);
const FIRST_BYTES_MAX: usize = 4 * 1024;

struct TrackedMeter<'a>(&'a Arc<Tracked>);

impl Meter for TrackedMeter<'_> {
    fn on_upload(&self, bytes: u64) {
        self.0.uploaded(bytes);
    }

    fn on_download(&self, bytes: u64) {
        self.0.downloaded(bytes);
    }
}

pub(crate) async fn handle(inner: Arc<Inner>, meta: FlowMeta, stream: BoxStream) {
    let accepted = Instant::now();
    let closing = inner.table.closing();
    let closes = inner.table.closes();
    let Some(runtime) = inner.runtime_for(meta.inbound.kind) else {
        return;
    };
    let Some(Some(SetUp {
        flow,
        stream,
        head,
        remote,
        decision,
    })) = closing
        .run_until_cancelled(set_up(&inner, &runtime, meta, stream, accepted))
        .await
    else {
        return;
    };
    let live = inner.live();
    tracing::info!("{}", decision.match_text(&flow, &live));

    let Some(registration) = inner
        .table
        .register_since(record_of(&flow, &decision, &remote), closes)
    else {
        return;
    };
    let tracked = registration.tracked();
    let local: BoxStream = if head.is_empty() {
        stream
    } else {
        Box::new(PeekedStream::new(head, stream))
    };
    let cancel = tracked.record.cancel.clone();
    relay(local, remote, &TrackedMeter(tracked), &cancel).await;
}

struct SetUp {
    flow: FlowState,
    stream: BoxStream,
    head: Vec<u8>,
    remote: BoxStream,
    decision: Decision,
}

async fn set_up(
    inner: &Arc<Inner>,
    runtime: &Arc<Runtime>,
    meta: FlowMeta,
    mut stream: BoxStream,
    accepted: Instant,
) -> Option<SetUp> {
    let mut flow = FlowState::new(meta);
    if !flow.valid() {
        tracing::warn!(
            "[Metadata] not valid: {} --> {}",
            flow.meta.src,
            flow.meta.dst
        );
        return None;
    }

    let mut pre_handle_failed = false;
    if let Err(err) = pre_handle(&mut flow, &runtime.dns) {
        tracing::debug!("[Metadata PreHandle] error: {err}");
        pre_handle_failed = true;
    }

    let mut head = Vec::new();
    if runtime.sniffer.enabled() {
        let mut target = flow.sniff_target();
        if runtime
            .sniffer
            .sniff_tcp(&mut stream, &mut head, &mut target)
            .await
        {
            pre_handle_failed = false;
        }
    }
    if pre_handle_failed {
        tracing::debug!(
            "[Metadata PreHandle] failed to sniff a domain for connection {} --> {}, give up",
            flow.source_detail(),
            flow.remote_text()
        );
        return None;
    }

    if let Some(slot) = inner.interceptor.load_full() {
        match slot.0.offer(&flow.intercept(), stream, head).await {
            Offer::Taken => return None,
            Offer::Declined {
                stream: declined,
                head: read,
            } => {
                stream = declined;
                head = read;
            }
        }
    }

    let (remote, decision) = dial_reading_first_bytes(
        inner,
        runtime,
        &mut flow,
        &mut stream,
        &mut head,
        accepted + FIRST_BYTES_WINDOW,
    )
    .await
    .ok()?;
    Some(SetUp {
        flow,
        stream,
        head,
        remote,
        decision,
    })
}

/// A read the remote has no header to pair with is dropped unfinished, which loses nothing.
async fn dial_reading_first_bytes(
    inner: &Arc<Inner>,
    runtime: &Arc<Runtime>,
    flow: &mut FlowState,
    stream: &mut BoxStream,
    head: &mut Vec<u8>,
    until: Instant,
) -> io::Result<(BoxStream, Decision)> {
    let dialing = dial_traced(inner, runtime, flow);
    if !head.is_empty() {
        return dialing.await.map_err(|failed| failed.error);
    }
    let mut dialing = pin!(dialing);
    let mut reading = pin!(read_first_bytes(stream, head, until));
    let mut read = false;
    let dialed = loop {
        tokio::select! {
            biased;
            dialed = &mut dialing => break dialed.map_err(|failed| failed.error)?,
            () = &mut reading, if !read => read = true,
        }
    };
    if !read && dialed.0.needs_handshake() {
        reading.await;
    }
    Ok(dialed)
}

async fn read_first_bytes(stream: &mut BoxStream, head: &mut Vec<u8>, until: Instant) {
    head.reserve_exact(FIRST_BYTES_MAX);
    if timeout_at(until, stream.read_buf(head)).await.is_err() {
        head.shrink_to_fit();
    }
}

pub(crate) struct FailedDial {
    pub error: io::Error,
    /// Absent when no route was found.
    pub decision: Option<Box<Decision>>,
}

impl From<io::Error> for FailedDial {
    fn from(error: io::Error) -> Self {
        FailedDial {
            error,
            decision: None,
        }
    }
}

pub(crate) async fn dial_traced(
    inner: &Arc<Inner>,
    runtime: &Arc<Runtime>,
    flow: &mut FlowState,
) -> Result<(BoxStream, Decision), FailedDial> {
    let decision = route_traced(inner, runtime, flow).await?;
    dial_decided(inner, runtime, flow, decision).await
}

pub(crate) async fn route_traced(
    inner: &Arc<Inner>,
    runtime: &Arc<Runtime>,
    flow: &mut FlowState,
) -> io::Result<Decision> {
    let live = inner.live();
    route(flow, runtime, &live, Touch::Yes)
        .await
        .inspect_err(|err| {
            tracing::warn!("[Metadata] parse failed: {err}");
        })
}

/// Dials what [route_traced] decided for `flow`.
pub(crate) async fn dial_decided(
    inner: &Arc<Inner>,
    runtime: &Arc<Runtime>,
    flow: &mut FlowState,
    decision: Decision,
) -> Result<(BoxStream, Decision), FailedDial> {
    let mut dst = flow.remote_address();
    if let Some(host) = flow.host.clone()
        && let (Some(node), true) = runtime.dns.hosts().search(&host, false)
        && let Some(ip) = node.rand_ip()
        && !runtime.dns.is_fake_ip(ip)
    {
        flow.dst_ip = Some(ip);
        flow.dns_mode = Some(concord_common::DnsMode::Hosts);
        dst = flow.pure_address();
    }

    let deadline = Instant::now() + DIAL_TIMEOUT;
    let outcome = dial_once(inner, runtime, flow, &decision, &dst, deadline).await;
    let kind = decision.leaf.info().kind;
    match outcome {
        Ok(remote) => {
            let remote = runtime
                .outbounds
                .watch_first_write(&decision.chain, kind, remote);
            Ok((remote, decision))
        }
        Err(err) => {
            runtime
                .outbounds
                .note_dial_failed(&decision.chain, kind, Network::Tcp, &err);
            tracing::warn!(
                "[{}] dial {} {} --> {} error: {err}",
                flow.network_name(),
                decision.dial_label(),
                flow.source_detail(),
                flow.remote_text()
            );
            Err(FailedDial {
                error: err,
                decision: Some(Box::new(decision)),
            })
        }
    }
}

async fn dial_once(
    inner: &Inner,
    runtime: &Runtime,
    flow: &FlowState,
    decision: &Decision,
    dst: &Address,
    deadline: Instant,
) -> io::Result<BoxStream> {
    if decision.leaf.info().kind.is_direct() {
        inner
            .loopback
            .check_flow(flow.meta.src, flow.meta.arrived_at())?;
    }
    let env = runtime.env_for(flow);
    let cx = DialCx::new(&env, Initiator::Other, Some(deadline));
    match timeout_at(deadline, decision.leaf.connect(&cx, dst)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::from(io::ErrorKind::TimedOut)),
    }
}

pub(crate) fn record_of(
    flow: &FlowState,
    decision: &Decision,
    remote: &BoxStream,
) -> Arc<ConnRecord> {
    let info = decision.leaf.info();
    let destination = match remote.peer_addr() {
        Some(addr) => addr.ip().to_string(),
        None => server_host(&info.addr),
    };
    new_record(flow, decision, destination)
}

pub(crate) fn new_record(
    flow: &FlowState,
    decision: &Decision,
    remote_destination: String,
) -> Arc<ConnRecord> {
    let (rule, payload) = match &decision.rule {
        Some(rule) => (rule.type_name.clone(), rule.payload.clone()),
        None => (Arc::from(""), Arc::from("")),
    };
    Arc::new(ConnRecord::new(
        flow.conn_meta(remote_destination),
        decision.chain.clone(),
        decision.provider_chain.clone(),
        rule,
        payload,
        decision.leaf.info().kind.is_direct(),
        0,
    ))
}

pub(crate) fn server_host(addr: &str) -> String {
    concord_common::addr::split_host_port(addr)
        .map(|(host, _)| host.to_string())
        .unwrap_or_default()
}

pub(crate) fn inner_flow(dst: &Address, network: Network, proxy: Option<&str>) -> FlowState {
    let meta = FlowMeta {
        dscp: 0,
        network,
        inbound: InboundInfo::new(InboundKind::Inner),
        src: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
        dst: dst.clone(),
    };
    let mut flow = FlowState::new(meta);
    flow.special_proxy = proxy.map(Arc::from);
    flow
}

/// The core's own connection through a proxy (provider fetches, delay probes,
/// DNS over a proxy). It shows in the connection table for as long as it lives.
pub(crate) async fn dial_inner(
    inner: &Arc<Inner>,
    target: &Address,
    proxy: Option<&str>,
) -> io::Result<(BoxStream, Box<[Arc<str>]>)> {
    let runtime = inner
        .runtime_for(InboundKind::Inner)
        .ok_or_else(|| concord_common::io_error("the core is not running"))?;
    let mut flow = inner_flow(target, Network::Tcp, proxy);
    pre_handle(&mut flow, &runtime.dns).map_err(concord_common::io_error)?;
    let (remote, decision) = dial_traced(inner, &runtime, &mut flow)
        .await
        .map_err(|failed| failed.error)?;
    let live = inner.live();
    tracing::info!("{}", decision.match_text(&flow, &live));
    let registration = inner
        .table
        .register(record_of(&flow, &decision, &remote), 0);
    Ok((
        Box::new(MeteredStream::new(remote, registration)),
        decision.chain,
    ))
}

/// A UDP session the core uses itself, with the same bookkeeping as `dial_inner`.
pub(crate) async fn associate_inner(
    inner: &Arc<Inner>,
    target: &Address,
    proxy: Option<&str>,
) -> io::Result<Arc<dyn PacketSession>> {
    let runtime = inner
        .runtime_for(InboundKind::Inner)
        .ok_or_else(|| concord_common::io_error("the core is not running"))?;
    let mut flow = inner_flow(target, Network::Udp, proxy);
    pre_handle(&mut flow, &runtime.dns).map_err(concord_common::io_error)?;
    let live = inner.live();
    let decision = route(&mut flow, &runtime, &live, Touch::Yes).await?;
    let deadline = Instant::now() + DIAL_TIMEOUT;
    let env = runtime.env_for(&flow);
    let cx = DialCx::new(&env, Initiator::Other, Some(deadline));
    let hint = flow.pure_address();
    let session = match timeout_at(deadline, decision.leaf.associate(&cx, &hint)).await {
        Ok(result) => result?,
        Err(_) => return Err(io::Error::from(io::ErrorKind::TimedOut)),
    };
    let destination = server_host(&decision.leaf.info().addr);
    let record = new_record(&flow, &decision, destination);
    let registration = inner.table.register(record, 0);
    Ok(Arc::new(MeteredSession {
        inner: session,
        registration,
    }))
}

struct MeteredSession {
    inner: Arc<dyn PacketSession>,
    registration: Registration,
}

impl PacketSession for MeteredSession {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        let bytes = pkt.len() as u64;
        let sent = ready!(self.inner.poll_send(cx, pkt, dst));
        if sent.is_ok() {
            self.registration.tracked().uploaded(bytes);
        }
        Poll::Ready(sent)
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        let received = ready!(self.inner.poll_recv(cx, buf));
        if received.is_ok() {
            self.registration.tracked().downloaded(buf.len() as u64);
        }
        Poll::Ready(received)
    }

    fn headroom(&self) -> usize {
        self.inner.headroom()
    }

    fn close(&self) {
        self.inner.close();
    }
}

pub(crate) struct MeteredStream {
    inner: BoxStream,
    registration: Registration,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl MeteredStream {
    pub(crate) fn new(inner: BoxStream, registration: Registration) -> Self {
        let cancelled = Box::pin(
            registration
                .tracked()
                .record
                .cancel
                .clone()
                .cancelled_owned(),
        );
        MeteredStream {
            inner,
            registration,
            cancelled,
        }
    }

    fn check_closed(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        match self.cancelled.as_mut().poll(cx) {
            Poll::Ready(()) => Err(io::Error::from(io::ErrorKind::ConnectionAborted)),
            Poll::Pending => Ok(()),
        }
    }
}

impl AsyncRead for MeteredStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check_closed(cx)?;
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        let bytes = buf.filled().len().saturating_sub(before) as u64;
        if bytes > 0 {
            this.registration.tracked().downloaded(bytes);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MeteredStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check_closed(cx)?;
        let written = ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
        this.registration.tracked().uploaded(written as u64);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for MeteredStream {
    concord_common::stream_policy!(inner;
        forward: read_requirements, write_requirements, peer_addr;
        own: into_split, poll_read_buffer, poll_write_buffer;
        default: raw_socket, tcp, needs_handshake, direct, into_tcp);

    fn poll_read_buffer(
        &mut self,
        cx: &mut Context<'_>,
        options: ReadBufferOptions,
    ) -> Poll<io::Result<StreamBuffer>> {
        self.check_closed(cx)?;
        let buffer = ready!(self.inner.poll_read_buffer(cx, options))?;
        if !buffer.is_empty() {
            self.registration.tracked().downloaded(buffer.len() as u64);
        }
        Poll::Ready(Ok(buffer))
    }

    fn poll_write_buffer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        self.check_closed(cx)?;
        let written = ready!(self.inner.poll_write_buffer(cx, buffer))?;
        self.registration.tracked().uploaded(written as u64);
        Poll::Ready(Ok(written))
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let MeteredStream {
            inner,
            registration,
            cancelled,
        } = *self;
        let (read, write) = inner.into_split();
        let registration = Arc::new(registration);
        let write_cancelled = Box::pin(
            registration
                .tracked()
                .record
                .cancel
                .clone()
                .cancelled_owned(),
        );
        (
            Box::new(MeteredRead {
                inner: read,
                registration: registration.clone(),
                cancelled,
            }),
            Box::new(MeteredWrite {
                inner: write,
                registration,
                cancelled: write_cancelled,
            }),
        )
    }
}

struct MeteredRead {
    inner: BoxRead,
    registration: Arc<Registration>,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl AsyncRead for MeteredRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionAborted)));
        }
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        let bytes = buf.filled().len().saturating_sub(before) as u64;
        if bytes > 0 {
            this.registration.tracked().downloaded(bytes);
        }
        Poll::Ready(Ok(()))
    }
}

struct MeteredWrite {
    inner: BoxWrite,
    registration: Arc<Registration>,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl AsyncWrite for MeteredWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionAborted)));
        }
        let written = ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
        this.registration.tracked().uploaded(written as u64);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

use std::future::Future;
