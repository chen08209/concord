use std::collections::VecDeque;
use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;

use concord_common::{Network, Tasks};
use concord_netstack::frag::Reassembler;
use concord_netstack::wire::{
    DropReason, IpView, L4Checksum, L4Kind, Parsed, UdpView, build_echo_reply, parse_packet,
    parse_tcp, parse_udp, parse_udp_unverified,
};
use concord_netstack::{Admit, Egress, Gather, StackConfig, TcpConfig, TcpInput, TcpStack};
use concord_platform::SparseBuf;
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;
use tokio::time::Sleep;
use tokio_util::sync::CancellationToken;

use super::own_wake::OwnWake;
use super::pool::{Slot, TxPool};
use super::queues::Queues;
use super::replies::ReplySources;
use super::stats::{StackStats, report};
use super::udp::UdpTable;
use super::{DnsConfig, FlowSink, StackOptions, Verdict, flow_key};
use crate::device::{Device, MAX_BATCH};
use crate::dns;

const RX_BATCH: usize = 64;
const RX_BATCH_START: usize = 8;
const MAX_ROUNDS: usize = 8;
/// Bytes a round reads before the stack answers them, as sing-tun ends a read burst: an
/// upload's ACKs go out while the sender still has window, not after the device runs dry.
const ROUND_READ_BYTES: usize = 1 << 20;
const SWEEP_INTERVAL: u64 = 15_000_000;
const RX_BUFFER: usize = 65_536 + 16;
const DNS_CONCURRENCY: usize = 256;
const TX_POOL_BYTES: usize = 1 << 20;
/// Slots start at the MTU and grow to a frame's size the first time they carry one.
const SEGMENTED_SLOTS: usize = 64;
const MAX_FRAME: usize = 65_535;
const TAG_FLOW: u32 = 0;
const TAG_DNS: u32 = 1;

enum Route {
    Local,
    Reserved,
    Forwarded,
}

pub(super) struct Prepared<D> {
    dev: D,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
}

pub(super) fn prepare<D: Device>(dev: D) -> io::Result<Vec<Prepared<D>>> {
    dev.into_queues()
        .into_iter()
        .map(|dev| {
            let dev = dev.prepare()?;
            Ok(Prepared { dev, ready: None })
        })
        .collect()
}

impl<D> Prepared<D> {
    pub fn ready(&mut self) -> tokio::sync::oneshot::Receiver<()> {
        let (sent, received) = tokio::sync::oneshot::channel();
        self.ready = Some(sent);
        received
    }
}

pub(super) async fn run<D: Device>(
    options: StackOptions,
    dev: D,
    sink: Arc<dyn FlowSink>,
    stop: CancellationToken,
) -> io::Result<()> {
    run_prepared(options, prepare(dev)?, sink, stop).await
}

pub(super) async fn run_prepared<D: Device>(
    options: StackOptions,
    devs: Vec<Prepared<D>>,
    sink: Arc<dyn FlowSink>,
    stop: CancellationToken,
) -> io::Result<()> {
    let count = devs.len();
    if count <= 1 {
        let Some(dev) = devs.into_iter().next() else {
            return Ok(());
        };
        return run_queue(options, dev, sink, stop, None).await;
    }
    let queues = Arc::new(Queues::new(count));
    let stop = stop.child_token();
    let _cancel = stop.clone().drop_guard();
    let mut running = FuturesUnordered::new();
    for (index, dev) in devs.into_iter().enumerate() {
        let options = StackOptions {
            max_tcp_flows: options.max_tcp_flows.div_ceil(count),
            max_half_open_tcp: options.max_half_open_tcp.div_ceil(count),
            ..options.clone()
        };
        running.push(options.tasks.clone().spawn_returning(run_queue(
            options,
            dev,
            Arc::clone(&sink),
            stop.clone(),
            Some((index, Arc::clone(&queues))),
        )));
    }
    let mut result = Ok(());
    while let Some(joined) = running.next().await {
        if let Err(err) = joined
            .map_err(io::Error::other)
            .and_then(|done| done.unwrap_or(Ok(())))
            && result.is_ok()
        {
            result = Err(err);
            stop.cancel();
        }
    }
    result
}

async fn run_queue<D: Device>(
    options: StackOptions,
    prepared: Prepared<D>,
    sink: Arc<dyn FlowSink>,
    stop: CancellationToken,
    queue: Option<(usize, Arc<Queues>)>,
) -> io::Result<()> {
    let Prepared { dev, ready } = prepared;
    let stop = stop.child_token();
    let cancelled = stop.clone();
    let work = move || async move {
        let mut driver = Driver::new(options, dev, sink);
        if let Some((index, queues)) = queue {
            driver = driver.with_queue(index, &queues);
        }
        drive(driver, stop, ready).await
    };
    let _cancel = cancelled.drop_guard();
    work().await
}

async fn drive<D: Device>(
    mut driver: Driver<D>,
    stop: CancellationToken,
    mut ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> io::Result<()> {
    let mut cancelled = Box::pin(stop.cancelled_owned());
    let (own, waker) = OwnWake::new();
    poll_fn(|task| {
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Ok(()));
        }
        let cx = &mut Context::from_waker(&waker);
        if let Poll::Ready(Err(error)) = own.before_pass(task.waker(), || driver.dev.poll_io(cx)) {
            return Poll::Ready(Err(error));
        }
        let result = driver.poll_run(cx);
        if result.is_pending() {
            // Cooperative Pending already schedules another poll; it is not an empty I/O set.
            let busy = !driver.drained || !tokio::task::coop::has_budget_remaining();
            match driver.dev.set_busy(busy) {
                Ok(true) => {
                    driver.replies.requeue();
                    cx.waker().wake_by_ref();
                }
                Err(error) => return Poll::Ready(Err(error)),
                Ok(false) => {}
            }
            if !busy && let Poll::Ready(outcome) = driver.dev.poll_park(cx) {
                if let Err(error) = outcome {
                    return Poll::Ready(Err(error));
                }
                cx.waker().wake_by_ref();
            }
        }
        if result.is_pending()
            && let Some(ready) = ready.take()
        {
            let _ = ready.send(());
        }
        result
    })
    .await
}

/// Builds the stack's packets in place in the device's transmit pool, or hands a payload
/// straight to the device while nothing waits ahead of it.
struct PoolEgress<'a, D> {
    pool: &'a TxPool,
    dev: &'a D,
    direct: bool,
}

impl<'a, D: Device> PoolEgress<'a, D> {
    fn new(pool: &'a TxPool, dev: &'a D, inflight: &VecDeque<Slot>) -> Self {
        let direct = inflight.is_empty() && !pool.has_filled();
        PoolEgress { pool, dev, direct }
    }
}

impl<D: Device> Egress for PoolEgress<'_, D> {
    fn checksum(&self) -> L4Checksum {
        self.pool.checksum
    }

    fn segment_limit(&self) -> usize {
        self.pool.segment_limit.load(Ordering::Relaxed)
    }

    fn send(&mut self, build: &mut dyn FnMut(&mut [u8]) -> Option<usize>) -> bool {
        self.send_segmented(0, build)
    }

    fn send_segmented(
        &mut self,
        segment: u16,
        build: &mut dyn FnMut(&mut [u8]) -> Option<usize>,
    ) -> bool {
        let Some(mut slot) = self.pool.take_free() else {
            return false;
        };
        if segment > 0 {
            slot.grow(MAX_FRAME);
        }
        match build(&mut slot.buf) {
            Some(len) => {
                slot.len = len;
                slot.segment = segment;
                self.pool.push_filled(slot);
                self.direct = false;
            }
            None => {
                self.pool.note_oversize();
                self.pool.release(slot);
            }
        }
        true
    }

    fn send_in_place(&mut self, segment: u16, head: &[u8], payload: &[IoSlice<'_>]) -> bool {
        if !self.direct {
            return false;
        }
        let mut parts = [IoSlice::new(&[]); 9];
        let Some((first, rest)) = parts.split_first_mut() else {
            return false;
        };
        let Some(tail) = rest.get_mut(..payload.len()) else {
            return false;
        };
        *first = IoSlice::new(head);
        tail.copy_from_slice(payload);
        let count = payload.len() + 1;
        self.direct = self
            .dev
            .try_send_parts(parts.get(..count).unwrap_or_default(), segment)
            .is_ok();
        self.direct
    }
}

struct Driver<D: Device> {
    dev: D,
    tcp: TcpStack,
    pool: Arc<TxPool>,
    stats: Arc<StackStats>,
    sink: Arc<dyn FlowSink>,
    handlers: Tasks,
    dns: Option<Arc<DnsConfig>>,
    dns_slots: Arc<Semaphore>,
    udp: UdpTable,
    replies: ReplySources,
    fragments: Reassembler,
    reassembled: Vec<u8>,
    inflight: VecDeque<Slot>,
    /// Room for one batch of reads: a batch's TCP payload goes to attached sockets straight
    /// from here when the batch ends.
    rx_buf: SparseBuf,
    rx_stride: usize,
    rx_extended: bool,
    rx_receive_epoch: u64,
    /// `recvmsg_x` walks every slot it is handed, so the batch follows what the device delivers.
    rx_batch: usize,
    options: StackOptions,
    sleep: Pin<Box<Sleep>>,
    next_sweep: u64,
    queue: Option<(usize, Arc<Queues>)>,
    tcp_reported: usize,
    udp_reported: usize,
    drained: bool,
}

impl<D: Device> Drop for Driver<D> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn echo_reply(pool: &TxPool, stats: &StackStats, view: &IpView<'_>) {
    let Some(mut slot) = pool.take_free() else {
        return;
    };
    match build_echo_reply(&mut slot.buf, view) {
        Some(len) => {
            slot.len = len;
            pool.push_filled(slot);
            stats.icmp_echo.fetch_add(1, Ordering::Relaxed);
        }
        None => pool.release(slot),
    }
}

impl<D: Device> Driver<D> {
    fn new(options: StackOptions, dev: D, sink: Arc<dyn FlowSink>) -> Self {
        let mtu = options.mtu.clamp(576, 65_535);
        let device_batch = D::BATCH.clamp(1, MAX_BATCH);
        let rx_stride = if device_batch == 1 { RX_BUFFER } else { mtu };
        let (checksum, segment_limit) = if dev.checksum_offload() {
            (L4Checksum::Pseudo, dev.segment_limit())
        } else {
            (L4Checksum::Full, 0)
        };
        let slots = if segment_limit > 0 {
            SEGMENTED_SLOTS
        } else {
            (TX_POOL_BYTES / mtu).clamp(32, 256)
        };
        let pool = TxPool::new(slots, mtu);
        let pool = Arc::new(pool.with_offload(checksum, segment_limit));
        let stats = Arc::clone(&options.stats);
        let udp_timeout = i64::try_from(options.udp_timeout.as_micros()).unwrap_or(i64::MAX);
        let tcp = TcpStack::new(StackConfig {
            tcp: TcpConfig {
                mtu,
                congestion: options.congestion,
                ..TcpConfig::default()
            },
            max_connections: options.max_tcp_flows,
            max_half_open: options.max_half_open_tcp,
        })
        .with_socket_owner(dev.socket_owner());
        let mut replies = ReplySources::new(Arc::clone(&pool), mtu, Arc::clone(&stats));
        replies.watch_with(dev.socket_watcher());
        Driver {
            dev,
            tcp,
            udp: UdpTable::new(
                udp_timeout,
                Arc::clone(&pool),
                replies.queue(),
                mtu,
                Arc::clone(&stats),
            ),
            replies,
            pool,
            stats,
            sink,
            handlers: options.tasks.clone(),
            dns: options.dns.clone(),
            dns_slots: Arc::new(Semaphore::new(DNS_CONCURRENCY)),
            fragments: Reassembler::default(),
            reassembled: Vec::new(),
            inflight: VecDeque::with_capacity(device_batch),
            rx_buf: SparseBuf::zeroed(rx_stride * RX_BATCH),
            rx_stride,
            rx_extended: false,
            rx_receive_epoch: 0,
            rx_batch: device_batch.min(RX_BATCH_START),
            options: StackOptions { mtu, ..options },
            sleep: Box::pin(tokio::time::sleep(Duration::from_secs(3600))),
            next_sweep: SWEEP_INTERVAL,
            queue: None,
            tcp_reported: 0,
            udp_reported: 0,
            drained: true,
        }
    }

    fn with_queue(mut self, index: usize, queues: &Arc<Queues>) -> Self {
        self.tcp.set_flow_owner(queues.flow_owner(index));
        self.queue = Some((index, Arc::clone(queues)));
        self
    }

    fn poll_run(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.pool.register_driver(cx.waker());
        self.tcp.register_waker(cx.waker());
        if let Some((index, queues)) = &self.queue {
            queues.register(*index, cx.waker());
        }
        let mut busy = true;
        let mut rounds = 0;
        let mut deadline = None;
        let mut replies_left = false;
        while busy && rounds < MAX_ROUNDS {
            rounds += 1;
            self.udp.set_now(self.tcp.now());
            busy = false;
            let sink = Arc::clone(&self.sink);
            let mut drained = Ok(false);
            sink.udp_round(&mut || {
                drained = self.drain_rx(cx).map(|read| self.drain_handoffs() | read);
            });
            match drained {
                Ok(read) => busy |= read,
                Err(err) => return Poll::Ready(Err(err)),
            }
            // Once a poll, after the first TUN reads, as sing-tun dispatches socket events once a
            // run loop (`stack_go_engine.go:283-298`).
            if rounds == 1 {
                replies_left = self.replies.drain();
            }
            deadline = self
                .tcp
                .poll(&mut PoolEgress::new(&self.pool, &self.dev, &self.inflight));
            self.announce();
            busy |= self.flush(cx);
            busy |= self.tcp.has_blocked() && self.pool.free_count() > 0;
        }
        let now = self.tcp.now();
        if now >= self.next_sweep {
            let now_i = i64::try_from(now).unwrap_or(i64::MAX);
            self.udp.sweep(now_i);
            report(
                &self.stats.udp_sessions,
                &mut self.udp_reported,
                self.udp.len(),
            );
            if let Some((index, queues)) = &self.queue {
                queues.retain(*index, |(local, remote)| self.tcp.owns(*local, *remote));
            }
            self.next_sweep = now + SWEEP_INTERVAL;
        }
        report(
            &self.stats.tcp_active,
            &mut self.tcp_reported,
            self.tcp.len(),
        );
        self.retire_rx();
        busy |= replies_left;
        self.drained = !busy;
        if busy {
            cx.waker().wake_by_ref();
        } else {
            self.arm_timer(cx, deadline);
        }
        Poll::Pending
    }

    fn retire_rx(&mut self) {
        let epoch = self.tcp.receive_epoch();
        if epoch != self.rx_receive_epoch {
            self.rx_receive_epoch = epoch;
            if self.rx_extended {
                // Every gather has been flushed; closed receive owners no longer need this
                // working set. Keep single-frame traffic from rebuilding it on each close.
                self.rx_buf = SparseBuf::zeroed(self.rx_stride * RX_BATCH);
                self.rx_extended = false;
            }
        }
    }

    fn flush(&mut self, cx: &mut Context<'_>) -> bool {
        let batch = self.dev.send_batch().clamp(1, MAX_BATCH);
        let mut released = false;
        loop {
            while self.inflight.len() < batch
                && let Some(slot) = self.pool.pop_filled()
            {
                self.inflight.push_back(slot);
            }
            if self.inflight.is_empty() {
                return released;
            }
            if let Some(front) = self.inflight.front()
                && front.segment > 0
            {
                let Poll::Ready(result) =
                    self.dev
                        .poll_send_segmented(cx, front.packet(), front.segment)
                else {
                    return released;
                };
                if let Err(err) = result {
                    self.stats.tx_errors.fetch_add(1, Ordering::Relaxed);
                    if err.kind() == io::ErrorKind::InvalidInput {
                        tracing::warn!("tun refused a segmented frame, sending segments: {err}");
                        self.pool.segment_limit.store(0, Ordering::Relaxed);
                    }
                }
                if let Some(slot) = self.inflight.pop_front() {
                    self.pool.release(slot);
                }
                released = true;
                continue;
            }
            let plain = self
                .inflight
                .iter()
                .take_while(|slot| slot.segment == 0)
                .count();
            let mut packets: [&[u8]; MAX_BATCH] = [&[]; MAX_BATCH];
            for (packet, slot) in packets.iter_mut().zip(&self.inflight) {
                *packet = slot.packet();
            }
            let mut failed = 0;
            let ready = packets.get(..plain).unwrap_or_default();
            let Poll::Ready(sent) = self.dev.poll_send_batch(cx, ready, &mut failed) else {
                return released;
            };
            if sent == 0 {
                return released;
            }
            self.stats
                .tx_errors
                .fetch_add(failed as u64, Ordering::Relaxed);
            for slot in self.inflight.drain(..sent.min(self.inflight.len())) {
                self.pool.release(slot);
            }
            released = true;
        }
    }

    fn drain_rx(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        let mut buf = std::mem::take(&mut self.rx_buf);
        let mut read = 0;
        let mut bytes = 0;
        let mut outcome = Ok(());
        loop {
            let mut gather = Gather::default();
            let again = self.read_into(
                cx,
                &mut buf,
                (&mut read, &mut bytes),
                &mut outcome,
                &mut gather,
            );
            self.tcp.flush(&mut gather);
            if !again {
                break;
            }
        }
        self.rx_buf = buf;
        outcome.map(|()| read > 0)
    }

    /// Reads packets into `buf`, each right after the last; true when `gather` holds none of
    /// them and the batch goes on, so the next read can start over at the front.
    fn read_into<'a>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &'a mut [u8],
        (read, bytes): (&mut usize, &mut usize),
        outcome: &mut io::Result<()>,
        gather: &mut Gather<'a>,
    ) -> bool {
        let device_batch = D::BATCH.clamp(1, MAX_BATCH);
        let stride = self.rx_stride;
        let offset = self.dev.rx_offset();
        let lens = [0usize; MAX_BATCH];
        let capacity = buf.len();
        let mut free: &'a mut [u8] = buf;
        while *read < RX_BATCH && *bytes < ROUND_READ_BYTES {
            let want = self.rx_batch.min(RX_BATCH - *read).min(free.len() / stride);
            if want == 0 {
                return false;
            }
            let mut lens = lens;
            let wanted = lens.get_mut(..want).unwrap_or_default();
            let received = match self.dev.poll_recv_batch(cx, free, stride, wanted) {
                Poll::Pending => return false,
                Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::Interrupted => continue,
                Poll::Ready(Err(err)) => {
                    tracing::error!("tun device read failed, the stack stops: {err}");
                    *outcome = Err(err);
                    return false;
                }
                Poll::Ready(Ok(received)) => received.min(want),
            };
            if device_batch > 1 {
                if received == want {
                    self.rx_batch = (want * 2).min(device_batch);
                } else if received * 2 < want {
                    self.rx_batch = (want / 2).max(1);
                }
            }
            *read += received.max(1);
            *bytes += lens.iter().take(received).sum::<usize>();
            self.stats
                .rx_packets
                .fetch_add(received as u64, Ordering::Relaxed);
            let used = match received.checked_sub(1) {
                Some(last) => last * stride + offset + lens.get(last).copied().unwrap_or(0),
                None => 0,
            };
            let rest = std::mem::take(&mut free);
            let (filled, rest) = rest.split_at_mut(used.min(rest.len()));
            free = rest;
            self.rx_extended |= capacity - free.len() > stride;
            let filled: &'a [u8] = filled;
            for (index, len) in lens.iter().take(received).enumerate() {
                let start = index * stride + offset;
                match filled
                    .get(start..start + len)
                    .filter(|packet| !packet.is_empty())
                {
                    Some(packet) => self.handle_packet(packet, gather),
                    None => self.stats.count_drop(DropReason::Malformed),
                }
            }
            if gather.is_empty() && *read < RX_BATCH && *bytes < ROUND_READ_BYTES {
                return true;
            }
        }
        false
    }

    fn handle_packet<'a>(&mut self, packet: &'a [u8], gather: &mut Gather<'a>) {
        match parse_packet(packet) {
            Ok(Parsed::Packet(view)) => self.dispatch(&view, gather),
            Ok(Parsed::Fragment(frag)) => {
                self.tcp.flush(gather);
                let mut whole = std::mem::take(&mut self.reassembled);
                if self.fragments.push(&frag, self.tcp.now(), &mut whole) {
                    match parse_packet(&whole) {
                        Ok(Parsed::Packet(view)) => {
                            let mut own = Gather::default();
                            self.dispatch(&view, &mut own);
                            self.tcp.flush(&mut own);
                        }
                        Ok(Parsed::Fragment(_)) => self.stats.count_drop(DropReason::Fragment),
                        Err(reason) => self.stats.count_drop(reason),
                    }
                }
                self.reassembled = whole;
            }
            Err(reason) => self.stats.count_drop(reason),
        }
    }

    fn parse_udp<'a>(&self, view: &IpView<'a>) -> Result<UdpView<'a>, DropReason> {
        match self.pool.checksum {
            L4Checksum::Full => parse_udp(view),
            L4Checksum::Pseudo => parse_udp_unverified(view),
        }
    }

    fn dispatch<'a>(&mut self, view: &IpView<'a>, gather: &mut Gather<'a>) {
        if self.options.broadcast == Some(view.dst) {
            return self.stats.count_drop(DropReason::Martian);
        }
        match view.kind {
            L4Kind::Icmp => self.on_icmp(view),
            L4Kind::Udp => match self.parse_udp(view) {
                Ok(udp) => self.on_udp(view, udp.src_port, udp.dst_port, udp.payload),
                Err(reason) => self.stats.count_drop(reason),
            },
            L4Kind::Tcp => self.on_tcp(view, gather),
        }
    }

    fn on_icmp(&mut self, view: &IpView<'_>) {
        if !self.options.disable_icmp_forwarding {
            let request = view.packet.to_vec();
            let pool = Arc::clone(&self.pool);
            let stats = Arc::clone(&self.stats);
            let answer = Box::new(move || {
                if let Ok(Parsed::Packet(view)) = parse_packet(&request) {
                    echo_reply(&pool, &stats, &view);
                }
            });
            if self.sink.icmp(view.dst, view.l4, answer) {
                return;
            }
        }
        echo_reply(&self.pool, &self.stats, view);
    }

    fn hijacks(dns: Option<&DnsConfig>, dst: SocketAddr) -> bool {
        dns.is_some_and(|dns| dns.matcher.matches(dst))
    }

    fn on_udp(&mut self, view: &IpView<'_>, src_port: u16, dst_port: u16, payload: &[u8]) {
        let src = SocketAddr::new(view.src, src_port);
        let dst = SocketAddr::new(view.dst, dst_port);
        self.stats.udp_packets.fetch_add(1, Ordering::Relaxed);
        let reply = self.udp.reply_for(src);
        if Self::hijacks(self.dns.as_deref(), dst) {
            self.stats.dns_hijacked.fetch_add(1, Ordering::Relaxed);
            if let (Some(dns), Ok(permit)) = (
                self.dns.as_ref(),
                Arc::clone(&self.dns_slots).try_acquire_owned(),
            ) {
                let handler = Arc::clone(&dns.handler);
                let query = payload.to_vec();
                let reply = reply.into_owned();
                self.handlers.spawn(async move {
                    let _permit = permit;
                    dns::answer_udp(handler, reply, dst, query).await;
                });
            }
            return;
        }
        self.sink
            .udp(flow_key(Network::Udp, src, dst), payload, &reply);
    }

    fn drain_handoffs(&mut self) -> bool {
        let Some((index, queues)) = &self.queue else {
            return false;
        };
        let packets = queues.take(*index);
        let any = !packets.is_empty();
        for packet in packets {
            let mut own = Gather::default();
            self.handle_packet(&packet, &mut own);
            self.tcp.flush(&mut own);
        }
        any
    }

    /// Hands a segment to its owner, or records a new local reservation for admission.
    fn hand_off(&self, view: &IpView<'_>) -> Route {
        let (Some((index, queues)), Ok(seg)) = (&self.queue, parse_tcp(view.l4)) else {
            return Route::Local;
        };
        let local = SocketAddr::new(view.dst, seg.dst_port);
        let remote = SocketAddr::new(view.src, seg.src_port);
        if self.tcp.owns(local, remote) {
            return Route::Local;
        }
        let owner = if seg.is_syn() {
            queues.claim((local, remote), *index)
        } else {
            queues.owner(&(local, remote)).unwrap_or(*index)
        };
        if owner == *index {
            return if seg.is_syn() {
                Route::Reserved
            } else {
                Route::Local
            };
        }
        if !queues.forward(owner, view.packet) {
            self.stats.rx_handoff.fetch_add(1, Ordering::Relaxed);
        }
        Route::Forwarded
    }

    fn on_tcp<'a>(&mut self, view: &IpView<'a>, gather: &mut Gather<'a>) {
        let reserved = match self.hand_off(view) {
            Route::Forwarded => return,
            Route::Local => false,
            Route::Reserved => true,
        };
        let dns = self.dns.as_deref();
        let sink = &self.sink;
        let packet = view.packet;
        let result = self.tcp.input_gathered(
            view.src,
            view.dst,
            view.l4,
            &mut PoolEgress::new(&self.pool, &self.dev, &self.inflight),
            |remote, local| {
                if Self::hijacks(dns, local) {
                    return Admit::Accept(TAG_DNS);
                }
                match sink.judge(&flow_key(Network::Tcp, remote, local), packet) {
                    Verdict::Accept => Admit::Accept(TAG_FLOW),
                    Verdict::Reject => Admit::Reject,
                    Verdict::Drop => Admit::Drop,
                }
            },
            gather,
        );
        if reserved
            && let Some((index, queues)) = &self.queue
            && let Ok(seg) = parse_tcp(view.l4)
        {
            let local = SocketAddr::new(view.dst, seg.dst_port);
            let remote = SocketAddr::new(view.src, seg.src_port);
            if !self.tcp.owns(local, remote) {
                queues.release_unopened(&(local, remote), *index);
            }
        }
        match result {
            TcpInput::Refused => {
                self.stats.tcp_refused.fetch_add(1, Ordering::Relaxed);
            }
            TcpInput::Dropped(reason) => self.stats.count_drop(reason),
            TcpInput::Handled | TcpInput::Opened | TcpInput::Reset => {}
        }
    }

    fn announce(&mut self) {
        while let Some(accepted) = self.tcp.take_accepted() {
            self.stats.tcp_accepted.fetch_add(1, Ordering::Relaxed);
            if accepted.tag == TAG_DNS {
                self.stats.dns_hijacked.fetch_add(1, Ordering::Relaxed);
                if let Some(dns) = &self.dns {
                    self.handlers
                        .spawn(dns::serve_tcp(accepted.stream, Arc::clone(&dns.handler)));
                }
                continue;
            }
            self.sink.tcp(
                flow_key(Network::Tcp, accepted.remote, accepted.local),
                Box::new(accepted.stream),
            );
        }
    }

    fn arm_timer(&mut self, cx: &mut Context<'_>, deadline: Option<u64>) {
        let next = deadline.map_or(self.next_sweep, |at| at.min(self.next_sweep));
        self.sleep.as_mut().reset(self.tcp.instant_at(next));
        if self.sleep.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
    }

    fn shutdown(&mut self) {
        self.tcp.shutdown();
        self.pool.close();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test setup and assertions")]
mod owner_tests {
    use std::sync::atomic::{AtomicU8, Ordering};

    use super::*;
    use tokio::io::AsyncReadExt;

    struct Silent;
    impl Device for Silent {
        fn poll_recv(&self, _: &mut Context<'_>, _: &mut [u8]) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
        fn poll_send(&self, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
    }
    struct Idle;
    impl FlowSink for Idle {
        fn tcp(&self, _: concord_common::FlowKey, _: concord_common::BoxStream) {}
        fn udp(&self, _: concord_common::FlowKey, _: &[u8], _: &Arc<dyn concord_common::UdpReply>) {
        }
    }

    #[tokio::test]
    async fn unused_receive_lifetimes_release_extended_rx_but_keep_single_frame_storage() {
        let mut driver = Driver::new(StackOptions::default(), Silent, Arc::new(Idle));
        let mut previous = driver.rx_buf.as_ptr();
        for extended in [false, true, false, true] {
            let stream = driver
                .tcp
                .connect(
                    "10.0.0.1:1234".parse().unwrap(),
                    "10.0.0.2:80".parse().unwrap(),
                    concord_netstack::Congestion::Cubic,
                )
                .unwrap();
            let written = if extended { driver.rx_stride * 2 } else { 64 };
            driver.rx_buf[..written].fill(0x7b);
            driver.rx_extended = extended;
            driver.retire_rx();
            assert_eq!(
                driver.rx_buf.as_ptr(),
                previous,
                "an active receiver keeps storage"
            );
            assert_eq!(driver.rx_buf[0], 0x7b);
            driver.tcp.shutdown();
            driver.retire_rx();
            if extended {
                assert_ne!(driver.rx_buf.as_ptr(), previous);
                assert!(driver.rx_buf[..written].iter().all(|byte| *byte == 0));
            } else {
                assert_eq!(
                    driver.rx_buf.as_ptr(),
                    previous,
                    "small traffic does not remap on close"
                );
            }
            previous = driver.rx_buf.as_ptr();
            drop(stream);
        }
    }

    #[tokio::test]
    async fn cooperative_pending_keeps_the_owner_runnable_but_idle_io_can_park() {
        struct PendingDevice {
            exhaust: bool,
            stop: CancellationToken,
            observed: Arc<AtomicU8>,
        }
        impl Device for PendingDevice {
            fn poll_recv(&self, cx: &mut Context<'_>, _: &mut [u8]) -> Poll<io::Result<usize>> {
                if self.exhaust {
                    while tokio::task::coop::has_budget_remaining() {
                        match tokio::task::coop::poll_proceed(cx) {
                            Poll::Ready(budget) => budget.made_progress(),
                            Poll::Pending => break,
                        }
                    }
                    let Poll::Pending = tokio::task::coop::poll_proceed(cx) else {
                        return Poll::Ready(Err(io::Error::other("budget did not exhaust")));
                    };
                }
                Poll::Pending
            }

            fn poll_send(&self, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
                Poll::Pending
            }

            fn set_busy(&self, busy: bool) -> io::Result<bool> {
                self.observed
                    .store(if busy { 2 } else { 1 }, Ordering::Release);
                self.stop.cancel();
                Ok(false)
            }
        }
        for exhaust in [false, true] {
            let observed = Arc::new(AtomicU8::new(0));
            let stop = CancellationToken::new();
            let device = PendingDevice {
                exhaust,
                stop: stop.clone(),
                observed: Arc::clone(&observed),
            };
            let task = tokio::spawn(async move {
                let driver = Driver::new(StackOptions::default(), device, Arc::new(Idle));
                drive(driver, stop, None).await
            });
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(
                observed.load(Ordering::Acquire),
                if exhaust { 2 } else { 1 }
            );
        }
    }

    #[tokio::test]
    async fn a_full_transmit_pool_does_not_stop_reading_the_device() {
        struct Queued(std::sync::atomic::AtomicUsize);
        impl Device for Queued {
            fn poll_recv(&self, _: &mut Context<'_>, _: &mut [u8]) -> Poll<io::Result<usize>> {
                match self
                    .0
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                        left.checked_sub(1)
                    }) {
                    Ok(_) => Poll::Ready(Ok(1)),
                    Err(_) => Poll::Pending,
                }
            }
            fn poll_send(&self, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
                Poll::Pending
            }
        }
        let device = Queued(std::sync::atomic::AtomicUsize::new(5));
        let mut driver = Driver::new(StackOptions::default(), device, Arc::new(Idle));
        let mut held = Vec::new();
        driver.pool.take_up_to(&mut held, usize::MAX);
        assert_eq!(driver.pool.free_count(), 0);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(driver.drain_rx(&mut cx).unwrap());
        assert_eq!(
            driver.dev.0.load(Ordering::Relaxed),
            0,
            "the peer's ACKs are read while every transmit slot is taken"
        );
        driver.pool.give_back(&mut held, 0);
    }

    #[tokio::test]
    async fn reading_without_transmit_room_is_bounded_and_returns() {
        struct Flood(std::sync::atomic::AtomicUsize);
        impl Device for Flood {
            fn poll_recv(&self, _: &mut Context<'_>, _: &mut [u8]) -> Poll<io::Result<usize>> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Ok(1))
            }
            fn poll_send(&self, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
                Poll::Pending
            }
        }
        let device = Flood(std::sync::atomic::AtomicUsize::new(0));
        let mut driver = Driver::new(StackOptions::default(), device, Arc::new(Idle));
        let mut held = Vec::new();
        driver.pool.take_up_to(&mut held, usize::MAX);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(driver.poll_run(&mut cx).is_pending());
        let reads = driver.dev.0.load(Ordering::Relaxed);
        assert!(
            (1..=RX_BATCH * MAX_ROUNDS).contains(&reads),
            "{reads} reads in one pass"
        );
        driver.pool.give_back(&mut held, 0);
    }

    #[tokio::test]
    async fn queued_writes_leave_the_cooperative_budget_room_for_reads() {
        #[derive(Default)]
        struct Busy {
            reads: std::sync::atomic::AtomicUsize,
            writes: std::sync::atomic::AtomicUsize,
        }
        impl Device for Busy {
            fn poll_recv(&self, cx: &mut Context<'_>, _: &mut [u8]) -> Poll<io::Result<usize>> {
                let budget = std::task::ready!(tokio::task::coop::poll_proceed(cx));
                budget.made_progress();
                self.reads.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Ok(1))
            }
            fn poll_send(&self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
                let budget = std::task::ready!(tokio::task::coop::poll_proceed(cx));
                budget.made_progress();
                self.writes.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Ok(packet.len()))
            }
        }
        let mut driver = Driver::new(StackOptions::default(), Busy::default(), Arc::new(Idle));
        let mut queued = Vec::new();
        driver.pool.take_up_to(&mut queued, usize::MAX);
        for mut slot in queued {
            slot.len = 20;
            driver.pool.push_filled(slot);
        }
        std::future::poll_fn(|cx| {
            let _ = driver.poll_run(cx);
            Poll::Ready(())
        })
        .await;
        let reads = driver.dev.reads.load(Ordering::Relaxed);
        let writes = driver.dev.writes.load(Ordering::Relaxed);
        assert!(
            reads >= RX_BATCH && writes > 0,
            "{reads} reads and {writes} writes in one pass"
        );
    }

    #[tokio::test]
    async fn a_round_answers_its_reads_after_a_mebibyte() {
        struct Upload(std::sync::atomic::AtomicUsize);
        impl Device for Upload {
            fn poll_recv(&self, _: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_send(&self, _: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(packet.len()))
            }
        }
        let device = Upload(std::sync::atomic::AtomicUsize::new(0));
        let mut driver = Driver::new(StackOptions::default(), device, Arc::new(Idle));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(driver.drain_rx(&mut cx).unwrap());
        let reads = driver.dev.0.load(Ordering::Relaxed);
        assert!(
            reads < RX_BATCH && reads * driver.rx_stride >= ROUND_READ_BYTES,
            "{reads} reads of {} bytes in one round",
            driver.rx_stride
        );
    }

    #[tokio::test]
    async fn dropping_the_driver_closes_outstanding_connections() {
        let mut driver = Driver::new(StackOptions::default(), Silent, Arc::new(Idle));
        let mut stream = driver
            .tcp
            .connect(
                "10.0.0.1:1234".parse().unwrap(),
                "10.0.0.2:80".parse().unwrap(),
                concord_netstack::Congestion::Cubic,
            )
            .unwrap();
        drop(driver);
        let error = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }
}
