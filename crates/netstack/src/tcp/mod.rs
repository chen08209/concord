mod rate;
mod recovery;
mod recv;
mod send;
mod timers;

use std::collections::VecDeque;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::task::Waker;

use crate::attach::Gather;
use crate::buffer::{ChunkPool, Reassembly};
use crate::cc::{Congestion, Controller, Rtt};
use crate::seq::Seq;
use crate::stream::SharedState;
use crate::wire::{
    FLAG_ACK, FLAG_RST, FLAG_SYN, IPV4_HEADER, IPV6_HEADER, L4Checksum, MAX_SACK_BLOCKS,
    TCP_HEADER, TcpOptions, TcpSegment,
};
use rate::{Delivery, Stamp};

/// Where the stack writes the packets it sends.
pub trait Egress {
    /// Builds one packet: `build` gets a buffer of at least the MTU and returns the packet's
    /// length. Returns false, without calling `build`, when there is no room for a packet.
    fn send(&mut self, build: &mut dyn FnMut(&mut [u8]) -> Option<usize>) -> bool;

    fn checksum(&self) -> L4Checksum {
        L4Checksum::Full
    }

    /// The most payload one frame may carry when the device cuts frames into segments; 0
    /// when it does not.
    fn segment_limit(&self) -> usize {
        0
    }

    /// Like `send`, for a frame the device cuts into segments of `segment` payload bytes.
    fn send_segmented(
        &mut self,
        _segment: u16,
        build: &mut dyn FnMut(&mut [u8]) -> Option<usize>,
    ) -> bool {
        self.send(build)
    }

    /// Sends `head`, with checksums left to the device, followed by `payload` where it lies.
    /// False when the packet has to be built with `send` instead.
    fn send_in_place(&mut self, _segment: u16, _head: &[u8], _payload: &[IoSlice<'_>]) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Open,
    Recovery,
    Loss,
}

#[derive(Clone, Copy, Debug)]
struct Sent {
    start: Seq,
    end: Seq,
    fin: bool,
    sent_at: u64,
    sacked: bool,
    lost: bool,
    retrans: bool,
    stamp: Stamp,
}

impl Sent {
    fn len(&self) -> u32 {
        self.end.since(self.start)
    }

    fn payload(&self) -> usize {
        (self.len() - u32::from(self.fin)) as usize
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Rack {
    valid: bool,
    xmit: u64,
    end: Seq,
    rtt: u64,
    reordering: bool,
    reo_mult: u32,
    reo_persist: u32,
    dsack_round: Option<Seq>,
}

#[derive(Clone, Copy, Debug)]
struct Probe {
    end: Seq,
    retrans: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct TcpConfig {
    pub mtu: usize,
    pub congestion: Congestion,
    pub recv_buffer: usize,
    pub recv_buffer_max: usize,
    pub send_buffer_max: usize,
}

impl Default for TcpConfig {
    fn default() -> Self {
        TcpConfig {
            mtu: 1500,
            congestion: Congestion::Cubic,
            recv_buffer: 128 * 1024,
            recv_buffer_max: 4 << 20,
            send_buffer_max: 4 << 20,
        }
    }
}

const KEEP_ALIVE: u64 = 120_000_000;
const TIME_WAIT: u64 = 2_000_000;
const ORPHAN_TIMEOUT: u64 = 60_000_000;

/// What `input` did that the engine has to act on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Event {
    pub established: bool,
    pub closed: bool,
}

/// Wakers collected while the shared state is locked, woken after it is released.
#[derive(Default)]
pub(crate) struct Wakes(Vec<Waker>);

impl Wakes {
    pub fn add(&mut self, waker: Option<Waker>) {
        if let Some(waker) = waker {
            self.0.push(waker);
        }
    }

    pub fn wake(&mut self) {
        for waker in self.0.drain(..) {
            waker.wake();
        }
    }
}

pub(crate) struct Tcb {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: State,
    config: TcpConfig,
    clock_offset: u32,

    iss: Seq,
    snd_una: Seq,
    snd_nxt: Seq,
    send_base: Seq,
    snd_wnd: u32,
    snd_wl1: Seq,
    snd_wl2: Seq,
    snd_shift: u8,
    rcv_shift: u8,
    mss: u32,
    ws_ok: bool,
    sack_ok: bool,
    ts_ok: bool,
    ts_recent: u32,
    syn_pending: bool,
    fin_seq: Option<Seq>,

    rcv_nxt: Seq,
    rcv_adv: Seq,
    rcv_cap: u32,
    ooo: Reassembly,
    peer_fin: Option<Seq>,
    dsack: Option<(Seq, Seq)>,
    ack_pending: bool,
    ack_now: bool,
    ack_at: Option<u64>,
    ack_sent: Seq,
    delivered_total: u64,
    rcv_rtt: u64,
    rcv_rtt_mark: Option<(Seq, u64)>,
    drs_time: u64,
    drs_copied: u64,
    drs_space: u64,

    sent: VecDeque<Sent>,
    sacked_bytes: u32,
    lost_bytes: u32,
    retrans_bytes: u32,
    high_sacked: Seq,

    rtt: Rtt,
    rack: Rack,
    probe: Option<Probe>,
    cc: Controller,
    phase: Phase,
    recover: Seq,
    prr_delivered: u32,
    prr_out: u32,
    recover_fs: u32,
    dupacks: u32,
    cwnd_blocked: bool,
    max_inflight: u32,
    last_send: u64,
    delivery: Delivery,
    /// Nanoseconds, on the same clock as `now`.
    pace_next: u64,
    pace_at: Option<u64>,
    segs_out: u64,

    rto_at: Option<u64>,
    probe_at: Option<u64>,
    reorder_at: Option<u64>,
    persist_at: Option<u64>,
    close_at: Option<u64>,
    keepalive_at: Option<u64>,
    last_recv: u64,
    backoff: u32,
    retries: u32,
    reset_pending: bool,
    sack_scratch: Vec<(Seq, Seq)>,
}

fn mss_for(mtu: usize, remote: SocketAddr) -> u32 {
    let ip = if remote.is_ipv4() {
        IPV4_HEADER
    } else {
        IPV6_HEADER
    };
    mtu.saturating_sub(ip + TCP_HEADER).max(536) as u32
}

fn window_shift(max: usize) -> u8 {
    let mut shift = 0u8;
    while (max >> shift) > 65_535 && shift < 14 {
        shift += 1;
    }
    shift
}

impl Tcb {
    fn blank(
        local: SocketAddr,
        remote: SocketAddr,
        state: State,
        config: TcpConfig,
        iss: Seq,
        now: u64,
    ) -> Tcb {
        let mss = mss_for(config.mtu, remote);
        Tcb {
            local,
            remote,
            state,
            config,
            clock_offset: iss.0.rotate_left(13),
            iss,
            snd_una: iss,
            snd_nxt: iss,
            send_base: iss + 1,
            snd_wnd: 0,
            snd_wl1: Seq(0),
            snd_wl2: iss,
            snd_shift: 0,
            rcv_shift: 0,
            mss,
            ws_ok: false,
            sack_ok: false,
            ts_ok: false,
            ts_recent: 0,
            syn_pending: true,
            fin_seq: None,
            rcv_nxt: Seq(0),
            rcv_adv: Seq(0),
            rcv_cap: config.recv_buffer as u32,
            ooo: Reassembly::default(),
            peer_fin: None,
            dsack: None,
            ack_pending: false,
            ack_now: false,
            ack_at: None,
            ack_sent: Seq(0),
            delivered_total: 0,
            rcv_rtt: 0,
            rcv_rtt_mark: None,
            drs_time: now,
            drs_copied: 0,
            drs_space: 0,
            sent: VecDeque::new(),
            sacked_bytes: 0,
            lost_bytes: 0,
            retrans_bytes: 0,
            high_sacked: iss,
            rtt: Rtt::default(),
            rack: Rack {
                reo_mult: 1,
                ..Rack::default()
            },
            probe: None,
            cc: Controller::new(config.congestion, mss, iss.0, now),
            phase: Phase::Open,
            recover: iss,
            prr_delivered: 0,
            prr_out: 0,
            recover_fs: 0,
            dupacks: 0,
            cwnd_blocked: false,
            max_inflight: 0,
            last_send: now,
            delivery: Delivery::default(),
            pace_next: now * 1000,
            pace_at: None,
            segs_out: 0,
            rto_at: None,
            probe_at: None,
            reorder_at: None,
            persist_at: None,
            close_at: None,
            keepalive_at: None,
            last_recv: now,
            backoff: 0,
            retries: 0,
            reset_pending: false,
            sack_scratch: Vec::with_capacity(MAX_SACK_BLOCKS),
        }
    }

    /// A connection answering `syn`, in SYN-RECEIVED with the SYN-ACK still to send.
    pub fn passive(
        local: SocketAddr,
        remote: SocketAddr,
        syn: &TcpSegment<'_>,
        config: TcpConfig,
        iss: Seq,
        now: u64,
    ) -> Tcb {
        let mut tcb = Tcb::blank(local, remote, State::SynReceived, config, iss, now);
        tcb.rcv_nxt = Seq(syn.seq) + 1;
        tcb.snd_wnd = u32::from(syn.window);
        tcb.snd_wl1 = Seq(syn.seq);
        tcb.negotiate(&syn.options);
        tcb.rto_at = Some(now + tcb.rtt.rto);
        tcb
    }

    /// A connection opening to `remote`, in SYN-SENT with the SYN still to send.
    pub fn active(
        local: SocketAddr,
        remote: SocketAddr,
        config: TcpConfig,
        iss: Seq,
        now: u64,
    ) -> Tcb {
        let mut tcb = Tcb::blank(local, remote, State::SynSent, config, iss, now);
        tcb.rcv_shift = window_shift(config.recv_buffer_max);
        tcb.rto_at = Some(now + tcb.rtt.rto);
        tcb
    }

    fn negotiate(&mut self, options: &TcpOptions) {
        if let Some(shift) = options.window_scale {
            self.ws_ok = true;
            self.snd_shift = shift;
            self.rcv_shift = window_shift(self.config.recv_buffer_max);
        } else {
            self.ws_ok = false;
            self.snd_shift = 0;
            self.rcv_shift = 0;
            self.rcv_cap = self.rcv_cap.min(65_535);
        }
        self.sack_ok = options.sack_permitted;
        if let Some((value, _)) = options.timestamp {
            self.ts_ok = true;
            self.ts_recent = value;
        } else {
            self.ts_ok = false;
        }
        let own = mss_for(self.config.mtu, self.remote);
        let peer = options.mss.map_or(536, u32::from);
        let mss = own.min(peer).max(64) - if self.ts_ok { 12 } else { 0 };
        self.mss = mss;
        self.cc.set_mss(mss);
    }

    pub(super) fn rcv_cap_max(&self) -> u32 {
        let max = self.config.recv_buffer_max as u32;
        if self.rcv_shift == 0 {
            max.min(65_535)
        } else {
            max
        }
    }

    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    pub fn is_half_open(&self) -> bool {
        self.state == State::SynReceived
    }

    /// Whether `seg`, a SYN, starts a new incarnation of this connection: always once it is
    /// closed, and in TIME_WAIT only when it is newer than the old one (RFC 6191).
    pub fn accepts_new_syn(&self, seg: &TcpSegment<'_>) -> bool {
        match self.state {
            State::Closed => true,
            State::TimeWait => {
                Seq(seg.seq).gt(self.rcv_nxt)
                    || self.ts_ok
                        && seg.options.timestamp.is_some_and(|(value, _)| {
                            (value.wrapping_sub(self.ts_recent) as i32) > 0
                        })
            }
            _ => false,
        }
    }

    pub(super) fn inflight(&self) -> u32 {
        (self.snd_nxt.since(self.snd_una))
            .saturating_sub(self.sacked_bytes + self.lost_bytes)
            .saturating_add(self.retrans_bytes)
    }

    pub(super) fn ts_value(&self, now: u64) -> u32 {
        ((now / 1000) as u32).wrapping_add(self.clock_offset)
    }
    pub(super) fn close(
        &mut self,
        state: &mut SharedState,
        wakes: &mut Wakes,
        kind: Option<io::ErrorKind>,
    ) {
        self.state = State::Closed;
        self.rto_at = None;
        self.probe_at = None;
        self.reorder_at = None;
        self.persist_at = None;
        self.close_at = None;
        self.keepalive_at = None;
        self.ack_at = None;
        if let Some(kind) = kind {
            for waker in state.fail(kind) {
                wakes.add(waker);
            }
        } else {
            wakes.add(state.wake_reader());
            wakes.add(state.wake_writer());
        }
    }

    /// Sends a reset and closes, for an application that went away with data unread or a
    /// connection that timed out.
    pub fn abort(&mut self, state: &mut SharedState, wakes: &mut Wakes, kind: io::ErrorKind) {
        if self.state != State::Closed && self.state != State::SynSent {
            self.reset_pending = true;
        }
        self.close(state, wakes, Some(kind));
    }

    pub fn take_reset(&mut self) -> Option<(SocketAddr, SocketAddr, Seq, Seq)> {
        if !std::mem::take(&mut self.reset_pending) {
            return None;
        }
        Some((self.local, self.remote, self.snd_nxt, self.rcv_nxt))
    }

    pub fn input<'a>(
        &mut self,
        seg: &TcpSegment<'a>,
        now: u64,
        state: &mut SharedState,
        pool: &ChunkPool,
        wakes: &mut Wakes,
        gather: &mut Gather<'a>,
    ) -> Event {
        let mut event = Event::default();
        match self.state {
            State::Closed => return event,
            State::SynSent => {
                self.input_syn_sent(seg, now, state, wakes, &mut event);
                return event;
            }
            State::SynReceived if seg.is_syn() => {
                if Seq(seg.seq) + 1 == self.rcv_nxt {
                    self.syn_pending = true;
                }
                return event;
            }
            _ => {}
        }
        if !self.acceptable(seg) {
            if !seg.has(FLAG_RST) {
                let end = Seq(seg.seq) + seg.payload.len() as u32;
                if !seg.payload.is_empty() && end.le(self.rcv_nxt) {
                    self.dsack = Some((Seq(seg.seq), end));
                }
                self.ack_now = true;
            }
            return event;
        }
        self.last_recv = now;
        if seg.has(FLAG_RST) {
            if Seq(seg.seq) == self.rcv_nxt {
                let kind = if self.state == State::SynReceived {
                    io::ErrorKind::ConnectionRefused
                } else {
                    io::ErrorKind::ConnectionReset
                };
                self.close(state, wakes, Some(kind));
                event.closed = true;
            } else {
                self.ack_now = true;
            }
            return event;
        }
        if seg.has(FLAG_SYN) {
            self.ack_now = true;
            return event;
        }
        if !seg.has(FLAG_ACK) {
            return event;
        }
        if self.ts_ok
            && let Some((value, _)) = seg.options.timestamp
            && Seq(seg.seq).le(self.rcv_nxt)
        {
            self.ts_recent = value;
        }
        if self.state == State::SynReceived {
            if Seq(seg.ack) != self.iss + 1 {
                self.reset_pending = true;
                return event;
            }
            self.snd_una = self.iss + 1;
            self.snd_nxt = self.snd_nxt.max(self.snd_una);
            self.state = State::Established;
            self.syn_pending = false;
            self.on_established(now, state);
            event.established = true;
        }
        self.process_ack(seg, now, state, pool, wakes, &mut event);
        if self.state == State::Closed {
            return event;
        }
        self.process_data(seg, now, state, pool, wakes, &mut event, gather);
        event
    }

    fn on_established(&mut self, now: u64, state: &mut SharedState) {
        state.established = true;
        self.rto_at = None;
        self.backoff = 0;
        self.retries = 0;
        self.drs_time = now;
        self.last_recv = now;
        self.keepalive_at = Some(now + KEEP_ALIVE);
        self.update_send_cap(state);
    }

    fn input_syn_sent(
        &mut self,
        seg: &TcpSegment<'_>,
        now: u64,
        state: &mut SharedState,
        wakes: &mut Wakes,
        event: &mut Event,
    ) {
        if seg.has(FLAG_ACK) && Seq(seg.ack) != self.iss + 1 {
            if !seg.has(FLAG_RST) {
                self.reset_pending = true;
            }
            return;
        }
        if seg.has(FLAG_RST) {
            if seg.has(FLAG_ACK) {
                self.close(state, wakes, Some(io::ErrorKind::ConnectionRefused));
                event.closed = true;
            }
            return;
        }
        if !seg.has(FLAG_SYN) || !seg.has(FLAG_ACK) {
            return;
        }
        self.rcv_nxt = Seq(seg.seq) + 1;
        self.negotiate(&seg.options);
        self.rcv_adv = self.rcv_nxt + self.rcv_cap.min(65_535);
        self.snd_una = self.iss + 1;
        self.snd_wnd = u32::from(seg.window) << self.snd_shift;
        self.snd_wl1 = Seq(seg.seq);
        self.snd_wl2 = Seq(seg.ack);
        self.syn_pending = false;
        self.state = State::Established;
        if !self.rtt.sampled && self.backoff == 0 {
            self.rtt.sample(now.saturating_sub(self.last_send), now);
        }
        self.on_established(now, state);
        self.ack_now = true;
        wakes.add(state.wake_writer());
        event.established = true;
    }

    fn acceptable(&self, seg: &TcpSegment<'_>) -> bool {
        let seq = Seq(seg.seq);
        let len = seg.seq_len();
        let wnd = self.rcv_adv.since(self.rcv_nxt).max(1);
        let in_window = |s: Seq| s.ge(self.rcv_nxt) && s.lt(self.rcv_nxt + wnd);
        if len == 0 {
            return in_window(seq) || (seq == self.rcv_nxt);
        }
        in_window(seq)
            || in_window(seq + (len - 1))
            || (seq.lt(self.rcv_nxt) && (seq + len).gt(self.rcv_nxt))
    }

    /// Reacts to the application dropping its handle: unread data turns the close into a
    /// reset, and otherwise the connection gets a deadline to finish closing.
    pub fn on_app_dropped(&mut self, now: u64, state: &mut SharedState, wakes: &mut Wakes) -> bool {
        if !state.dropped {
            return false;
        }
        let unread = !state.recv.is_empty() || !self.ooo.is_empty();
        if unread || matches!(self.state, State::SynSent | State::SynReceived) {
            self.abort(state, wakes, io::ErrorKind::ConnectionAborted);
            return true;
        }
        if self.state != State::TimeWait && self.close_at.is_none() {
            self.close_at = Some(now + ORPHAN_TIMEOUT);
        }
        false
    }
}
