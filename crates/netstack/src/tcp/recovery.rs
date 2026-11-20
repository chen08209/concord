use crate::buffer::ChunkPool;
use crate::seq::Seq;
use crate::stream::SharedState;
use crate::wire::{FLAG_FIN, TcpSegment};

use super::rate::Acked;
use super::{Event, ORPHAN_TIMEOUT, Phase, Sent, State, TIME_WAIT, Tcb, Wakes};

const REO_PERSIST: u32 = 16;
const MAX_REO_MULT: u32 = 16;

impl Tcb {
    pub(super) fn process_ack(
        &mut self,
        seg: &TcpSegment<'_>,
        now: u64,
        state: &mut SharedState,
        pool: &ChunkPool,
        wakes: &mut Wakes,
        event: &mut Event,
    ) {
        let ack = Seq(seg.ack);
        if ack.gt(self.snd_nxt) {
            self.ack_now = true;
            return;
        }
        let seq = Seq(seg.seq);
        let window = u32::from(seg.window) << self.snd_shift;
        let window_changed = window != self.snd_wnd;
        if self.snd_wl1.lt(seq) || (self.snd_wl1 == seq && self.snd_wl2.le(ack)) {
            if window > 0 && self.snd_wnd == 0 {
                self.persist_at = None;
                self.backoff = 0;
            }
            self.snd_wnd = window;
            self.snd_wl1 = seq;
            self.snd_wl2 = ack;
        }
        if ack.lt(self.snd_una) {
            return;
        }
        let prior_inflight = self.inflight();
        let prior_fack = self.high_sacked.max(self.snd_una);
        let mut delivered = 0u32;
        let mut acked = self.acked();
        let mut dsack = false;
        if self.sack_ok {
            let blocks = seg.options.sack_blocks();
            for (i, (left, right)) in blocks.iter().enumerate() {
                let (left, right) = (Seq(*left), Seq(*right));
                if !left.lt(right) {
                    continue;
                }
                if i == 0 {
                    let inside_next = blocks
                        .get(1)
                        .is_some_and(|(l, r)| left.ge(Seq(*l)) && right.le(Seq(*r)));
                    if right.le(ack) || inside_next {
                        dsack = true;
                        continue;
                    }
                }
                if right.gt(self.snd_nxt) {
                    continue;
                }
                let left = left.max(ack);
                if left.lt(right) {
                    delivered += self.mark_sacked(left, right, now, prior_fack, &mut acked);
                }
            }
        }
        if dsack {
            self.on_dsack();
        }
        let advanced = ack.gt(self.snd_una);
        if advanced {
            delivered += self.cumulative_ack(ack, now, prior_fack, &mut acked);
            self.drop_acked(ack, state, pool, wakes);
            self.snd_una = ack;
            self.backoff = 0;
            self.retries = 0;
            self.dupacks = 0;
        } else if seg.payload.is_empty()
            && !window_changed
            && self.snd_una != self.snd_nxt
            && !seg.has(FLAG_FIN)
        {
            self.dupacks += 1;
        }
        if let Some((rtt, _)) = acked.rtt {
            self.rtt.sample(rtt, now);
        }
        if let Some(probe) = self.probe
            && ack.ge(probe.end)
        {
            self.probe = None;
            if probe.retrans && !dsack && self.phase == Phase::Open {
                self.cc.on_probe_loss();
            }
        }
        self.detect_losses(now, advanced);
        if self.phase == Phase::Open && self.lost_bytes > 0 {
            self.enter_recovery(prior_inflight);
        }
        match self.phase {
            Phase::Recovery | Phase::Loss if self.snd_una.ge(self.recover) => {
                if self.phase == Phase::Recovery {
                    self.cc.end_recovery();
                    self.rack.reo_persist = self.rack.reo_persist.saturating_sub(1);
                    if self.rack.reo_persist == 0 {
                        self.rack.reo_mult = 1;
                    }
                }
                self.phase = Phase::Open;
            }
            Phase::Recovery => self.prr_update(delivered),
            _ => {}
        }
        self.on_delivery(delivered, prior_inflight, &acked, now);
        self.cwnd_blocked = false;
        self.max_inflight = self.inflight();
        if advanced || delivered > 0 {
            self.update_send_cap(state);
            wakes.add(state.wake_writer());
        }
        if self.snd_una == self.snd_nxt {
            self.rto_at = None;
            self.probe_at = None;
            self.reorder_at = None;
        } else if advanced {
            self.rto_at = Some(now + self.rto());
            self.arm_probe(now);
        }
        self.on_fin_acked(now, state, wakes, event);
    }

    fn on_fin_acked(
        &mut self,
        now: u64,
        state: &mut SharedState,
        wakes: &mut Wakes,
        event: &mut Event,
    ) {
        let Some(fin) = self.fin_seq else {
            return;
        };
        if !self.snd_una.gt(fin) {
            return;
        }
        match self.state {
            State::FinWait1 => {
                self.state = State::FinWait2;
                if state.dropped && self.close_at.is_none() {
                    self.close_at = Some(now + ORPHAN_TIMEOUT);
                }
            }
            State::Closing => {
                self.state = State::TimeWait;
                self.close_at = Some(now + TIME_WAIT);
            }
            State::LastAck => {
                self.close(state, wakes, None);
                event.closed = true;
            }
            _ => {}
        }
    }

    fn on_delivery(&mut self, delivered: u32, prior_inflight: u32, acked: &Acked, now: u64) {
        if !self.cc.paced() {
            if self.phase != Phase::Recovery && delivered > 0 && self.cwnd_limited() {
                self.cc.on_ack(delivered, now, self.rtt.smoothed());
            }
            return;
        }
        self.count_delivered(delivered, now);
        if !acked.outstanding {
            return;
        }
        let sample = self.rate_sample(delivered, prior_inflight, acked, now);
        let flow = self.flow(now);
        if let Some(mark) = self.cc.on_rate_sample(&flow, &sample) {
            self.mark_app_limited(mark);
        }
    }

    fn cwnd_limited(&self) -> bool {
        if self.cwnd_blocked {
            return true;
        }
        if self.cc.in_slow_start() {
            return self.max_inflight.saturating_mul(2) >= self.cc.cwnd;
        }
        self.max_inflight + self.mss >= self.cc.cwnd
    }

    fn mark_sacked(
        &mut self,
        left: Seq,
        right: Seq,
        now: u64,
        prior_fack: Seq,
        acked: &mut Acked,
    ) -> u32 {
        acked.sacked = true;
        let mut delivered = 0;
        let first = self.sent.partition_point(|s| s.start.lt(left));
        let mut updates = Vec::new();
        for seg in self.sent.range_mut(first..) {
            if seg.end.gt(right) {
                break;
            }
            if seg.sacked {
                continue;
            }
            seg.sacked = true;
            let len = seg.len();
            self.sacked_bytes += len;
            if seg.lost {
                self.lost_bytes -= len;
            }
            if seg.retrans {
                self.retrans_bytes -= len;
            }
            delivered += len;
            updates.push(*seg);
        }
        for seg in updates {
            self.on_delivered(&seg, now, prior_fack, acked);
        }
        if right.gt(self.high_sacked) {
            self.high_sacked = right;
        }
        delivered
    }

    fn cumulative_ack(&mut self, ack: Seq, now: u64, prior_fack: Seq, acked: &mut Acked) -> u32 {
        let mut delivered = 0;
        while let Some(seg) = self.sent.front().copied() {
            if seg.end.le(ack) {
                self.sent.pop_front();
                let len = seg.len();
                if seg.sacked {
                    self.sacked_bytes -= len;
                } else {
                    delivered += len;
                    if seg.lost {
                        self.lost_bytes -= len;
                    }
                    if seg.retrans {
                        self.retrans_bytes -= len;
                    }
                    self.on_delivered(&seg, now, prior_fack, acked);
                }
                continue;
            }
            if seg.start.lt(ack) {
                let cut = ack.since(seg.start);
                if let Some(front) = self.sent.front_mut() {
                    front.start = ack;
                    if !front.sacked {
                        delivered += cut;
                        if front.lost {
                            self.lost_bytes -= cut;
                        }
                        if front.retrans {
                            self.retrans_bytes -= cut;
                        }
                    } else {
                        self.sacked_bytes -= cut;
                    }
                }
            }
            break;
        }
        delivered
    }

    fn on_delivered(&mut self, seg: &Sent, now: u64, prior_fack: Seq, acked: &mut Acked) {
        let rtt = now.saturating_sub(seg.sent_at);
        if !seg.retrans && acked.rtt.is_none_or(|(_, at)| seg.sent_at > at) {
            acked.rtt = Some((rtt, seg.sent_at));
        }
        if self.cc.paced() {
            self.rate_delivered(seg, acked);
        }
        if seg.end.lt(prior_fack) && !seg.retrans {
            self.rack.reordering = true;
        }
        if seg.retrans && self.rtt.sampled && rtt < self.rtt.min_rtt {
            return;
        }
        let rack = &mut self.rack;
        if !rack.valid
            || seg.sent_at > rack.xmit
            || (seg.sent_at == rack.xmit && seg.end.gt(rack.end))
        {
            rack.valid = true;
            rack.xmit = seg.sent_at;
            rack.end = seg.end;
            rack.rtt = rtt;
        }
    }

    fn on_dsack(&mut self) {
        let rack = &mut self.rack;
        if rack.dsack_round.is_none_or(|round| self.snd_una.ge(round)) {
            rack.reo_mult = (rack.reo_mult + 1).min(MAX_REO_MULT);
            rack.dsack_round = Some(self.snd_nxt);
            rack.reo_persist = REO_PERSIST;
        }
    }

    fn drop_acked(
        &mut self,
        ack: Seq,
        state: &mut SharedState,
        pool: &ChunkPool,
        wakes: &mut Wakes,
    ) {
        let data_end = self.send_base + state.send.len() as u32;
        let upto = ack.min(data_end);
        let n = upto.since(self.send_base) as usize;
        if n > 0 {
            state.send.consume(pool, n);
            self.send_base = self.send_base + n as u32;
            self.sync_sent(state);
            wakes.add(state.wake_writer());
        }
    }

    fn reo_wnd(&self) -> u64 {
        if !self.rack.reordering {
            let sacked_segments = self.sacked_bytes / self.mss.max(1);
            if self.phase != Phase::Open || sacked_segments >= 3 {
                return 0;
            }
        }
        let min_rtt = if self.rtt.min_rtt == u64::MAX {
            self.rtt.smoothed()
        } else {
            self.rtt.min_rtt
        };
        (u64::from(self.rack.reo_mult) * min_rtt / 4).min(self.rtt.smoothed())
    }

    pub(super) fn mark_lost_at(&mut self, index: usize) {
        let Some(seg) = self.sent.get_mut(index) else {
            return;
        };
        if seg.sacked || (seg.lost && !seg.retrans) {
            return;
        }
        let len = seg.len();
        if seg.retrans {
            seg.retrans = false;
            self.retrans_bytes -= len;
        }
        if !seg.lost {
            seg.lost = true;
            self.lost_bytes += len;
            if self.cc.paced() {
                self.count_lost(len);
            }
        }
    }

    fn detect_losses(&mut self, now: u64, advanced: bool) {
        if !self.sack_ok {
            let third_dupack = self.dupacks == 3 && self.phase == Phase::Open;
            let partial_ack =
                advanced && self.phase == Phase::Recovery && self.snd_una.lt(self.recover);
            if third_dupack || partial_ack {
                self.mark_lost_at(0);
            }
            return;
        }
        self.rack_detect(now);
    }

    pub(super) fn rack_detect(&mut self, now: u64) {
        self.reorder_at = None;
        if !self.rack.valid
            || (self.sacked_bytes == 0 && self.phase == Phase::Open && self.retrans_bytes == 0)
        {
            return;
        }
        let reo = self.reo_wnd();
        let (xmit, end, rtt) = (self.rack.xmit, self.rack.end, self.rack.rtt);
        let mut wait: Option<u64> = None;
        let mut lost = Vec::new();
        for (i, seg) in self.sent.iter().enumerate() {
            if seg.sacked || (seg.lost && !seg.retrans) {
                continue;
            }
            let before = seg.sent_at < xmit || (seg.sent_at == xmit && seg.end.lt(end));
            if !before {
                continue;
            }
            let deadline = seg.sent_at + rtt + reo;
            if deadline <= now {
                lost.push(i);
            } else {
                let left = deadline - now;
                wait = Some(wait.map_or(left, |w| w.min(left)));
            }
        }
        for i in lost {
            self.mark_lost_at(i);
        }
        if let Some(wait) = wait {
            self.reorder_at = Some(now + wait.max(1_000));
        }
    }

    pub(super) fn enter_recovery(&mut self, prior_inflight: u32) {
        self.phase = Phase::Recovery;
        self.recover = self.snd_nxt;
        self.recover_fs = prior_inflight.max(self.mss);
        self.prr_delivered = 0;
        self.prr_out = 0;
        self.cc.on_loss();
        self.probe = None;
        self.probe_at = None;
    }

    pub(super) fn prr_update(&mut self, delivered: u32) {
        if self.cc.paced() {
            return;
        }
        self.prr_delivered += delivered;
        let pipe = self.inflight();
        let ssthresh = self.cc.ssthresh;
        let mut sndcnt = if pipe > ssthresh {
            let target = (u64::from(self.prr_delivered) * u64::from(ssthresh)
                + u64::from(self.recover_fs)
                - 1)
                / u64::from(self.recover_fs.max(1));
            (target as i64) - i64::from(self.prr_out)
        } else {
            let limit = i64::from(self.prr_delivered.saturating_sub(self.prr_out))
                .max(i64::from(delivered))
                + i64::from(self.mss);
            limit.min(i64::from(ssthresh - pipe))
        };
        if self.prr_out == 0 {
            sndcnt = sndcnt.max(i64::from(self.mss));
        }
        self.cc.cwnd = pipe + sndcnt.max(0) as u32;
    }
}
