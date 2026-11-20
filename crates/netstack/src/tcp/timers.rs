use std::io;

use crate::cc::MAX_RTO;
use crate::stream::SharedState;
use crate::wire::{FLAG_ACK, FLAG_FIN};

use super::{Egress, Event, KEEP_ALIVE, Phase, Probe, Sent, State, Tcb, Wakes};

const MAX_RETRIES: u32 = 15;
const MAX_SYN_RETRIES: u32 = 4;
const IDLE_TIMEOUT: u64 = 360_000_000;
const DELAYED_ACK_WORST: u64 = 200_000;
const PROBE_FLOOR: u64 = 10_000;

impl Tcb {
    pub fn next_deadline(&self) -> Option<u64> {
        [
            self.rto_at,
            self.probe_at,
            self.reorder_at,
            self.persist_at,
            self.close_at,
            self.keepalive_at,
            self.ack_at,
            self.pace_at,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub(super) fn rto(&self) -> u64 {
        (self.rtt.rto << self.backoff.min(16)).min(MAX_RTO)
    }

    pub(super) fn arm_probe(&mut self, now: u64) {
        self.probe_at = None;
        if !self.sack_ok
            || self.phase != Phase::Open
            || self.probe.is_some()
            || self.snd_una == self.snd_nxt
        {
            return;
        }
        let mut pto = if self.rtt.sampled {
            2 * self.rtt.srtt
        } else {
            1_000_000
        };
        if self.snd_nxt.since(self.snd_una) <= self.mss {
            pto += DELAYED_ACK_WORST;
        }
        let at = now + pto.max(PROBE_FLOOR);
        if self.rto_at.is_some_and(|rto| at >= rto) {
            return;
        }
        self.probe_at = Some(at);
    }

    /// Runs the timers that are due. The caller sends whatever `output` then finds to send.
    pub fn on_timer(
        &mut self,
        now: u64,
        state: &mut SharedState,
        egress: &mut dyn Egress,
        wakes: &mut Wakes,
    ) -> Event {
        let mut event = Event::default();
        if self.close_at.is_some_and(|at| at <= now) {
            if matches!(self.state, State::TimeWait | State::FinWait2) {
                self.close(state, wakes, None);
            } else {
                self.abort(state, wakes, io::ErrorKind::TimedOut);
            }
            event.closed = true;
            return event;
        }
        if self.pace_at.is_some_and(|at| at <= now) {
            self.pace_at = None;
        }
        if self.ack_at.is_some_and(|at| at <= now) {
            self.ack_at = None;
            self.ack_now |= self.ack_pending;
        }
        if self.keepalive_at.is_some_and(|at| at <= now) {
            let idle = now.saturating_sub(self.last_recv);
            if idle >= IDLE_TIMEOUT {
                self.abort(state, wakes, io::ErrorKind::TimedOut);
                event.closed = true;
                return event;
            }
            if idle + 1_000 >= KEEP_ALIVE {
                self.emit(egress, state, self.snd_una - 1, 0, FLAG_ACK, now);
                self.keepalive_at = Some(now + KEEP_ALIVE);
            } else {
                self.keepalive_at = Some(self.last_recv + KEEP_ALIVE);
            }
        }
        if self.persist_at.is_some_and(|at| at <= now) {
            self.persist_at = None;
            let probe = self.snd_una - 1;
            if self.emit(egress, state, probe, 0, FLAG_ACK, now) {
                self.backoff += 1;
            }
            if self.snd_wnd == 0 {
                self.persist_at = Some(now + self.rto());
            }
        }
        if self.reorder_at.is_some_and(|at| at <= now) {
            self.reorder_at = None;
            let inflight = self.inflight();
            self.rack_detect(now);
            if self.phase == Phase::Open && self.lost_bytes > 0 {
                self.enter_recovery(inflight);
                self.prr_update(0);
            }
        }
        if self.probe_at.is_some_and(|at| at <= now) {
            self.probe_at = None;
            self.send_probe(now, state, egress);
        }
        if self.rto_at.is_some_and(|at| at <= now) {
            self.rto_at = None;
            self.on_rto(now, state, wakes, &mut event);
        }
        event
    }

    fn send_probe(&mut self, now: u64, state: &mut SharedState, egress: &mut dyn Egress) {
        if self.snd_una == self.snd_nxt {
            return;
        }
        let queued_end = self.send_base + state.send.len() as u32;
        let unsent = queued_end.since(self.snd_nxt);
        let by_window = (self.snd_una + self.snd_wnd).since(self.snd_nxt);
        let room = self.payload_room(0);
        if unsent > 0 && by_window > 0 {
            let len = unsent.min(room).min(by_window);
            let start = self.snd_nxt;
            if self.emit(egress, state, start, len as usize, FLAG_ACK, now) {
                self.advance_pacing(now, len, 1);
                let stamp = self.stamp(now);
                self.sent.push_back(Sent {
                    start,
                    end: start + len,
                    fin: false,
                    sent_at: now,
                    sacked: false,
                    lost: false,
                    retrans: false,
                    stamp,
                });
                self.snd_nxt = start + len;
                self.sync_sent(state);
                self.probe = Some(Probe {
                    end: self.snd_nxt,
                    retrans: false,
                });
            }
        } else if let Some(last) = self.sent.iter().rev().find(|s| !s.sacked).copied() {
            let mut flags = FLAG_ACK;
            if last.fin {
                flags |= FLAG_FIN;
            }
            if self.emit(egress, state, last.start, last.payload(), flags, now) {
                self.probe = Some(Probe {
                    end: last.end,
                    retrans: true,
                });
            }
        }
        self.rto_at = Some(now + self.rto());
    }

    fn on_rto(&mut self, now: u64, state: &mut SharedState, wakes: &mut Wakes, event: &mut Event) {
        self.retries += 1;
        self.backoff += 1;
        match self.state {
            State::SynSent | State::SynReceived => {
                if self.retries > MAX_SYN_RETRIES {
                    self.close(state, wakes, Some(io::ErrorKind::TimedOut));
                    event.closed = true;
                    return;
                }
                self.syn_pending = true;
                self.rto_at = Some(now + self.rto());
                return;
            }
            _ => {}
        }
        if self.snd_una == self.snd_nxt {
            return;
        }
        if self.retries > MAX_RETRIES {
            self.abort(state, wakes, io::ErrorKind::TimedOut);
            event.closed = true;
            return;
        }
        let first = self.phase != Phase::Loss;
        for i in 0..self.sent.len() {
            self.mark_lost_at(i);
        }
        self.phase = Phase::Loss;
        let flow = self.flow(now);
        self.cc.on_rto(first, &flow);
        self.recover = self.snd_nxt;
        self.probe = None;
        self.probe_at = None;
        self.reorder_at = None;
        self.rto_at = Some(now + self.rto());
    }
}
