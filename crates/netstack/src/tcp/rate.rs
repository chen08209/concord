//! The delivery-rate estimator of `tcp_rate.c` and the BBR send pacing, as sing-tun's Go stack has
//! them (`stack_go_tcp_rate.go`, `stack_go_tcp_output.go`), counted in bytes.

use crate::bbr::{CaState, Flow, PACING_SHIFT, RateSample};
use crate::seq::Seq;

use super::{Phase, Sent, Tcb};

const PACING_UNPACED_SEGMENTS: u64 = 10;
const PACING_TICK: u64 = 1_000;
const TSO_RTT_SHIFT: u32 = 9;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Delivery {
    delivered: u64,
    delivered_at: u64,
    first_sent_at: u64,
    /// The delivered count past which sending stops being application-limited; 0 when it is not.
    app_limited: u64,
    lost: u64,
}

/// The delivery state a segment was sent in.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Stamp {
    delivered: u64,
    delivered_at: u64,
    first_sent_at: u64,
    app_limited: bool,
}

#[derive(Clone, Copy, Debug)]
struct Newest {
    stamp: Stamp,
    end: Seq,
    send_interval: u64,
}

/// What one ACK delivered: the RTT sample and the newest-sent delivered segment.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Acked {
    pub rtt: Option<(u64, u64)>,
    pub sacked: bool,
    /// Data was outstanding when the ACK arrived; BBR runs only on such ACKs.
    pub outstanding: bool,
    prior_lost: u64,
    newest: Option<Newest>,
    segments: u32,
    retrans: bool,
}

impl Tcb {
    pub(super) fn acked(&self) -> Acked {
        Acked {
            outstanding: self.snd_una != self.snd_nxt,
            prior_lost: self.delivery.lost,
            ..Acked::default()
        }
    }

    pub(super) fn stamp(&mut self, now: u64) -> Stamp {
        if !self.cc.paced() {
            return Stamp::default();
        }
        let delivery = &mut self.delivery;
        if self.snd_una == self.snd_nxt {
            delivery.first_sent_at = now;
            delivery.delivered_at = now;
        }
        Stamp {
            delivered: delivery.delivered,
            delivered_at: delivery.delivered_at,
            first_sent_at: delivery.first_sent_at,
            app_limited: delivery.app_limited != 0,
        }
    }

    pub(super) fn count_lost(&mut self, len: u32) {
        self.delivery.lost += u64::from(len);
    }

    pub(super) fn rate_delivered(&mut self, seg: &Sent, acked: &mut Acked) {
        acked.segments += 1;
        acked.retrans |= seg.retrans;
        let first = self.delivery.first_sent_at;
        let newer = acked.newest.is_none_or(|newest| {
            seg.sent_at > first || (seg.sent_at == first && seg.end.gt(newest.end))
        });
        if newer {
            self.delivery.first_sent_at = seg.sent_at;
            acked.newest = Some(Newest {
                stamp: seg.stamp,
                end: seg.end,
                send_interval: seg.sent_at.saturating_sub(seg.stamp.first_sent_at),
            });
        }
    }

    /// Marks the flight application-limited when the application has nothing more to send.
    pub(super) fn check_app_limited(&mut self) {
        let inflight = self.inflight();
        if inflight < self.cc.cwnd {
            self.delivery.app_limited = (self.delivery.delivered + u64::from(inflight)).max(1);
        }
    }

    pub(super) fn mark_app_limited(&mut self, mark: u64) {
        self.delivery.app_limited = mark;
    }

    pub(super) fn count_delivered(&mut self, delivered: u32, now: u64) {
        let delivery = &mut self.delivery;
        delivery.delivered += u64::from(delivered);
        if delivered > 0 {
            delivery.delivered_at = now;
        }
        if delivery.app_limited != 0 && delivery.delivered > delivery.app_limited {
            delivery.app_limited = 0;
        }
    }

    pub(super) fn rate_sample(
        &self,
        delivered: u32,
        prior_inflight: u32,
        acked: &Acked,
        now: u64,
    ) -> RateSample {
        let mut sample = RateSample {
            acked_sacked: delivered,
            losses: u32::try_from(self.delivery.lost - acked.prior_lost).unwrap_or(u32::MAX),
            prior_inflight,
            rtt: acked
                .rtt
                .map_or(-1, |(rtt, _)| i64::try_from(rtt).unwrap_or(i64::MAX)),
            ack_delayed: acked.segments == 1
                && !acked.sacked
                && !acked.retrans
                && delivered < self.mss,
            ..RateSample::default()
        };
        let Some(newest) = acked.newest else {
            return sample;
        };
        sample.prior_delivered = newest.stamp.delivered;
        sample.app_limited = newest.stamp.app_limited;
        sample.delivered =
            i64::try_from(self.delivery.delivered - newest.stamp.delivered).unwrap_or(i64::MAX);
        let interval = newest
            .send_interval
            .max(now.saturating_sub(newest.stamp.delivered_at));
        if interval >= self.rtt.min_rtt {
            sample.interval = i64::try_from(interval).unwrap_or(i64::MAX);
        }
        sample
    }

    pub(super) fn flow(&self, now: u64) -> Flow {
        Flow {
            now,
            delivered: self.delivery.delivered,
            delivered_time: self.delivery.delivered_at,
            lost: self.delivery.lost,
            inflight: self.inflight(),
            mss: self.mss,
            srtt: self.rtt.sampled.then_some(self.rtt.srtt),
            min_rtt: (self.rtt.min_rtt != u64::MAX).then_some(self.rtt.min_rtt),
            state: match self.phase {
                Phase::Open => CaState::Open,
                Phase::Recovery => CaState::Recovery,
                Phase::Loss => CaState::Loss,
            },
            pace_next: self.pace_next / 1000,
            app_limited: self.delivery.app_limited != 0,
        }
    }

    /// The first send after the flight emptied.
    pub(super) fn tx_start(&mut self, now: u64) {
        if self.cc.paced() {
            let flow = self.flow(now);
            self.cc.on_tx_start(&flow);
        } else if now.saturating_sub(self.last_send) > self.rto() {
            self.cc.on_idle();
        }
    }

    /// Whether the pacing clock holds the next send back; if so, arms the pacing timer.
    pub(super) fn pace_blocked(&mut self, now: u64) -> bool {
        if !self.cc.paced()
            || self.segs_out < PACING_UNPACED_SEGMENTS
            || self.pace_next <= (now + PACING_TICK) * 1000
        {
            return false;
        }
        self.pace_at = Some(self.pace_next / 1000 - PACING_TICK);
        true
    }

    pub(super) fn advance_pacing(&mut self, now: u64, len: u32, segments: u64) {
        let Some(rate) = self.cc.pacing_rate() else {
            return;
        };
        self.segs_out += segments;
        let now = now * 1000;
        if rate == 0 || self.segs_out < PACING_UNPACED_SEGMENTS {
            self.pace_next = now;
            return;
        }
        let stamp = self.pace_next.max(now);
        let cost = u64::from(len) * 1_000_000_000 / rate;
        let credit = stamp - self.pace_next;
        self.pace_next = stamp + cost - (cost / 2).min(credit);
    }

    /// `tcp_tso_autosize`: under pacing, a frame carries about a millisecond of the pacing rate.
    pub(super) fn frame_cap(&self, frame: u32, room: u32) -> u32 {
        let Some(rate) = self.cc.pacing_rate() else {
            return frame;
        };
        let frame = u64::from(frame);
        let mut bytes = rate >> PACING_SHIFT;
        let shift = self.rtt.min_rtt >> TSO_RTT_SHIFT;
        if shift < 64 {
            bytes += frame >> shift;
        }
        let room = u64::from(room.max(1));
        let segments = (bytes.min(frame) / room).max(u64::from(self.cc.min_tso_segments()));
        u32::try_from((segments * room).min(frame)).unwrap_or(u32::MAX)
    }
}
