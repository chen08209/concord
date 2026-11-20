//! BBR v1 as sing-tun's Go stack ports Linux `tcp_bbr.c` (`stack_go_tcp_bbr.go`), counted in bytes where
//! the kernel counts packets: windows, deliveries and losses are bytes, the ratios and the packet-timed
//! state changes are the kernel's.

use crate::cc::initial_window;

const BW_SCALE: u32 = 24;
const BW_UNIT: u64 = 1 << BW_SCALE;
const SCALE: u32 = 8;
const UNIT: u32 = 1 << SCALE;
const CYCLE_LEN: u32 = 8;
const BW_RTTS: u32 = CYCLE_LEN + 2;
const MIN_RTT_WINDOW_MS: u32 = 10_000;
const PROBE_RTT_MODE_MS: u32 = 200;
const MIN_TSO_RATE: u64 = 1_200_000;
const PACING_MARGIN_PERCENT: u64 = 1;
const HIGH_GAIN: u32 = UNIT * 2885 / 1000 + 1;
const DRAIN_GAIN: u32 = UNIT * 1000 / 2885;
const CWND_GAIN: u32 = UNIT * 2;
const CYCLE_RAND: u32 = 7;
const CWND_MIN_TARGET: u32 = 4;
const FULL_BW_THRESH: u64 = (UNIT * 5 / 4) as u64;
const FULL_BW_COUNT: u32 = 3;
const LT_INTERVAL_MIN_RTTS: u32 = 4;
const LT_LOSS_THRESH: u64 = 50;
const LT_BW_RATIO: u64 = (UNIT / 8) as u64;
const LT_BW_DIFF: u64 = 4000 / 8;
const LT_BW_MAX_RTTS: u32 = 48;
const EXTRA_ACKED_WIN_RTTS: u32 = 5;
const ACK_EPOCH_RESET_THRESH: u64 = 1 << 20;
const EXTRA_ACKED_MAX_US: u64 = 100_000;
pub(crate) const PACING_SHIFT: u32 = 10;
const GSO_MAX_BYTES: u64 = 0xffff - 1 - 128;
const TSO_MAX_SEGMENTS: u64 = 0x7f;

const PACING_GAINS: [u32; 8] = [320, 192, 256, 256, 256, 256, 256, 256];

/// The connection's loss-recovery state, ordered as the kernel's `tcp_ca_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CaState {
    Open,
    Recovery,
    Loss,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

/// One ACK's delivery-rate sample (`tcp_rate.c`), in bytes and microseconds; -1 marks a missing value.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RateSample {
    pub delivered: i64,
    pub interval: i64,
    pub prior_delivered: u64,
    pub app_limited: bool,
    pub rtt: i64,
    pub ack_delayed: bool,
    pub prior_inflight: u32,
    pub losses: u32,
    pub acked_sacked: u32,
}

impl Default for RateSample {
    fn default() -> Self {
        RateSample {
            delivered: -1,
            interval: -1,
            prior_delivered: 0,
            app_limited: false,
            rtt: -1,
            ack_delayed: false,
            prior_inflight: 0,
            losses: 0,
            acked_sacked: 0,
        }
    }
}

/// What BBR reads from the connection on an event.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Flow {
    pub now: u64,
    pub delivered: u64,
    pub delivered_time: u64,
    pub lost: u64,
    pub inflight: u32,
    pub mss: u32,
    pub srtt: Option<u64>,
    pub min_rtt: Option<u64>,
    pub state: CaState,
    pub pace_next: u64,
    pub app_limited: bool,
}

pub(crate) struct Window {
    pub cwnd: u32,
    pub ssthresh: u32,
}

/// Lib `win_minmax.c`: the running maximum of a value over a window of rounds.
#[derive(Clone, Copy, Debug, Default)]
struct MinMax {
    samples: [(u32, u64); 3],
}

impl MinMax {
    fn get(&self) -> u64 {
        self.samples[0].1
    }

    fn reset(&mut self, time: u32, value: u64) {
        self.samples = [(time, value); 3];
    }

    fn running_max(&mut self, window: u32, time: u32, value: u64) {
        let sample = (time, value);
        let [first, second, third] = self.samples;
        if value >= first.1 || time.wrapping_sub(third.0) > window {
            self.reset(time, value);
            return;
        }
        if value >= second.1 {
            self.samples[1] = sample;
            self.samples[2] = sample;
        } else if value >= third.1 {
            self.samples[2] = sample;
        }
        let dt = time.wrapping_sub(self.samples[0].0);
        if dt > window {
            self.samples = [self.samples[1], self.samples[2], sample];
            if time.wrapping_sub(self.samples[0].0) > window {
                self.samples = [self.samples[1], self.samples[2], sample];
            }
        } else if self.samples[1].0 == self.samples[0].0 && dt > window / 4 {
            self.samples[1] = sample;
            self.samples[2] = sample;
        } else if self.samples[2].0 == self.samples[1].0 && dt > window / 2 {
            self.samples[2] = sample;
        }
    }
}

pub(crate) struct Bbr {
    min_rtt_us: u32,
    min_rtt_stamp: u32,
    probe_rtt_done_stamp: u32,
    bw: MinMax,
    rtt_count: u32,
    next_rtt_delivered: u64,
    cycle_stamp: u64,
    pub(crate) mode: Mode,
    prev_ca_state: CaState,
    packet_conservation: bool,
    round_start: bool,
    idle_restart: bool,
    probe_rtt_round_done: bool,
    lt_is_sampling: bool,
    lt_rtt_count: u32,
    lt_use_bw: bool,
    lt_bw: u64,
    lt_last_delivered: u64,
    lt_last_stamp: u64,
    lt_last_lost: u64,
    pacing_gain: u32,
    cwnd_gain: u32,
    full_bw_reached: bool,
    full_bw_count: u32,
    cycle_idx: u32,
    has_seen_rtt: bool,
    prior_cwnd: u32,
    full_bw: u64,
    ack_epoch_stamp: u64,
    extra_acked: [u64; 2],
    ack_epoch_acked: u64,
    extra_acked_win_rtts: u32,
    extra_acked_win_idx: usize,
    pacing_rate: u64,
    seed: u32,
}

fn jiffies(now: u64) -> u32 {
    (now / 1000) as u32
}

fn after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

impl Bbr {
    /// `bbr_init`, before the connection has a window or an RTT sample.
    pub fn new(cwnd: u32, seed: u32, now: u64) -> Bbr {
        let mut bbr = Bbr {
            min_rtt_us: u32::MAX,
            min_rtt_stamp: jiffies(now),
            probe_rtt_done_stamp: 0,
            bw: MinMax::default(),
            rtt_count: 0,
            next_rtt_delivered: 0,
            cycle_stamp: 0,
            mode: Mode::Startup,
            prev_ca_state: CaState::Open,
            packet_conservation: false,
            round_start: false,
            idle_restart: false,
            probe_rtt_round_done: false,
            lt_is_sampling: false,
            lt_rtt_count: 0,
            lt_use_bw: false,
            lt_bw: 0,
            lt_last_delivered: 0,
            lt_last_stamp: 0,
            lt_last_lost: 0,
            pacing_gain: HIGH_GAIN,
            cwnd_gain: HIGH_GAIN,
            full_bw_reached: false,
            full_bw_count: 0,
            cycle_idx: 0,
            has_seen_rtt: false,
            prior_cwnd: 0,
            full_bw: 0,
            ack_epoch_stamp: now,
            extra_acked: [0; 2],
            ack_epoch_acked: 0,
            extra_acked_win_rtts: 0,
            extra_acked_win_idx: 0,
            pacing_rate: 0,
            seed: seed | 1,
        };
        bbr.init_pacing_rate(cwnd, None);
        bbr
    }

    /// Bytes per second; the sender's pacing clock spends it.
    pub fn pacing_rate(&self) -> u64 {
        self.pacing_rate
    }

    fn random_below(&mut self, bound: u32) -> u32 {
        let mut x = self.seed;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.seed = x;
        x % bound
    }

    fn bw(&self) -> u64 {
        if self.lt_use_bw {
            self.lt_bw
        } else {
            self.bw.get()
        }
    }

    fn extra_acked_max(&self) -> u64 {
        self.extra_acked[0].max(self.extra_acked[1])
    }

    fn rate_bytes_per_sec(rate: u64, gain: u32) -> u64 {
        let rate = (u128::from(rate) * u128::from(gain)) >> SCALE;
        let rate = rate * u128::from(1_000_000 / 100 * (100 - PACING_MARGIN_PERCENT));
        u64::try_from(rate >> BW_SCALE).unwrap_or(u64::MAX)
    }

    fn init_pacing_rate(&mut self, cwnd: u32, srtt: Option<u64>) {
        let rtt = match srtt {
            Some(srtt) => {
                self.has_seen_rtt = true;
                srtt.max(1)
            }
            None => 1_000,
        };
        let bw = u64::from(cwnd) * BW_UNIT / rtt;
        self.pacing_rate = Self::rate_bytes_per_sec(bw, HIGH_GAIN);
    }

    fn set_pacing_rate(&mut self, flow: &Flow, cwnd: u32, bw: u64, gain: u32) {
        let rate = Self::rate_bytes_per_sec(bw, gain);
        if !self.has_seen_rtt && flow.srtt.is_some() {
            self.init_pacing_rate(cwnd, flow.srtt);
        }
        if self.full_bw_reached || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    pub fn min_tso_segments(&self) -> u32 {
        if self.pacing_rate < MIN_TSO_RATE >> 3 {
            1
        } else {
            2
        }
    }

    /// `bbr_tso_segs_goal`: the segments one frame may carry at the current pacing rate.
    pub fn tso_segments(&self, mss: u32) -> u32 {
        let bytes = (self.pacing_rate >> PACING_SHIFT).min(GSO_MAX_BYTES);
        let segments = (bytes / u64::from(mss.max(1))).max(u64::from(self.min_tso_segments()));
        segments.min(TSO_MAX_SEGMENTS) as u32
    }

    fn save_cwnd(&mut self, cwnd: u32) {
        if self.prev_ca_state < CaState::Recovery && self.mode != Mode::ProbeRtt {
            self.prior_cwnd = cwnd;
        } else {
            self.prior_cwnd = self.prior_cwnd.max(cwnd);
        }
    }

    /// `bbr_cwnd_event(CA_EVENT_TX_START)`: the first send after the flight emptied.
    pub fn on_tx_start(&mut self, flow: &Flow, window: &mut Window) {
        if !flow.app_limited {
            return;
        }
        self.idle_restart = true;
        self.ack_epoch_stamp = flow.now;
        self.ack_epoch_acked = 0;
        match self.mode {
            Mode::ProbeBw => self.set_pacing_rate(flow, window.cwnd, self.bw(), UNIT),
            Mode::ProbeRtt => self.check_probe_rtt_done(flow, window),
            _ => {}
        }
    }

    fn bdp(&self, bw: u64, gain: u32, mss: u32) -> u32 {
        if self.min_rtt_us == u32::MAX {
            return initial_window(mss);
        }
        let w = u128::from(bw) * u128::from(self.min_rtt_us);
        let bytes =
            (((w * u128::from(gain)) >> SCALE) + u128::from(BW_UNIT) - 1) / u128::from(BW_UNIT);
        u32::try_from(bytes).unwrap_or(u32::MAX)
    }

    fn quantization_budget(&self, window: u32, mss: u32) -> u32 {
        let mut window = window.saturating_add(3 * self.tso_segments(mss) * mss);
        let pair = 2 * mss.max(1);
        window = window.div_ceil(pair).saturating_mul(pair);
        if self.mode == Mode::ProbeBw && self.cycle_idx == 0 {
            window = window.saturating_add(pair);
        }
        window
    }

    fn inflight_target(&self, bw: u64, gain: u32, mss: u32) -> u32 {
        self.quantization_budget(self.bdp(bw, gain, mss), mss)
    }

    fn in_net_at_departure(&self, flow: &Flow, inflight_now: u32) -> u32 {
        let interval = flow.pace_next.saturating_sub(flow.now);
        let delivered = (u128::from(self.bw()) * u128::from(interval)) >> BW_SCALE;
        let mut at_departure = inflight_now;
        if self.pacing_gain > UNIT {
            at_departure = at_departure.saturating_add(self.tso_segments(flow.mss) * flow.mss);
        }
        u32::try_from(u128::from(at_departure).saturating_sub(delivered)).unwrap_or(0)
    }

    fn ack_aggregation_cwnd(&self) -> u32 {
        if !self.full_bw_reached {
            return 0;
        }
        let max_aggr = (u128::from(self.bw()) * u128::from(EXTRA_ACKED_MAX_US)) >> BW_SCALE;
        let aggr = u128::from(self.extra_acked_max());
        u32::try_from(aggr.min(max_aggr)).unwrap_or(u32::MAX)
    }

    fn set_cwnd_to_recover_or_restore(
        &mut self,
        flow: &Flow,
        window: &Window,
        sample: &RateSample,
    ) -> (u32, bool) {
        let acked = sample.acked_sacked;
        let mut cwnd = window.cwnd;
        if sample.losses > 0 {
            cwnd = cwnd.saturating_sub(sample.losses).max(flow.mss);
        }
        if flow.state == CaState::Recovery && self.prev_ca_state != CaState::Recovery {
            self.packet_conservation = true;
            self.next_rtt_delivered = flow.delivered;
            cwnd = flow.inflight.saturating_add(acked);
        } else if self.prev_ca_state >= CaState::Recovery && flow.state < CaState::Recovery {
            cwnd = cwnd.max(self.prior_cwnd);
            self.packet_conservation = false;
        }
        self.prev_ca_state = flow.state;
        if self.packet_conservation {
            return (cwnd.max(flow.inflight.saturating_add(acked)), true);
        }
        (cwnd, false)
    }

    fn set_cwnd(&mut self, flow: &Flow, window: &mut Window, sample: &RateSample, bw: u64) {
        let acked = sample.acked_sacked;
        let mut cwnd = window.cwnd;
        if acked != 0 {
            let (restored, conserving) = self.set_cwnd_to_recover_or_restore(flow, window, sample);
            cwnd = restored;
            if !conserving {
                let target = self.bdp(bw, self.cwnd_gain, flow.mss);
                let target = target.saturating_add(self.ack_aggregation_cwnd());
                let target = self.quantization_budget(target, flow.mss);
                if self.full_bw_reached {
                    cwnd = cwnd.saturating_add(acked).min(target);
                } else if cwnd < target || flow.delivered < u64::from(initial_window(flow.mss)) {
                    cwnd = cwnd.saturating_add(acked);
                }
                cwnd = cwnd.max(CWND_MIN_TARGET * flow.mss);
            }
        }
        window.cwnd = cwnd;
        if self.mode == Mode::ProbeRtt {
            window.cwnd = window.cwnd.min(CWND_MIN_TARGET * flow.mss);
        }
    }

    fn is_next_cycle_phase(&self, flow: &Flow, sample: &RateSample) -> bool {
        let full_length =
            flow.delivered_time.saturating_sub(self.cycle_stamp) > u64::from(self.min_rtt_us);
        if self.pacing_gain == UNIT {
            return full_length;
        }
        let inflight = self.in_net_at_departure(flow, sample.prior_inflight);
        let bw = self.bw.get();
        if self.pacing_gain > UNIT {
            return full_length
                && (sample.losses > 0
                    || inflight >= self.inflight_target(bw, self.pacing_gain, flow.mss));
        }
        full_length || inflight <= self.inflight_target(bw, UNIT, flow.mss)
    }

    fn advance_cycle_phase(&mut self, flow: &Flow) {
        self.cycle_idx = (self.cycle_idx + 1) & (CYCLE_LEN - 1);
        self.cycle_stamp = flow.delivered_time;
    }

    fn reset_probe_bw_mode(&mut self, flow: &Flow) {
        self.mode = Mode::ProbeBw;
        self.cycle_idx = CYCLE_LEN - 1 - self.random_below(CYCLE_RAND);
        self.advance_cycle_phase(flow);
    }

    fn reset_mode(&mut self, flow: &Flow) {
        if self.full_bw_reached {
            self.reset_probe_bw_mode(flow);
        } else {
            self.mode = Mode::Startup;
        }
    }

    fn reset_lt_interval(&mut self, flow: &Flow) {
        self.lt_last_stamp = flow.delivered_time / 1000;
        self.lt_last_delivered = flow.delivered;
        self.lt_last_lost = flow.lost;
        self.lt_rtt_count = 0;
    }

    fn reset_lt_sampling(&mut self, flow: &Flow) {
        self.lt_bw = 0;
        self.lt_use_bw = false;
        self.lt_is_sampling = false;
        self.reset_lt_interval(flow);
    }

    fn lt_interval_done(&mut self, flow: &Flow, bw: u64) {
        if self.lt_bw != 0 {
            let diff = bw.abs_diff(self.lt_bw);
            if u128::from(diff) * u128::from(UNIT)
                <= u128::from(LT_BW_RATIO) * u128::from(self.lt_bw)
                || Self::rate_bytes_per_sec(diff, UNIT) <= LT_BW_DIFF
            {
                self.lt_bw = (bw + self.lt_bw) >> 1;
                self.lt_use_bw = true;
                self.pacing_gain = UNIT;
                self.lt_rtt_count = 0;
                return;
            }
        }
        self.lt_bw = bw;
        self.reset_lt_interval(flow);
    }

    fn lt_sample(&mut self, flow: &Flow, sample: &RateSample) {
        if self.lt_use_bw {
            if self.mode == Mode::ProbeBw && self.round_start {
                self.lt_rtt_count += 1;
                if self.lt_rtt_count >= LT_BW_MAX_RTTS {
                    self.reset_lt_sampling(flow);
                    self.reset_probe_bw_mode(flow);
                }
            }
            return;
        }
        if !self.lt_is_sampling {
            if sample.losses == 0 {
                return;
            }
            self.reset_lt_interval(flow);
            self.lt_is_sampling = true;
        }
        if sample.app_limited {
            self.reset_lt_sampling(flow);
            return;
        }
        if self.round_start {
            self.lt_rtt_count += 1;
        }
        if self.lt_rtt_count < LT_INTERVAL_MIN_RTTS {
            return;
        }
        if self.lt_rtt_count > 4 * LT_INTERVAL_MIN_RTTS {
            self.reset_lt_sampling(flow);
            return;
        }
        if sample.losses == 0 {
            return;
        }
        let lost = flow.lost - self.lt_last_lost;
        let delivered = flow.delivered - self.lt_last_delivered;
        if delivered == 0
            || u128::from(lost) << SCALE < u128::from(LT_LOSS_THRESH) * u128::from(delivered)
        {
            return;
        }
        let ms = (flow.delivered_time / 1000).saturating_sub(self.lt_last_stamp);
        if ms < 1 {
            return;
        }
        if ms >= u64::from(u32::MAX) / 1000 {
            self.reset_lt_sampling(flow);
            return;
        }
        let bw = u64::try_from(u128::from(delivered) * u128::from(BW_UNIT) / u128::from(ms * 1000))
            .unwrap_or(u64::MAX);
        self.lt_interval_done(flow, bw);
    }

    fn update_bw(&mut self, flow: &Flow, sample: &RateSample) {
        self.round_start = false;
        if sample.delivered < 0 || sample.interval <= 0 {
            return;
        }
        if sample.prior_delivered >= self.next_rtt_delivered {
            self.next_rtt_delivered = flow.delivered;
            self.rtt_count = self.rtt_count.wrapping_add(1);
            self.round_start = true;
            self.packet_conservation = false;
        }
        self.lt_sample(flow, sample);
        let bw = u64::try_from(
            u128::from(sample.delivered.unsigned_abs()) * u128::from(BW_UNIT)
                / u128::from(sample.interval.unsigned_abs()),
        )
        .unwrap_or(u64::MAX);
        if !sample.app_limited || bw >= self.bw.get() {
            self.bw.running_max(BW_RTTS, self.rtt_count, bw);
        }
    }

    fn update_ack_aggregation(&mut self, flow: &Flow, window: &Window, sample: &RateSample) {
        if sample.acked_sacked == 0 || sample.delivered < 0 || sample.interval <= 0 {
            return;
        }
        if self.round_start {
            self.extra_acked_win_rtts = (self.extra_acked_win_rtts + 1).min(0x1f);
            if self.extra_acked_win_rtts >= EXTRA_ACKED_WIN_RTTS {
                self.extra_acked_win_rtts = 0;
                self.extra_acked_win_idx = 1 - self.extra_acked_win_idx;
                if let Some(slot) = self.extra_acked.get_mut(self.extra_acked_win_idx) {
                    *slot = 0;
                }
            }
        }
        let reset = ACK_EPOCH_RESET_THRESH * u64::from(flow.mss);
        let epoch = flow.delivered_time.saturating_sub(self.ack_epoch_stamp);
        let mut expected = u64::try_from((u128::from(self.bw()) * u128::from(epoch)) >> BW_SCALE)
            .unwrap_or(u64::MAX);
        let acked = u64::from(sample.acked_sacked);
        if self.ack_epoch_acked <= expected || self.ack_epoch_acked + acked >= reset {
            self.ack_epoch_acked = 0;
            self.ack_epoch_stamp = flow.delivered_time;
            expected = 0;
        }
        self.ack_epoch_acked = (self.ack_epoch_acked + acked).min(reset - 1);
        let extra = self
            .ack_epoch_acked
            .saturating_sub(expected)
            .min(u64::from(window.cwnd));
        if let Some(slot) = self.extra_acked.get_mut(self.extra_acked_win_idx)
            && extra > *slot
        {
            *slot = extra;
        }
    }

    fn check_full_bw_reached(&mut self, sample: &RateSample) {
        if self.full_bw_reached || !self.round_start || sample.app_limited {
            return;
        }
        let threshold = (u128::from(self.full_bw) * u128::from(FULL_BW_THRESH)) >> SCALE;
        if u128::from(self.bw.get()) >= threshold {
            self.full_bw = self.bw.get();
            self.full_bw_count = 0;
            return;
        }
        self.full_bw_count += 1;
        self.full_bw_reached = self.full_bw_count >= FULL_BW_COUNT;
    }

    fn check_drain(&mut self, flow: &Flow, window: &mut Window) {
        if self.mode == Mode::Startup && self.full_bw_reached {
            self.mode = Mode::Drain;
            window.ssthresh = self.inflight_target(self.bw.get(), UNIT, flow.mss);
        }
        if self.mode == Mode::Drain
            && self.in_net_at_departure(flow, flow.inflight)
                <= self.inflight_target(self.bw.get(), UNIT, flow.mss)
        {
            self.reset_probe_bw_mode(flow);
        }
    }

    fn check_probe_rtt_done(&mut self, flow: &Flow, window: &mut Window) {
        if self.probe_rtt_done_stamp == 0 || !after(jiffies(flow.now), self.probe_rtt_done_stamp) {
            return;
        }
        self.min_rtt_stamp = jiffies(flow.now);
        window.cwnd = window.cwnd.max(self.prior_cwnd);
        self.reset_mode(flow);
    }

    /// Returns the delivered count that marks the flight application-limited while ProbeRTT
    /// holds the window down.
    fn update_min_rtt(
        &mut self,
        flow: &Flow,
        window: &mut Window,
        sample: &RateSample,
    ) -> Option<u64> {
        let now = jiffies(flow.now);
        let expired = after(now, self.min_rtt_stamp.wrapping_add(MIN_RTT_WINDOW_MS));
        if sample.rtt >= 0
            && ((sample.rtt as u64) < u64::from(self.min_rtt_us)
                || (expired && !sample.ack_delayed))
        {
            self.min_rtt_us = u32::try_from(sample.rtt).unwrap_or(u32::MAX - 1);
            self.min_rtt_stamp = now;
        }
        if expired && !self.idle_restart && self.mode != Mode::ProbeRtt {
            self.mode = Mode::ProbeRtt;
            self.save_cwnd(window.cwnd);
            self.probe_rtt_done_stamp = 0;
        }
        let mut app_limited = None;
        if self.mode == Mode::ProbeRtt {
            app_limited = Some((flow.delivered + u64::from(flow.inflight)).max(1));
            if self.probe_rtt_done_stamp == 0 && flow.inflight <= CWND_MIN_TARGET * flow.mss {
                self.probe_rtt_done_stamp = now.wrapping_add(PROBE_RTT_MODE_MS).max(1);
                self.probe_rtt_round_done = false;
                self.next_rtt_delivered = flow.delivered;
            } else if self.probe_rtt_done_stamp != 0 {
                if self.round_start {
                    self.probe_rtt_round_done = true;
                }
                if self.probe_rtt_round_done {
                    self.check_probe_rtt_done(flow, window);
                }
            }
        }
        if sample.delivered > 0 {
            self.idle_restart = false;
        }
        app_limited
    }

    fn update_gains(&mut self) {
        let (pacing, cwnd) = match self.mode {
            Mode::Startup => (HIGH_GAIN, HIGH_GAIN),
            Mode::Drain => (DRAIN_GAIN, HIGH_GAIN),
            Mode::ProbeBw if self.lt_use_bw => (UNIT, CWND_GAIN),
            Mode::ProbeBw => (
                PACING_GAINS
                    .get(self.cycle_idx as usize)
                    .copied()
                    .unwrap_or(UNIT),
                CWND_GAIN,
            ),
            Mode::ProbeRtt => (UNIT, UNIT),
        };
        self.pacing_gain = pacing;
        self.cwnd_gain = cwnd;
    }

    /// `bbr_main` on an ACK. Returns a new application-limited mark when ProbeRTT sets one.
    pub fn on_ack(&mut self, flow: &Flow, window: &mut Window, sample: &RateSample) -> Option<u64> {
        if self.min_rtt_us == u32::MAX
            && let Some(min_rtt) = flow.min_rtt
        {
            self.min_rtt_us = u32::try_from(min_rtt).unwrap_or(u32::MAX - 1);
            self.min_rtt_stamp = jiffies(flow.now);
        }
        self.update_bw(flow, sample);
        self.update_ack_aggregation(flow, window, sample);
        if self.mode == Mode::ProbeBw && self.is_next_cycle_phase(flow, sample) {
            self.advance_cycle_phase(flow);
        }
        self.check_full_bw_reached(sample);
        self.check_drain(flow, window);
        let app_limited = self.update_min_rtt(flow, window, sample);
        self.update_gains();
        let bw = self.bw();
        self.set_pacing_rate(flow, window.cwnd, bw, self.pacing_gain);
        self.set_cwnd(flow, window, sample, bw);
        app_limited
    }

    /// `bbr_ssthresh` on entering recovery or loss: the window is kept for the exit.
    pub fn on_loss(&mut self, window: &Window) -> u32 {
        self.save_cwnd(window.cwnd);
        window.ssthresh
    }

    /// `bbr_set_state(TCP_CA_Loss)` after a retransmission timeout.
    pub fn on_rto(&mut self, flow: &Flow) {
        self.prev_ca_state = CaState::Loss;
        self.full_bw = 0;
        self.round_start = true;
        let sample = RateSample {
            losses: 1,
            ..RateSample::default()
        };
        self.lt_sample(flow, &sample);
    }
}

#[cfg(test)]
#[path = "bbr_tests.rs"]
mod tests;
