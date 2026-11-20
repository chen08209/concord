use super::*;

const MSS: u32 = 1000;

#[derive(Clone, Copy)]
struct Packet {
    sent_at: u64,
    acked_at: u64,
    delivered: u64,
    delivered_at: u64,
    first_sent_at: u64,
    app_limited: bool,
}

/// A paced sender behind one FIFO bottleneck of `bw` bytes per µs; the base RTT is all on the
/// return path. It samples delivery rate as `tcp_rate.c` does, one packet per ACK.
struct Link {
    bbr: Bbr,
    window: Window,
    bw: f64,
    rtt: u64,
    now: u64,
    pipe: std::collections::VecDeque<Packet>,
    link_free: u64,
    pace_next: u64,
    sent: u64,
    delivered: u64,
    delivered_at: u64,
    first_sent_at: u64,
    lost: u64,
    app_limited: u64,
    state: CaState,
    marks: u32,
}

impl Link {
    fn new(bw: f64, rtt: u64) -> Link {
        let cwnd = initial_window(MSS);
        let now = 1_000_000;
        Link {
            bbr: Bbr::new(cwnd, 7, now),
            window: Window {
                cwnd,
                ssthresh: u32::MAX,
            },
            bw,
            rtt,
            now,
            pipe: std::collections::VecDeque::new(),
            link_free: now,
            pace_next: now,
            sent: 0,
            delivered: 0,
            delivered_at: now,
            first_sent_at: now,
            lost: 0,
            app_limited: 0,
            state: CaState::Open,
            marks: 0,
        }
    }

    fn bdp(&self) -> u32 {
        (self.bw * self.rtt as f64) as u32
    }

    fn inflight(&self) -> u32 {
        self.pipe.len() as u32 * MSS
    }

    fn flow(&self) -> Flow {
        Flow {
            now: self.now,
            delivered: self.delivered,
            delivered_time: self.delivered_at,
            lost: self.lost,
            inflight: self.inflight(),
            mss: MSS,
            srtt: Some(self.rtt),
            min_rtt: None,
            state: self.state,
            pace_next: self.pace_next,
            app_limited: self.app_limited != 0,
        }
    }

    fn send(&mut self) {
        if self.pipe.is_empty() {
            self.first_sent_at = self.now;
            self.delivered_at = self.now;
        }
        let serve = (f64::from(MSS) / self.bw) as u64;
        self.link_free = self.link_free.max(self.now) + serve;
        self.pipe.push_back(Packet {
            sent_at: self.now,
            acked_at: self.link_free + self.rtt,
            delivered: self.delivered,
            delivered_at: self.delivered_at,
            first_sent_at: self.first_sent_at,
            app_limited: self.app_limited != 0,
        });
        self.sent += 1;
        let rate = self.bbr.pacing_rate().max(1);
        self.pace_next = if self.sent < 10 {
            self.now
        } else {
            self.pace_next.max(self.now) + u64::from(MSS) * 1_000_000 / rate
        };
    }

    fn ack(&mut self, packet: Packet) {
        let prior_inflight = self.inflight() + MSS;
        self.delivered += u64::from(MSS);
        self.delivered_at = self.now;
        if self.app_limited != 0 && self.delivered > self.app_limited {
            self.app_limited = 0;
        }
        let send_interval = packet.sent_at - packet.first_sent_at;
        self.first_sent_at = packet.sent_at;
        let interval = send_interval.max(self.now - packet.delivered_at);
        let sample = RateSample {
            delivered: (self.delivered - packet.delivered) as i64,
            interval: if interval < self.rtt {
                -1
            } else {
                interval as i64
            },
            prior_delivered: packet.delivered,
            app_limited: packet.app_limited,
            rtt: (self.now - packet.sent_at) as i64,
            prior_inflight,
            acked_sacked: MSS,
            ..RateSample::default()
        };
        let flow = self.flow();
        if let Some(mark) = self.bbr.on_ack(&flow, &mut self.window, &sample) {
            self.app_limited = mark;
            self.marks += 1;
        }
    }

    fn step(&mut self) {
        let can_send = self.inflight() + MSS <= self.window.cwnd;
        let send_at = can_send.then_some(self.pace_next.max(self.now));
        let ack_at = self.pipe.front().map(|p| p.acked_at);
        match (send_at, ack_at) {
            (Some(send), Some(ack)) if ack <= send => self.take_ack(ack),
            (Some(send), _) => {
                self.now = send;
                self.send();
            }
            (None, Some(ack)) => self.take_ack(ack),
            (None, None) => unreachable!("an empty pipe always has window"),
        }
    }

    fn take_ack(&mut self, at: u64) {
        self.now = at;
        if let Some(packet) = self.pipe.pop_front() {
            self.ack(packet);
        }
    }

    /// Runs for at most `micros` of simulated time; true once `done` holds.
    fn run_until(&mut self, micros: u64, mut done: impl FnMut(&Link) -> bool) -> bool {
        let end = self.now + micros;
        while self.now < end {
            self.step();
            if done(self) {
                return true;
            }
        }
        false
    }
}

fn steady() -> Link {
    let mut link = Link::new(10.0, 10_000);
    assert!(link.run_until(1_000_000, |l| l.bbr.mode == Mode::ProbeBw));
    link.run_until(500_000, |_| false);
    link
}

#[test]
fn startup_finds_the_bandwidth_then_drains_into_probe_bw() {
    let mut link = Link::new(10.0, 10_000);
    let mut modes = vec![link.bbr.mode];
    link.run_until(1_000_000, |l| {
        if modes.last() != Some(&l.bbr.mode) {
            modes.push(l.bbr.mode);
        }
        l.bbr.mode == Mode::ProbeBw
    });
    assert_eq!(modes, [Mode::Startup, Mode::Drain, Mode::ProbeBw]);
    assert!(link.bbr.full_bw_reached);
    let bw = link.bbr.bw.get() as f64 / BW_UNIT as f64;
    assert!((bw / 10.0 - 1.0).abs() < 0.02, "bandwidth estimate {bw}");
    let bdp = link.bdp();
    let budget = 3 * u32::from(u8::MAX) * MSS;
    assert!(
        link.window.ssthresh >= bdp && link.window.ssthresh < bdp + budget,
        "ssthresh {} against bdp {bdp}",
        link.window.ssthresh
    );
}

#[test]
fn probe_bw_holds_about_two_bdp_and_cycles_its_gain() {
    let mut link = steady();
    let bdp = link.bdp();
    let mut gains = std::collections::BTreeSet::new();
    let mut cwnd = (u32::MAX, 0);
    link.run_until(1_000_000, |l| {
        gains.insert(l.bbr.pacing_gain);
        cwnd = (cwnd.0.min(l.window.cwnd), cwnd.1.max(l.window.cwnd));
        false
    });
    assert_eq!(
        gains.into_iter().collect::<Vec<_>>(),
        [UNIT * 3 / 4, UNIT, UNIT * 5 / 4]
    );
    assert!(
        cwnd.0 >= 2 * bdp && cwnd.1 <= 3 * bdp,
        "cwnd {cwnd:?} against bdp {bdp}"
    );
}

#[test]
fn pacing_rate_is_the_bandwidth_times_gain_less_the_margin() {
    let link = Link::new(10.0, 10_000);
    let start = f64::from(initial_window(MSS)) * 1000.0 * f64::from(HIGH_GAIN) / f64::from(UNIT);
    let rate = link.bbr.pacing_rate() as f64;
    assert!(
        (rate / (start * 0.99) - 1.0).abs() < 0.01,
        "initial rate {rate}"
    );

    let mut link = steady();
    let mut rates = Vec::new();
    link.run_until(1_000_000, |l| {
        let bw = l.bbr.bw() as f64 * 1e6 / BW_UNIT as f64;
        let gain = f64::from(l.bbr.pacing_gain) / f64::from(UNIT);
        rates.push(l.bbr.pacing_rate() as f64 / (bw * gain * 0.99));
        false
    });
    assert!(rates.iter().all(|r| (r - 1.0).abs() < 0.01), "{rates:?}");
}

#[test]
fn a_lower_rtt_sample_replaces_the_min_rtt() {
    let mut link = steady();
    assert!(
        link.bbr.min_rtt_us.abs_diff(10_000) < 200,
        "{}",
        link.bbr.min_rtt_us
    );
    let flow = link.flow();
    let sample = RateSample {
        rtt: 8_000,
        acked_sacked: MSS,
        prior_inflight: link.inflight(),
        ..RateSample::default()
    };
    link.bbr.on_ack(&flow, &mut link.window, &sample);
    assert_eq!(link.bbr.min_rtt_us, 8_000);
}

#[test]
fn probe_rtt_after_ten_seconds_drains_to_four_segments_and_restores() {
    let mut link = steady();
    let stamp = link.bbr.min_rtt_stamp;
    assert!(link.run_until(11_000_000, |l| l.bbr.mode == Mode::ProbeRtt));
    let waited = jiffies(link.now).wrapping_sub(stamp);
    assert!(waited > MIN_RTT_WINDOW_MS, "ProbeRTT after {waited} ms");
    let cwnd = link.bbr.prior_cwnd;
    assert!(cwnd >= 2 * link.bdp());
    let marks = link.marks;
    let entered = link.now;
    assert!(link.run_until(1_000_000, |l| {
        assert!(l.bbr.mode != Mode::ProbeRtt || l.window.cwnd <= CWND_MIN_TARGET * MSS);
        l.bbr.mode != Mode::ProbeRtt
    }));
    assert!(link.now - entered >= u64::from(PROBE_RTT_MODE_MS) * 1000);
    assert!(
        link.marks > marks,
        "ProbeRTT marks the flight application-limited"
    );
    assert_eq!(link.bbr.mode, Mode::ProbeBw);
    assert!(
        link.window.cwnd >= cwnd,
        "{} restored against {cwnd}",
        link.window.cwnd
    );
}

#[test]
fn app_limited_samples_cannot_lower_the_bandwidth() {
    let mut link = steady();
    let before = link.bbr.bw.get();
    let flow = link.flow();
    let sample = RateSample {
        delivered: i64::from(MSS),
        interval: 10_000,
        prior_delivered: link.delivered,
        app_limited: true,
        rtt: 10_000,
        acked_sacked: MSS,
        prior_inflight: MSS,
        ..RateSample::default()
    };
    link.bbr.on_ack(&flow, &mut link.window, &sample);
    assert_eq!(link.bbr.bw.get(), before);
}

#[test]
fn the_bandwidth_filter_forgets_a_peak_after_its_window() {
    let mut filter = MinMax::default();
    filter.running_max(BW_RTTS, 0, 100);
    for round in 1..=BW_RTTS {
        filter.running_max(BW_RTTS, round, 40);
        assert_eq!(filter.get(), 100);
    }
    filter.running_max(BW_RTTS, BW_RTTS + 1, 40);
    assert_eq!(filter.get(), 40);
}

#[test]
fn recovery_conserves_packets_then_restores_the_window() {
    let mut link = steady();
    let cwnd = link.window.cwnd;
    link.bbr.on_loss(&link.window);
    link.state = CaState::Recovery;
    let lost = link.pipe.len() / 2;
    link.pipe.truncate(link.pipe.len() - lost);
    link.lost += lost as u64 * u64::from(MSS);
    let at = link.pipe.front().map_or(link.now, |p| p.acked_at);
    link.take_ack(at);
    assert!(link.bbr.packet_conservation);
    assert_eq!(link.window.cwnd, link.inflight() + MSS);
    link.run_until(link.rtt, |_| false);
    link.state = CaState::Open;
    link.run_until(link.rtt, |_| false);
    assert!(
        link.window.cwnd >= 2 * link.bdp(),
        "{} restored against {cwnd}",
        link.window.cwnd
    );
    assert!(!link.bbr.packet_conservation);
}

#[test]
fn a_timeout_ends_the_round_and_forgets_the_full_bandwidth_mark() {
    let mut link = steady();
    let rounds = link.bbr.rtt_count;
    link.bbr.on_rto(&link.flow());
    assert_eq!(link.bbr.prev_ca_state, CaState::Loss);
    assert_eq!(link.bbr.full_bw, 0);
    assert!(link.bbr.round_start);
    assert_eq!(link.bbr.rtt_count, rounds);
}

#[test]
fn a_policer_switches_to_the_long_term_bandwidth() {
    let mut link = steady();
    let step = 10 * MSS;
    for _ in 0..40 {
        link.now += 1_000;
        link.delivered += u64::from(step);
        link.delivered_at = link.now;
        link.lost += u64::from(step / 4);
        let sample = RateSample {
            delivered: i64::from(step),
            interval: 1_000,
            prior_delivered: link.delivered,
            rtt: 10_000,
            acked_sacked: step,
            losses: step / 4,
            prior_inflight: link.window.cwnd,
            ..RateSample::default()
        };
        let flow = link.flow();
        link.bbr.on_ack(&flow, &mut link.window, &sample);
        if link.bbr.lt_use_bw {
            break;
        }
    }
    assert!(link.bbr.lt_use_bw);
    assert_eq!(link.bbr.pacing_gain, UNIT);
    let lt = link.bbr.lt_bw as f64 / BW_UNIT as f64;
    assert!((lt / 10.0 - 1.0).abs() < 0.05, "long-term bandwidth {lt}");
}

#[test]
fn a_connection_made_late_on_the_clock_stays_in_startup_without_an_rtt() {
    let now = 60_000_000;
    let mut window = Window {
        cwnd: initial_window(MSS),
        ssthresh: u32::MAX,
    };
    let mut bbr = Bbr::new(window.cwnd, 7, now);
    let flow = Flow {
        now: now + 1_000,
        delivered: 0,
        delivered_time: now,
        lost: 0,
        inflight: 0,
        mss: MSS,
        srtt: None,
        min_rtt: None,
        state: CaState::Open,
        pace_next: now,
        app_limited: false,
    };
    bbr.on_ack(&flow, &mut window, &RateSample::default());
    assert_eq!(bbr.mode, Mode::Startup);
    assert_eq!(window.cwnd, initial_window(MSS));
}
