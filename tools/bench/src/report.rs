//! Results on disk (JSON with every trial, so later tools can recompute) and the
//! Markdown and terminal views of them.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::load::{Metrics, Workload};
use crate::stats::{self, Verdict};

pub const SCHEMA: u32 = 1;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Cell {
    pub case: String,
    pub workload: String,
    pub core: String,
    pub trials: Vec<Metrics>,
    pub errors: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Results {
    pub schema: u32,
    pub started: String,
    pub finished: Option<String>,
    pub args: Vec<String>,
    pub env: Value,
    pub plan: Value,
    pub cores: Value,
    /// The order cores were given in; the first is the subject the others are compared to.
    pub core_order: Vec<String>,
    pub cells: Vec<Cell>,
}

impl Results {
    /// Whether `core` was measured without being what the run is judged against.
    fn is_diagnostic(&self, core: &str) -> bool {
        self.cores.as_array().is_some_and(|cores| {
            cores
                .iter()
                .any(|c| c["name"] == core && c["role"] == "diagnostic")
        })
    }

    pub fn cell(&mut self, case: &str, workload: Workload, core: &str) -> &mut Cell {
        let name = workload.name();
        let index = match self
            .cells
            .iter()
            .position(|c| c.case == case && c.workload == name && c.core == core)
        {
            Some(i) => i,
            None => {
                self.cells.push(Cell {
                    case: case.into(),
                    workload: name.into(),
                    core: core.into(),
                    ..Cell::default()
                });
                self.cells.len() - 1
            }
        };
        &mut self.cells[index]
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        let tmp = dir.join("results.json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(tmp, dir.join("results.json"))?;
        std::fs::write(dir.join("report.md"), markdown(self))
    }

    pub fn load(path: &Path) -> Result<Results, String> {
        let text = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let results: Results =
            serde_json::from_slice(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        if results.schema != SCHEMA {
            return Err(format!(
                "{}: schema {} (this tool reads {SCHEMA})",
                path.display(),
                results.schema
            ));
        }
        Ok(results)
    }

    fn samples(&self, case: &str, workload: &str, core: &str, metric: &str) -> Vec<f64> {
        self.cells
            .iter()
            .find(|c| c.case == case && c.workload == workload && c.core == core)
            .map(|c| {
                c.trials
                    .iter()
                    .filter_map(|t| t.get(metric).copied())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn cases(&self) -> Vec<String> {
        let mut seen = Vec::new();
        for c in &self.cells {
            if !seen.contains(&c.case) {
                seen.push(c.case.clone());
            }
        }
        seen
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Better {
    Higher,
    Lower,
    Neither,
}

pub struct Meta {
    pub label: &'static str,
    pub better: Better,
}

pub fn meta(key: &str) -> Meta {
    use Better::*;
    let (label, better) = match key {
        "gbps" => ("Gbit/s", Higher),
        "mbps" => ("Mbit/s", Higher),
        "pps" => ("packets/s", Higher),
        "tps" => ("transactions/s", Higher),
        "cps" => ("connections/s", Higher),
        "jain" => ("fairness (Jain)", Higher),
        "min_flow_gbps" => ("slowest flow Gbit/s", Higher),
        "interval_p10_gbps" => ("p10 of 100 ms rates, Gbit/s", Higher),
        "ipc" => ("instructions/cycle", Higher),
        "cpu_s_per_gb" => ("core CPU-s/GB", Lower),
        "server_cpu_s_per_gb" => ("server CPU-s/GB", Neither),
        "cycles_per_byte" => ("core cycles/byte", Lower),
        "instructions_per_byte" => ("core instructions/byte", Lower),
        "ctx_per_mb" => ("context switches/MB", Lower),
        "syscalls_per_mb" => ("syscalls/MB", Lower),
        "syscalls_per_tx" => ("syscalls/transaction", Lower),
        "syscalls_per_conn" => ("syscalls/connection", Lower),
        "recv_calls_per_mb" => ("core receive-family calls/MB", Neither),
        "send_calls_per_mb" => ("core send-family calls/MB", Neither),
        "server_syscalls_per_mb" => ("server syscalls/MB", Neither),
        "socket_bytes_per_recv_call" => ("socket bytes per receive call", Neither),
        "socket_bytes_per_send_call" => ("socket bytes per send call", Neither),
        k if k.starts_with("sys_") || k.starts_with("server_sys_") => ("calls/MB", Neither),
        "vfs_reads_per_mb" => ("core VFS reads/MB", Neither),
        "vfs_writes_per_mb" => ("core VFS writes/MB", Neither),
        "vfs_read_bytes_per_call" => ("core bytes per VFS read", Neither),
        "vfs_write_bytes_per_call" => ("core bytes per VFS write", Neither),
        "far_rx_segment_bytes" => ("bytes per data segment in, far leg", Neither),
        "far_tx_segment_bytes" => ("bytes per data segment out, far leg", Neither),
        "near_rx_segment_bytes" => ("bytes per data segment in, near leg", Neither),
        "near_tx_segment_bytes" => ("bytes per data segment out, near leg", Neither),
        k if k.ends_with("_nondata_rx_per_mb") || k.ends_with("_nondata_tx_per_mb") => {
            ("segments without data per wire MB", Neither)
        }
        k if k.ends_with("_retrans_per_mb") => ("retransmits per wire MB", Lower),
        k if k.starts_with("nstat_") => ("kernel counter per payload MB", Neither),
        k if k.starts_with("flow_") => ("one flow's Gbit/s, in connect order", Neither),
        "link_to_core_bytes_per_packet" => ("bytes per link packet, server to core", Neither),
        "link_to_server_bytes_per_packet" => ("bytes per link packet, core to server", Neither),
        "link_to_core_packets_per_mb" => ("link packets per payload MB, server to core", Neither),
        "link_to_server_packets_per_mb" => ("link packets per payload MB, core to server", Neither),
        "server_link_flows" => ("server flows to the core", Neither),
        "server_link_rwnd_held_flows" => (
            "server flows receive-window limited for half the window",
            Neither,
        ),
        "server_link_busy_share" => (
            "server flows: share of the window with data to send",
            Neither,
        ),
        "server_link_rwnd_limited_share" => {
            ("server flows: receive-window limited / busy", Neither)
        }
        "server_link_sndbuf_limited_share" => ("server flows: send-buffer limited / busy", Neither),
        "server_link_unsent_bytes" => ("server flows: unsent bytes at close, median", Neither),
        "far_rcv_rtt_us" => ("core far leg: receiver RTT estimate µs, median", Neither),
        "far_rcv_space_bytes" => ("core far leg: receive space, median", Neither),
        "far_rcv_wnd_bytes" => ("core far leg: receive window, median", Neither),
        "cpu_us_per_tx" => ("core CPU-µs/transaction", Lower),
        "kcycles_per_tx" => ("core kcycles/transaction", Lower),
        "cpu_us_per_conn" => ("core CPU-µs/connection", Lower),
        "kcycles_per_conn" => ("core kcycles/connection", Lower),
        "cores" => ("core CPUs busy", Neither),
        "server_cores" => ("server CPUs busy", Neither),
        "origin_cores" => ("origin CPUs busy", Neither),
        "client_cores" => ("load generator CPUs busy", Neither),
        "sys_share" => ("kernel share of core CPU", Neither),
        "wait_share" => ("runnable-but-waiting / CPU", Lower),
        "interval_cv" => ("rate jitter (CV of 100 ms rates)", Lower),
        "peak_mib" => ("peak MiB", Lower),
        "footprint_mib" => ("MiB", Lower),
        "rss_mib" => ("RSS MiB", Lower),
        "loss_pct" => ("loss %", Lower),
        "error_pct" => ("errors %", Lower),
        "kib_per_conn" => ("KiB/held connection", Lower),
        "retained_kib_per_conn" => ("KiB/connection left after close", Lower),
        "server_kib_per_conn" => ("server KiB/held connection", Neither),
        "fds_per_conn" => ("fds/held connection", Lower),
        "open_ms" => ("ms to open all", Lower),
        "ready_ms" => ("ms to ready", Lower),
        "stop_ms" => ("ms to exit", Lower),
        "ready_cpu_ms" => ("CPU-ms at first byte", Lower),
        "startup_cpu_ms" => ("CPU-ms after settling", Lower),
        "threads" | "threads_loaded" => ("threads", Lower),
        "fds" | "fds_after" => ("open fds", Lower),
        "failed" => ("failed", Lower),
        k if k.ends_with("_us") || k.ends_with("_ms") => ("latency", Lower),
        _ => ("", Neither),
    };
    Meta { label, better }
}

pub fn primary(workload: &str) -> &'static [&'static str] {
    match workload {
        "tcp-down" | "tcp-up" => &[
            "gbps",
            "cpu_s_per_gb",
            "cycles_per_byte",
            "server_cpu_s_per_gb",
            "peak_mib",
        ],
        "tcp-multi" => &["gbps", "cpu_s_per_gb", "jain", "peak_mib"],
        "tcp-rr" | "mitm-rr" | "mitm-h2-rr" | "http-rr" => {
            &["tps", "p50_us", "p99_us", "cpu_us_per_tx"]
        }
        "tcp-crr" | "mitm-crr" => &["cps", "p50_ms", "p99_ms", "cpu_us_per_conn", "error_pct"],
        "udp-stream" => &["mbps", "loss_pct", "rtt_p99_us", "cpu_s_per_gb"],
        "udp-rr" => &["rtt_p50_us", "rtt_p99_us", "loss_pct"],
        "idle" => &["kib_per_conn", "retained_kib_per_conn", "open_ms"],
        "startup" => &["ready_ms", "footprint_mib", "threads", "stop_ms"],
        "large" => &["ready_ms", "peak_mib", "footprint_mib"],
        _ => &[],
    }
}

pub fn headline(workload: Workload, m: &Metrics) -> String {
    let mut out = String::new();
    for key in primary(workload.name()) {
        if let Some(v) = m.get(*key) {
            let _ = write!(out, "{key} {}  ", number(*v));
        }
    }
    out.trim_end().to_string()
}

pub fn number(v: f64) -> String {
    let a = v.abs();
    if !v.is_finite() {
        "–".into()
    } else if a >= 1000.0 {
        format!("{v:.0}")
    } else if a >= 100.0 {
        format!("{v:.1}")
    } else if a >= 1.0 {
        format!("{v:.2}")
    } else {
        format!("{v:.3}")
    }
}

fn mark(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Better => "▲",
        Verdict::Worse => "▼",
        Verdict::Same => "≈",
        Verdict::Unknown => "?",
    }
}

fn seed(parts: &[&str]) -> u64 {
    parts
        .iter()
        .flat_map(|p| p.bytes())
        .fold(0xcbf2_9ce4_8422_2325, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
        })
}

/// One row: the subject's median and interval, and its ratio to each other core.
fn row(results: &Results, case: &str, workload: &str, metric: &str) -> Option<String> {
    let order = &results.core_order;
    let subject = order.first()?;
    let meta = meta(metric);
    let mut cells = Vec::new();
    let mut any = false;
    for core in order {
        let samples = results.samples(case, workload, core, metric);
        match stats::summarize(&samples, seed(&[case, workload, core, metric])) {
            Some(s) => {
                any = true;
                let half = (s.ci[1] - s.ci[0]) / 2.0;
                let spread = if s.median != 0.0 {
                    half / s.median.abs() * 100.0
                } else {
                    0.0
                };
                cells.push(format!("{} ±{spread:.0}%", number(s.median)));
            }
            None => cells.push("–".into()),
        }
    }
    if !any {
        return None;
    }
    let base = results.samples(case, workload, subject, metric);
    for other in order.iter().skip(1) {
        let reference = results.samples(case, workload, other, metric);
        if base.is_empty() || reference.is_empty() || meta.better == Better::Neither {
            cells.push(if base.is_empty() || reference.is_empty() {
                "–".into()
            } else {
                ratio_text(
                    &base,
                    &reference,
                    true,
                    seed(&[case, workload, metric, other]),
                    false,
                )
            });
            continue;
        }
        cells.push(ratio_text(
            &base,
            &reference,
            meta.better == Better::Higher,
            seed(&[case, workload, metric, other]),
            true,
        ));
    }
    let name = if meta.label.is_empty() {
        metric.to_string()
    } else {
        format!("{metric} ({})", meta.label)
    };
    Some(format!("| {case} | {name} | {} |", cells.join(" | ")))
}

fn ratio_text(subject: &[f64], reference: &[f64], higher: bool, seed: u64, judged: bool) -> String {
    let c = stats::compare(subject, reference, higher, seed);
    if !c.ratio.is_finite() {
        return "–".into();
    }
    let pct = (c.ratio - 1.0) * 100.0;
    let marker = if judged { mark(c.verdict) } else { "" };
    format!(
        "{marker}{pct:+.1}% [{:+.0},{:+.0}]",
        (c.ci[0] - 1.0) * 100.0,
        (c.ci[1] - 1.0) * 100.0
    )
}

/// Far-leg segment state of one trial. Over loopback a client that reads faster than the server writes leaves the
/// server app-limited, so each record write leaves as its own small segment; a slightly slower client keeps it
/// receive-window limited and writes coalesce. `.agents/benchmarking.md` explains why these are reported apart.
pub fn far_state(trial: &Metrics) -> Option<&'static str> {
    let segment = *trial.get("far_rx_segment_bytes")?;
    let nondata = *trial.get("far_nondata_tx_per_mb")?;
    Some(if segment < 25_000.0 && nondata > 15.0 {
        "small"
    } else if segment >= 35_000.0 && nondata <= 15.0 {
        "large"
    } else {
        "between"
    })
}

/// Per case and core of the multi-flow workload on loopback: trials in each far-leg state with their median server
/// CPU per GB and throughput. A diagnostic: the state depends on the client's read speed against the server, not on
/// a regression, so these medians are not compared across cores.
fn far_states(results: &Results) -> String {
    let mut out = String::new();
    // Over a veth link (MTU 1500) the far leg counts every MSS as a segment, so the thresholds do not apply.
    if !results.env["link"].is_null() {
        return out;
    }
    for cell in results.cells.iter().filter(|c| c.workload == "tcp-multi") {
        let mut groups: BTreeMap<&str, Vec<&Metrics>> = BTreeMap::new();
        for trial in &cell.trials {
            if let Some(state) = far_state(trial) {
                groups.entry(state).or_default().push(trial);
            }
        }
        for (state, trials) in groups {
            let median = |key: &str| {
                let mut v: Vec<f64> = trials.iter().filter_map(|t| t.get(key).copied()).collect();
                v.sort_by(f64::total_cmp);
                stats::quantile(&v, 0.5)
            };
            let _ = writeln!(
                out,
                "| {} | {} | {state} | {} | {} | {} |",
                cell.case,
                cell.core,
                trials.len(),
                number(median("server_cpu_s_per_gb")),
                number(median("gbps")),
            );
        }
    }
    out
}

pub fn markdown(results: &Results) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Concord bench\n");
    let _ = writeln!(
        out,
        "Started {}; {}.\n",
        results.started,
        results
            .finished
            .as_deref()
            .map_or("still running".to_string(), |f| format!("finished {f}"))
    );
    let _ = writeln!(
        out,
        "```json\n{}\n```\n",
        serde_json::to_string_pretty(&results.env).unwrap_or_default()
    );
    let subject = results.core_order.first().cloned().unwrap_or_default();
    let _ = writeln!(
        out,
        "Each cell is the median over rounds with the half-width of its 95% bootstrap interval. \
         Comparison columns are `{subject}` relative to that core with the 95% interval of the ratio; \
         ▲ better, ▼ worse, ≈ no significant difference (Mann-Whitney p ≥ 0.05, interval spans 0, \
         or under {:.0}%).\n",
        stats::NOISE_FLOOR * 100.0
    );
    let mut header = String::from("| case | metric |");
    let mut rule = String::from("|---|---|");
    for core in &results.core_order {
        let _ = write!(header, " {core} |");
        rule.push_str("---:|");
    }
    for other in results.core_order.iter().skip(1) {
        let note = if results.is_diagnostic(other) {
            ", not the reference"
        } else {
            ""
        };
        let _ = write!(header, " {subject} vs {other}{note} |");
        rule.push_str("---:|");
    }
    for workload in Workload::ALL {
        let name = workload.name();
        if !results.cells.iter().any(|c| c.workload == name) {
            continue;
        }
        let _ = writeln!(out, "## {name}\n\n{}\n\n{header}\n{rule}", workload.about());
        for case in results.cases() {
            for metric in primary(name) {
                if let Some(line) = row(results, &case, name, metric) {
                    let _ = writeln!(out, "{line}");
                }
            }
        }
        let _ = writeln!(out);
        let mut detail = String::new();
        for case in results.cases() {
            let mut keys: Vec<String> = results
                .cells
                .iter()
                .filter(|c| c.case == case && c.workload == name)
                .flat_map(|c| c.trials.iter().flat_map(|t| t.keys().cloned()))
                .collect();
            keys.sort();
            keys.dedup();
            for key in keys.iter().filter(|k| !primary(name).contains(&k.as_str())) {
                if let Some(line) = row(results, &case, name, key) {
                    let _ = writeln!(detail, "{line}");
                }
            }
        }
        if !detail.is_empty() {
            let _ = writeln!(
                out,
                "<details><summary>all metrics</summary>\n\n{header}\n{rule}\n{detail}\n</details>\n"
            );
        }
    }
    let states = far_states(results);
    if !states.is_empty() {
        let _ = writeln!(
            out,
            "## tcp-multi far-leg states (diagnostic)\n\n\
             | case | core | state | trials | server CPU-s/GB | Gbit/s |\n|---|---|---|---:|---:|---:|\n{states}"
        );
    }
    let errors: Vec<&Cell> = results
        .cells
        .iter()
        .filter(|c| !c.errors.is_empty())
        .collect();
    if !errors.is_empty() {
        let _ = writeln!(out, "## Errors\n");
        for c in errors {
            let mut unique = c.errors.clone();
            unique.dedup();
            let _ = writeln!(
                out,
                "- {} {} {}: {}× {}",
                c.case,
                c.workload,
                c.core,
                c.errors.len(),
                unique.join("; ")
            );
        }
    }
    out
}

/// The first two headline metrics of each workload, one aligned line per case.
pub fn terminal(results: &Results) -> String {
    let mut out = String::new();
    let order = &results.core_order;
    let Some(subject) = order.first() else {
        return out;
    };
    let _ = write!(out, "\n{:<12} {:<14} {:<22}", "", "case", "metric");
    for core in order {
        let _ = write!(out, " {core:>16}");
    }
    for other in order.iter().skip(1) {
        let _ = write!(out, " {:>18}", format!("{subject}/{other}"));
    }
    for workload in Workload::ALL {
        let name = workload.name();
        if !results.cells.iter().any(|c| c.workload == name) {
            continue;
        }
        for case in results.cases() {
            for metric in primary(name).iter().take(2) {
                let medians: Vec<Option<stats::Summary>> = order
                    .iter()
                    .map(|core| stats::summarize(&results.samples(&case, name, core, metric), 1))
                    .collect();
                if medians.iter().all(Option::is_none) {
                    continue;
                }
                let _ = write!(out, "\n{name:<12} {case:<14} {metric:<22}");
                for m in &medians {
                    let cell = m.as_ref().map_or("–".to_string(), |s| {
                        let half =
                            (s.ci[1] - s.ci[0]) / 2.0 / s.median.abs().max(f64::MIN_POSITIVE)
                                * 100.0;
                        format!("{} ±{half:.0}%", number(s.median))
                    });
                    let _ = write!(out, " {cell:>16}");
                }
                let better = meta(metric).better;
                let base = results.samples(&case, name, subject, metric);
                for other in order.iter().skip(1) {
                    let reference = results.samples(&case, name, other, metric);
                    let c = stats::compare(
                        &base,
                        &reference,
                        better == Better::Higher,
                        seed(&[&case, name, metric, other]),
                    );
                    let cell = if c.ratio.is_finite() {
                        let marker = if better == Better::Neither {
                            " "
                        } else {
                            mark(c.verdict)
                        };
                        format!("{marker}{:+.1}%", (c.ratio - 1.0) * 100.0)
                    } else {
                        "–".to_string()
                    };
                    let _ = write!(out, " {cell:>18}");
                }
            }
        }
    }
    out.push('\n');
    out
}

/// `new` against `base`, matching cells by case, workload and the chosen core
/// names. Returns the report and whether a headline metric regressed beyond
/// `threshold` with significance.
pub fn compare(
    base: &Results,
    new: &Results,
    base_core: &str,
    new_core: &str,
    threshold: f64,
) -> (String, bool) {
    let mut out = String::new();
    let mut regressed = false;
    let _ = writeln!(
        out,
        "| case | workload | metric | base `{base_core}` | new `{new_core}` | change | p | |\n|---|---|---|---:|---:|---:|---:|---|"
    );
    let mut keys: BTreeMap<(String, String), ()> = BTreeMap::new();
    for c in new.cells.iter().filter(|c| c.core == new_core) {
        keys.insert((c.case.clone(), c.workload.clone()), ());
    }
    for (case, workload) in keys.keys() {
        for metric in primary(workload) {
            let a = base.samples(case, workload, base_core, metric);
            let b = new.samples(case, workload, new_core, metric);
            if a.is_empty() || b.is_empty() {
                continue;
            }
            let better = meta(metric).better;
            let c = stats::compare(
                &b,
                &a,
                better == Better::Higher,
                seed(&[case, workload, metric]),
            );
            let median = |v: &[f64]| stats::summarize(v, 1).map_or(f64::NAN, |s| s.median);
            let change = c.ratio - 1.0;
            let bad = better != Better::Neither
                && c.verdict == Verdict::Worse
                && change.abs() > threshold;
            regressed |= bad;
            let _ = writeln!(
                out,
                "| {case} | {workload} | {metric} | {} | {} | {:+.1}% [{:+.0},{:+.0}] | {:.3} | {}{} |",
                number(median(&a)),
                number(median(&b)),
                change * 100.0,
                (c.ci[0] - 1.0) * 100.0,
                (c.ci[1] - 1.0) * 100.0,
                c.p,
                if better == Better::Neither {
                    ""
                } else {
                    mark(c.verdict)
                },
                if bad { " regression" } else { "" },
            );
        }
    }
    (out, regressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trial(segment: f64, nondata: f64) -> Metrics {
        Metrics::from([
            ("far_rx_segment_bytes".to_string(), segment),
            ("far_nondata_tx_per_mb".to_string(), nondata),
        ])
    }

    #[test]
    fn far_state_needs_both_signals() {
        assert_eq!(far_state(&trial(16_400.0, 26.0)), Some("small"));
        assert_eq!(far_state(&trial(53_000.0, 7.0)), Some("large"));
        assert_eq!(far_state(&trial(16_400.0, 7.0)), Some("between"));
        assert_eq!(far_state(&Metrics::new()), None);
    }

    #[test]
    fn far_states_are_reported_on_loopback_only() {
        let mut results = Results {
            cells: vec![Cell {
                case: "trojan-tls".into(),
                workload: "tcp-multi".into(),
                core: "main".into(),
                trials: vec![trial(16_400.0, 26.0)],
                errors: Vec::new(),
            }],
            ..Results::default()
        };
        assert!(far_states(&results).contains("| trojan-tls | main | small | 1 |"));
        results.env = serde_json::json!({"link": {"rtt_ms": 0.0, "usec_ts": true}});
        assert!(far_states(&results).is_empty());
    }
}
