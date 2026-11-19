use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use concord_common::{
    Address, FlowMeta, InboundInfo, InboundKind, Network, ProcessInfo, RouteState,
};
use concord_config::rule::parse_rule;
use indexmap::IndexMap;

use crate::geo::GeoStore;
use crate::{CompileEnv, MatchCtx, RouteProgram, RuleDef, RuleSetStore, Step};

pub(crate) fn defs(lines: &[&str]) -> Vec<RuleDef> {
    lines
        .iter()
        .map(|line| parse_rule(line).unwrap_or_else(|err| panic!("{line}: {err}")))
        .collect()
}

pub(crate) struct Kit {
    pub geo: Arc<GeoStore>,
    pub sets: Arc<RuleSetStore>,
    pub dir: tempfile::TempDir,
}

impl Kit {
    pub fn new() -> Kit {
        let dir = tempfile::tempdir().unwrap();
        Kit {
            geo: Arc::new(GeoStore::new(dir.path())),
            sets: Arc::new(RuleSetStore::new()),
            dir,
        }
    }

    pub fn env(&self, merge_min: usize) -> CompileEnv {
        let mut env = CompileEnv::new(self.geo.clone(), self.sets.clone());
        env.merge_min = merge_min;
        env
    }

    pub fn compile(&self, lines: &[&str], merge_min: usize) -> RouteProgram {
        self.compile_with(lines, &[], merge_min)
    }

    pub fn compile_with(
        &self,
        lines: &[&str],
        subs: &[(&str, &[&str])],
        merge_min: usize,
    ) -> RouteProgram {
        let sub_rules: IndexMap<String, Vec<RuleDef>> = subs
            .iter()
            .map(|(name, lines)| (name.to_string(), defs(lines)))
            .collect();
        RouteProgram::compile(&defs(lines), &sub_rules, &self.env(merge_min))
            .unwrap_or_else(|err| panic!("{err}"))
    }
}

#[derive(Clone)]
pub(crate) struct Flow {
    pub network: Network,
    pub kind: InboundKind,
    pub inbound_name: &'static str,
    pub user: Option<&'static str>,
    pub in_port: u16,
    pub src: SocketAddr,
    pub host: Option<&'static str>,
    pub dst_port: u16,
    pub literal_ip: Option<IpAddr>,
    pub resolves_to: Option<IpAddr>,
    pub process: Option<(&'static str, &'static str, u32)>,
    pub dscp: u8,
    /// The request's URL and User-Agent, once read.
    pub http: Option<(&'static str, Option<&'static str>)>,
    /// The name sniffed from the flow, which the rules see in place of `host`.
    pub sniffed: Option<&'static str>,
    pub connect_agent: Option<&'static str>,
}

impl Flow {
    pub fn domain(host: &'static str) -> Flow {
        Flow {
            network: Network::Tcp,
            kind: InboundKind::Http,
            inbound_name: "in",
            user: None,
            in_port: 7890,
            src: "192.168.1.5:50000".parse().unwrap(),
            host: Some(host),
            dst_port: 443,
            literal_ip: None,
            resolves_to: None,
            process: None,
            dscp: 0,
            http: None,
            connect_agent: None,
            sniffed: None,
        }
    }

    pub fn ip(ip: &str) -> Flow {
        Flow {
            host: None,
            literal_ip: Some(ip.parse().unwrap()),
            ..Flow::domain("")
        }
    }

    pub fn meta(&self) -> FlowMeta {
        let mut inbound = InboundInfo::new(self.kind);
        inbound.name = Arc::from(self.inbound_name);
        inbound.user = self.user.map(Arc::from);
        inbound.user_agent = self.connect_agent.map(Arc::from);
        inbound.addr = Some(SocketAddr::from(([127, 0, 0, 1], self.in_port)));
        let dst = match (self.literal_ip, self.host) {
            (Some(ip), _) => Address::Socket(SocketAddr::new(ip, self.dst_port)),
            (None, host) => Address::Domain(host.unwrap_or("").into(), self.dst_port),
        };
        FlowMeta {
            dscp: 0,
            network: self.network,
            inbound,
            src: self.src,
            dst,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Trace {
    /// Every candidate in the order the program offered them: top-level rule index and target.
    pub candidates: Vec<(usize, String)>,
    pub accepted: Option<(usize, String)>,
    pub ip_lookups: u32,
    pub process_lookups: u32,
    pub observed: crate::Observed,
    pub http_pending: bool,
}

/// Drives a program like the tunnel does. Targets `PASS` and `PASS-RULE` are
/// skipped the way mihomo skips them; with `accept_first` anything else ends
/// the run, otherwise it is recorded and skipped too.
pub(crate) fn drive(
    program: &RouteProgram,
    geo: &GeoStore,
    flow: &Flow,
    accept_first: bool,
) -> Trace {
    let meta = flow.meta();
    let mut state = RouteState::seed(&meta.dst);
    if let Some(name) = flow.sniffed {
        state.dialed = state.host.take();
        state.host = Some(name.into());
    }
    state.http = flow.http.map(|(url, user_agent)| {
        let host = url
            .split_once("://")
            .map_or("", |(_, rest)| rest)
            .split(['/', ':', '?'])
            .next()
            .unwrap_or_default();
        Arc::new(concord_common::HttpFacts {
            url: url.into(),
            host: host.to_ascii_lowercase().into(),
            user_agent: user_agent.map(Into::into),
        })
    });
    let mut ctx = MatchCtx::new(geo);
    ctx.dscp = flow.dscp;
    let mut trace = Trace::default();
    let mut run = program.start();
    let mut guard = 0;
    loop {
        guard += 1;
        assert!(guard < 100_000, "the run does not end");
        match run.step(&meta, &state, &ctx) {
            Step::Done => {
                trace.observed = run.take_observed();
                trace.http_pending = run.http_pending();
                return trace;
            }
            Step::NeedIp => {
                trace.ip_lookups += 1;
                state.ip = flow.resolves_to;
                state.ip_resolved = true;
            }
            Step::NeedProcess => {
                trace.process_lookups += 1;
                state.process = flow.process.map(|(name, path, uid)| {
                    Arc::new(ProcessInfo {
                        uid: Some(uid),
                        name: name.to_string(),
                        path: path.to_string(),
                    })
                });
                state.process_looked_up = true;
            }
            Step::Candidate { target, rule } => {
                trace.candidates.push((rule.index(), target.to_string()));
                match target {
                    "PASS-RULE" => run.skip_pass_rule(),
                    "PASS" => run.skip(),
                    _ if accept_first => {
                        trace.accepted = trace.candidates.last().cloned();
                        trace.observed = run.take_observed();
                        trace.http_pending = run.http_pending();
                        return trace;
                    }
                    _ => run.skip(),
                }
            }
        }
    }
}
