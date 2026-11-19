use concord_config::rule::{Cond, RuleDef};

use crate::eval::{Ev, EvResult, Node, has_domain_suffix};
use crate::runs::{DomainRun, IpRun};
use crate::table::RuleTable;

#[derive(Clone, Copy)]
pub(crate) enum HostMatch {
    Exact,
    Suffix,
    Keyword,
}

impl HostMatch {
    pub(crate) fn matches(self, host: &str, payload: &str) -> bool {
        match self {
            HostMatch::Exact => host == payload,
            HostMatch::Suffix => has_domain_suffix(host, payload),
            HostMatch::Keyword => host.contains(payload),
        }
    }
}

impl Op {
    pub(crate) fn host(idx: u32, how: HostMatch, extended: bool) -> Op {
        Op::Host { idx, how, extended }
    }
}

pub(crate) enum Op {
    Leaf {
        idx: u32,
        node: u32,
    },
    /// A lone domain rule, which needs nothing beyond its payload in the table.
    Host {
        idx: u32,
        how: HostMatch,
        extended: bool,
    },
    Domain(u32),
    Ip(u32),
}

/// One compiled rule list: the main list, a sub-rule list, or a classical rule set.
#[derive(Default)]
pub(crate) struct Prog {
    pub(crate) table: RuleTable,
    pub(crate) ops: Box<[Op]>,
    pub(crate) nodes: Box<[Node]>,
    pub(crate) domain_runs: Box<[DomainRun]>,
    pub(crate) ip_runs: Box<[IpRun]>,
}

impl Prog {
    pub(crate) fn heap_bytes(&self) -> usize {
        self.table.heap_bytes()
            + self.ops.len() * std::mem::size_of::<Op>()
            + self.nodes.len() * std::mem::size_of::<Node>()
            + self
                .domain_runs
                .iter()
                .map(DomainRun::heap_bytes)
                .sum::<usize>()
            + self.ip_runs.iter().map(IpRun::heap_bytes).sum::<usize>()
    }

    /// True when any rule of the list holds, evaluated in order.
    pub(crate) fn any_match(&self, ev: &mut Ev<'_>) -> EvResult {
        let mut unknown = false;
        for op in self.ops.iter() {
            match op {
                Op::Leaf { node, .. } => {
                    if let Some(node) = self.nodes.get(*node as usize) {
                        if ev.eval(node)? {
                            return Ok(true);
                        }
                        unknown |= ev.unknown;
                    }
                }
                Op::Host { idx, how, extended } => {
                    if self
                        .table
                        .payload(*idx)
                        .is_some_and(|payload| host_holds(ev, *how, *extended, payload))
                    {
                        return Ok(true);
                    }
                }
                Op::Domain(run) => {
                    if let Some(run) = self.domain_runs.get(*run as usize)
                        && run.next_in(ev, run.start, &self.table).is_some()
                    {
                        return Ok(true);
                    }
                }
                Op::Ip(run) => {
                    let Some(run) = self.ip_runs.get(*run as usize) else {
                        continue;
                    };
                    let ip = if run.src {
                        ev.src_ip()
                    } else {
                        ev.dst_ip(run.resolves)?
                    };
                    if ip.is_some_and(|ip| run.next_from(ip, run.start).is_some()) {
                        return Ok(true);
                    }
                }
            }
        }
        ev.unknown = unknown;
        Ok(false)
    }
}

/// Whether a lone domain rule holds for the flow's name, or for any of its names when the
/// rule asks for `extended-matching`.
pub(crate) fn host_holds(ev: &Ev<'_>, how: HostMatch, extended: bool, payload: &str) -> bool {
    how.matches(ev.host, payload)
        || extended
            && ev
                .other_hosts()
                .into_iter()
                .flatten()
                .any(|host| how.matches(host, payload))
}

/// How to match a lone domain rule from its payload alone. The payload shows the rule
/// to the user, so it only stands in for the condition when the two agree.
pub(crate) fn host_match(def: &RuleDef, payload: Option<&str>) -> Option<HostMatch> {
    let (how, pattern) = match &def.cond {
        Cond::Domain(pattern) => (HostMatch::Exact, pattern),
        Cond::DomainSuffix(pattern) => (HostMatch::Suffix, pattern),
        Cond::DomainKeyword(pattern) => (HostMatch::Keyword, pattern),
        _ => return None,
    };
    let payload = payload?;
    let same = if pattern.is_ascii() {
        payload.eq_ignore_ascii_case(pattern)
    } else {
        payload == pattern.to_lowercase()
    };
    same.then_some(how)
}
