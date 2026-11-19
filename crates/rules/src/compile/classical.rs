use concord_config::rule::{Cond, RuleDef, parse_rule};

use super::{Cx, Loc, compile_list, node_for_def};
use crate::prog::Prog;
use crate::program::{CompileEnv, Demands};
use crate::ruleset::GeoFault;

pub(crate) struct Classical {
    pub(crate) prog: Prog,
    pub(crate) demands: Demands,
    pub(crate) count: usize,
    pub(crate) warnings: Vec<String>,
    pub(crate) geo_faults: Vec<GeoFault>,
}

const COMMA_IN_PAYLOAD: &[&str] = &[
    "NOT",
    "OR",
    "AND",
    "SUB-RULE",
    "DOMAIN-REGEX",
    "PROCESS-NAME-REGEX",
    "PROCESS-PATH-REGEX",
];

fn classical_rule(entry: &str) -> Result<RuleDef, String> {
    if let Some(line) = concord_config::rule::with_quoted_target(entry, "DIRECT") {
        return parse_rule(&line).map_err(|err| err.message);
    }
    let items: Vec<&str> = entry
        .split(',')
        .map(|part| part.trim_matches(' '))
        .collect();
    let kind = items.first().copied().unwrap_or_default().to_uppercase();
    if matches!(kind.as_str(), "MATCH" | "RULE-SET" | "SUB-RULE" | "SCRIPT") {
        return Err(format!(
            "unsupported rule type on classical rule-set: {kind}"
        ));
    }
    let with_target = if COMMA_IN_PAYLOAD.contains(&kind.as_str()) {
        format!("{entry},DIRECT")
    } else {
        let payload = items.get(1).copied().unwrap_or_default();
        if payload.is_empty() {
            return Err(format!("missing subsequent parameters: {kind}"));
        }
        let mut parts = vec![
            items.first().copied().unwrap_or_default(),
            payload,
            "DIRECT",
        ];
        parts.extend(items.iter().skip(2));
        parts.join(",")
    };
    parse_rule(&with_target).map_err(|err| err.message)
}

pub(crate) fn compile_classical(entries: &[String], env: &CompileEnv) -> Classical {
    let mut cx = Cx::new(env, false);
    let mut warnings = Vec::new();
    let mut geo_faults = Vec::new();
    let mut defs = Vec::with_capacity(entries.len());
    for entry in entries {
        let def = match classical_rule(entry) {
            Ok(def) => def,
            Err(message) => {
                warnings.push(format!("parse classical rule [{entry}] error: {message}"));
                continue;
            }
        };
        let probe = matches!(
            def.cond,
            Cond::GeoSite(_)
                | Cond::GeoIp(_)
                | Cond::SrcGeoIp(_)
                | Cond::IpAsn(_)
                | Cond::SrcIpAsn(_)
                | Cond::And(_)
                | Cond::Or(_)
                | Cond::Not(_)
        );
        if probe {
            let loc = Loc {
                section: "classical",
                index: defs.len(),
                line: entry,
            };
            let mut scratch = Cx::new(env, false);
            if let Err(err) = node_for_def(&mut scratch, &def, &loc) {
                if let Some(fault) = GeoFault::of(&err)
                    && !geo_faults.contains(&fault)
                {
                    geo_faults.push(fault);
                }
                warnings.push(format!("parse classical rule [{entry}] error: {err}"));
                continue;
            }
        }
        defs.push(def);
    }
    let count = defs.len();
    let prog = compile_list(&mut cx, defs.iter().map(Ok), "classical").unwrap_or_default();
    for file in cx.deferred_geo {
        let fault = GeoFault::Missing(file);
        if !geo_faults.contains(&fault) {
            geo_faults.push(fault);
        }
    }
    Classical {
        prog,
        demands: cx.demands,
        count,
        warnings,
        geo_faults,
    }
}
