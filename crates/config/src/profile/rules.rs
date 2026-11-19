use std::collections::{HashMap, HashSet};

use indexmap::IndexMap;

use super::Names;
use crate::builtin::is_builtin;
use crate::error::{ConfigError, Result};
use crate::mitm::modules::Modules;
use crate::proxy::Capabilities;
use crate::report::LoadReport;
use crate::rule::{Cond, RuleDef, RuleLines, parse_rule};

/// The profile's rules with every module's ahead of them, and its sub-rules, each line checked.
pub(super) fn checked_rules(
    rules: RuleLines,
    source_lines: &[u32],
    modules: &mut Modules,
    ctx: &RuleContext<'_>,
    report: &mut LoadReport,
) -> Result<(RuleLines, IndexMap<String, Vec<RuleDef>>)> {
    each_checked_rule(rules.iter(), source_lines, "rules", ctx, report, drop)?;
    let module_ctx = RuleContext {
        refuse_unknown_scripts: true,
        ..*ctx
    };
    let rules = modules.ahead(rules, |line| {
        each_checked_rule([line].into_iter(), &[], "rules", &module_ctx, report, drop)
    });
    let mut sub_rules = IndexMap::with_capacity(ctx.sub_rules.len());
    for (name, lines) in ctx.sub_rules {
        let mut defs = Vec::with_capacity(lines.len());
        each_checked_rule(
            lines.iter().map(String::as_str),
            &[],
            &format!("sub-rules[{name}]"),
            ctx,
            report,
            |rule| defs.push(rule),
        )?;
        sub_rules.insert(name.clone(), defs);
    }
    if let Some(cycle) = find_sub_rule_cycle(&sub_rules) {
        return Err(ConfigError::new(format!(
            "sub-rule error: circular references [{}]",
            cycle.join("->")
        )));
    }
    Ok((rules, sub_rules))
}

fn cond_types(cond: &Cond, out: &mut Vec<&'static str>) {
    if let Cond::Flagged { cond: inner, .. } = cond {
        return cond_types(inner, out);
    }
    out.push(cond.type_name());
    match cond {
        Cond::And(items) | Cond::Or(items) => items.iter().for_each(|c| cond_types(c, out)),
        Cond::Not(inner) | Cond::SubRule(inner) => cond_types(inner, out),
        _ => {}
    }
}

#[derive(Clone, Copy)]
pub(super) struct RuleContext<'a> {
    pub(super) names: &'a Names,
    pub(super) sub_rules: &'a IndexMap<String, Vec<String>>,
    pub(super) rule_providers: &'a HashSet<&'a str>,
    pub(super) capabilities: &'a Capabilities,
    pub(super) rule_scripts: &'a HashSet<String>,
    /// A rule naming no declared script is refused, not kept with a warning.
    pub(super) refuse_unknown_scripts: bool,
}

/// `DOMAIN` and `DOMAIN-SUFFIX` compare literally, and no host has a `*` or `+` in it.
fn is_dead_domain(cond: &Cond) -> bool {
    match cond {
        Cond::Domain(payload) | Cond::DomainSuffix(payload) => payload.contains(['*', '+']),
        _ => false,
    }
}

fn report_dead_rules(report: &mut LoadReport, path: &str, after_match: usize, dead: &[String]) {
    if after_match > 0 {
        report.info(
            "rule_unreachable",
            path,
            format!("{after_match} rules after MATCH are never reached"),
        );
    }
    if let Some(first) = dead.first() {
        let more = match dead.len() {
            1 => String::new(),
            count => format!(" and {} more", count - 1),
        };
        report.info(
            "rule_never_matches",
            path,
            format!(
                "[{first}]{more} never match: DOMAIN and DOMAIN-SUFFIX take no wildcard, \
                 use DOMAIN-WILDCARD"
            ),
        );
    }
}

fn each_checked_rule<'a>(
    lines: impl Iterator<Item = &'a str>,
    source_lines: &[u32],
    format: &str,
    ctx: &RuleContext<'_>,
    report: &mut LoadReport,
    mut keep: impl FnMut(RuleDef),
) -> Result<()> {
    let mut types: Vec<&'static str> = Vec::new();
    let mut matched = false;
    let mut after_match = 0;
    let mut dead = Vec::new();
    for (index, line) in lines.enumerate() {
        let fail = |message: &str| {
            ConfigError::new(format!("{format}[{index}] [{line}] error: {message}"))
                .with_line(source_lines.get(index).copied())
        };
        let rule = parse_rule(line).map_err(|err| fail(&err.message))?;
        types.clear();
        cond_types(&rule.cond, &mut types);
        if let Some(unsupported) = types
            .iter()
            .find(|t| !ctx.capabilities.rule_types.contains(t))
        {
            if *unsupported == "UID" {
                return Err(fail("uid rule not support this platform"));
            }
            return Err(fail(&format!(
                "rule type {unsupported} is not supported by this core"
            )));
        }
        let proxy = is_builtin(&rule.target) || ctx.names.resolves(&rule.target);
        if !matches!(rule.cond, Cond::SubRule(_)) {
            if !proxy {
                return Err(fail(&format!("proxy [{}] not found", rule.target)));
            }
        } else if !ctx.sub_rules.contains_key(&rule.target) {
            if !proxy || format != "rules" {
                return Err(fail(&format!("sub-rule [{}] not found", rule.target)));
            }
            let message = format!(
                "SUB-RULE target {} is not a sub-rule, so the rule never matches",
                rule.target
            );
            report.info("rule_never_matches", format!("rules[{index}]"), message);
        }
        let mut sets = Vec::new();
        rule.cond.rule_sets(&mut sets);
        if let Some(missing) = sets
            .into_iter()
            .find(|name| !ctx.rule_providers.contains(name))
        {
            return Err(fail(&format!("rule set [{missing}] not found")));
        }
        let mut scripts = Vec::new();
        rule.cond.scripts(&mut scripts);
        if let Some(missing) = scripts
            .into_iter()
            .find(|name| !ctx.rule_scripts.contains(*name))
        {
            let message = format!("rule script [{missing}] not found, so the rule never matches");
            if ctx.refuse_unknown_scripts {
                return Err(fail(&message));
            }
            report.warn("rule_unknown_script", format!("{format}[{index}]"), message);
        }
        if matched {
            after_match += 1;
        } else if is_dead_domain(&rule.cond) {
            dead.push(rule.text.clone());
        }
        matched |= rule.cond == Cond::Match;
        keep(rule);
    }
    report_dead_rules(report, format, after_match, &dead);
    Ok(())
}

fn find_sub_rule_cycle(sub_rules: &IndexMap<String, Vec<RuleDef>>) -> Option<Vec<String>> {
    fn visit<'a>(
        name: &'a str,
        graph: &HashMap<&'a str, Vec<&'a str>>,
        path: &mut Vec<&'a str>,
        done: &mut HashSet<&'a str>,
    ) -> Option<Vec<String>> {
        if done.contains(name) {
            return None;
        }
        if let Some(at) = path.iter().position(|p| *p == name) {
            let mut cycle: Vec<String> = path.iter().skip(at).map(|s| (*s).to_string()).collect();
            cycle.push(name.to_string());
            return Some(cycle);
        }
        path.push(name);
        for next in graph.get(name).into_iter().flatten() {
            if let Some(cycle) = visit(next, graph, path, done) {
                return Some(cycle);
            }
        }
        path.pop();
        done.insert(name);
        None
    }
    let graph: HashMap<&str, Vec<&str>> = sub_rules
        .iter()
        .map(|(name, rules)| {
            let targets = rules
                .iter()
                .filter(|r| matches!(r.cond, Cond::SubRule(_)))
                .map(|r| r.target.as_str())
                .collect();
            (name.as_str(), targets)
        })
        .collect();
    let mut done = HashSet::new();
    for name in sub_rules.keys() {
        if let Some(cycle) = visit(name, &graph, &mut Vec::new(), &mut done) {
            return Some(cycle);
        }
    }
    None
}
