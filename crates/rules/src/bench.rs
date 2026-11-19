use std::time::Instant;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::testkit::{Flow, Kit, defs};
use crate::{MatchCtx, RouteProgram, Step};

const RULES: usize = 2_000_000;

fn lines(rng: &mut StdRng) -> Vec<String> {
    let mut lines = Vec::with_capacity(RULES + 8);
    lines.push("PROCESS-NAME,never,X".to_string());
    for i in 0..RULES {
        let line = if i >= RULES * 3 / 4 {
            format!(
                "IP-CIDR,{}.{}.{}.0/24,T{}",
                rng.random_range(1..224),
                rng.random_range(0..256),
                rng.random_range(0..256),
                i % 5
            )
        } else {
            match i % 6 {
                0..=2 => format!("DOMAIN-SUFFIX,host{}.example{}.com,T{}", i, i % 977, i % 5),
                3 | 4 => format!("DOMAIN,www.site{i}.net,T{}", i % 5),
                _ => format!("DOMAIN-KEYWORD,kw{i}x,T{}", i % 5),
            }
        };
        lines.push(line);
    }
    lines.push("MATCH,FINAL".to_string());
    lines
}

fn sweep(program: &RouteProgram, kit: &Kit, flows: &[Flow]) -> Vec<u128> {
    let mut times = Vec::with_capacity(flows.len());
    for flow in flows {
        let meta = flow.meta();
        let mut state = concord_common::RouteState::seed(&meta.dst);
        let ctx = MatchCtx::new(&kit.geo);
        let started = Instant::now();
        let mut run = program.start();
        loop {
            match run.step(&meta, &state, &ctx) {
                Step::NeedIp => {
                    state.ip = flow.resolves_to;
                    state.ip_resolved = true;
                }
                Step::NeedProcess => state.process_looked_up = true,
                Step::NeedScript { id, .. } => state.scripts.push((id, false)),
                Step::Candidate { .. } | Step::Done => break,
            }
        }
        times.push(started.elapsed().as_nanos());
    }
    times.sort_unstable();
    times
}

#[test]
#[ignore = "benchmark; run with --release -- --ignored --nocapture"]
fn two_million_rules() {
    let mut rng = StdRng::seed_from_u64(7);
    let text = lines(&mut rng);
    let parse_started = Instant::now();
    let rules = defs(&text.iter().map(String::as_str).collect::<Vec<_>>());
    let parse = parse_started.elapsed();
    let kit = Kit::new();
    let compile_started = Instant::now();
    let program = RouteProgram::compile(&rules, &Default::default(), &kit.env(8)).unwrap();
    let compile = compile_started.elapsed();
    println!(
        "rules {} parse {parse:?} compile {compile:?} memory {} MiB",
        program.len(),
        program.memory_estimate() >> 20
    );

    let mut flows = Vec::new();
    for i in 0..100_000usize {
        let mut flow = match i % 4 {
            0 => Flow::domain(Box::leak(
                format!("a.b.host{}.example{}.com", i * 6, (i * 6) % 977).into_boxed_str(),
            )),
            1 => Flow::domain(Box::leak(
                format!("www.site{}.net", i * 6 + 3).into_boxed_str(),
            )),
            2 => Flow::domain(Box::leak(format!("miss{i}.nowhere.test").into_boxed_str())),
            _ => Flow::ip(&format!(
                "{}.{}.{}.7",
                rng.random_range(1..224),
                rng.random_range(0..256),
                rng.random_range(0..256)
            )),
        };
        flow.resolves_to = Some(
            format!(
                "{}.{}.{}.9",
                rng.random_range(1..224),
                rng.random_range(0..256),
                rng.random_range(0..256)
            )
            .parse()
            .unwrap(),
        );
        flows.push(flow);
    }
    let times = sweep(&program, &kit, &flows);
    let at = |q: f64| times[((times.len() as f64 * q) as usize).min(times.len() - 1)];
    println!(
        "match ns: p50 {} p90 {} p99 {} p99.9 {} max {}",
        at(0.5),
        at(0.9),
        at(0.99),
        at(0.999),
        times[times.len() - 1]
    );
}
