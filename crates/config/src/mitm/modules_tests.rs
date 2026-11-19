use std::collections::BTreeMap;

use super::*;
use crate::hosts::HostValue;
use crate::{LoadOptions, Profile, load_str};

const BASE: &str = "\
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1080}
proxy-groups:
  - {name: sel, type: select, proxies: [a, DIRECT]}
dns:
  enable: true
  nameserver: [1.1.1.1]
hosts:
  own.test: 9.9.9.9
rules:
  - DOMAIN,own.test,DIRECT
  - MATCH,sel
";

const ADS: &str = "\
#!name=Ads
[General]
dns-server = %INSERT% 8.8.8.8
skip-proxy = %APPEND% bypass.test
[Rule]
DOMAIN,ad.test,REJECT-TINYGIF,extended-matching
URL-REGEX,^https://a\\.test/x,PROXY
DOMAIN,b.test,Nowhere
RULE-SET,https://rules.test/ads.list,REJECT
[Host]
a.test = 1.2.3.4
[MITM]
hostname = %APPEND% a.test
[Script]
s = type=http-response,pattern=^https://a\\.test,script-path=https://cdn.test/s.js
";

fn indented(text: &str) -> String {
    text.lines()
        .map(|line| format!("        {line}\n"))
        .collect()
}

fn profile(modules: &str, texts: ModuleTexts) -> Profile {
    let text = format!(
        "{BASE}mitm:\n  enable: true\n  hostname: [own.test]\n  module-policy: {{PROXY: sel}}\n  modules:\n{modules}"
    );
    let options = LoadOptions {
        modules: texts,
        ..LoadOptions::default()
    };
    load_str(&text, &options).unwrap()
}

fn inline(name: &str, text: &str) -> String {
    format!("    - name: {name}\n      text: |\n{}", indented(text))
}

#[test]
fn a_module_rule_goes_ahead_of_the_profiles_with_its_policy_mapped() {
    let profile = profile(&inline("ads", ADS), BTreeMap::new());
    let rules: Vec<&str> = profile.rules.iter().collect();
    let set = rules
        .iter()
        .find_map(|rule| rule.strip_prefix("RULE-SET,"))
        .and_then(|rest| rest.split(',').next())
        .unwrap();
    assert_eq!(
        rules,
        [
            "DOMAIN,ad.test,REJECT-TINYGIF,extended-matching",
            r"URL-REGEX,^https://a\.test/x,sel",
            &format!("RULE-SET,{set},REJECT"),
            "DOMAIN,own.test,DIRECT",
            "MATCH,sel",
        ]
    );
    let module = &profile.modules[0];
    assert_eq!(module.refused_rules.len(), 1);
    assert_eq!(module.refused_rules[0].line, 8);
    assert!(
        module.refused_rules[0].detail.contains("Nowhere"),
        "{:?}",
        module.refused_rules
    );
    let provider = profile
        .rule_providers
        .iter()
        .find(|provider| provider.name == set)
        .unwrap();
    assert!(matches!(
        &provider.source,
        crate::provider::RuleSource::Http(http) if http.url == "https://rules.test/ads.list"
    ));
}

#[test]
fn a_module_edits_dns_and_hosts_and_leaves_routes_to_the_host() {
    let profile = profile(&inline("ads", ADS), BTreeMap::new());
    let servers: Vec<String> = profile
        .dns
        .nameserver
        .iter()
        .map(|server| server.text.clone())
        .collect();
    assert_eq!(servers.len(), 2, "{servers:?}");
    assert!(servers[0].contains("8.8.8.8"), "{servers:?}");
    assert!(profile.hosts.lookup("a.test").is_some());
    assert!(profile.hosts.lookup("own.test").is_some());
    let host = host_network(&profile.modules);
    assert_eq!(host.bypass_domain.unwrap().after, ["bypass.test"]);
    assert!(host.nameserver.is_none());
}

#[test]
fn a_module_that_cannot_be_read_or_is_named_twice_takes_no_effect() {
    let modules = format!(
        "    - {{name: gone, path: modules/gone.txt}}\n{}{}    - {{name: none}}\n",
        inline("ads", ADS),
        inline("ads", "[Rule]\nDOMAIN,twice.test,REJECT\n"),
    );
    let texts = BTreeMap::from([(
        "gone".to_string(),
        Err(Unreadable("no such file".to_string())),
    )]);
    let profile = profile(&modules, texts);
    let problems: Vec<_> = profile
        .modules
        .iter()
        .map(|module| (module.spec.name.as_str(), module.problem.clone()))
        .collect();
    assert_eq!(
        problems,
        [
            (
                "gone",
                Some(ModuleProblem::Unreadable {
                    detail: "no such file".into()
                })
            ),
            ("ads", None),
            ("ads", Some(ModuleProblem::Duplicate)),
            (
                "none",
                Some(ModuleProblem::Unreadable {
                    detail: "neither path nor text is given".into()
                })
            ),
        ]
    );
    assert!(!profile.rules.iter().any(|rule| rule.contains("twice.test")));
}

#[test]
fn a_module_its_requirement_turns_off_is_not_merged() {
    let text = "#!requirement=CORE_VERSION < 1\n[Rule]\nDOMAIN,off.test,REJECT\n";
    let profile = profile(&inline("off", text), BTreeMap::new());
    assert!(profile.modules[0].def.off.is_some());
    assert!(!profile.rules.iter().any(|rule| rule.contains("off.test")));
}

#[test]
fn a_module_turned_off_is_read_and_adds_nothing() {
    let modules = inline("ads", ADS).replacen("\n", "\n      enabled: false\n", 1);
    let profile = profile(&modules, BTreeMap::new());
    let module = &profile.modules[0];
    assert!(!module.spec.enabled && !module.in_force());
    assert_eq!(module.def.resources[0].url, "https://cdn.test/s.js");
    assert!(!profile.rules.iter().any(|rule| rule.contains("ad.test")));
    assert!(profile.hosts.lookup("a.test").is_none());
    assert_eq!(profile.dns.nameserver.len(), 1);
    let section = compose(&profile.mitm, &profile.modules, |_| None);
    assert!(section.script.is_empty());
    assert!(profile.mitm.modules_listed);
}

#[test]
fn a_composed_line_names_its_module_by_its_name_and_the_hosts() {
    let modules = format!("{}{}", inline("ads", ADS), inline("Ads", ADS));
    let profile = profile(&modules, BTreeMap::new());
    let section = compose(&profile.mitm, &profile.modules, |_| None);
    let origins: Vec<_> = section
        .hostname
        .iter()
        .map(|line| line.origin.as_deref())
        .collect();
    assert_eq!(origins, [None, Some("Ads (ads)"), Some("Ads")]);
}

#[test]
fn a_section_without_a_module_list_is_not_listed() {
    let options = LoadOptions::default();
    let empty = load_str(
        &format!("{BASE}mitm:\n  enable: true\n  modules: []\n"),
        &options,
    );
    assert!(empty.unwrap().mitm.modules_listed);
    let absent = load_str(&format!("{BASE}mitm:\n  enable: true\n"), &options);
    assert!(!absent.unwrap().mitm.modules_listed);
}

#[test]
fn a_module_read_from_its_path_takes_the_text_the_engine_read() {
    let texts = BTreeMap::from([("ads".to_string(), Ok(ADS.to_string()))]);
    let profile = profile("    - {name: ads, path: modules/ads.txt}\n", texts);
    assert!(profile.modules[0].in_force());
    let mitm_warnings: Vec<_> = profile
        .report
        .warnings
        .iter()
        .filter(|warning| warning.path.starts_with("mitm"))
        .collect();
    assert!(mitm_warnings.is_empty(), "{mitm_warnings:?}");
    assert_eq!(
        profile.rules.iter().next(),
        Some("DOMAIN,ad.test,REJECT-TINYGIF,extended-matching")
    );
}

#[test]
fn the_section_in_force_follows_the_profiles_lines_with_stored_files() {
    let modules = format!(
        "{}{}",
        inline("ads", ADS),
        inline("first", "[MITM]\nhostname = %INSERT% first.test\n")
    );
    let profile = profile(&modules, BTreeMap::new());
    let hosts = |section: &MitmDef| -> Vec<String> {
        section
            .hostname
            .iter()
            .map(|line| line.text.clone())
            .collect()
    };
    let stored = |url: &str| (url == "https://cdn.test/s.js").then(|| "abc.js".to_string());
    let section = compose(&profile.mitm, &profile.modules, stored);
    assert_eq!(
        hosts(&section),
        [
            "own.test",
            "hostname = %INSERT% first.test",
            "hostname = %APPEND% a.test"
        ]
    );
    let script = section.script[0].read.as_ref().unwrap();
    assert_eq!(script.path, "abc.js");
    let missing = compose(&profile.mitm, &profile.modules, |_| None);
    assert_eq!(
        missing.script[0].read.as_ref().unwrap().path,
        "https://cdn.test/s.js"
    );
}

#[test]
fn a_stored_file_is_named_by_its_content_and_keeps_its_extension() {
    let name = stored_name("https://cdn.test/a/b.js?v=2#x", b"body");
    assert_eq!(name, "230d8358dc8e8890b4c58deeb62912ee.js");
    assert_eq!(stored_name("https://cdn.test/a/b.js", b"body"), name);
    assert_eq!(
        stored_name("https://cdn.test/a/b", b"body"),
        "230d8358dc8e8890b4c58deeb62912ee"
    );
    assert_eq!(
        stored_name("https://cdn.test/a.b/c.toolongext", b"body"),
        "230d8358dc8e8890b4c58deeb62912ee"
    );
    assert_ne!(stored_name("https://cdn.test/b.js", b"other"), name);
}

#[test]
fn h2_from_any_module_turns_it_on() {
    let off = "[MITM]\nh2 = false\n";
    let both = profile(
        &format!(
            "{}{}",
            inline("off", off),
            inline("on", "[MITM]\nh2 = true\n")
        ),
        BTreeMap::new(),
    );
    assert!(!both.mitm.h2);
    assert!(compose(&both.mitm, &both.modules, |_| None).h2);
    let alone = profile(&inline("off", off), BTreeMap::new());
    assert!(!compose(&alone.mitm, &alone.modules, |_| None).h2);
}

#[test]
fn an_inline_rule_set_of_one_name_gathers_its_lines_from_every_module() {
    let modules = format!(
        "{}{}",
        inline(
            "a",
            "[Ruleset Ads]\nDOMAIN,a.com\n[Rule]\nRULE-SET,Ads,REJECT\n"
        ),
        inline("b", "[Ruleset Ads]\nDOMAIN,b.com\n"),
    );
    let loaded = profile(&modules, BTreeMap::new());
    let [provider] = loaded.rule_providers.as_slice() else {
        panic!("{:?}", loaded.rule_providers);
    };
    assert!(provider.name.starts_with("mitm-"), "{}", provider.name);
    assert_eq!(
        provider.raw["payload"],
        json!(["DOMAIN,a.com", "DOMAIN,b.com"])
    );
    let rule = format!("RULE-SET,{},REJECT", provider.name);
    assert_eq!(loaded.rules.iter().next(), Some(rule.as_str()));
}

#[test]
fn later_modules_go_over_earlier_ones() {
    let modules = format!(
        "{}{}",
        inline("first", "[General]\ndns-server = 1.1.1.1\nskip-proxy = a\n"),
        inline(
            "second",
            "[General]\ndns-server = 8.8.8.8\nskip-proxy = b\n"
        ),
    );
    let loaded = profile(&modules, BTreeMap::new());
    let servers: Vec<&str> = loaded
        .dns
        .nameserver
        .iter()
        .map(|server| server.text.as_str())
        .collect();
    assert_eq!(servers, ["8.8.8.8"]);
    assert_eq!(
        host_network(&loaded.modules).bypass_domain,
        Some(ListEdit {
            replace: true,
            before: vec!["b".to_string()],
            after: Vec::new(),
        })
    );
}

#[test]
fn the_system_resolver_a_host_appends_comes_after_the_modules() {
    let servers = |text: &str| -> Vec<String> {
        let loaded = load_str(text, &LoadOptions::default()).unwrap();
        loaded
            .dns
            .nameserver
            .iter()
            .map(|server| server.text.clone())
            .collect()
    };
    let base = BASE.replace(
        "  nameserver: [1.1.1.1]\n",
        "  nameserver: [1.1.1.1]\n  append-system: true\n",
    );
    let replacing = format!(
        "{base}mitm:\n  enable: true\n  modules:\n{}",
        inline("dns", "[General]\ndns-server = 8.8.8.8\n")
    );
    assert_eq!(servers(&replacing), ["8.8.8.8", "system://"]);
    assert_eq!(servers(&base), ["1.1.1.1", "system://"]);
    let named = base.replace("[1.1.1.1]", "[system, 1.1.1.1]");
    assert_eq!(servers(&named), ["system", "1.1.1.1"]);
    assert_eq!(servers(BASE), ["1.1.1.1"]);
}

#[test]
fn a_script_rule_needs_a_rule_script_the_profile_or_a_module_declares() {
    let module = "\
#!name=Pick
[Rule]
SCRIPT,pick,PROXY,requires-resolve
SCRIPT,own,DIRECT
SCRIPT,nowhere,REJECT
[Script]
pick = type=rule,script-path=https://cdn.test/pick.js
";
    let text = format!(
        "{BASE}mitm:\n  enable: true\n  module-policy: {{PROXY: sel}}\n  \
         script: ['own = type=rule,script-path=own.js']\n  modules:\n{}",
        inline("pick", module)
    )
    .replace("  - MATCH,sel\n", "  - SCRIPT,gone,DIRECT\n  - MATCH,sel\n");
    let profile = load_str(&text, &LoadOptions::default()).unwrap();
    let rules: Vec<&str> = profile.rules.iter().collect();
    assert_eq!(
        rules,
        [
            "SCRIPT,pick,sel,requires-resolve",
            "SCRIPT,own,DIRECT",
            "DOMAIN,own.test,DIRECT",
            "SCRIPT,gone,DIRECT",
            "MATCH,sel",
        ]
    );
    let refused = &profile.modules[0].refused_rules;
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0].line, 5);
    assert!(refused[0].detail.contains("nowhere"), "{refused:?}");
    let warned = profile
        .report
        .warnings
        .iter()
        .find(|warning| warning.code == "rule_unknown_script")
        .unwrap();
    assert_eq!(warned.path, "rules[1]");
}

#[test]
fn a_host_answered_by_a_script_needs_a_dns_script_the_profile_or_a_module_declares() {
    let module = "\
#!name=Pick
[Host]
*.pick.test = script:pick
own.test = script:own
gone.test = script:nowhere
[Script]
pick = type=dns,script-path=https://cdn.test/pick.js
";
    let text = format!(
        "{}mitm:\n  enable: true\n  module-policy: {{PROXY: sel}}\n  \
         script: ['own = type=dns,script-path=own.js']\n  modules:\n{}",
        BASE.replace(
            "  own.test: 9.9.9.9\n",
            "  mine.test: script:own\n  lost.test: script:lost\n"
        ),
        inline("pick", module)
    );
    let profile = load_str(&text, &LoadOptions::default()).unwrap();
    let script = |domain: &str| match profile.hosts.lookup(domain).map(|entry| &entry.value) {
        Some(HostValue::Script(name)) => Some(name.clone()),
        _ => None,
    };
    assert_eq!(script("a.pick.test").as_deref(), Some("pick"));
    assert_eq!(script("own.test").as_deref(), Some("own"));
    assert_eq!(script("mine.test").as_deref(), Some("own"));
    assert!(profile.hosts.lookup("gone.test").is_none());
    assert!(profile.hosts.lookup("lost.test").is_none());
    let refused = &profile.modules[0].refused_rules;
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0].line, 5);
    assert!(refused[0].detail.contains("nowhere"), "{refused:?}");
    let mut warned: Vec<&str> = profile
        .report
        .warnings
        .iter()
        .filter(|warning| warning.code == "invalid_host")
        .map(|warning| warning.path.as_str())
        .collect();
    warned.sort_unstable();
    assert_eq!(warned, ["hosts.gone.test", "hosts.lost.test"]);
}
