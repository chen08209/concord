use std::collections::BTreeMap;

use http::header::HeaderName;

use crate::mitm::module::{
    Environment, IgnoreReason, ModuleDef, ModuleInput, ModuleLists, read_module,
};
use crate::mitm::{BodyActionDef, HeaderEditDef, ScriptKind};

fn read(text: &str) -> ModuleDef {
    let none = BTreeMap::new();
    let environment = Environment {
        system: String::new(),
        language: String::new(),
    };
    read_module(
        text,
        &ModuleInput {
            arguments: &none,
            attachments: &none,
            environment: &environment,
        },
    )
}

fn ignored(def: &ModuleDef) -> Vec<(u32, IgnoreReason)> {
    def.ignored
        .iter()
        .map(|line| (line.line, line.reason))
        .collect()
}

fn skipped(def: &ModuleDef) -> Option<Vec<&str>> {
    def.lists.skip_server_cert_verify.as_ref().map(|line| {
        line.def
            .iter()
            .map(|entry| entry.pattern.as_str())
            .collect()
    })
}

#[test]
fn mitm_settings_turn_on_h2_and_leave_the_ca_to_the_host() {
    let def = read(
        "[MITM]\nhostname = a.example.com\nh2 = true\nca-p12 = MIIJ...\nca-passphrase = secret\ntcp-connection = true\n",
    );
    assert_eq!(def.lists.h2, Some(3));
    assert_eq!(
        ignored(&def),
        [
            (4, IgnoreReason::ManagedCa),
            (5, IgnoreReason::ManagedCa),
            (6, IgnoreReason::Setting)
        ]
    );
    assert_eq!(read("[MITM]\nh2 = false\n").lists.h2, None);
}

#[test]
fn a_module_skips_verifying_only_its_own_hostnames() {
    let own = read(
        "[MITM]\nhostname = %APPEND% api.example.com, *.ads.test, -skip.test\nskip-server-cert-verify = true\nclient-source-address = %APPEND% -192.168.1.2, 192.168.1.0/24\n",
    );
    assert_eq!(skipped(&own), Some(vec!["api.example.com", "*.ads.test"]));
    let sources: Vec<(String, bool)> = own.lists.client_source_address[0]
        .def
        .items
        .iter()
        .map(|entry| (entry.network.to_string(), entry.exclude))
        .collect();
    assert_eq!(
        sources,
        [
            ("192.168.1.2/32".to_string(), true),
            ("192.168.1.0/24".to_string(), false)
        ]
    );
    assert!(own.asks_consent());
    assert_eq!(ignored(&own), []);

    let all =
        read("[MITM]\nhostname = %APPEND% *, api.example.com\nskip-server-cert-verify = true\n");
    assert_eq!(skipped(&all), Some(vec!["api.example.com"]));
    assert_eq!(ignored(&all), [(3, IgnoreReason::SkipVerifyAll)]);

    let off =
        read("[MITM]\nhostname = %APPEND% api.example.com\nskip-server-cert-verify = false\n");
    assert_eq!(skipped(&off), None);
    assert!(!off.asks_consent());
}

#[test]
fn surge_header_and_body_rewrites_pass_on_jq_included() {
    let def = read(
        r#"#!name=Ads
[Header Rewrite]
http-request ^https://example\.com header-del Cookie

[Body Rewrite]
http-response ^https://example\.com/api "ad":true "ad":false
http-response-jq ^https://example\.com/api 'del(.ad)'
"#,
    );
    assert_eq!(ignored(&def), []);
    let header = def.lists.header_rewrite[0].def.as_ref().unwrap();
    assert_eq!(
        (header.response, header.pattern.as_str(), &header.edit),
        (
            false,
            r"^https://example\.com",
            &HeaderEditDef::Del(HeaderName::from_static("cookie"))
        )
    );
    let bodies: Vec<_> = def
        .lists
        .body_rewrite
        .iter()
        .map(|line| {
            let body = line.def.as_ref().unwrap();
            (line.line, body.response, body.action.clone())
        })
        .collect();
    assert_eq!(
        bodies,
        [
            (
                6,
                true,
                BodyActionDef::Replace(vec![(r#""ad":true"#.into(), r#""ad":false"#.into())])
            ),
            (7, true, BodyActionDef::Jq("del(.ad)".into())),
        ]
    );
}

#[test]
fn a_script_line_an_argument_fills_in_whole_still_asks_for_consent() {
    let def = read(
        "#!arguments=Line:http-request ^https://a script-path=https://cdn.test/a.js\n[Script]\n{{{Line}}}\n",
    );
    let script = def.lists.script[0].def.as_ref().unwrap();
    assert_eq!(script.kind, ScriptKind::HttpRequest);
    assert_eq!(def.declared_scripts, [3]);
}

#[test]
fn a_placeholder_in_a_script_of_a_type_not_run_declares_nothing() {
    let def = read(
        "#!arguments=Line:http-request ^https://a script-path=https://cdn.test/a.js\n[Script]\nA = type=dhcp,x={{{Line}}}\n",
    );
    assert!(def.lists.script[0].def.is_err());
    assert!(def.declared_scripts.is_empty());
}

#[test]
fn text_without_a_section_is_not_a_module() {
    let def = read("#!name=Nothing\nhello");
    assert_eq!(def.lists, ModuleLists::default());
    assert!(def.rules.is_empty() && def.rule_sets.is_empty() && def.resources.is_empty());
    assert!(def.network.is_empty() && def.declared_scripts.is_empty());
    assert_eq!(ignored(&def), [(2, IgnoreReason::Section)]);
}

#[test]
fn a_redirect_to_the_gateway_waits_on_a_value_only_the_network_knows() {
    let def = read(
        "#!name=Gate\n[URL Rewrite]\n^http://a\\.test/ http://{{{GATEWAY_ADDRESS}}}/ 302\n^http://b\\.test/ http://c.test/ 302\n",
    );
    assert_eq!(ignored(&def), [(3, IgnoreReason::RuntimeValue)]);
    assert_eq!(def.lists.url_rewrite.len(), 1);
}

#[test]
fn hostname_disabled_reads_as_a_list_of_its_own() {
    let def = read(
        "#!name=Off\n[MITM]\nhostname = %APPEND% a.test, b.test\nhostname-disabled = %APPEND% b.test\n",
    );
    assert!(ignored(&def).is_empty(), "{:?}", def.ignored);
    let section = def.section("");
    let disabled: Vec<&str> = section.hostname_disabled[0]
        .read
        .items
        .iter()
        .map(|entry| entry.pattern.as_str())
        .collect();
    assert_eq!(disabled, ["b.test"]);
}
