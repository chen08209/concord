use std::collections::BTreeMap;

use serde_json::json;

use crate::mitm::module::{
    Environment, IgnoreReason, InlineFile, ModuleDef, ModuleFormat, ModuleInput, read_module,
};
use crate::mitm::modules::stored_name;
use crate::mitm::{BodyActionDef, HeaderEditDef, MapLocalBody, ScriptKind, UrlAction};

fn read(text: &str, values: &[(&str, &str)]) -> ModuleDef {
    let values: BTreeMap<String, String> = values
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    let attachments = BTreeMap::from([("local.js".to_string(), "f0.js".to_string())]);
    let environment = Environment {
        system: String::new(),
        language: String::new(),
    };
    read_module(
        text,
        &ModuleInput {
            arguments: &values,
            attachments: &attachments,
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

#[test]
fn a_quantumult_x_snippet_reads_without_sections() {
    let def = read(
        r#"hostname = a.test, *.b.test
^https://a\.test/ad url reject-dict
^https://a\.test/old url 302 https://a.test/new
^https://a\.test/h url request-header ^GET /h HTTP/1\.1(\r\n) request-header GET /i HTTP/1.1$1
^https://a\.test/b url response-body "ad":true response-body "ad":false
^https://a\.test/j url jsonjq-response-body '.data |= {}'
^https://a\.test/e url echo-response text/html\r\nX-A: 1 echo-response https://cdn.test/e.html
^https://a\.test/s \r\nUser-Agent: app url-and-header script-response-body https://cdn.test/s.js
^https://a\.test/u ^POST url-and-header reject
host-suffix, ad.test, reject, force-cellular
final, proxy
10 8 * * * https://cdn.test/task.js, tag=Daily, img-url=https://cdn.test/i.png
event-network local.js
event-interaction https://cdn.test/i.js, enabled=false
"#,
        &[],
    );
    assert_eq!(def.format, ModuleFormat::QuantumultX);
    assert_eq!(
        ignored(&def),
        [(11, IgnoreReason::FinalRule), (14, IgnoreReason::Disabled)]
    );
    let urls: Vec<_> = def
        .lists
        .url_rewrite
        .iter()
        .map(|line| line.def.as_ref().unwrap())
        .collect();
    assert_eq!(urls[0].action, UrlAction::RejectDict);
    assert_eq!(
        (urls[1].action, urls[1].replacement.as_str()),
        (UrlAction::Redirect302, "https://a.test/new")
    );
    assert_eq!(urls[2].head.as_deref(), Some("^POST"));
    let head = def.lists.header_rewrite[0].def.as_ref().unwrap();
    assert_eq!(
        head.edit,
        HeaderEditDef::Text(
            r"^GET /h HTTP/1\.1(\r\n)".into(),
            "GET /i HTTP/1.1$1".into()
        )
    );
    let bodies: Vec<_> = def
        .lists
        .body_rewrite
        .iter()
        .map(|line| &line.def.as_ref().unwrap().action)
        .collect();
    assert_eq!(
        *bodies[0],
        BodyActionDef::Replace(vec![(r#""ad":true"#.into(), r#""ad":false"#.into())])
    );
    assert_eq!(*bodies[1], BodyActionDef::Jq(".data |= {}".into()));
    let echo = def.lists.map_local[0].def.as_ref().unwrap();
    assert_eq!(echo.body, MapLocalBody::File { base64: false });
    assert_eq!(
        (
            echo.header["content-type"].to_str().unwrap(),
            echo.header["x-a"].to_str().unwrap()
        ),
        ("text/html", "1")
    );
    let scripts: Vec<_> = def
        .lists
        .script
        .iter()
        .map(|line| line.def.as_ref().unwrap())
        .collect();
    assert_eq!(
        scripts[0].conditions.request.as_deref(),
        Some(r"\r\nUser-Agent: app")
    );
    assert!(scripts[0].requires_body && scripts[0].kind == ScriptKind::HttpResponse);
    assert_eq!(
        (
            scripts[1].kind,
            scripts[1].cronexp.as_str(),
            scripts[1].name.as_str()
        ),
        (ScriptKind::Cron, "10 8 * * *", "Daily")
    );
    assert_eq!(
        (scripts[2].kind, scripts[2].path.as_str()),
        (ScriptKind::Event, "f0.js")
    );
    assert_eq!(def.declared_scripts, [8, 12, 13, 14]);
    assert_eq!(def.rules[0].def.rule, "DOMAIN-SUFFIX,ad.test");
}

#[test]
fn quantumult_x_mitm_keys_read_as_their_counterparts() {
    let def = read(
        "[mitm]\nhostname = a.test\nskip_validating_cert = true\nskip_src_ip = 192.168.1.5\nskip_dst_ip = 17.0.0.1\np12 = x\n",
        &[],
    );
    assert_eq!(
        ignored(&def),
        [(5, IgnoreReason::Setting), (6, IgnoreReason::ManagedCa)]
    );
    assert!(def.lists.skip_server_cert_verify.is_some());
    let source = &def.lists.client_source_address[0].def.items[0];
    assert!(source.exclude);
}

const OVERRIDE: &str = r#"name: Test
desc: A ${args.region} override
arguments-version: 1
arguments:
  region:
    type: select
    title: Region
    default: HK
    options:
      - value: HK
      - value: JP
  on:
    type: switch
    title: On
    default: true
http:
  mitm:
    - a.test
    - "b.test:*"
    - c.test:8443
  force-http-engine:
    - "*:4480"
  url-rewrite:
    - ^http://g\.cn https://www.google.com transparent
    - ^https?://ad\.example - reject
  header-rewrite:
    - ^http://g\.cn request-replace-regex User-Agent Go-http-client curl
  body-rewrite:
    - '^https://api\.example\.com/ response-replace-regex old new disabled enabled'
    - '^https://api\.example\.com/ response-json-add meta.source "${args.region}" meta.version 1'
    - '^https://api\.example\.com/ response-json-del $.debug'
  mock:
    - match: ^https?://example.stash\.ws/base64
      base64: 'CgVUZXJyeQ=='
      status-code: 201
      headers:
        Content-Type: application/x-protobuf
  script:
    - match: ^https://a\.test/
      name: s
      type: response
      require-body: '${args.on}'
      timeout: 10
      argument: '{"region":${args.region|json},"on":${args.on|json},"raw":"$${args.region}"}'
    - match: ^https://a\.test/
      name: inline
      type: request
  ca: ''
cron:
  script:
    - name: s
      cron: '*/5 * * * *'
script-providers:
  s:
    url: https://cdn.test/s.js
    interval: 86400
  inline:
    payload: |
      $done();
rules:
  - DOMAIN-SUFFIX,ad.test,REJECT
  - RULE-SET,extra,DIRECT
rule-providers:
  extra:
    type: inline
    behavior: classical
    payload:
      - DOMAIN,x.test
  cidr:
    behavior: ipcidr
    url: https://cdn.test/c.txt
dns:
  nameserver: #!replace
    - 1.1.1.1
hosts:
  router.test: 192.168.1.1
tiles:
  - name: t
"#;

#[test]
fn a_stash_script_payload_is_written_out_by_its_content() {
    let def = read(OVERRIDE, &[]);
    let file = stored_name("inline.js", b"$done();\n");
    let script = def
        .lists
        .script
        .iter()
        .find(|line| line.line == 45)
        .and_then(|line| line.def.as_ref().ok())
        .unwrap();
    assert_eq!(script.kind, ScriptKind::HttpRequest);
    assert_eq!(script.path, file);
    assert_eq!(
        def.inline_files,
        [InlineFile {
            file,
            content: "$done();\n".into(),
        }]
    );
    assert!(def.declared_scripts.contains(&45));
    assert!(
        def.resources
            .iter()
            .all(|resource| resource.url != "inline.js")
    );
}

#[test]
fn a_stash_script_reads_its_attached_file() {
    let def = read(
        "name: Local\nhttp:\n  script:\n    - match: ^https://a\\.test/\n      name: own\n      type: response\nscript-providers:\n  own:\n    path: local.js\n",
        &[],
    );
    assert_eq!(ignored(&def), []);
    assert_eq!(def.lists.script[0].def.as_ref().unwrap().path, "f0.js");
}

#[test]
fn a_stash_override_reads_with_its_arguments() {
    let def = read(OVERRIDE, &[("region", "JP")]);
    assert_eq!(def.format, ModuleFormat::Stash);
    assert_eq!(def.meta.desc.as_deref(), Some("A ${args.region} override"));
    assert_eq!(
        ignored(&def),
        [
            (48, IgnoreReason::ManagedCa),
            (69, IgnoreReason::RuleType),
            (77, IgnoreReason::AppOnly),
        ]
    );
    let hosts: Vec<_> = def
        .lists
        .hostname
        .iter()
        .map(|line| {
            let entry = &line.def.items.items[0];
            (line.line, entry.pattern.as_str(), entry.port, entry.bare)
        })
        .collect();
    assert_eq!(
        hosts,
        [
            (18, "a.test", 443, false),
            (19, "b.test", 0, false),
            (20, "c.test", 8443, false)
        ]
    );
    assert_eq!(def.lists.force_http_hostname[0].line, 22);
    let urls: Vec<_> = def
        .lists
        .url_rewrite
        .iter()
        .map(|line| line.def.as_ref().unwrap())
        .collect();
    assert_eq!(
        (urls[0].action, urls[1].action),
        (UrlAction::Header, UrlAction::Reject)
    );
    let bodies: Vec<_> = def
        .lists
        .body_rewrite
        .iter()
        .map(|line| &line.def.as_ref().unwrap().action)
        .collect();
    assert_eq!(
        *bodies[0],
        BodyActionDef::Replace(vec![
            ("old".into(), "new".into()),
            ("disabled".into(), "enabled".into())
        ])
    );
    assert_eq!(
        *bodies[1],
        BodyActionDef::Jq(
            r#"if .meta.source == null then .meta.source = "JP" else . end | if .meta.version == null then .meta.version = 1 else . end"#.into()
        )
    );
    assert_eq!(
        *bodies[2],
        BodyActionDef::Jq(
            "if (.debug | . != null and . != false) then del(.debug) else . end".into()
        )
    );
    let mock = def.lists.map_local[0].def.as_ref().unwrap();
    assert_eq!(
        (
            mock.status.as_u16(),
            mock.header["content-type"].to_str().unwrap()
        ),
        (201, "application/x-protobuf")
    );
    let script = |line: u32| {
        def.lists
            .script
            .iter()
            .find(|each| each.line == line)
            .and_then(|each| each.def.as_ref().ok())
            .unwrap()
    };
    assert!(script(39).requires_body);
    assert_eq!(
        script(39).argument,
        Some(json!(r#"{"region":"JP","on":true,"raw":"${args.region}"}"#))
    );
    assert_eq!(
        (script(51).kind, script(51).cronexp.as_str()),
        (ScriptKind::Cron, "*/5 * * * *")
    );
    assert_eq!(def.declared_scripts, [39, 45, 51]);
    assert_eq!(def.rules.len(), 2);
    assert_eq!(def.rule_sets.len(), 1);
    let nameserver = def.network.nameserver.as_ref().unwrap();
    assert!(nameserver.replace);
    assert_eq!(def.network.hosts[0].domain, "router.test");
}

#[test]
fn a_profile_like_yaml_without_override_keys_reads_as_surge() {
    assert_eq!(read("name: x\n", &[]).format, ModuleFormat::Surge);
}
