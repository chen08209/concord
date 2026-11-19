use std::collections::BTreeMap;

use serde_json::json;

use crate::mitm::module::{Environment, IgnoreReason, ModuleDef, ModuleInput, read_module};
use crate::mitm::{BodyActionDef, HeaderEditDef, MapLocalBody, ScriptKind, UrlAction};

fn read(text: &str, values: &[(&str, &str)]) -> ModuleDef {
    let values: BTreeMap<String, String> = values
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    let attachments = BTreeMap::new();
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

const ARGUMENTS: &str = r#"[Argument]
name = input,"Loon",type=string,tag=名称
region = select,"CN","US","JP",type=string
price = input,9.99,type=number
level = select,1,2,3,type=number
enabled = switch,true,type=boolean
note = input
"#;

#[test]
fn the_plugin_pages_script_hands_on_typed_arguments() {
    let text = format!(
        "{ARGUMENTS}[Script]\nresponse if ${{url}} ~= /^https?:\\/\\/example\\.com\\/conf/ then script(\"https://a.test/remove_ads.js\", {{${{name}}, ${{region}}, ${{price}}, ${{level}}, ${{enabled}}, ${{note}}}}) with enable=${{enabled}}, requires_body=true, tag=\"移除广告\"\n"
    );
    let def = read(&text, &[("level", "2")]);
    assert_eq!(ignored(&def), []);
    let script = def.lists.script[0].def.as_ref().unwrap();
    assert_eq!(script.kind, ScriptKind::HttpResponse);
    assert_eq!(script.name, "移除广告");
    assert!(script.requires_body);
    assert_eq!(script.timeout, Some(20.0));
    assert_eq!(
        script.argument,
        Some(
            json!({"name": "Loon", "region": "CN", "price": 9.99, "level": 2, "enabled": true, "note": null})
        )
    );
    assert_eq!(def.declared_scripts, [9]);
    let off = read(&text, &[("enabled", "false")]);
    assert_eq!(ignored(&off), [(9, IgnoreReason::Disabled)]);
}

#[test]
fn a_rewrite_decides_its_argument_tests_and_fills_typed_values() {
    let text = format!(
        "{ARGUMENTS}[Rewrite]\nresponse if ${{enabled}} == true && ${{url}} ~= /^https:\\/\\/example\\.com\\/price/ && ${{request.header['X-Region']}} == ${{region}} then response.json.replace(\"data.price\", ${{price}})\n"
    );
    let def = read(&text, &[]);
    let body = def.lists.body_rewrite[0].def.as_ref().unwrap();
    assert!(body.response);
    assert_eq!(body.pattern, r"^https:\/\/example\.com\/price");
    assert_eq!(
        body.conditions.request.as_deref(),
        Some(r"^(?=[\s\S]*\r\n(?i:X\-Region): CN\r\n)")
    );
    assert_eq!(
        body.action,
        BodyActionDef::Jq("if .data.price != null then .data.price = 9.99 else . end".into())
    );
    assert_eq!(
        ignored(&read(&text, &[("enabled", "false")])),
        [(9, IgnoreReason::Disabled)]
    );
}

#[test]
fn captures_fill_url_rewrites_and_wait_for_the_runtime_elsewhere() {
    let def = read(
        r#"[Rewrite]
request if ${url} ~= /^https:\/\/old\.test(\/.*)$/ as m then url.replace("https://new.test${m.1}?p=$")
request if ${url} ~= /^https:\/\/a\.test\/(\d+)/ as item then request.header.set("X-Item", "${item.1}")
request if ${url} ~= /a/ then request.header.add("X-UA", "${request.header['User-Agent']}")
request if ${url} ~= /a/ || ${request.method} == "POST" then reject(404)
request if ${url} ~= /(a)/ as m then url.replace("${m.2}")
"#,
        &[],
    );
    let url = def.lists.url_rewrite[0].def.as_ref().unwrap();
    assert_eq!(url.replacement, "https://new.test${1}?p=$$");
    assert_eq!(url.action, UrlAction::Header);
    assert_eq!(
        ignored(&def),
        [
            (3, IgnoreReason::RuntimeValue),
            (4, IgnoreReason::RuntimeValue),
            (5, IgnoreReason::Condition),
            (6, IgnoreReason::Unreadable),
        ]
    );
}

#[test]
fn actions_become_concord_definitions() {
    let def = read(
        r#"[Rewrite]
request if ${request.header['X-Optional']} == null then reject(451, "gone")
request if ${url} ~= /api/ then request.header.set(["X-A", "X-B"], ["1", "2"])
response if ${url} ~= /api/ then response.json.delete(["$.data.ads", "data.apps[0].name"])
response if ${url} ~= /api/ then response.body.mock_file("png", "https://cdn.test/a.base64", 200, true) | response.header.set("X-M", "1")
request if ${url} ~= /ad/ then reject_dict(200) | reject_video(204)
"#,
        &[],
    );
    assert_eq!(ignored(&def), []);
    let local = def.lists.map_local[0].def.as_ref().unwrap();
    assert_eq!(local.status.as_u16(), 451);
    assert_eq!(local.data, "gone");
    assert_eq!(
        local.conditions.request.as_deref(),
        Some(r"^(?![\s\S]*\r\n(?i:X\-Optional):)")
    );
    let edits: Vec<&HeaderEditDef> = def
        .lists
        .header_rewrite
        .iter()
        .map(|line| &line.def.as_ref().unwrap().edit)
        .collect();
    assert_eq!(edits.len(), 6);
    assert!(matches!(edits[0], HeaderEditDef::Del(name) if name == "x-a"));
    assert!(matches!(edits[1], HeaderEditDef::Add(name, value) if name == "x-a" && value == "1"));
    let jq = &def.lists.body_rewrite[0].def.as_ref().unwrap().action;
    assert_eq!(
        *jq,
        BodyActionDef::Jq("del(.data.ads, .data.apps[0].name)".into())
    );
    let mock = def.lists.map_local[1].def.as_ref().unwrap();
    assert_eq!(mock.body, MapLocalBody::File { base64: true });
    assert_eq!(mock.data, "https://cdn.test/a.base64");
    assert_eq!(def.resources[0].url, "https://cdn.test/a.base64");
    assert_eq!(
        def.lists.url_rewrite[0].def.as_ref().unwrap().action,
        UrlAction::RejectDict
    );
    let video = def.lists.map_local[2].def.as_ref().unwrap();
    assert_eq!(
        (video.status.as_u16(), video.content_type),
        (204, "video/mp4")
    );
}

#[test]
fn legacy_lines_spread_over_concord_lists() {
    let def = read(
        r#"#!name=Legacy
[Argument]
region = select,"CN","US"
[Rewrite]
^http://a\.test header-del Cookie Connection
^http://a\.test response-header-replace-regex A x y B z w
^http://a\.test response-body-json-add data.apps[0] {"appName":"loon"} data.category tool\x20x
^http://a\.test mock-response-body data-type=json data="{}" status-code=201
^http://a\.test reject-video
[Remote Rule]
https://rules.test/a.list,PROXY,tag=t
https://rules.test/b.list, policy=REJECT, enabled=false
[Script]
http-response ^https://a\.test/x script-path=https://a.test/s.js, argument=[{region}], tag=s
"#,
        &[],
    );
    assert_eq!(ignored(&def), [(12, IgnoreReason::Disabled)]);
    assert_eq!(def.lists.header_rewrite.len(), 4);
    let jq = &def.lists.body_rewrite[0].def.as_ref().unwrap().action;
    assert_eq!(
        *jq,
        BodyActionDef::Jq(
            r#".data.apps[0] = {"appName":"loon"} | .data.category = "tool x""#.into()
        )
    );
    let mock = def.lists.map_local[0].def.as_ref().unwrap();
    assert_eq!(
        (mock.status.as_u16(), mock.content_type, mock.data.as_str()),
        (201, "application/json", "{}")
    );
    assert_eq!(
        def.rules[0].def.rule,
        format!("RULE-SET,{}", def.rule_sets[0].name)
    );
    let script = def.lists.script[0].def.as_ref().unwrap();
    assert_eq!(script.pattern.as_deref(), Some("(?i)^https://a\\.test/x"));
    assert_eq!(script.argument, Some(json!({"region": "CN"})));
}

#[test]
fn a_surge_map_local_reads_json_as_text() {
    let def = read(
        "[Map Local]\n^https://a\\.test data-type=json data=\"{}\"\n",
        &[],
    );
    let local = def.lists.map_local[0].def.as_ref().unwrap();
    assert_eq!(
        (&local.body, local.content_type),
        (&MapLocalBody::Text, "application/json")
    );
}
