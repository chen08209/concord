use std::collections::BTreeMap;

use serde_json::json;

use http::header::{HeaderName, HeaderValue};

use crate::mitm::module::{
    Environment, IgnoreReason, ListEdit, ModuleDef, ModuleInput, read_module,
};
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
fn a_request_script_hands_on_the_arguments_it_names() {
    let text = format!(
        "{ARGUMENTS}[Script]\nrequest if ${{url}} ~= /^https?:\\/\\/a\\.com\\/c\\?cmd=\\d+/i then script(\"https://a.test/s.js\", {{${{region}}, ${{level}}, ${{note}}}}) with tag=\"Proto\", timeout=10\n"
    );
    let def = read(&text, &[("region", "US")]);
    assert_eq!(ignored(&def), []);
    let script = def.lists.script[0].def.as_ref().unwrap();
    assert_eq!(script.kind, ScriptKind::HttpRequest);
    assert_eq!(script.name, "Proto");
    assert_eq!(
        script.argument,
        Some(json!({"region": "US", "level": 1, "note": null}))
    );
    assert_eq!(def.declared_scripts, [9]);
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

const STATUS_200: &str = r"^(?=\S+ 200(?: |\r\n))";
const POST: &str = "^(?=POST )";

#[test]
fn mock_request_body_answers_with_its_data() {
    let def = read(
        r#"[Rewrite]
^https?://api\.example\.com/log mock-request-body data-type=json data="{\"a\":1}" status-code=200
"#,
        &[],
    );
    assert_eq!(ignored(&def), []);
    assert!(def.lists.map_local.is_empty());
    let mock = def.lists.request_body_mock[0].def.as_ref().unwrap();
    assert_eq!(
        (
            mock.pattern.as_str(),
            &mock.body,
            mock.data.as_str(),
            mock.request
        ),
        (
            r"^https?://api\.example\.com/log",
            &MapLocalBody::Text,
            r#"{"a":1}"#,
            true
        )
    );
    assert_eq!(
        mock.header["content-type"].to_str().unwrap(),
        "application/json"
    );
}

#[test]
fn a_plugin_adds_its_dns_servers_routes_and_real_ip_domains() {
    let def = read(
        "[General]\ndns-server = 119.29.29.29\ndoh-server = https://doh.pub/dns-query\nbypass-tun = 10.0.0.0/8\ninclude-tun = 172.16.0.0/12\nreal-ip = *.lan\n\n[Rewrite]\n^https://a\\.com/ad reject\n",
        &[],
    );
    let appended = |items: &[&str]| {
        Some(ListEdit {
            after: items.iter().map(|item| item.to_string()).collect(),
            ..ListEdit::default()
        })
    };
    let network = &def.network;
    assert_eq!(
        network.nameserver,
        appended(&["119.29.29.29", "https://doh.pub/dns-query"])
    );
    assert_eq!(network.default_nameserver, None);
    assert_eq!(network.route_exclude_address, appended(&["10.0.0.0/8"]));
    assert_eq!(network.route_address, ["172.16.0.0/12"]);
    assert_eq!(network.fake_ip_filter, appended(&["*.lan"]));
    assert_eq!(network.lines, [2, 3, 4, 5, 6]);
    assert_eq!(def.lists.url_rewrite.len(), 1);
}

#[test]
fn a_rewrite_tests_the_status_and_both_heads_of_a_response() {
    let def = read(
        r#"[Rewrite]
response if ${url} ~= /^https:\/\/api\.example\.com\/profile$/ && ${response.status} == 200 then response.json.replace("data.vip", true)
response if ${url} ~= /^https:\/\/a\.com\/c/ && ${response.header['Content-Type']} ~= /json/i && ${request.method} == "POST" then response.json.delete("ads") | response.header.set("Cache-Control", "no-store")
response if ${url} ~= /^https:\/\/a\.com\/s/ && ${response.status} ~= /^30[12]$/ then response.body.replace(/ad/, "")
request if ${url} ~= /^https:\/\/a\.com\/q/ && ${response.status} == 200 then request.header.del("X")
response if ${url} ~= /^https:\/\/a\.com\/m/ && ${response.status} == 200 then response.body.mock("json", "{}")
response if ${url} ~= /^https:\/\/a\.com\/u/ && ${response.status} == 200 then reject(200)
"#,
        &[],
    );
    let json_type = r"^(?=[\s\S]*\r\n(?i:Content\-Type): [^\r\n]*?(?:(?i:json))[^\r\n]*\r\n)";
    let bodies: Vec<_> = def
        .lists
        .body_rewrite
        .iter()
        .map(|line| {
            let body = line.def.as_ref().unwrap();
            (
                line.line,
                body.conditions.request.as_deref(),
                body.conditions.response.as_deref(),
                body.action.clone(),
            )
        })
        .collect();
    assert_eq!(
        bodies,
        [
            (
                2,
                None,
                Some(STATUS_200),
                BodyActionDef::Jq("if .data.vip != null then .data.vip = true else . end".into())
            ),
            (
                3,
                Some(POST),
                Some(json_type),
                BodyActionDef::Jq("del(.ads)".into())
            ),
            (
                4,
                None,
                Some(r"^(?=\S+ \d*?(?:(?<= )30[12](?=[ \r]))\d*(?: |\r\n))"),
                BodyActionDef::Replace(vec![("ad".into(), String::new())])
            ),
        ]
    );
    let heads: Vec<_> = def
        .lists
        .header_rewrite
        .iter()
        .map(|line| {
            let head = line.def.as_ref().unwrap();
            (
                line.line,
                head.response,
                head.conditions.request.as_deref(),
                head.conditions.response.as_deref(),
                head.edit.clone(),
            )
        })
        .collect();
    let cache = HeaderName::from_static("cache-control");
    assert_eq!(
        heads,
        [
            (
                3,
                true,
                Some(POST),
                Some(json_type),
                HeaderEditDef::Del(cache.clone())
            ),
            (
                3,
                true,
                Some(POST),
                Some(json_type),
                HeaderEditDef::Add(cache, HeaderValue::from_static("no-store"))
            ),
        ]
    );
    assert_eq!(
        ignored(&def),
        [
            (5, IgnoreReason::Unreadable),
            (6, IgnoreReason::Unreadable),
            (7, IgnoreReason::Condition)
        ]
    );
}

#[test]
fn scripts_run_by_the_request_and_response_heads() {
    let def = read(
        r#"[Rewrite]
request if ${url} ~= /^https:\/\/a\.com\/s/ && ${request.method} == "POST" then script("https://cdn.test/s.js") with tag="S"
response if ${url} ~= /^https:\/\/a\.com\/r/ && ${response.status} == 200 then script("https://cdn.test/s.js") with tag="R"
"#,
        &[],
    );
    assert_eq!(ignored(&def), []);
    let scripts: Vec<_> = def
        .lists
        .script
        .iter()
        .map(|line| {
            let script = line.def.as_ref().unwrap();
            (
                script.name.as_str(),
                script.kind,
                script.conditions.request.as_deref(),
                script.conditions.response.as_deref(),
                script.path.as_str(),
            )
        })
        .collect();
    assert_eq!(
        scripts,
        [
            (
                "S",
                ScriptKind::HttpRequest,
                Some(POST),
                None,
                "https://cdn.test/s.js"
            ),
            (
                "R",
                ScriptKind::HttpResponse,
                None,
                Some(STATUS_200),
                "https://cdn.test/s.js"
            ),
        ]
    );
    assert_eq!(def.declared_scripts, [2, 3]);
}

#[test]
fn body_mocks_go_by_the_request_head() {
    let def = read(
        r#"[Rewrite]
request if ${url} ~= /^https:\/\/api\.example\.com\/v1\/report/ && ${request.method} == "POST" then request.body.mock("json", `{"events":[]}`)
request if ${url} ~= /^https:\/\/api\.example\.com\/v1\/upload/ then request.body.mock_file("json", "https://cdn.test/m.json")
response if ${url} ~= /^https:\/\/api\.example\.com\/ad/ && ${request.header['User-Agent']} ~= /^Example\// then response.body.mock("json", "{}", 200)
"#,
        &[],
    );
    assert_eq!(ignored(&def), []);
    let mocks: Vec<_> = def
        .lists
        .request_body_mock
        .iter()
        .map(|line| {
            let mock = line.def.as_ref().unwrap();
            (
                line.line,
                mock.conditions.request.as_deref(),
                mock.body.clone(),
                mock.data.as_str(),
            )
        })
        .collect();
    assert_eq!(
        mocks,
        [
            (2, Some(POST), MapLocalBody::Text, r#"{"events":[]}"#),
            (
                3,
                None,
                MapLocalBody::File { base64: false },
                "https://cdn.test/m.json"
            ),
        ]
    );
    let local = def.lists.map_local[0].def.as_ref().unwrap();
    assert_eq!(
        (
            local.conditions.request.as_deref(),
            local.data.as_str(),
            local.status.as_u16(),
            local.request
        ),
        (
            Some(
                r"^(?=[\s\S]*\r\n(?i:User\-Agent): [^\r\n]*?(?:(?<=\n(?i:User\-Agent): )Example\/)[^\r\n]*\r\n)"
            ),
            "{}",
            200,
            false
        )
    );
    let urls: Vec<_> = def
        .resources
        .iter()
        .map(|resource| (resource.url.as_str(), resource.lines.clone()))
        .collect();
    assert_eq!(urls, [("https://cdn.test/m.json", vec![3])]);
}

#[test]
fn a_cron_expression_an_argument_fills_in_keeps_every_field() {
    for expression in ["{cron}", "\"55 23 * * *\""] {
        let def = read(
            &format!(
                "[Argument]\ncron=input, \"55 23 * * *\", tag=Schedule\n\n[Script]\ncron {expression} script-path=https://cdn.test/sync.js, timeout=900, tag=Sync\n"
            ),
            &[],
        );
        assert_eq!(ignored(&def), [], "{expression}");
        let script = def.lists.script[0].def.as_ref().unwrap();
        assert_eq!(
            (
                script.kind,
                script.cronexp.as_str(),
                script.name.as_str(),
                script.path.as_str(),
                script.timeout
            ),
            (
                ScriptKind::Cron,
                "55 23 * * *",
                "Sync",
                "https://cdn.test/sync.js",
                Some(900.0)
            ),
            "{expression}"
        );
    }
}
