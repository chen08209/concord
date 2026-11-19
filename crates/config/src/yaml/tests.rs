use super::*;

fn parse(text: &str) -> Map {
    parse_document(text).unwrap().root
}

#[test]
fn plain_scalars_keep_their_spelling_when_ambiguous() {
    let root = parse("a: 443\nb: 0x1BB\nc: 000000\nd: yes\ne: 1.5\nf: ~\ng: true\nh: \"443\"\n");
    assert_eq!(root["a"], Value::from(443));
    assert_eq!(root["b"], Value::from("0x1BB"));
    assert_eq!(root["c"], Value::from("000000"));
    assert_eq!(root["d"], Value::from("yes"));
    assert_eq!(root["e"], Value::from(1.5));
    assert_eq!(root["f"], Value::Null);
    assert_eq!(root["g"], Value::from(true));
    assert_eq!(root["h"], Value::from("443"));
}

#[test]
fn merge_keys_and_anchors_expand() {
    let root = parse(
        "base: &b {type: ss, port: 1, name: base}\nitems:\n  - <<: *b\n    name: one\n  - <<: [*b]\n    port: 2\n",
    );
    let items = root["items"].as_array().unwrap();
    assert_eq!(items[0]["name"], "one");
    assert_eq!(items[0]["type"], "ss");
    assert_eq!(items[0]["port"], 1);
    assert_eq!(items[1]["name"], "base");
    assert_eq!(items[1]["port"], 2);
}

#[test]
fn aliasing_is_held_to_go_yaml_ratio() {
    let list = format!("[{}]", vec!["x"; 1000].join(", "));
    let refs = |count: usize| vec!["*a"; count].join(", ");
    let few = format!("a: &a {list}\nb: [{}]\n", refs(50));
    assert!(parse_document(&few).is_ok());
    let many = format!("a: &a {list}\nb: [{}]\n", refs(150));
    let err = parse_document(&many).unwrap_err().to_string();
    assert!(err.contains("excessive aliasing"), "{err}");
}

#[test]
fn duplicate_keys_are_rejected() {
    let err = parse_document("a: 1\na: 2\n").unwrap_err();
    assert!(err.message.contains("already defined"), "{err}");
    assert_eq!(err.line, Some(2));
}

#[test]
fn short_ids_stay_text_in_every_position() {
    let root = parse(
        "proxies:\n  - {name: o, reality-opts: {public-key: k, short-id: 0123}}\n  - name: z\n    reality-opts:\n      short-id: 00\n  - name: e\n    reality-opts:\n      short-id: 1e5\n  - name: q\n    reality-opts:\n      short-id: \"0189\"\nlisteners:\n  - reality-config:\n      short-id: [01234567, \"\"]\n",
    );
    let proxies = root["proxies"].as_array().unwrap();
    assert_eq!(proxies[0]["reality-opts"]["short-id"], "0123");
    assert_eq!(proxies[1]["reality-opts"]["short-id"], "00");
    assert_eq!(proxies[2]["reality-opts"]["short-id"], "1e5");
    assert_eq!(proxies[3]["reality-opts"]["short-id"], "0189");
    let ids = root["listeners"][0]["reality-config"]["short-id"]
        .as_array()
        .unwrap();
    assert_eq!(ids[0], "01234567");
    assert_eq!(ids[1], "");
}

#[test]
fn the_rules_fast_path_matches_the_full_parse() {
    let text = "mixed-port: 7890\nrules:\n  - DOMAIN,a.com,DIRECT # note\n  # comment\n\n  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n  - MATCH,PROXY\nmode: rule\n";
    let fast = parse_document(text).unwrap();
    let slow = parse_document_slow(text).unwrap();
    assert!(!fast.root.contains_key("rules"));
    let fast_rules: Vec<&str> = fast.rules.as_ref().unwrap().iter().collect();
    assert_eq!(serde_json::json!(fast_rules), slow.root["rules"]);
    assert_eq!(fast.root["mode"], slow.root["mode"]);
    assert_eq!(fast.lines.rules, vec![3, 6, 7]);
}

#[test]
fn the_rules_fast_path_falls_back_on_quotes_and_flow() {
    for text in [
        "rules:\n  - \"DOMAIN,a.com,DIRECT\"\n  - MATCH,P\n",
        "rules: [MATCH,P]\n",
        "rules:\n  - &x MATCH,P\n",
        "rules:\n  - a: b\n",
        "rules:\n  - AND,((DOMAIN,a),(NETWORK,UDP)),X\n  - 'MATCH,P'\n",
    ] {
        assert!(scan_rules(text).is_none(), "{text}");
        assert!(parse_document(text).is_ok(), "{text}");
    }
}

#[test]
fn indentless_rule_lists_are_scanned() {
    let doc = parse_document("rules:\n- MATCH,P\nmode: global\n").unwrap();
    assert_eq!(doc.rules.unwrap(), ["MATCH,P"]);
    assert_eq!(doc.root["mode"], "global");
}

#[test]
fn written_yaml_parses_back_to_the_same_tree() {
    let value = serde_json::json!({
        "proxies": [
            {"name": "a b", "port": 443, "short-id": "0123", "alpn": ["h2", "http/1.1"], "empty": [], "nested": {"x": null, "y": true, "z": "yes"}},
            {"name": "- dash", "pass": "p: w # x", "text": "line\nbreak"}
        ],
        "dns": {"nameserver": ["https://doh.pub/dns-query", "tls://223.5.5.5:853"]},
        "rule": ["DOMAIN,a,b"],
        "hosts": {},
        "list": [[1, 2], [3]]
    });
    let text = to_yaml(&value);
    let parsed = parse_document_slow(&text).unwrap();
    assert_eq!(Value::Object(parsed.root), value, "{text}");
}

#[test]
fn a_scalar_document_is_not_a_config() {
    assert!(parse_document("just text").is_err());
    assert!(parse_document("").unwrap().root.is_empty());
}
