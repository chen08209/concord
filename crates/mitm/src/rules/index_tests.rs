use super::*;
use crate::rules::parse_url_rewrite;

const PATTERNS: [&str; 17] = [
    r"^http:\/\/apicloud\.zol\.com\.cn\/Article\/WapLaunchLogo",
    r"^https?:\/\/(h3\.)?open\.taou\.com\/maimai\/adshow\?",
    r"^https:\/\/api\.weibo\.cn\/2\/statuses\/(container_timeline(?>_hot|_topic)?|unread_hot_timeline)\?",
    r"^https://example\.com:8443/ads/\d+",
    r"^https?://ad\.example\.com/banner\?id=\w+",
    r"(?i)^https://cdn\.ads\.test/",
    r"(?i)^https://www\.example\.org/promotions/summer-sale/banner",
    r"^\w+://tracker\.test/",
    r"/collect\?",
    r"^https://a\.com/(?=x)",
    r"^https://a\.com/x\d+$",
    r"^https?://(www\.)?video\.test/(ad|pre)roll",
    r"^https://API\.Mixed\.test/v1",
    r"^",
    r"^https?:\/\/[\w-]+\.amap\.com\/ws\/(boss|shield)\/",
    r"^https?://[^/]+/(api|v2)/promo(tion)?s?/",
    r"(?i)/ADS/",
];

const URLS: [&str; 27] = [
    "http://apicloud.zol.com.cn/Article/WapLaunchLogo?x=1",
    "https://apicloud.zol.com.cn/Article/WapLaunchLogo",
    "https://h3.open.taou.com/maimai/adshow?a=1",
    "http://open.taou.com/maimai/adshow?a=1",
    "https://api.weibo.cn/2/statuses/container_timeline_hot?gsid=1",
    "https://api.weibo.cn/2/statuses/unread_hot_timeline?from=1",
    "https://example.com:8443/ads/12",
    "https://example.com/ads/12",
    "https://ad.example.com/banner?id=abc",
    "HTTPS://CDN.ADS.TEST/x.js",
    "https://Cdn.Ads.Test/x.js",
    "https://WWW.EXAMPLE.ORG/PROMOTIONS/SUMMER-SALE/BANNER.png",
    "ws://tracker.test/x",
    "https://site.test/collect?v=1",
    "https://a.com/xyz",
    "https://a.com/x12",
    "https://video.test/preroll.mp4",
    "http://www.video.test/adroll",
    "https://api.mixed.test/v1",
    "https://API.Mixed.test/v1/list",
    "https://www.unrelated.test/index.html",
    "",
    "https://m5.amap.com/ws/boss/order",
    "https://m5.amap.com/ws/other/x",
    "https://shop.test/api/promotions/1",
    "https://shop.test/v2/promo/1?x=/ads/",
    "https://cdn.test/Ads/x.png",
];

fn rules_of(patterns: &[&str]) -> Rules {
    let mut rules = Rules::default();
    for pattern in patterns {
        let line = format!("{pattern} _ reject");
        rules
            .url_rewrites
            .push(parse_url_rewrite(&line).unwrap_or_else(|err| panic!("{line}: {err}")));
    }
    rules
}

fn naive(rules: &Rules, url: &str) -> Vec<*const super::super::UrlRewrite> {
    rules
        .url_rewrites
        .iter()
        .filter(|rule| rule.pattern.is_match(url))
        .map(std::ptr::from_ref)
        .collect()
}

fn indexed(rules: &Rules, url: &str) -> Vec<*const super::super::UrlRewrite> {
    rules
        .url_rewrite_candidates(url)
        .filter(|rule| rule.pattern.is_match(url))
        .map(std::ptr::from_ref)
        .collect()
}

#[test]
fn the_index_finds_the_rules_a_full_scan_finds_in_the_same_order() {
    let rules = rules_of(&PATTERNS);
    for url in URLS {
        assert_eq!(indexed(&rules, url), naive(&rules, url), "{url}");
    }
    let hits: usize = URLS.iter().map(|url| naive(&rules, url).len()).sum();
    assert!(hits > URLS.len(), "the corpus has to hit");
}

#[test]
fn a_prefix_only_makes_a_candidate_and_the_pattern_decides() {
    let rules = rules_of(&[r"^https://a\.com/x\d+$"]);
    assert!(rules.index_of_url_rewrites().always().is_empty());
    assert_eq!(rules.url_rewrite_candidates("https://a.com/xyz").count(), 1);
    assert!(
        rules
            .rewrite_url("https://a.com/xyz", &crate::heads::Heads::new(None, None))
            .is_none()
    );
    assert!(
        rules
            .rewrite_url("https://a.com/x12", &crate::heads::Heads::new(None, None))
            .is_some()
    );
    assert_eq!(rules.url_rewrite_candidates("https://b.com/x12").count(), 0);
}

#[test]
fn patterns_without_a_literal_to_look_up_are_always_tried() {
    let cases = [
        (r"^", "an empty prefix"),
        (r"^.+", "no literal at all"),
        (r"^\w+\d*$", "only classes"),
    ];
    for (pattern, why) in cases {
        let rules = rules_of(&[pattern]);
        assert_eq!(rules.index_of_url_rewrites().always(), [0], "{why}");
    }
}

#[test]
fn a_literal_anywhere_in_the_pattern_looks_it_up() {
    let cases = [
        (
            r"^\w+://tracker\.test/",
            "ws://tracker.test/x",
            "wss://other.test/",
        ),
        (
            r"/collect\?",
            "https://site.test/collect?v=1",
            "https://site.test/collect",
        ),
        (
            r"^https?:\/\/[\w-]+\.amap\.com\/ws\/",
            "https://m5.amap.com/ws/x",
            "https://www.example.com/ws/x",
        ),
    ];
    for (pattern, hit, miss) in cases {
        let rules = rules_of(&[pattern]);
        assert!(
            rules.index_of_url_rewrites().always().is_empty(),
            "{pattern}"
        );
        assert_eq!(
            rules.url_rewrite_candidates(hit).count(),
            1,
            "{pattern} {hit}"
        );
        assert_eq!(
            rules.url_rewrite_candidates(miss).count(),
            0,
            "{pattern} {miss}"
        );
    }
}

#[test]
fn a_case_insensitive_pattern_is_found_in_any_case() {
    for pattern in [
        r"(?i)^https://cdn\.ads\.test/",
        r"(?i)^https://www\.example\.org/promotions/summer-sale/banner",
    ] {
        let rules = rules_of(&[pattern]);
        for url in [
            "https://cdn.ads.test/a",
            "HTTPS://CDN.ADS.TEST/a",
            "hTtPs://cDn.AdS.tEsT/a",
            "https://WWW.EXAMPLE.ORG/PROMOTIONS/SUMMER-SALE/BANNER",
            "https://www.Example.org/promotions/Summer-Sale/banner",
        ] {
            assert_eq!(indexed(&rules, url), naive(&rules, url), "{pattern} {url}");
        }
    }
}

#[test]
fn a_url_builds_only_the_patterns_it_may_match() {
    let patterns: Vec<String> = (0..1000)
        .map(|n| format!(r"^https?://ad{n}\.example\.com/banner"))
        .collect();
    let rules = rules_of(&patterns.iter().map(String::as_str).collect::<Vec<_>>());
    let built = |rules: &Rules| {
        rules
            .url_rewrites
            .iter()
            .filter(|rule| rule.pattern.is_built())
            .count()
    };
    let heads = crate::heads::Heads::new(None, None);
    for n in 0..200 {
        assert!(
            rules
                .rewrite_url(&format!("https://www.site{n}.test/page?q={n}"), &heads)
                .is_none()
        );
    }
    assert_eq!(built(&rules), 0);
    assert!(
        rules
            .rewrite_url("https://ad7.example.com/banner", &heads)
            .is_some()
    );
    assert_eq!(built(&rules), 1);
}

#[test]
fn relaxing_a_pattern_keeps_every_match() {
    let cases = [
        (r"^a(?>b|c)d", r"^a(?:b|c)d"),
        (r"^a(?!x|y\))b", r"^ab"),
        (r"^a(?<=a)b(?<!c)", r"^ab"),
        (r"^(\w)x\1", r"^(\w)x(?s:.*)"),
        (r"^(?<n>\w)\k<n>", r"^(?<n>\w)(?s:.*)"),
        (r"^[(?!]x", r"^[(?!]x"),
        (r"^a\(?!b", r"^a\(?!b"),
    ];
    for (source, relaxed) in cases {
        assert_eq!(super::relax(source), relaxed, "{source}");
    }
}
