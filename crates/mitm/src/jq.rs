use concord_config::mitm::text::quote;
use concord_config::mitm::{IssueKind, LineError};
use jaq_core::compile;
use jaq_core::load::{Arena, File, Loader, lex, parse};
use jaq_core::{Compiler, Ctx, Vars, data, unwrap_valr};
use jaq_json::{Val, read};

type Filter = jaq_core::Filter<data::JustLut<Val>>;

/// A jq filter over a JSON body, as Surge's `http-request-jq` and `http-response-jq` run it.
pub(crate) struct Jq {
    filter: Filter,
    code: String,
}

impl std::fmt::Debug for Jq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Jq")
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid jq expression: {0}")]
pub(crate) struct JqError(String);

impl From<JqError> for LineError {
    fn from(err: JqError) -> LineError {
        LineError::new(IssueKind::Jq, err.to_string())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum JqOutcome {
    Rewritten(String),
    NotJson,
    /// Surge keeps the body as it was when the filter gives nothing.
    Empty,
    Failed(String),
}

impl Jq {
    pub(crate) fn compile(code: &str) -> Result<Jq, JqError> {
        let defs = jaq_core::defs()
            .chain(jaq_std::defs())
            .chain(jaq_json::defs())
            .chain(jq_defs());
        let funs = jaq_core::funs()
            .chain(jaq_std::funs())
            .chain(jaq_json::funs());
        let arena = Arena::default();
        let modules = Loader::new(defs)
            .load(&arena, File { code, path: () })
            .map_err(|errors| load_error(code, errors))?;
        let filter = Compiler::default()
            .with_funs(funs)
            .compile(modules)
            .map_err(compile_error)?;
        Ok(Jq {
            filter,
            code: code.to_string(),
        })
    }

    pub(crate) fn code(&self) -> &str {
        &self.code
    }

    /// Runs on `body` and keeps the first value it gives, as the body that replaces it.
    pub(crate) fn run(&self, body: &str) -> JqOutcome {
        let Ok(input) = read::parse_single(body.as_bytes()) else {
            return JqOutcome::NotJson;
        };
        let ctx = Ctx::<data::JustLut<Val>>::new(&self.filter.lut, Vars::new([]));
        match self.filter.id.run((ctx, input)).map(unwrap_valr).next() {
            None => JqOutcome::Empty,
            Some(Ok(value)) => JqOutcome::Rewritten(value.to_string()),
            Some(Err(err)) => JqOutcome::Failed(err.to_string()),
        }
    }
}

/// jq 1.7 builtins that jaq leaves out: the SQL-style operators, the stream conversions and
/// the CSV and TSV formats.
fn jq_defs() -> impl Iterator<Item = jaq_core::load::parse::Def<&'static str>> {
    jaq_core::load::parse(include_str!("jq.jq"), |p| p.defs())
        .unwrap_or_default()
        .into_iter()
}

fn near(code: &str, rest: &str) -> String {
    let at = code.len().saturating_sub(rest.len());
    match code.get(at..).map(str::trim) {
        Some(tail) if !tail.is_empty() => {
            let shown: String = tail.chars().take(24).collect();
            format!(" near {}", quote(&shown))
        }
        _ => " at the end".to_string(),
    }
}

fn load_error(code: &str, errors: jaq_core::load::Errors<&str, ()>) -> JqError {
    let mut messages = Vec::new();
    for (_, error) in errors {
        match error {
            jaq_core::load::Error::Io(items) => {
                messages.extend(
                    items
                        .into_iter()
                        .map(|(path, err)| format!("{path}: {err}")),
                );
            }
            jaq_core::load::Error::Lex(items) => {
                messages.extend(items.into_iter().map(|(expect, rest): lex::Error<&str>| {
                    format!("expected {}{}", expect.as_str(), near(code, rest))
                }));
            }
            jaq_core::load::Error::Parse(items) => {
                messages.extend(items.into_iter().map(|(expect, rest): parse::Error<&str>| {
                    format!("expected {}{}", expect.as_str(), near(code, rest))
                }));
            }
        }
    }
    JqError(messages.join("; "))
}

fn compile_error(errors: compile::Errors<&str, ()>) -> JqError {
    let names: Vec<String> = errors
        .into_iter()
        .flat_map(|(_, undefined)| undefined)
        .map(|(name, kind)| match kind {
            compile::Undefined::Filter(arity) => format!("{name}/{arity}"),
            other => format!("{} {name}", other.as_str()),
        })
        .collect();
    JqError(format!("undefined {}", names.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(code: &str, body: &str) -> JqOutcome {
        Jq::compile(code)
            .unwrap_or_else(|err| panic!("{code}: {err}"))
            .run(body)
    }

    fn rewritten(text: &str) -> JqOutcome {
        JqOutcome::Rewritten(text.to_string())
    }

    #[test]
    fn module_filters_rewrite_bodies_in_place() {
        let cases = [
            (".dt = []", r#"{"dt":[1,2],"v":1}"#, r#"{"dt":[],"v":1}"#),
            (
                ".dt.hot = [] | .dt.recommand = [] | .dt.bannerList = []",
                r#"{"dt":{"hot":[1],"recommand":[2],"bannerList":[3],"keep":"é\"\n"}}"#,
                r#"{"dt":{"hot":[],"recommand":[],"bannerList":[],"keep":"é\"\n"}}"#,
            ),
            (
                "del(.reskinConfig.sidebarExSquareStyle.moreList, .reskinConfig.sidebarExSquareStyle.topList)",
                r#"{"reskinConfig":{"sidebarExSquareStyle":{"moreList":[1],"topList":[2],"x":3}}}"#,
                r#"{"reskinConfig":{"sidebarExSquareStyle":{"x":3}}}"#,
            ),
            (
                r#".headers |= with_entries(select(.key | test("^X-") | not))"#,
                r#"{"headers":{"X-A":"1","Accept":"*/*"}}"#,
                r#"{"headers":{"Accept":"*/*"}}"#,
            ),
            (".[0]", "[{\"a\":1},2]", r#"{"a":1}"#),
            (
                r#"def filter_nodes: map(if .data.componentId? and (.data.componentId | type == "string") and (.data.componentId | (contains("tpp_banner") or . == "tpp_guess_like")) then empty else .nodes |= (if . then filter_nodes else . end) end); .data.nodes |= (if . then filter_nodes else . end)"#,
                r#"{"data":{"nodes":[{"data":{"componentId":"tpp_banner_x"}},{"data":{"componentId":"keep"},"nodes":[{"data":{"componentId":"tpp_guess_like"}},{"data":{}}]}]}}"#,
                r#"{"data":{"nodes":[{"data":{"componentId":"keep"},"nodes":[{"data":{},"nodes":null}]}]}}"#,
            ),
        ];
        for (code, body, want) in cases {
            assert_eq!(rewrite(code, body), rewritten(want), "{code}");
        }
    }

    #[test]
    fn a_body_that_is_not_json_or_gives_nothing_is_kept() {
        assert_eq!(rewrite(".a = 1", "<html>"), JqOutcome::NotJson);
        assert_eq!(rewrite(".a = 1", ""), JqOutcome::NotJson);
        assert_eq!(rewrite("empty", "{}"), JqOutcome::Empty);
        assert!(matches!(rewrite(".a.b", "[1]"), JqOutcome::Failed(_)));
        assert_eq!(rewrite(".[]", "[1,2]"), rewritten("1"));
    }

    #[test]
    fn a_bad_expression_says_what_is_wrong() {
        let err = Jq::compile(".a = ").unwrap_err().to_string();
        assert!(err.contains("at the end"), "{err}");
        let err = Jq::compile(".a | nosuchfn(1)").unwrap_err().to_string();
        assert!(err.contains("nosuchfn/1"), "{err}");
        let err = Jq::compile(".a ]").unwrap_err().to_string();
        assert!(err.starts_with("invalid jq expression"), "{err}");
    }

    /// jq 1.7.1's `builtins` that the jq 1.7 manual documents, less those that read the
    /// program's input stream, which a body filter has none of.
    const JQ_BUILTINS: &str = "
        now/0 localtime/0 gmtime/0 mktime/0 strflocaltime/1 strftime/1 strptime/1 stderr/0
        debug/0 halt_error/1 halt/0 env/0 error/0 max/0 min/0 sort/0 nan/0 infinite/0
        isnormal/0 isnan/0 isinfinite/0 type/0 utf8bytelength/0 length/0 contains/1 has/1
        delpaths/1 getpath/1 setpath/2 implode/0 explode/0 split/1 rtrimstr/1 ltrimstr/1
        endswith/1 startswith/1 keys_unsorted/0 keys/0 tostring/0 tonumber/0 fromjson/0
        tojson/0 modf/0 frexp/0 ldexp/2 trunc/0 significand/0 scalbln/2 scalb/2 round/0 rint/0
        nexttoward/2 nextafter/2 nearbyint/0 logb/0 log1p/0 lgamma/0 gamma/0 fmod/2 fmin/2
        fmax/2 fma/3 fdim/2 fabs/0 expm1/0 exp10/0 erfc/0 erf/0 drem/2 copysign/2 ceil/0 yn/2
        jn/2 y1/0 y0/0 tgamma/0 tanh/0 tan/0 sqrt/0 sinh/0 sin/0 remainder/2 pow/2 log2/0
        log10/0 log/0 j1/0 j0/0 hypot/2 floor/0 exp2/0 exp/0 cosh/0 cos/0 cbrt/0 atanh/0
        atan2/2 atan/0 asinh/0 asin/0 acosh/0 acos/0 empty/0 not/0 path/1 range/2 halt_error/0
        error/1 map/1 select/1 sort_by/1 group_by/1 unique/0 unique_by/1 max_by/1 min_by/1
        add/0 del/1 abs/0 map_values/1 recurse/1 recurse/2 recurse/0 to_entries/0
        from_entries/0 with_entries/1 reverse/0 indices/1 index/1 rindex/1 paths/0 paths/1
        isfinite/0 arrays/0 objects/0 iterables/0 booleans/0 numbers/0 normals/0 finites/0
        strings/0 nulls/0 values/0 scalars/0 join/1 flatten/1 flatten/0 range/1
        fromdateiso8601/0 todateiso8601/0 fromdate/0 todate/0 match/2 match/1 test/2 test/1
        capture/2 capture/1 scan/2 scan/1 splits/2 splits/1 split/2 sub/3 sub/2 gsub/3 gsub/2
        while/2 until/2 limit/2 range/3 first/1 isempty/1 all/2 any/2 all/1 any/1 all/0 any/0
        last/1 nth/2 first/0 last/0 nth/1 combinations/0 combinations/1 transpose/0 in/1
        inside/1 repeat/1 ascii_downcase/0 ascii_upcase/0 truncate_stream/1 fromstream/1
        tostream/0 bsearch/1 walk/1 pick/1 debug/1 INDEX/2 INDEX/1 JOIN/2 JOIN/3 JOIN/4 IN/1
        IN/2 pow10/0
    ";

    #[test]
    fn every_jq_builtin_is_defined() {
        let undefined: Vec<&str> = JQ_BUILTINS
            .split_whitespace()
            .filter(|builtin| {
                let (name, arity) = builtin.split_once('/').unwrap();
                let arity: usize = arity.parse().unwrap();
                let code = match arity {
                    0 => name.to_string(),
                    n => format!("{name}({})", vec!["."; n].join("; ")),
                };
                Jq::compile(&code).is_err()
            })
            .collect();
        assert!(undefined.is_empty(), "undefined: {undefined:?}");
    }

    #[test]
    fn every_jq_format_is_defined() {
        let formats = [
            "@text", "@json", "@html", "@uri", "@csv", "@tsv", "@sh", "@base64", "@base64d",
        ];
        let undefined: Vec<&str> = formats
            .into_iter()
            .filter(|format| Jq::compile(format).is_err())
            .collect();
        assert!(undefined.is_empty(), "undefined: {undefined:?}");
    }

    #[test]
    fn sql_style_and_stream_builtins_follow_jq() {
        let cases = [
            (
                r#".data.nodes[]?.nodes |= map(select(.data.componentId | IN("tpp_banner_loop", "tpp_guess_like") | not))"#,
                r#"{"data":{"nodes":[{"nodes":[{"data":{"componentId":"tpp_banner_loop"}},{"data":{"componentId":"keep"}}]}]}}"#,
                r#"{"data":{"nodes":[{"nodes":[{"data":{"componentId":"keep"}}]}]}}"#,
            ),
            ("[.[] | IN(2, 3)]", "[1,2,3]", "[false,true,true]"),
            ("IN(.[]; 5, 6)", "[1,6]", "true"),
            (
                r#"INDEX(.id)"#,
                r#"[{"id":1,"v":"a"},{"id":"x","v":"b"}]"#,
                r#"{"1":{"id":1,"v":"a"},"x":{"id":"x","v":"b"}}"#,
            ),
            (
                r#"[JOIN({"1":"one"}; .[]; tostring)]"#,
                "[1,2]",
                r#"[[1,"one"],[2,null]]"#,
            ),
            (
                "[tostream]",
                r#"{"a":[1]}"#,
                r#"[[["a",0],1],[["a",0]],[["a"]]]"#,
            ),
            (
                "fromstream(tostream)",
                r#"{"a":[1,{"b":2}]}"#,
                r#"{"a":[1,{"b":2}]}"#,
            ),
            (
                "[1 | truncate_stream([[0], 1], [[1, 0], 2], [[1, 0]], [[1]])]",
                "null",
                "[[[0],2],[[0]]]",
            ),
            (
                r#"@csv"#,
                r#"[1,"a\"b",null,true]"#,
                r#""1,\"a\"\"b\",,true""#,
            ),
            (r#"@tsv"#, r#"["a\tb","c\\d",1]"#, r#""a\\tb\tc\\\\d\t1""#),
        ];
        for (code, body, want) in cases {
            assert_eq!(rewrite(code, body), rewritten(want), "{code}");
        }
    }

    #[test]
    fn a_filter_runs_on_other_threads() {
        fn shared<T: Send + Sync>(_: &T) {}
        shared(&Jq::compile(".").unwrap());
    }
}
