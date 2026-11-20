use std::sync::OnceLock;

use concord_config::mitm::{IssueKind, LineError, parses, regex_source};
use fancy_regex::{Captures, Regex};

/// A backtracking regex, as Surge's and Loon's patterns need. fancy-regex's default step
/// limit stands in for a match timeout; a pattern that exceeds it matches nothing.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PatternError(String);

impl From<PatternError> for LineError {
    fn from(err: PatternError) -> LineError {
        LineError::new(IssueKind::Pattern, err.0)
    }
}

/// Built on first use: a module can list thousands of patterns that most traffic never
/// reaches, and every built regex keeps a match cache for each thread that ran it.
#[derive(Clone, Debug)]
pub struct Pattern {
    source: String,
    regex: OnceLock<Option<Regex>>,
}

impl Pattern {
    pub fn new(pattern: &str) -> Result<Pattern, PatternError> {
        Self::build(pattern, false)
    }

    pub fn multiline(pattern: &str) -> Result<Pattern, PatternError> {
        Self::build(pattern, true)
    }

    fn build(pattern: &str, multiline: bool) -> Result<Pattern, PatternError> {
        let source = if multiline {
            concord_config::mitm::multiline(pattern)
        } else {
            pattern.to_string()
        };
        check(&regex_source(&source))?;
        Ok(Pattern {
            source,
            regex: OnceLock::new(),
        })
    }

    /// The regex as compiled, `(?m)` included for a multiline one.
    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    fn regex(&self) -> Option<&Regex> {
        self.regex
            .get_or_init(|| {
                Regex::new(&regex_source(&self.source))
                    .inspect_err(|err| {
                        tracing::warn!("[MITM] {} matches nothing: {err}", self.source);
                    })
                    .ok()
            })
            .as_ref()
    }

    #[cfg(test)]
    pub(crate) fn is_built(&self) -> bool {
        self.regex.get().is_some()
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.regex()
            .is_some_and(|regex| regex.is_match(text).unwrap_or(false))
    }

    /// `None` when the pattern fails to run, which leaves the text as it was.
    pub fn replace(&self, text: &str, template: &str, all: bool) -> Option<String> {
        let regex = self.regex()?;
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for caps in regex.captures_iter(text) {
            let caps = caps.ok()?;
            let whole = caps.get(0)?;
            out.push_str(text.get(last..whole.start())?);
            Self::expand(regex, &caps, template, text, &mut out);
            last = whole.end();
            if !all {
                break;
            }
        }
        out.push_str(text.get(last..)?);
        Some(out)
    }

    /// .NET replacement syntax: `$1`, `${name}`, `$&`, `` $` ``, `$'`, `$_`, `$$`.
    fn expand(
        regex: &Regex,
        caps: &Captures<'_, str>,
        template: &str,
        input: &str,
        out: &mut String,
    ) {
        let bytes = template.as_bytes();
        let mut i = 0;
        while let Some(&c) = bytes.get(i) {
            if c != b'$' {
                let end = template
                    .get(i..)
                    .and_then(|rest| rest.find('$'))
                    .map_or(template.len(), |at| i + at);
                out.push_str(template.get(i..end).unwrap_or_default());
                i = end;
                continue;
            }
            let Some(&next) = bytes.get(i + 1) else {
                out.push('$');
                break;
            };
            match next {
                b'$' => {
                    out.push('$');
                    i += 2;
                }
                b'&' => {
                    push_group(caps, 0, out);
                    i += 2;
                }
                b'`' => {
                    let start = caps.get(0).map_or(0, |m| m.start());
                    out.push_str(input.get(..start).unwrap_or_default());
                    i += 2;
                }
                b'\'' => {
                    let end = caps.get(0).map_or(0, |m| m.end());
                    out.push_str(input.get(end..).unwrap_or_default());
                    i += 2;
                }
                b'_' => {
                    out.push_str(input);
                    i += 2;
                }
                b'{' => {
                    let close = template.get(i + 2..).and_then(|rest| rest.find('}'));
                    match close {
                        Some(len) => {
                            let name = template.get(i + 2..i + 2 + len).unwrap_or_default();
                            if !Self::push_named(regex, caps, name, out) {
                                out.push_str(template.get(i..i + 3 + len).unwrap_or_default());
                            }
                            i += 3 + len;
                        }
                        None => {
                            out.push('$');
                            i += 1;
                        }
                    }
                }
                b'0'..=b'9' => {
                    let digits = bytes.get(i + 1..).map_or(0, |rest| {
                        rest.iter().take_while(|b| b.is_ascii_digit()).count()
                    });
                    let mut taken = digits;
                    let number = loop {
                        if taken == 0 {
                            break None;
                        }
                        let text = template.get(i + 1..i + 1 + taken).unwrap_or_default();
                        match text.parse::<usize>() {
                            Ok(n) if n < caps.len() => break Some(n),
                            _ => taken -= 1,
                        }
                    };
                    match number {
                        Some(n) => {
                            push_group(caps, n, out);
                            i += 1 + taken;
                        }
                        None => {
                            out.push('$');
                            i += 1;
                        }
                    }
                }
                _ => {
                    out.push('$');
                    i += 1;
                }
            }
        }
    }

    fn push_named(regex: &Regex, caps: &Captures<'_, str>, name: &str, out: &mut String) -> bool {
        if let Ok(n) = name.parse::<usize>() {
            if n >= caps.len() {
                return false;
            }
            push_group(caps, n, out);
            return true;
        }
        match caps.name(name) {
            Some(group) => {
                out.push_str(group.as_str());
                true
            }
            None => regex.capture_names().flatten().any(|known| known == name),
        }
    }
}

fn push_group(caps: &Captures<'_, str>, n: usize, out: &mut String) {
    if let Some(group) = caps.get(n) {
        out.push_str(group.as_str());
    }
}

/// Built here only when [parses] refuses it, for fancy-regex's own message.
fn check(source: &str) -> Result<(), PatternError> {
    if parses(source) {
        return Ok(());
    }
    Regex::new(source)
        .map(drop)
        .map_err(|err| PatternError(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pattern_is_checked_when_read_and_built_on_first_use() {
        for bad in ["(a", r"\p{Nope}", "[z-a]", r"(?<n>a)\k<m>"] {
            assert!(Pattern::new(bad).is_err(), "{bad}");
        }
        let p = Pattern::new(r"^https://(?>a|b)(?=\.)\.c/(\w+)\1").unwrap();
        assert!(!p.is_built());
        assert!(p.is_match("https://a.c/xx"));
        assert!(p.is_built());
    }

    #[test]
    fn replaces_with_dotnet_templates() {
        let p = Pattern::new(r"^https://a\.com/(\w+)/(\d+)").unwrap();
        let got = p.replace("https://a.com/item/42", "https://b.com/$2/$1", false);
        assert_eq!(got.as_deref(), Some("https://b.com/42/item"));
        let p = Pattern::new(r"(?<k>a)(b)").unwrap();
        assert_eq!(
            p.replace("xaby", "[${k}$2$$$1x]", true).as_deref(),
            Some("x[ab$ax]y")
        );
        assert_eq!(
            p.replace("xaby", "$3 ${nope}", true).as_deref(),
            Some("x$3 ${nope}y")
        );
    }

    #[test]
    fn digits_take_the_longest_valid_group() {
        let p = Pattern::new("(a)").unwrap();
        assert_eq!(p.replace("a", "$10", true).as_deref(), Some("a0"));
    }

    #[test]
    fn first_only_and_multiline() {
        let p = Pattern::new("a").unwrap();
        assert_eq!(p.replace("aaa", "b", false).as_deref(), Some("baa"));
        let m = Pattern::multiline("^line$").unwrap();
        assert_eq!(
            m.replace("x\nline\ny", "r", true).as_deref(),
            Some("x\nr\ny")
        );
    }

    #[test]
    fn a_control_escape_matches_its_control_character() {
        let p = Pattern::new(r"^https?:\/\/res\.kfc\.com.\cn\/").unwrap();
        assert!(!p.is_match("https://res.kfc.com.cn/"));
        assert!(p.is_match("https://res.kfc.com.\u{e}/"));
        let p = Pattern::new(r"^[\ca-\cz]\\cn$").unwrap();
        assert!(p.is_match("\u{1}\\cn"));
        assert!(!p.is_match("\u{1}\u{e}"));
    }

    #[test]
    fn a_runaway_pattern_matches_nothing() {
        let p = Pattern::new(r"(a+)+\1b").unwrap();
        assert!(!p.is_match(&"a".repeat(40)));
    }
}
