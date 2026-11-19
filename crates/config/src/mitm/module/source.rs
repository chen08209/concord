/// The lines of `text` with their numbers from 1, ending at `\r\n`, `\r` or `\n`.
pub(super) fn numbered(text: &str) -> impl Iterator<Item = (u32, &str)> {
    let mut rest = Some(text);
    let mut number = 0u32;
    std::iter::from_fn(move || {
        let text = rest?;
        number = number.saturating_add(1);
        let Some(end) = text.find(['\r', '\n']) else {
            rest = None;
            return Some((number, text));
        };
        let (line, tail) = text.split_at(end);
        rest = Some(
            tail.strip_prefix("\r\n")
                .or_else(|| tail.get(1..))
                .unwrap_or_default(),
        );
        Some((number, line))
    })
}

/// The name of a `[Section]` line, trimmed.
pub(super) fn section_name(line: &str) -> Option<&str> {
    let inner = line.strip_prefix('[')?.strip_suffix(']')?;
    (!inner.contains(']')).then(|| inner.trim())
}

pub(super) fn is_comment(line: &str) -> bool {
    line.starts_with('#') || line.starts_with(';') || line.starts_with("//")
}

/// What decides whether a line applies: Surge's requirement expression, or the system one of
/// its `#!IOS-ONLY` marks names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LineRequirement<'a> {
    Expression(&'a str),
    System(&'static str),
}

/// A line with its Surge requirement taken off, in the start-of-line form
/// `#!REQUIREMENT <expr> <line>` or the end-of-line one (`<line> //!REQUIREMENT <expr>`).
pub(super) fn split_requirement(line: &str) -> (&str, Option<LineRequirement<'_>>) {
    if let Some(rest) = line.strip_prefix("#!REQUIREMENT")
        && rest.starts_with([' ', '\t'])
        && let Some((expression, rest)) = expression(rest.trim_start())
        && rest.starts_with([' ', '\t'])
    {
        return (rest.trim(), Some(LineRequirement::Expression(expression)));
    }
    for (at, mark) in line.rmatch_indices("!") {
        let Some((head, tail)) = line.split_at_checked(at + mark.len()) else {
            continue;
        };
        let head = head.strip_suffix('!').unwrap_or(head);
        let Some(head) = head.strip_suffix('#').or_else(|| head.strip_suffix("//")) else {
            continue;
        };
        if !head.ends_with([' ', '\t']) {
            continue;
        }
        if let Some(requirement) = trailing(tail) {
            return (head.trim(), Some(requirement));
        }
    }
    (line, None)
}

fn trailing(tail: &str) -> Option<LineRequirement<'_>> {
    let tail = tail.trim_end();
    if let Some(rest) = tail.strip_prefix("REQUIREMENT")
        && rest.starts_with([' ', '\t'])
    {
        let (expression, rest) = expression(rest.trim_start())?;
        return rest
            .is_empty()
            .then_some(LineRequirement::Expression(expression));
    }
    Some(LineRequirement::System(match tail {
        "IOS-ONLY" => "iOS",
        "MACOS-ONLY" => "macOS",
        "TVOS-ONLY" => "tvOS",
        _ => return None,
    }))
}

/// A quoted run without its quotes, or a run without spaces, and what follows it.
fn expression(text: &str) -> Option<(&str, &str)> {
    if let Some(quoted) = text.strip_prefix('"') {
        let end = quoted.find('"')?;
        return Some((quoted.get(..end)?, quoted.get(end + 1..)?));
    }
    let end = text.find([' ', '\t']).unwrap_or(text.len());
    let (expression, rest) = text.split_at(end);
    (!expression.is_empty()).then_some((expression, rest))
}

/// Without one pair of surrounding double or single quotes.
pub(super) fn unquote(text: &str) -> &str {
    for mark in ['"', '\''] {
        if text.len() >= 2
            && let Some(inner) = text.strip_prefix(mark).and_then(|t| t.strip_suffix(mark))
        {
            return inner;
        }
    }
    text
}

/// `text` split on the commas outside double quotes, each part trimmed; empty parts are kept.
pub(super) fn split_commas(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (at, c) in text.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parts.push(text.get(start..at).unwrap_or_default().trim());
                start = at + 1;
            }
            _ => {}
        }
    }
    parts.push(text.get(start..).unwrap_or_default().trim());
    parts
}

/// `key = value` with both sides trimmed and the key in lower case.
pub(super) fn key_value(line: &str) -> Option<(String, &str)> {
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    (!key.is_empty()).then(|| (key.to_ascii_lowercase(), value.trim()))
}

/// The value without a leading `%APPEND%` or `%INSERT%`, and which it was.
pub(super) fn list_mark(value: &str) -> (ListMark, &str) {
    if let Some(rest) = value.strip_prefix("%INSERT%") {
        (ListMark::Insert, rest.trim())
    } else if let Some(rest) = value.strip_prefix("%APPEND%") {
        (ListMark::Append, rest.trim())
    } else {
        (ListMark::Plain, value)
    }
}

/// How a module's list combines with the profile's: Surge's `%INSERT%` and `%APPEND%`, or
/// neither, which replaces the profile's in Surge and appends to it in Loon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ListMark {
    Plain,
    Insert,
    Append,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_end_at_every_line_break() {
        let lines: Vec<_> = numbered("a\r\nb\rc\n\nd").collect();
        assert_eq!(lines, [(1, "a"), (2, "b"), (3, "c"), (4, ""), (5, "d")]);
    }

    #[test]
    fn requirements_come_off_either_end() {
        assert_eq!(
            split_requirement("#!REQUIREMENT CORE_VERSION>=20 a = b"),
            (
                "a = b",
                Some(LineRequirement::Expression("CORE_VERSION>=20"))
            )
        );
        assert_eq!(
            split_requirement(r#"#!REQUIREMENT "SYSTEM == 'iOS'" a = b"#),
            (
                "a = b",
                Some(LineRequirement::Expression("SYSTEM == 'iOS'"))
            )
        );
        assert_eq!(
            split_requirement("a = b //!REQUIREMENT CORE_VERSION>=20"),
            (
                "a = b",
                Some(LineRequirement::Expression("CORE_VERSION>=20"))
            )
        );
        assert_eq!(
            split_requirement("a = b #!MACOS-ONLY"),
            ("a = b", Some(LineRequirement::System("macOS")))
        );
        assert_eq!(split_requirement("a = b"), ("a = b", None));
        assert_eq!(
            split_requirement("a=b#!MACOS-ONLY"),
            ("a=b#!MACOS-ONLY", None)
        );
    }

    #[test]
    fn sections_and_commas() {
        assert_eq!(section_name("[ Map Local ]"), Some("Map Local"));
        assert_eq!(section_name("[a]b]"), None);
        assert_eq!(split_commas(r#"a, "b,c" ,"#), ["a", r#""b,c""#, ""]);
    }
}
