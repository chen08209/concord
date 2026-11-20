use std::borrow::Cow;
use std::fmt::Write as _;

use fancy_regex::{Expr, Regex};

use super::issue::{IssueKind, LineError};

/// A line's regex as fancy-regex takes it. ICU (Apple's NSRegularExpression) and ECMAScript
/// read `\cX` as the control character X & 0x1F, which fancy-regex rejects as an escape.
pub fn regex_source(pattern: &str) -> Cow<'_, str> {
    if !pattern.contains("\\c") {
        return Cow::Borrowed(pattern);
    }
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('c') => match chars.next_if(char::is_ascii_alphabetic) {
                Some(letter) => {
                    let _ = write!(out, "\\x{:02X}", u32::from(letter) & 0x1F);
                }
                None => out.push_str("\\c"),
            },
            Some(next) => {
                out.push('\\');
                out.push(next);
            }
            None => out.push('\\'),
        }
    }
    Cow::Owned(out)
}

/// Checks a line's regex, building it only when [parses] refuses it, for fancy-regex's own
/// message: the rule that runs it builds its own on first use.
pub fn check_pattern(pattern: &str) -> Result<(), LineError> {
    compile(pattern)
}

/// The flag a body regex is compiled with, so that it matches line by line.
pub const MULTILINE: &str = "(?m)";

pub fn multiline(pattern: &str) -> String {
    format!("{MULTILINE}{pattern}")
}

/// As [check_pattern] for a body regex.
pub fn check_multiline(pattern: &str) -> Result<(), LineError> {
    compile(&multiline(pattern))
}

fn compile(source: &str) -> Result<(), LineError> {
    let source = regex_source(source);
    if parses(&source) {
        return Ok(());
    }
    Regex::new(&source)
        .map(drop)
        .map_err(|err| LineError::new(IssueKind::Pattern, err.to_string()))
}

/// Whether both parsers take a regex, as fancy-regex's source: parsing is a small part of
/// building one, and a module lists thousands. One they pass whose build still fails, past a
/// size limit, matches nothing.
pub fn parses(source: &str) -> bool {
    Expr::parse_tree(source).is_ok() && regex_syntax::parse(&super::relax(source)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_control_escape_compiles() {
        check_pattern(r"(?i:^https?:\/\/res\.kfc\.com.\cn\/advertisement\/)").unwrap();
        check_pattern(r"[\cA-\cZ]").unwrap();
        check_multiline(r"^\cJ").unwrap();
    }
}
