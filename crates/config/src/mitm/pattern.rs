use std::borrow::Cow;
use std::fmt::Write as _;

use fancy_regex::Regex;

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

/// Compiles a line's regex to check it and drops it: the rule that runs it compiles its own.
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
    Regex::new(&regex_source(source))
        .map(drop)
        .map_err(|err| LineError::new(IssueKind::Pattern, err.to_string()))
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
