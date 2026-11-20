/// `source` in the syntax regex-syntax reads, matching at least what it matches: an atomic
/// group becomes a plain one, a lookaround goes, and a backreference matches anything.
/// Lookups and [parses](super::parses) read it; the pattern itself still runs as
/// written.
pub fn relax(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        match c {
            '\\' => {
                let next = chars.get(at + 1).copied();
                match next {
                    Some('1'..='9') => {
                        out.push_str("(?s:.*)");
                        at += 2;
                        while chars.get(at).is_some_and(char::is_ascii_digit) {
                            at += 1;
                        }
                    }
                    Some('k') if chars.get(at + 2) == Some(&'<') => {
                        out.push_str("(?s:.*)");
                        at += 3;
                        while chars.get(at).is_some_and(|c| *c != '>') {
                            at += 1;
                        }
                        at += 1;
                    }
                    Some(next) => {
                        out.push(c);
                        out.push(next);
                        at += 2;
                    }
                    None => {
                        out.push(c);
                        at += 1;
                    }
                }
            }
            '[' => {
                let end = class_end(&chars, at);
                out.extend(chars.get(at..end).unwrap_or_default());
                at = end;
            }
            '(' if chars.get(at + 1) == Some(&'?') => {
                let rest: String = chars
                    .get(at + 2..chars.len().min(at + 5))
                    .unwrap_or_default()
                    .iter()
                    .collect();
                if rest.starts_with('>') {
                    out.push_str("(?:");
                    at += 3;
                } else if rest.starts_with('=')
                    || rest.starts_with('!')
                    || rest.starts_with("<=")
                    || rest.starts_with("<!")
                {
                    at = group_end(&chars, at);
                } else {
                    out.push(c);
                    at += 1;
                }
            }
            _ => {
                out.push(c);
                at += 1;
            }
        }
    }
    out
}

/// Just past the class that opens at `start`.
fn class_end(chars: &[char], start: usize) -> usize {
    let mut at = start + 1;
    if chars.get(at) == Some(&'^') {
        at += 1;
    }
    if chars.get(at) == Some(&']') {
        at += 1;
    }
    while let Some(&c) = chars.get(at) {
        match c {
            '\\' => at += 2,
            ']' => return at + 1,
            _ => at += 1,
        }
    }
    chars.len()
}

/// Just past the group that opens at `start`.
fn group_end(chars: &[char], start: usize) -> usize {
    let mut depth = 0;
    let mut at = start;
    while let Some(&c) = chars.get(at) {
        match c {
            '\\' => at += 2,
            '[' => at = class_end(chars, at),
            '(' => {
                depth += 1;
                at += 1;
            }
            ')' => {
                depth -= 1;
                at += 1;
                if depth == 0 {
                    return at;
                }
            }
            _ => at += 1,
        }
    }
    chars.len()
}
