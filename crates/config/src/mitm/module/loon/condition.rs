//! A Loon condition read into the URL pattern and the head patterns Concord matches a rule by.
//! Plugin arguments are known when the module is read, so a test on one is decided then.

use fancy_regex::Regex;
use regex::escape;
use serde_json::Value;

use super::lexer::Token;
use super::{Cursor, Refusal, Scope, condition, unreadable};

#[derive(Debug)]
enum Cond {
    Any(Vec<Cond>),
    All(Vec<Cond>),
    Test(Test),
    Known(bool),
}

#[derive(Debug)]
struct Test {
    subject: Subject,
    check: Check,
    capture: Option<String>,
    /// The groups a URL regex captures.
    groups: Option<usize>,
}

#[derive(Debug, PartialEq)]
enum Subject {
    Url,
    Method,
    Status,
    Header { response: bool, name: String },
}

#[derive(Debug)]
enum Check {
    /// `None` is `null`: the header is absent.
    Equals(Option<String>),
    Finds(String),
}

/// What a rule matches: a regex over the URL, and over each head a regex of lookaheads.
#[derive(Debug, Default, PartialEq)]
pub(super) struct Match {
    pub url: String,
    /// The one URL regex every match passes, which `url.replace` and `redirect` rewrite.
    pub single_url: bool,
    /// Some URL regex is part of every match, as a response script needs.
    pub url_guard: bool,
    pub request: Option<String>,
    pub response: Option<String>,
}

/// `if` up to `then`; `None` when the arguments rule the line out.
pub(super) fn read(
    cursor: &mut Cursor,
    scope: &mut Scope<'_>,
    response: bool,
) -> Result<Option<Match>, Refusal> {
    let tree = any(cursor, scope, response)?;
    match fold(tree) {
        Cond::Known(false) => Ok(None),
        Cond::Known(true) => Ok(Some(Match {
            url: "^".to_string(),
            ..Match::default()
        })),
        tree => translate(tree, scope).map(Some),
    }
}

fn any(cursor: &mut Cursor, scope: &mut Scope<'_>, response: bool) -> Result<Cond, Refusal> {
    let mut branches = vec![all(cursor, scope, response)?];
    while cursor.symbol("||") {
        branches.push(all(cursor, scope, response)?);
    }
    Ok(if branches.len() == 1 {
        branches.remove(0)
    } else {
        Cond::Any(branches)
    })
}

fn all(cursor: &mut Cursor, scope: &mut Scope<'_>, response: bool) -> Result<Cond, Refusal> {
    let mut items = Vec::new();
    loop {
        if cursor.symbol("(") {
            items.push(any(cursor, scope, response)?);
            cursor.expect(")")?;
        } else {
            items.push(test(cursor, scope, response)?);
        }
        if !cursor.symbol("&&") {
            break;
        }
    }
    Ok(if items.len() == 1 {
        items.remove(0)
    } else {
        Cond::All(items)
    })
}

fn test(cursor: &mut Cursor, scope: &mut Scope<'_>, response: bool) -> Result<Cond, Refusal> {
    let Some(Token::Var(variable)) = cursor.next() else {
        return Err(unreadable("a test starts with a ${variable}"));
    };
    let operator = match cursor.next() {
        Some(Token::Symbol(op @ ("==" | "~="))) => op,
        _ => return Err(unreadable("a test compares with == or ~=")),
    };
    let value = cursor
        .next()
        .ok_or_else(|| unreadable("a test needs a value"))?;
    let capture = if cursor.word("as") {
        match cursor.next() {
            Some(Token::Word(name)) => Some(name),
            _ => return Err(unreadable("as needs a name")),
        }
    } else {
        None
    };
    if capture.is_some() && operator != "~=" {
        return Err(unreadable("as follows a ~= test"));
    }
    let subject = match subject(&variable) {
        Some(subject) => subject,
        None => return argument_test(scope, &variable, operator, &value).map(Cond::Known),
    };
    let on_response = matches!(
        subject,
        Subject::Status | Subject::Header { response: true, .. }
    );
    if on_response && !response {
        return Err(unreadable(format!(
            "a request rule cannot read ${{{variable}}}"
        )));
    }
    let check = if operator == "~=" {
        Check::Finds(regex_value(scope, &value)?)
    } else {
        match (&subject, value) {
            (Subject::Status, Token::Number(status)) => Check::Equals(Some(status)),
            (Subject::Header { .. }, Token::Word(word)) if word == "null" => Check::Equals(None),
            (Subject::Status, _) => return Err(unreadable("a status compares with a number")),
            (_, value) => Check::Equals(Some(scope.string(&value)?)),
        }
    };
    let groups = match (&capture, &subject, &check) {
        (Some(_), Subject::Url, Check::Finds(source)) => Some(groups(source)?),
        _ => None,
    };
    Ok(Cond::Test(Test {
        subject,
        check,
        capture,
        groups,
    }))
}

fn subject(variable: &str) -> Option<Subject> {
    Some(match variable {
        "url" => Subject::Url,
        "request.method" => Subject::Method,
        "response.status" => Subject::Status,
        _ => {
            let (side, rest) = variable.split_once(".header[")?;
            let name = rest
                .strip_suffix(']')?
                .trim()
                .trim_matches(|c| c == '\'' || c == '"')
                .to_string();
            let response = match side {
                "request" => false,
                "response" => true,
                _ => return None,
            };
            Subject::Header { response, name }
        }
    })
}

/// A test on a plugin argument, decided now as the argument's value is known.
fn argument_test(
    scope: &Scope<'_>,
    name: &str,
    operator: &str,
    value: &Token,
) -> Result<bool, Refusal> {
    let actual = scope.argument(name)?;
    if operator == "~=" {
        let Value::String(text) = &actual else {
            return Err(unreadable(format!("${{{name}}} is not a string to match")));
        };
        let source = regex_value(scope, value)?;
        let regex = Regex::new(&source).map_err(|err| unreadable(err.to_string()))?;
        return regex
            .is_match(text)
            .map_err(|err| unreadable(err.to_string()));
    }
    let expected = match value {
        Token::Number(text) => serde_json::from_str::<Value>(text).ok(),
        Token::Word(word) if word == "true" || word == "false" => Some(Value::Bool(word == "true")),
        Token::Var(other) => Some(scope.argument(other)?),
        other => scope.string(other).ok().map(Value::String),
    };
    let expected = expected.ok_or_else(|| unreadable(format!("${{{name}}} == ?")))?;
    let same_type = std::mem::discriminant(&expected) == std::mem::discriminant(&actual);
    if !same_type {
        return Err(unreadable(format!(
            "${{{name}}} is compared with another type"
        )));
    }
    Ok(match (&expected, &actual) {
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        _ => expected == actual,
    })
}

/// The right of `~=`: a regex as written, or a string argument holding one.
fn regex_value(scope: &Scope<'_>, value: &Token) -> Result<String, Refusal> {
    match value {
        Token::Regex { source, flags } => Ok(scoped(source, flags)),
        Token::Var(name) => match scope.argument(name)? {
            Value::String(source) => Ok(source),
            _ => Err(unreadable(format!("${{{name}}} is not a string regex"))),
        },
        _ => Err(unreadable("~= takes a regex")),
    }
}

pub(super) fn scoped(source: &str, flags: &str) -> String {
    if flags.is_empty() {
        source.to_string()
    } else {
        format!("(?{flags}:{source})")
    }
}

fn groups(source: &str) -> Result<usize, Refusal> {
    let regex = Regex::new(source).map_err(|err| unreadable(err.to_string()))?;
    Ok(regex.captures_len().saturating_sub(1))
}

fn fold(cond: Cond) -> Cond {
    match cond {
        Cond::All(items) => {
            let mut kept = Vec::new();
            for item in items.into_iter().map(fold) {
                match item {
                    Cond::Known(true) => {}
                    Cond::Known(false) => return Cond::Known(false),
                    item => kept.push(item),
                }
            }
            match kept.len() {
                0 => Cond::Known(true),
                1 => kept.remove(0),
                _ => Cond::All(kept),
            }
        }
        Cond::Any(branches) => {
            let mut kept = Vec::new();
            for branch in branches.into_iter().map(fold) {
                match branch {
                    Cond::Known(false) => {}
                    Cond::Known(true) => return Cond::Known(true),
                    branch => kept.push(branch),
                }
            }
            match kept.len() {
                0 => Cond::Known(false),
                1 => kept.remove(0),
                _ => Cond::Any(kept),
            }
        }
        other => other,
    }
}

/// A part of a condition as Concord tests it: on the URL, or as a lookahead over one head.
enum Piece {
    Url { regex: String, plain: bool },
    Head { response: bool, lookahead: String },
}

fn translate(tree: Cond, scope: &mut Scope<'_>) -> Result<Match, Refusal> {
    let items = match tree {
        Cond::All(items) => items,
        other => vec![other],
    };
    let mut urls = Vec::new();
    let mut plain_urls = 0;
    let (mut request, mut response) = (Vec::new(), Vec::new());
    let mut captures = Vec::new();
    for item in items {
        if let Cond::Test(Test {
            capture: Some(name),
            groups,
            ..
        }) = &item
        {
            captures.push((name.clone(), *groups));
        }
        match piece(item)? {
            Piece::Url { regex, plain } => {
                plain_urls += usize::from(plain);
                urls.push(regex);
            }
            Piece::Head {
                response: true,
                lookahead,
            } => response.push(lookahead),
            Piece::Head { lookahead, .. } => request.push(lookahead),
        }
    }
    let single_url = urls.len() == 1 && plain_urls == 1;
    for (name, groups) in captures {
        scope.capture(&name, groups.filter(|_| single_url))?;
    }
    let head = |lookaheads: Vec<String>| {
        (!lookaheads.is_empty()).then(|| format!("^{}", lookaheads.concat()))
    };
    Ok(Match {
        single_url,
        url_guard: !urls.is_empty(),
        url: match urls.len() {
            0 => "^".to_string(),
            1 => urls.remove(0),
            _ => all_of(&urls),
        },
        request: head(request),
        response: head(response),
    })
}

fn all_of(regexes: &[String]) -> String {
    let lookaheads: String = regexes
        .iter()
        .map(|regex| format!("(?=[\\s\\S]*?(?:{regex}))"))
        .collect();
    format!("^{lookaheads}")
}

fn piece(cond: Cond) -> Result<Piece, Refusal> {
    match cond {
        Cond::Test(test) => Ok(test_piece(test)),
        Cond::All(items) => {
            let pieces = items
                .into_iter()
                .map(piece)
                .collect::<Result<Vec<_>, _>>()?;
            join(pieces, false)
        }
        Cond::Any(branches) => {
            let pieces = branches
                .into_iter()
                .map(piece)
                .collect::<Result<Vec<_>, _>>()?;
            join(pieces, true)
        }
        Cond::Known(_) => Err(condition("a test left after folding")),
    }
}

/// Pieces that must all pass, or with `any` that one must, as one: Concord tests the URL
/// and each head apart, so the pieces must all be on one of them.
fn join(pieces: Vec<Piece>, any: bool) -> Result<Piece, Refusal> {
    if pieces
        .iter()
        .all(|piece| matches!(piece, Piece::Url { .. }))
    {
        let regexes: Vec<String> = pieces
            .into_iter()
            .filter_map(|piece| match piece {
                Piece::Url { regex, .. } => Some(regex),
                Piece::Head { .. } => None,
            })
            .collect();
        let regex = if any {
            regexes
                .iter()
                .map(|regex| format!("(?:{regex})"))
                .collect::<Vec<_>>()
                .join("|")
        } else {
            all_of(&regexes)
        };
        return Ok(Piece::Url {
            regex,
            plain: false,
        });
    }
    let mut side = None;
    let mut lookaheads = Vec::new();
    for piece in pieces {
        let Piece::Head {
            response,
            lookahead,
        } = piece
        else {
            return Err(condition("|| or a group mixes the URL with a head"));
        };
        if side.is_some_and(|side| side != response) {
            return Err(condition(
                "|| or a group mixes the request and the response",
            ));
        }
        side = Some(response);
        lookaheads.push(lookahead);
    }
    let lookahead = if any {
        format!("(?:{})", lookaheads.join("|"))
    } else {
        lookaheads.concat()
    };
    Ok(Piece::Head {
        response: side.unwrap_or_default(),
        lookahead,
    })
}

fn test_piece(test: Test) -> Piece {
    let Test { subject, check, .. } = test;
    let (response, lookahead) = match subject {
        Subject::Url => {
            let regex = match check {
                Check::Equals(value) => format!("^{}$", escape(&value.unwrap_or_default())),
                Check::Finds(regex) => regex,
            };
            return Piece::Url { regex, plain: true };
        }
        Subject::Method => (
            false,
            match check {
                Check::Equals(value) => format!("(?={} )", escape(&value.unwrap_or_default())),
                Check::Finds(regex) => {
                    format!("(?=[^ ]*?(?:{})[^ ]* )", anchored(&regex, "^", "(?= )"))
                }
            },
        ),
        Subject::Status => (
            true,
            match check {
                Check::Equals(value) => {
                    format!(
                        "(?=\\S+ {}(?: |\\r\\n))",
                        escape(&value.unwrap_or_default())
                    )
                }
                Check::Finds(regex) => format!(
                    "(?=\\S+ \\d*?(?:{})\\d*(?: |\\r\\n))",
                    anchored(&regex, "(?<= )", "(?=[ \\r])")
                ),
            },
        ),
        Subject::Header { response, name } => {
            let name = format!("(?i:{})", escape(&name));
            (
                response,
                match check {
                    Check::Equals(None) => format!("(?![\\s\\S]*\\r\\n{name}:)"),
                    Check::Equals(Some(value)) => {
                        format!("(?=[\\s\\S]*\\r\\n{name}: {}\\r\\n)", escape(&value))
                    }
                    Check::Finds(regex) => format!(
                        "(?=[\\s\\S]*\\r\\n{name}: [^\\r\\n]*?(?:{})[^\\r\\n]*\\r\\n)",
                        anchored(&regex, &format!("(?<=\\n{name}: )"), "(?=\\r\\n)")
                    ),
                },
            )
        }
    };
    Piece::Head {
        response,
        lookahead,
    }
}

/// `regex` with its `^` and `$` outside classes standing for the start and end of the value
/// it is found in, as Loon reads them; a head holds that value amid other lines.
fn anchored(regex: &str, start: &str, end: &str) -> String {
    let mut out = String::with_capacity(regex.len());
    let mut class = false;
    let mut chars = regex.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                out.push(c);
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            '[' if !class => {
                class = true;
                out.push(c);
            }
            ']' if class => {
                class = false;
                out.push(c);
            }
            '^' if !class => out.push_str(start),
            '$' if !class => out.push_str(end),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchors_stand_for_the_value() {
        assert_eq!(anchored(r"^a(?:;|$)[\^$]\$", "<", ">"), r"<a(?:;|>)[\^$]\$");
    }

    #[test]
    fn a_header_regex_anchored_with_an_alternation_matches_its_header() {
        let piece = test_piece(Test {
            subject: Subject::Header {
                response: true,
                name: "Content-Type".into(),
            },
            check: Check::Finds(scoped(r"^application\/json(?:;|$)", "i")),
            capture: None,
            groups: None,
        });
        let Piece::Head { lookahead, .. } = piece else {
            panic!("not a head piece");
        };
        let regex = Regex::new(&format!("^{lookahead}")).unwrap();
        let head = |value: &str| {
            format!("HTTP/1.1 200 OK\r\nX-A: application/json\r\nContent-Type: {value}\r\n")
        };
        assert!(
            regex
                .is_match(&head("application/json; charset=utf-8"))
                .unwrap()
        );
        assert!(regex.is_match(&head("APPLICATION/JSON")).unwrap());
        assert!(!regex.is_match(&head("text/application/json")).unwrap());
        assert!(!regex.is_match(&head("application/jsonp")).unwrap());
    }
}
