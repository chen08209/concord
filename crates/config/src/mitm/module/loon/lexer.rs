//! Tokens of Loon's new Rewrite and Script syntax (Rewrite/rewrite_v2, Script/script_v2).

use crate::mitm::module::Unreadable;

/// A piece of a double-quoted string: text as written, escapes read, or a `${...}` to fill.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Part {
    Text(String),
    Var(String),
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Token {
    Word(String),
    Var(String),
    /// A double-quoted string, which fills its variables.
    Template(Vec<Part>),
    /// A backquoted string, taken as written.
    Raw(String),
    Regex {
        source: String,
        flags: String,
    },
    Number(String),
    Symbol(&'static str),
    /// `{${a}, ${b}}`: the arguments a script gets as an object, by name.
    Object(Vec<String>),
}

const SYMBOLS: [&str; 11] = ["==", "~=", "&&", "||", "(", ")", ",", "[", "]", "|", "="];

pub(super) fn lex(line: &str) -> Result<Vec<Token>, Unreadable> {
    let mut lexer = Lexer { line, at: 0 };
    let mut tokens = Vec::new();
    while let Some(c) = lexer.peek() {
        if c == ' ' || c == '\t' {
            lexer.at += 1;
            continue;
        }
        tokens.push(lexer.token(c)?);
    }
    Ok(tokens)
}

struct Lexer<'a> {
    line: &'a str,
    at: usize,
}

impl<'a> Lexer<'a> {
    fn rest(&self) -> &'a str {
        self.line.get(self.at..).unwrap_or_default()
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn token(&mut self, c: char) -> Result<Token, Unreadable> {
        if self.rest().starts_with("${") {
            return self.variable().map(Token::Var);
        }
        match c {
            '"' => self.template(),
            '`' => self.raw(),
            '/' => self.regex(),
            '{' => self.object(),
            '-' | '0'..='9' => self.number(),
            c if c.is_ascii_alphabetic() || c == '_' => Ok(self.word()),
            _ => {
                let symbol = SYMBOLS
                    .into_iter()
                    .find(|symbol| self.rest().starts_with(symbol))
                    .ok_or_else(|| format!("unexpected {c:?}"))?;
                self.at += symbol.len();
                Ok(Token::Symbol(symbol))
            }
        }
    }

    /// The name inside `${...}`, which may hold `['Header-Name']`.
    fn variable(&mut self) -> Result<String, Unreadable> {
        let rest = self.rest();
        let end = rest.find('}').ok_or("unclosed ${")?;
        let name = rest.get(2..end).unwrap_or_default().trim().to_string();
        self.at += end + 1;
        if name.is_empty() {
            return Err("empty ${}".into());
        }
        Ok(name)
    }

    fn template(&mut self) -> Result<Token, Unreadable> {
        self.at += 1;
        let mut parts = Vec::new();
        let mut text = String::new();
        loop {
            let rest = self.rest();
            let Some(c) = rest.chars().next() else {
                return Err("unclosed string".into());
            };
            if c == '"' {
                self.at += 1;
                break;
            }
            if rest.starts_with("${") {
                if !text.is_empty() {
                    parts.push(Part::Text(std::mem::take(&mut text)));
                }
                parts.push(Part::Var(self.variable()?));
                continue;
            }
            if c == '\\' {
                let rest = rest.get(1..).unwrap_or_default();
                if rest.starts_with("${") {
                    text.push_str("${");
                    self.at += 3;
                    continue;
                }
                let escaped = rest.chars().next().ok_or("unclosed string")?;
                text.push(match escaped {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    other => other,
                });
                self.at += 1 + escaped.len_utf8();
                continue;
            }
            text.push(c);
            self.at += c.len_utf8();
        }
        if !text.is_empty() || parts.is_empty() {
            parts.push(Part::Text(text));
        }
        Ok(Token::Template(parts))
    }

    fn raw(&mut self) -> Result<Token, Unreadable> {
        self.at += 1;
        let mut text = String::new();
        loop {
            let rest = self.rest();
            if rest.starts_with("``") {
                text.push('`');
                self.at += 2;
                continue;
            }
            let c = rest.chars().next().ok_or("unclosed raw string")?;
            self.at += c.len_utf8();
            if c == '`' {
                return Ok(Token::Raw(text));
            }
            text.push(c);
        }
    }

    /// `/source/flags`: a slash inside a class or after a backslash is the regex's own.
    fn regex(&mut self) -> Result<Token, Unreadable> {
        let body = self.rest().get(1..).unwrap_or_default();
        let mut class = false;
        let mut escaped = false;
        let mut end = None;
        for (at, c) in body.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '[' => class = true,
                ']' => class = false,
                '/' if !class => {
                    end = Some(at);
                    break;
                }
                _ => {}
            }
        }
        let end = end.ok_or("unclosed regex")?;
        let source = body.get(..end).unwrap_or_default().to_string();
        let after = body.get(end + 1..).unwrap_or_default();
        let flags: String = after
            .chars()
            .take_while(|c| matches!(c, 'i' | 'm' | 's'))
            .collect();
        self.at += 1 + end + 1 + flags.len();
        Ok(Token::Regex { source, flags })
    }

    fn object(&mut self) -> Result<Token, Unreadable> {
        self.at += 1;
        let mut names = Vec::new();
        loop {
            self.skip_spaces();
            if !self.rest().starts_with("${") {
                return Err("an object argument lists ${name}s".into());
            }
            names.push(self.variable()?);
            self.skip_spaces();
            match self.peek() {
                Some(',') => self.at += 1,
                Some('}') => {
                    self.at += 1;
                    return Ok(Token::Object(names));
                }
                _ => return Err("unclosed object argument".into()),
            }
        }
    }

    fn skip_spaces(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.at += 1;
        }
    }

    fn number(&mut self) -> Result<Token, Unreadable> {
        let rest = self.rest();
        let len = rest
            .char_indices()
            .take_while(|&(at, c)| {
                c.is_ascii_digit()
                    || matches!(c, '.' | 'e' | 'E' | '+')
                    || (c == '-' && at == 0)
                    || (c == '-'
                        && rest
                            .get(..at)
                            .is_some_and(|head| head.ends_with(['e', 'E'])))
            })
            .count();
        let text = rest.get(..len).unwrap_or_default();
        if text.parse::<f64>().is_err() {
            return Err(format!("invalid number {text:?}").into());
        }
        self.at += len;
        Ok(Token::Number(text.to_string()))
    }

    fn word(&mut self) -> Token {
        let rest = self.rest();
        let len = rest
            .char_indices()
            .find(|&(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')))
            .map_or(rest.len(), |(at, _)| at);
        self.at += len;
        Token::Word(rest.get(..len).unwrap_or_default().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_lexes_into_its_tokens() {
        let tokens = lex(
            r#"request if ${url} ~= /^https:\/\/a[/]b/i as item && ${request.header['X-A']} == "v ${p}\n\${x}" then script("a.js", {${a}, ${b}}) | f(`r``aw`, -1.5e3)"#,
        )
        .unwrap();
        assert_eq!(
            tokens,
            [
                Token::Word("request".into()),
                Token::Word("if".into()),
                Token::Var("url".into()),
                Token::Symbol("~="),
                Token::Regex {
                    source: r"^https:\/\/a[/]b".into(),
                    flags: "i".into()
                },
                Token::Word("as".into()),
                Token::Word("item".into()),
                Token::Symbol("&&"),
                Token::Var("request.header['X-A']".into()),
                Token::Symbol("=="),
                Token::Template(vec![
                    Part::Text("v ".into()),
                    Part::Var("p".into()),
                    Part::Text("\n${x}".into()),
                ]),
                Token::Word("then".into()),
                Token::Word("script".into()),
                Token::Symbol("("),
                Token::Template(vec![Part::Text("a.js".into())]),
                Token::Symbol(","),
                Token::Object(vec!["a".into(), "b".into()]),
                Token::Symbol(")"),
                Token::Symbol("|"),
                Token::Word("f".into()),
                Token::Symbol("("),
                Token::Raw("r`aw".into()),
                Token::Symbol(","),
                Token::Number("-1.5e3".into()),
                Token::Symbol(")"),
            ]
        );
        assert!(lex(r#"a "unclosed"#).is_err());
        assert!(lex("f({})").is_err());
        assert_eq!(
            lex(r#""""#).unwrap(),
            [Token::Template(vec![Part::Text(String::new())])]
        );
    }
}
