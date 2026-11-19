//! Surge's requirement expressions (manual.nssurge.com/profile/requirement.html).

use serde::Serialize;

/// The values requirement expressions read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Environment {
    /// As Surge names it (`macOS`, `iOS`, `tvOS`); empty on a system Surge does not run on.
    pub system: String,
    /// As `zh-Hans`; empty when the host gives none.
    pub language: String,
}

impl Environment {
    /// The system Concord was built for, and `language` as the host gives it.
    pub fn current(language: String) -> Environment {
        let system = if cfg!(target_os = "macos") {
            "macOS"
        } else if cfg!(target_os = "ios") {
            "iOS"
        } else if cfg!(target_os = "tvos") {
            "tvOS"
        } else {
            ""
        };
        Environment {
            system: system.to_string(),
            language,
        }
    }

    fn value_of(&self, name: &str) -> Option<Value<'_>> {
        Some(match name {
            // Surge Mac 6.10.0 (`major * 1000000 + minor * 1000 + patch`), the newest the
            // manual's Core Version list names: Concord reads every feature a check guards.
            "CORE_VERSION" => Value::Number(6_010_000.0),
            "SYSTEM" => Value::Text(&self.system),
            "LANGUAGE" => Value::Text(&self.language),
            "SYSTEM_VERSION" | "DEVICE_MODEL" | "DEVICE_NAME" => Value::Text(""),
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum Value<'a> {
    Number(f64),
    Text(&'a str),
}

/// Whether `expression` holds; `None` when it cannot be read.
pub fn evaluate(expression: &str, environment: &Environment) -> Option<bool> {
    let tokens = lex(expression.trim())?;
    if tokens.is_empty() {
        return None;
    }
    let mut reader = Reader {
        tokens,
        at: 0,
        environment,
    };
    let value = reader.or()?;
    (reader.at == reader.tokens.len()).then_some(value)
}

const SYMBOLS: [&str; 15] = [
    "&&", "||", "==", "=>", ">=", "=<", "<=", "!=", "<>", "(", ")", "=", ">", "<", "!",
];

fn lex(text: &str) -> Option<Vec<&str>> {
    let mut tokens = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() {
        let end = if let Some(symbol) = SYMBOLS.iter().find(|symbol| rest.starts_with(**symbol)) {
            symbol.len()
        } else if rest.starts_with(['\'', '"']) {
            let mark = rest.chars().next()?;
            rest.get(1..)?.find(mark)? + 2
        } else if rest.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
            rest.find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(rest.len())
        } else if rest.starts_with(|c: char| c.is_ascii_digit() || c == '-') {
            let digits = rest.get(1..)?;
            1 + digits
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .unwrap_or(digits.len())
        } else {
            return None;
        };
        let (token, tail) = rest.split_at_checked(end)?;
        tokens.push(token);
        rest = tail.trim_start();
    }
    Some(tokens)
}

const COMPARISONS: [&str; 15] = [
    "=",
    "==",
    ">=",
    "=>",
    "<=",
    "=<",
    ">",
    "<",
    "!=",
    "<>",
    "BEGINSWITH",
    "CONTAINS",
    "ENDSWITH",
    "LIKE",
    "MATCHES",
];

struct Reader<'a> {
    tokens: Vec<&'a str>,
    at: usize,
    environment: &'a Environment,
}

impl<'a> Reader<'a> {
    fn take(&mut self, words: &[&str]) -> bool {
        let found = self
            .tokens
            .get(self.at)
            .is_some_and(|token| words.iter().any(|word| token.eq_ignore_ascii_case(word)));
        if found {
            self.at += 1;
        }
        found
    }

    fn next(&mut self) -> Option<&'a str> {
        let token = self.tokens.get(self.at).copied()?;
        self.at += 1;
        Some(token)
    }

    /// Both sides are read whatever the first gives, so that an unreadable one is found.
    fn or(&mut self) -> Option<bool> {
        let mut value = self.and()?;
        while self.take(&["||", "OR"]) {
            value = self.and()? || value;
        }
        Some(value)
    }

    fn and(&mut self) -> Option<bool> {
        let mut value = self.not()?;
        while self.take(&["&&", "AND"]) {
            value = self.not()? && value;
        }
        Some(value)
    }

    fn not(&mut self) -> Option<bool> {
        if self.take(&["!", "NOT"]) {
            return self.not().map(|value| !value);
        }
        if self.take(&["("]) {
            let value = self.or()?;
            return self.take(&[")"]).then_some(value);
        }
        let left = self.operand()?;
        let operator = self.next()?.to_ascii_uppercase();
        if !COMPARISONS.contains(&operator.as_str()) {
            return None;
        }
        let right = self.operand()?;
        compare(left, &operator, right)
    }

    fn operand(&mut self) -> Option<Value<'a>> {
        let token = self.next()?;
        for mark in ['\'', '"'] {
            if token.len() >= 2
                && let Some(text) = token.strip_prefix(mark).and_then(|t| t.strip_suffix(mark))
            {
                return Some(Value::Text(text));
            }
        }
        if let Ok(number) = token.parse::<f64>() {
            return Some(Value::Number(number));
        }
        self.environment.value_of(token)
    }
}

fn compare(left: Value<'_>, operator: &str, right: Value<'_>) -> Option<bool> {
    if let (Value::Number(a), Value::Number(b)) = (left, right) {
        return Some(match operator {
            "=" | "==" => a == b,
            "!=" | "<>" => a != b,
            ">=" | "=>" => a >= b,
            "<=" | "=<" => a <= b,
            ">" => a > b,
            "<" => a < b,
            _ => return None,
        });
    }
    let (a, b) = (text(left), text(right));
    Some(match operator {
        "=" | "==" => a == b,
        "!=" | "<>" => a != b,
        ">=" | "=>" => a >= b,
        "<=" | "=<" => a <= b,
        ">" => a > b,
        "<" => a < b,
        "BEGINSWITH" => a.starts_with(b.as_str()),
        "CONTAINS" => a.contains(b.as_str()),
        "ENDSWITH" => a.ends_with(b.as_str()),
        "LIKE" => like(&a, &b),
        _ => regex::Regex::new(&format!("^(?:{b})$")).ok()?.is_match(&a),
    })
}

fn text(value: Value<'_>) -> String {
    match value {
        Value::Number(number) => number.to_string(),
        Value::Text(text) => text.to_string(),
    }
}

/// `*` for any run and `?` for any one character.
fn like(text: &str, pattern: &str) -> bool {
    let pattern = regex::escape(pattern)
        .replace(r"\*", ".*")
        .replace(r"\?", ".");
    regex::Regex::new(&format!("(?s)^{pattern}$")).is_ok_and(|re| re.is_match(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(system: &str) -> Environment {
        Environment {
            system: system.to_string(),
            language: "zh-Hans".to_string(),
        }
    }

    #[test]
    fn expressions_read_as_surge_writes_them() {
        let mac = env("macOS");
        for (expression, want) in [
            ("CORE_VERSION>=20", Some(true)),
            ("CORE_VERSION < 20", Some(false)),
            ("SYSTEM == 'macOS'", Some(true)),
            ("SYSTEM = \"iOS\" || SYSTEM = 'macOS'", Some(true)),
            ("NOT (SYSTEM == 'iOS') AND CORE_VERSION > 5", Some(true)),
            ("!(LANGUAGE BEGINSWITH 'zh')", Some(false)),
            ("LANGUAGE LIKE 'zh-*'", Some(true)),
            ("LANGUAGE MATCHES 'zh-H.ns'", Some(true)),
            ("SYSTEM_VERSION != ''", Some(false)),
            ("UNKNOWN == 1", None),
            ("SYSTEM ==", None),
            ("(SYSTEM == 'macOS'", None),
            ("", None),
        ] {
            assert_eq!(evaluate(expression, &mac), want, "{expression}");
        }
        assert_eq!(evaluate("SYSTEM == 'macOS'", &env("")), Some(false));
    }
}
