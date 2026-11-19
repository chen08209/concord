//! The policies a profile names without defining them.

/// Surge's and Loon's REJECT variants, built in as `REJECT` is. They reject a connection as it
/// does; the MITM engine answers a request one rejects with the body the name asks for.
pub const REJECT_REPLIES: [&str; 7] = [
    "REJECT-NO-DROP",
    "REJECT-TINYGIF",
    "REJECT-IMG",
    "REJECT-DICT",
    "REJECT-ARRAY",
    "REJECT-200",
    "REJECT-VIDEO",
];

const BASE: [&str; 7] = [
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "PASS",
    "PASS-RULE",
    "COMPATIBLE",
    "GLOBAL",
];

pub fn is_builtin(name: &str) -> bool {
    BASE.contains(&name) || REJECT_REPLIES.contains(&name)
}

pub fn names() -> impl Iterator<Item = &'static str> {
    BASE.into_iter().chain(REJECT_REPLIES)
}
