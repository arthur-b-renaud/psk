//! Secret-like detector: data-driven token rules (`rules.toml`) plus
//! validated PII rules (IBAN, card, phone, email).

pub mod pattern;

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

pub use pattern::{Pattern, Rand};

pub const RULES_TOML: &str = include_str!("../rules.toml");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: String,
    pub value: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Deserialize)]
pub struct TokenRule {
    pub id: String,
    pub pattern: String,
}

#[derive(Deserialize)]
struct RulesFile {
    rule: Vec<TokenRule>,
}

pub fn token_rules() -> &'static [TokenRule] {
    static R: OnceLock<Vec<TokenRule>> = OnceLock::new();
    R.get_or_init(|| {
        toml::from_str::<RulesFile>(RULES_TOML)
            .expect("rules.toml")
            .rule
    })
}

struct Rule {
    kind: &'static str,
    re: Regex,
    validate: fn(&str) -> bool,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut v: Vec<Rule> = token_rules()
            .iter()
            .map(|t| Rule {
                kind: t.id.as_str(),
                // token must not be glued to identifier chars on either side
                re: Regex::new(&format!(
                    "(?:^|[^A-Za-z0-9_])({})(?:[^A-Za-z0-9_]|$)",
                    t.pattern
                ))
                .unwrap_or_else(|e| panic!("rule {}: {e}", t.id)),
                validate: |_| true,
            })
            .collect();
        v.push(Rule {
            kind: "email",
            re: Regex::new(
                r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b",
            )
            .unwrap(),
            validate: |_| true,
        });
        v.push(Rule {
            kind: "iban",
            re: Regex::new(r"\b([A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?)\b")
                .unwrap(),
            validate: iban_valid,
        });
        v.push(Rule {
            kind: "credit_card",
            re: Regex::new(r"\b((?:\d[ -]?){12,18}\d)\b").unwrap(),
            validate: luhn_valid,
        });
        v.push(Rule {
kind: "phone",
            // not glued to identifier/hex/dash chars (avoids UUID and hash segments)
            re: Regex::new(r"(?:^|[^A-Za-z0-9._-])((?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)|\d{1,4})(?:[ .-]?\d{2,4}){2,6})(?:[^A-Za-z0-9-]|$)").unwrap(),
            validate: phone_valid,
        });
        v
    })
}

fn digits(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

fn phone_valid(s: &str) -> bool {
    static US: OnceLock<Regex> = OnceLock::new();
    let us = US.get_or_init(|| Regex::new(r"^\d{3}[ .-]?\d{3}[ .-]?\d{4}$").unwrap());
    let d = digits(s);
    (8..=15).contains(&d.len())
        && (s.starts_with('+') || s.starts_with('(') || s.starts_with('0') || us.is_match(s))
}

pub fn luhn_valid(s: &str) -> bool {
    let d = digits(s);
    if !(13..=19).contains(&d.len()) {
        return false;
    }
    let sum: u32 = d
        .bytes()
        .rev()
        .enumerate()
        .map(|(i, b)| {
            let n = (b - b'0') as u32;
            if i % 2 == 1 {
                let x = n * 2;
                if x > 9 {
                    x - 9
                } else {
                    x
                }
            } else {
                n
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// ISO 13616 mod-97 check.
pub fn iban_valid(s: &str) -> bool {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 15 || compact.len() > 34 {
        return false;
    }
    let rearranged = format!("{}{}", &compact[4..], &compact[..4]);
    let mut rem: u32 = 0;
    for c in rearranged.chars() {
        let v = match c {
            '0'..='9' => c as u32 - '0' as u32,
            'A'..='Z' => c as u32 - 'A' as u32 + 10,
            _ => return false,
        };
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    rem == 1
}

pub fn iban_check_digits(cc: &str, bban: &str) -> String {
    for n in 2..=98u32 {
        if iban_valid(&format!("{cc}{n:02}{bban}")) {
            return format!("{n:02}");
        }
    }
    unreachable!()
}

pub fn luhn_complete(body: &str) -> String {
    for d in 0..10 {
        let cand = format!("{body}{d}");
        if luhn_valid(&cand) {
            return cand;
        }
    }
    unreachable!()
}

pub fn scan(text: &str) -> Vec<Finding> {
    let mut cands: Vec<Finding> = Vec::new();
    for rule in rules() {
        let mut at = 0;
        while let Some(caps) = rule.re.captures_at(text, at) {
            let m = caps.get(1).unwrap();
            // resume right after the token so a delimiter consumed by the
            // trailing context group can still start the next match
            at = m.end();
            if (rule.validate)(m.as_str()) {
                cands.push(Finding {
                    kind: rule.kind.to_string(),
                    value: m.as_str().to_string(),
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
    }
    // overlaps: earliest start wins, then the longest match
    cands.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut out: Vec<Finding> = Vec::new();
    for c in cands {
        if out.last().is_none_or(|p| c.start >= p.end) {
            out.push(c);
        }
    }
    out
}
