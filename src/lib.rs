//! Minimal secret-like detector: IBAN, phone, email, card number, AWS key.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Iban,
    Phone,
    Email,
    CreditCard,
    AwsAccessKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: Kind,
    pub value: String,
    pub start: usize,
    pub end: usize,
}

struct Rule {
    kind: Kind,
    re: Regex,
    validate: fn(&str) -> bool,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            Rule {
                kind: Kind::AwsAccessKey,
                re: Regex::new(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b").unwrap(),
                validate: |_| true,
            },
            Rule {
                kind: Kind::Email,
                re: Regex::new(
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b",
                )
                .unwrap(),
                validate: |_| true,
            },
            Rule {
                kind: Kind::Iban,
                // country code, 2 check digits, 11..30 alphanumerics, optional spaces every 4
                re: Regex::new(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
                    .unwrap(),
                validate: iban_valid,
            },
            Rule {
                kind: Kind::CreditCard,
                re: Regex::new(r"\b(?:\d[ -]?){12,18}\d\b").unwrap(),
                validate: luhn_valid,
            },
            Rule {
                kind: Kind::Phone,
                // +33 6 12 34 56 78 / 06 12 34 56 78 / (555) 123-4567 / +1-555-123-4567
                re: Regex::new(
                    r"(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)|\b\d{1,4})(?:[ .-]?\d{2,4}){2,6}\b",
                )
                .unwrap(),
                validate: phone_valid,
            },
        ]
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

fn luhn_valid(s: &str) -> bool {
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

/// Compute IBAN check digits for `cc` + bban.
pub fn iban_check_digits(cc: &str, bban: &str) -> String {
    for n in 2..=98u32 {
        let cand = format!("{cc}{n:02}{bban}");
        if iban_valid(&cand) {
            return format!("{n:02}");
        }
    }
    unreachable!()
}

/// Append a Luhn check digit to `body`.
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
    let mut out: Vec<Finding> = Vec::new();
    for rule in rules() {
        for m in rule.re.find_iter(text) {
            let overlaps = out.iter().any(|f| m.start() < f.end && f.start < m.end());
            if overlaps || !(rule.validate)(m.as_str()) {
                continue;
            }
            out.push(Finding {
                kind: rule.kind,
                value: m.as_str().to_string(),
                start: m.start(),
                end: m.end(),
            });
        }
    }
    out.sort_by_key(|f| f.start);
    out
}
