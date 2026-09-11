use psk::{iban_check_digits, luhn_complete, scan, token_rules, Pattern, Rand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{BufRead, Read, Write};

#[derive(Serialize, Deserialize)]
struct Expected {
    kind: String,
    value: String,
}

#[derive(Serialize, Deserialize)]
struct Example {
    text: String,
    expected: Vec<Expected>,
}

/// Deterministic xorshift PRNG so fixtures are reproducible without deps.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn digits(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from(b'0' + (self.next() % 10) as u8))
            .collect()
    }
    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[self.below(xs.len())]
    }
    fn upper(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from(b'A' + (self.next() % 26) as u8))
            .collect()
    }
}
impl Rand for Rng {
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn spaced4(s: &str) -> String {
    s.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Contexts a secret shows up in inside real tool output.
fn wrap(r: &mut Rng, v: &str) -> String {
    let t = [
        "Please wire the funds to {} before Friday.",
        "contact: {}",
        "{}",
        "Customer record updated -> {} (verified)",
        "export API_TOKEN={}",
        "API_TOKEN=\"{}\"",
        "  \"token\": \"{}\",",
        "Authorization: Bearer {}",
        "curl -H 'X-Api-Key: {}' https://api.example.com/v1/me",
        "token = '{}'  # TODO rotate",
        "[2026-09-11T10:32:01Z] INFO  using credential {} for upstream",
        "  --key={} \\",
    ];
    r.pick(&t).replace("{}", v)
}

fn negative(r: &mut Rng) -> String {
    match r.below(12) {
        0 => format!(
            "Order #{} shipped on 2026-09-{:02}, total {}.{} EUR",
            r.digits(6),
            1 + r.below(28),
            r.digits(3),
            r.digits(2)
        ),
        1 => format!(
            "commit {}{} by user{} at 14:{:02}",
            r.upper(4).to_lowercase(),
            r.digits(3),
            r.digits(3),
            r.below(60)
        ),
        // sha1 / sha256 hashes
        2 => format!(
            "sha256:{}",
            (0..64)
                .map(|_| "0123456789abcdef".chars().nth(r.below(16)).unwrap())
                .collect::<String>()
        ),
        3 => hex(r, 40),
        // uuid
        4 => format!(
            "id={}-{}-4{}-a{}-{}",
            hex(r, 8),
            hex(r, 4),
            hex(r, 3),
            hex(r, 3),
            hex(r, 12)
        ),
        // lookalike prefixes that are too short / wrong charset
        5 => r
            .pick(&[
                "ghp_short",
                "AKIAlowercase1234567",
                "sk-ant-api03-truncated",
                "xoxb-not-a-token",
                "glpat-",
                "npm_install_failed",
                "key-value store",
                "pat.example.com",
            ])
            .to_string(),
        6 => r
            .pick(&[
                "The meeting is at 10:30, room B2.",
                "version 1.2.3 released; 4096 tokens max",
                "FR76 is a prefix, not an IBAN",
                "call me at some point",
                "pi = 3.14159265358979",
                "port 8080 -> 127.0.0.1",
                "-----BEGIN CERTIFICATE-----",
                "See https://docs.example.com/api/v2/keys for details",
                "SELECT * FROM users WHERE id = 42;",
                "Error: ENOENT: no such file or directory, open '/tmp/x.log'",
            ])
            .to_string(),
        7 => format!(
            "base64: {}",
            (0..44)
                .map(
                    |_| "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                        .chars()
                        .nth(r.below(64))
                        .unwrap()
                )
                .collect::<String>()
        ),
        8 => format!("Cargo.lock: checksum = \"{}\"", hex(r, 64)),
        9 => format!(
            "{} bytes written in {}.{}s",
            r.digits(7),
            r.digits(2),
            r.digits(3)
        ),
        10 => format!(
            "PR #{} merged, {} files changed, +{} -{}",
            r.digits(4),
            r.digits(2),
            r.digits(3),
            r.digits(2)
        ),
        _ => format!(
            "temperature {}.{}°C, humidity {}%",
            r.digits(2),
            r.digits(1),
            r.digits(2)
        ),
    }
}

fn hex(r: &mut Rng, n: usize) -> String {
    (0..n)
        .map(|_| "0123456789abcdef".chars().nth(r.below(16)).unwrap())
        .collect()
}

fn gen(n: usize, seed: u64) -> Vec<Example> {
    let mut r = Rng(seed | 1);
    let tokens: Vec<(String, Pattern)> = token_rules()
        .iter()
        .map(|t| {
            (
                t.id.clone(),
                Pattern::parse(&t.pattern).unwrap_or_else(|e| panic!("rule {}: {e}", t.id)),
            )
        })
        .collect();
    let mut out = Vec::new();
    for i in 0..n {
        let (text, expected) = match i % 10 {
            0 => {
                let cc = r.pick(&["FR", "DE", "GB", "ES", "NL"]);
                let len = match cc {
                    "FR" => 23,
                    "DE" => 18,
                    "GB" => 18,
                    "ES" => 20,
                    _ => 14,
                };
                let bban = if cc == "GB" || cc == "NL" {
                    format!("{}{}", r.upper(4), r.digits(len - 4))
                } else {
                    r.digits(len)
                };
                let iban = format!("{cc}{}{bban}", iban_check_digits(cc, &bban));
                let v = if r.next().is_multiple_of(2) {
                    spaced4(&iban)
                } else {
                    iban
                };
                (
                    wrap(&mut r, &v),
                    vec![Expected {
                        kind: "iban".into(),
                        value: v,
                    }],
                )
            }
            1 => {
                let v = match r.below(4) {
                    0 => format!(
                        "+33 6 {} {} {} {}",
                        r.digits(2),
                        r.digits(2),
                        r.digits(2),
                        r.digits(2)
                    ),
                    1 => format!(
                        "0{} {} {} {} {}",
                        6 + r.below(2),
                        r.digits(2),
                        r.digits(2),
                        r.digits(2),
                        r.digits(2)
                    ),
                    2 => format!("({}) {}-{}", 200 + r.below(700), r.digits(3), r.digits(4)),
                    _ => format!("+1-{}-{}-{}", 200 + r.below(700), r.digits(3), r.digits(4)),
                };
                (
                    wrap(&mut r, &v),
                    vec![Expected {
                        kind: "phone".into(),
                        value: v,
                    }],
                )
            }
            2 => {
                let v = format!(
                    "{}.{}@{}.{}",
                    r.pick(&["alice", "bob", "carol", "dave"]),
                    r.pick(&["martin", "smith", "dupont"]),
                    r.pick(&["example", "acme-corp", "mail"]),
                    r.pick(&["com", "fr", "io"])
                );
                (
                    wrap(&mut r, &v),
                    vec![Expected {
                        kind: "email".into(),
                        value: v,
                    }],
                )
            }
            3 => {
                let body = format!("{}{}", r.pick(&["4", "51", "37"]), r.digits(15));
                let card = luhn_complete(&body[..15]);
                let v = if r.next().is_multiple_of(2) {
                    spaced4(&card)
                } else {
                    card
                };
                (
                    wrap(&mut r, &v),
                    vec![Expected {
                        kind: "credit_card".into(),
                        value: v,
                    }],
                )
            }
            4..=6 => {
                let (id, pat) = &tokens[r.below(tokens.len())];
                let v = pat.sample(&mut r);
                (
                    wrap(&mut r, &v),
                    vec![Expected {
                        kind: id.clone(),
                        value: v,
                    }],
                )
            }
            _ => (negative(&mut r), vec![]),
        };
        out.push(Example { text, expected });
    }
    out
}

fn eval(path: &str) -> std::io::Result<()> {
    let f = std::fs::File::open(path)?;
    let (mut total, mut ok) = (0usize, 0usize);
    for line in std::io::BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let ex: Example = serde_json::from_str(&line).expect("bad fixture line");
        let got: BTreeSet<(String, String)> = scan(&ex.text)
            .into_iter()
            .map(|f| (f.kind, f.value))
            .collect();
        let want: BTreeSet<(String, String)> =
            ex.expected.into_iter().map(|e| (e.kind, e.value)).collect();
        total += 1;
        if got == want {
            ok += 1;
        } else {
            println!(
                "MISMATCH: {:?}\n   want {:?}\n   got  {:?}",
                ex.text, want, got
            );
        }
    }
    println!(
        "accuracy: {}/{} = {:.2}%",
        ok,
        total,
        100.0 * ok as f64 / total.max(1) as f64
    );
    if ok != total {
        std::process::exit(1);
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen") => {
            let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(200);
            let seed: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(42);
            let mut out = std::io::stdout().lock();
            for ex in gen(n, seed) {
                writeln!(out, "{}", serde_json::to_string(&ex).unwrap())?;
            }
        }
        Some("eval") => eval(args.get(2).expect("usage: psk eval <fixtures.jsonl>"))?,
        Some("rules") => {
            for t in token_rules() {
                println!("{:36} {}", t.id, t.pattern);
            }
        }
        Some("scan") | None => {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text)?;
            for f in scan(&text) {
                println!("{}", serde_json::to_string(&f).unwrap());
            }
        }
        Some(other) => {
            eprintln!("unknown command {other}; use scan | gen [n] [seed] | eval <file> | rules");
            std::process::exit(2);
        }
    }
    Ok(())
}
