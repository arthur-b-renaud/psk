use psk::{iban_check_digits, luhn_complete, scan, Kind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{BufRead, Read, Write};

#[derive(Serialize, Deserialize)]
struct Expected {
    kind: Kind,
    value: String,
}

#[derive(Serialize, Deserialize)]
struct Example {
    text: String,
    expected: Vec<Expected>,
}

/// Tiny deterministic PRNG (xorshift) so fixtures are reproducible without deps.
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
        xs[(self.next() % xs.len() as u64) as usize]
    }
    fn upper(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from(b'A' + (self.next() % 26) as u8))
            .collect()
    }
}

fn spaced4(s: &str) -> String {
    s.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

fn gen(n: usize, seed: u64) -> Vec<Example> {
    let mut r = Rng(seed | 1);
    let mut out = Vec::new();
    let wrap = |r: &mut Rng, v: &str| -> String {
        let t = [
            "Please wire the funds to {} before Friday.",
            "contact: {}",
            "{}",
            "Customer record updated -> {} (verified)",
            "Note to self, the value was {} apparently.",
        ];
        r.pick(&t).replace("{}", v)
    };
    for i in 0..n {
        let (text, expected) = match i % 8 {
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
                        kind: Kind::Iban,
                        value: v,
                    }],
                )
            }
            1 => {
                let v = match r.next() % 4 {
                    0 => format!(
                        "+33 6 {} {} {} {}",
                        r.digits(2),
                        r.digits(2),
                        r.digits(2),
                        r.digits(2)
                    ),
                    1 => format!(
                        "0{} {} {} {} {}",
                        6 + r.next() % 2,
                        r.digits(2),
                        r.digits(2),
                        r.digits(2),
                        r.digits(2)
                    ),
                    2 => format!("({}) {}-{}", 200 + r.next() % 700, r.digits(3), r.digits(4)),
                    _ => format!(
                        "+1-{}-{}-{}",
                        200 + r.next() % 700,
                        r.digits(3),
                        r.digits(4)
                    ),
                };
                (
                    wrap(&mut r, &v),
                    vec![Expected {
                        kind: Kind::Phone,
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
                        kind: Kind::Email,
                        value: v,
                    }],
                )
            }
            3 => {
                let body = format!("{}{}", r.pick(&["4", "51", "37"]), r.digits(15));
                let body = &body[..15];
                let card = luhn_complete(body);
                let v = if r.next().is_multiple_of(2) {
                    spaced4(&card)
                } else {
                    card
                };
                (
                    wrap(&mut r, &v),
                    vec![Expected {
                        kind: Kind::CreditCard,
                        value: v,
                    }],
                )
            }
            4 => {
                let v = format!(
                    "AKIA{}",
                    (0..16)
                        .map(|_| {
                            let c = r.next() % 36;
                            if c < 10 {
                                char::from(b'0' + c as u8)
                            } else {
                                char::from(b'A' + (c - 10) as u8)
                            }
                        })
                        .collect::<String>()
                );
                (
                    wrap(&mut r, &v),
                    vec![Expected {
                        kind: Kind::AwsAccessKey,
                        value: v,
                    }],
                )
            }
            // hard negatives: must yield no finding
            5 => (
                format!(
                    "Order #{} shipped on 2026-09-{:02}, total {}.{} EUR",
                    r.digits(6),
                    1 + r.next() % 28,
                    r.digits(3),
                    r.digits(2)
                ),
                vec![],
            ),
            6 => (
                format!(
                    "commit {} by user{} at 14:{:02}",
                    r.upper(7).to_lowercase(),
                    r.digits(3),
                    r.next() % 60
                ),
                vec![],
            ),
            _ => (
                r.pick(&[
                    "The meeting is at 10:30, room B2.",
                    "version 1.2.3 released; 4096 tokens max",
                    "FR76 is a prefix, not an IBAN",
                    "call me at some point",
                    "pi = 3.14159265358979",
                    "port 8080 -> 127.0.0.1",
                ])
                .to_string(),
                vec![],
            ),
        };
        out.push(Example { text, expected });
    }
    out
}

fn eval(path: &str) -> std::io::Result<()> {
    let f = std::fs::File::open(path)?;
    let mut total = 0usize;
    let mut ok = 0usize;
    for line in std::io::BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let ex: Example = serde_json::from_str(&line).expect("bad fixture line");
        let got: BTreeSet<(Kind, String)> = scan(&ex.text)
            .into_iter()
            .map(|f| (f.kind, f.value))
            .collect();
        let want: BTreeSet<(Kind, String)> =
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
        Some("scan") | None => {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text)?;
            for f in scan(&text) {
                println!("{}", serde_json::to_string(&f).unwrap());
            }
        }
        Some(other) => {
            eprintln!("unknown command {other}; use scan | gen [n] [seed] | eval <file>");
            std::process::exit(2);
        }
    }
    Ok(())
}
