//! Tiny generator for a restricted regex subset used in `rules.toml`:
//! literals, `\x` escapes, `[classes]`, `{n}`/`{m,n}`/`?`, and `(?:a|b)` groups.
//! The same string is compiled by the `regex` crate for detection.

#[derive(Debug, Clone)]
enum Node {
    Lit(char),
    Class(Vec<char>),
    Group(Vec<Vec<Node>>),
    Repeat(Box<Node>, usize, usize),
}

pub struct Pattern(Vec<Node>);

/// Source of randomness the generator needs; keeps this module dependency-free.
pub trait Rand {
    fn below(&mut self, n: usize) -> usize;
}

impl Pattern {
    pub fn parse(src: &str) -> Result<Self, String> {
        let chars: Vec<char> = src.chars().collect();
        let mut pos = 0;
        let alts = parse_alts(&chars, &mut pos)?;
        if pos != chars.len() {
            return Err(format!("unexpected `{}` at {pos}", chars[pos]));
        }
        Ok(Pattern(vec![Node::Group(alts)]))
    }

    pub fn sample(&self, r: &mut dyn Rand) -> String {
        let mut out = String::new();
        for n in &self.0 {
            emit(n, r, &mut out);
        }
        out
    }
}

fn emit(n: &Node, r: &mut dyn Rand, out: &mut String) {
    match n {
        Node::Lit(c) => out.push(*c),
        Node::Class(cs) => out.push(cs[r.below(cs.len())]),
        Node::Group(alts) => {
            for n in &alts[r.below(alts.len())] {
                emit(n, r, out);
            }
        }
        Node::Repeat(inner, lo, hi) => {
            let k = lo + r.below(hi - lo + 1);
            for _ in 0..k {
                emit(inner, r, out);
            }
        }
    }
}

fn parse_alts(c: &[char], pos: &mut usize) -> Result<Vec<Vec<Node>>, String> {
    let mut alts = vec![Vec::new()];
    while *pos < c.len() {
        match c[*pos] {
            ')' => break,
            '|' => {
                *pos += 1;
                alts.push(Vec::new());
            }
            _ => {
                let atom = parse_atom(c, pos)?;
                let atom = parse_quant(c, pos, atom)?;
                alts.last_mut().unwrap().push(atom);
            }
        }
    }
    Ok(alts)
}

fn parse_atom(c: &[char], pos: &mut usize) -> Result<Node, String> {
    let ch = c[*pos];
    *pos += 1;
    match ch {
        '\\' => {
            let e = *c.get(*pos).ok_or("dangling escape")?;
            *pos += 1;
            Ok(match e {
                'd' => Node::Class(('0'..='9').collect()),
                'w' => Node::Class(
                    ('a'..='z')
                        .chain('A'..='Z')
                        .chain('0'..='9')
                        .chain(['_'])
                        .collect(),
                ),
                other => Node::Lit(other),
            })
        }
        '[' => {
            let mut set = Vec::new();
            while *pos < c.len() && c[*pos] != ']' {
                let mut a = c[*pos];
                *pos += 1;
                if a == '\\' {
                    a = c[*pos];
                    *pos += 1;
                }
                if *pos + 1 < c.len() && c[*pos] == '-' && c[*pos + 1] != ']' {
                    let b = c[*pos + 1];
                    *pos += 2;
                    set.extend(a..=b);
                } else {
                    set.push(a);
                }
            }
            if *pos >= c.len() {
                return Err("unterminated class".into());
            }
            *pos += 1;
            Ok(Node::Class(set))
        }
        '(' => {
            if c.get(*pos) == Some(&'?') && c.get(*pos + 1) == Some(&':') {
                *pos += 2;
            }
            let alts = parse_alts(c, pos)?;
            if c.get(*pos) != Some(&')') {
                return Err("unterminated group".into());
            }
            *pos += 1;
            Ok(Node::Group(alts))
        }
        '.' | '+' | '*' | '^' | '$' => Err(format!("unsupported metachar `{ch}`; escape it")),
        _ => Ok(Node::Lit(ch)),
    }
}

fn parse_quant(c: &[char], pos: &mut usize, atom: Node) -> Result<Node, String> {
    match c.get(*pos) {
        Some('?') => {
            *pos += 1;
            Ok(Node::Repeat(Box::new(atom), 0, 1))
        }
        Some('{') => {
            let end = c[*pos..]
                .iter()
                .position(|&x| x == '}')
                .ok_or("unterminated {")?
                + *pos;
            let body: String = c[*pos + 1..end].iter().collect();
            *pos = end + 1;
            let (lo, hi) = match body.split_once(',') {
                Some((a, b)) => (
                    a.parse().map_err(|_| "bad {m,n}")?,
                    b.parse().map_err(|_| "bad {m,n}")?,
                ),
                None => {
                    let n: usize = body.parse().map_err(|_| "bad {n}")?;
                    (n, n)
                }
            };
            Ok(Node::Repeat(Box::new(atom), lo, hi))
        }
        _ => Ok(atom),
    }
}
