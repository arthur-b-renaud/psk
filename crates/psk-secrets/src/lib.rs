//! The regex detection layer: rule patterns compiled once into a `RegexSet`, plus the
//! `psk-verifiers` gate that turns a pattern hit into a believed secret.
//!
//! This crate answers "where are the secrets in this text?" and nothing else. It does not know
//! about vaults, fakes, or substitution — `psk-core` composes those.

pub mod rules;

use std::sync::OnceLock;

use psk_vault::SecretKind;
use psk_verifiers::VerifierConfig;
use regex::{Regex, RegexSet};

pub use rules::{RULES, Rule};

/// A believed secret, located in the scanned text.
///
/// `start`/`end` are **byte** offsets into the haystack, as the `regex` crate reports them, and
/// always land on UTF-8 character boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMatch {
    pub start: usize,
    pub end: usize,
    pub kind: SecretKind,
}

impl RawMatch {
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// What to scan for.
///
/// `Default` is derived, and `bool`'s default is `false` — which is exactly the policy the brief
/// requires: the network rules are off unless a user turns them on.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanConfig {
    /// IP and email rules ship **disabled** (brief §6b). They fire constantly on loopback
    /// addresses, example domains, and version strings, and each false substitution actively
    /// breaks the LLM's reasoning about networking code.
    pub enable_network_rules: bool,
    pub verifier: VerifierConfig,
}

/// The compiled rule set.
///
/// Built once, behind a `OnceLock`, on the **first scan** rather than at process start, so cold
/// CLI startup stays under ~10 ms (brief §10). Compiling ~17 regexes is milliseconds, but `psk
/// gain` and `psk init` should not pay for it at all.
struct Compiled {
    /// The prefilter. One pass over the haystack answers *which* rules can possibly match, so the
    /// common case (a prompt containing no secrets) never runs a single individual regex.
    set: RegexSet,
    /// Parallel to `set`'s pattern indices.
    regexes: Vec<Regex>,
    kinds: Vec<SecretKind>,
    groups: Vec<usize>,
}

fn compiled() -> &'static Compiled {
    static COMPILED: OnceLock<Compiled> = OnceLock::new();
    COMPILED.get_or_init(|| {
        let (mut patterns, mut kinds, mut groups) = (Vec::new(), Vec::new(), Vec::new());
        for r in rules::all() {
            patterns.push(r.pattern);
            kinds.push(r.kind);
            groups.push(r.group);
        }
        // `expect` rather than a `Result`: these patterns are compile-time constants in this
        // crate, so a failure here is a bug in our own source, not bad user input. The unit test
        // `every_rule_compiles` catches it before it can ever reach a user.
        let set = RegexSet::new(&patterns).expect("PSK rule patterns must compile");
        let regexes = patterns
            .iter()
            .map(|p| Regex::new(p).expect("PSK rule patterns must compile"))
            .collect();
        Compiled {
            set,
            regexes,
            kinds,
            groups,
        }
    })
}

/// Find every believed secret in `text`.
///
/// Overlapping matches are **not** resolved here — a 40-character blob can match both the AWS
/// secret rule and, inside a longer PEM body, the PEM rule. `psk-core` resolves overlap by
/// longest-match-wins and applies the vault's fake-recognition guard.
pub fn scan(text: &str, cfg: &ScanConfig) -> Vec<RawMatch> {
    let c = compiled();
    let mut out = Vec::new();

    // The prefilter: one pass, then only the rules that can match are actually run.
    for idx in c.set.matches(text).iter() {
        let kind = c.kinds[idx];
        if !cfg.enable_network_rules && !kind.enabled_by_default() {
            continue;
        }
        for caps in c.regexes[idx].captures_iter(text) {
            // A rule's capture group is guaranteed to participate when the rule matched, except
            // for optional groups — none of ours are. `continue` rather than unwrap, regardless.
            let Some(m) = caps.get(c.groups[idx]) else {
                continue;
            };
            // The verifier is what separates "matched a shape" from "is a secret" (brief §6b).
            if psk_verifiers::verify(kind, m.as_str(), &cfg.verifier) {
                out.push(RawMatch {
                    start: m.start(),
                    end: m.end(),
                    kind,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_vault::sample;

    /// Guards the `expect`s in `compiled()`.
    #[test]
    fn every_rule_compiles() {
        for r in rules::all() {
            Regex::new(r.pattern).unwrap_or_else(|e| panic!("{:?}: {e}", r.kind));
        }
        assert!(RegexSet::new(rules::all().map(|r| r.pattern)).is_ok());
    }

    fn network_cfg() -> ScanConfig {
        ScanConfig {
            enable_network_rules: true,
            ..Default::default()
        }
    }

    fn kinds_found(text: &str, cfg: &ScanConfig) -> Vec<SecretKind> {
        let mut k: Vec<_> = scan(text, cfg).into_iter().map(|m| m.kind).collect();
        k.sort();
        k.dedup();
        k
    }

    /// Brief §12: 100% detection on the fixtures. Every kind's representative sample is found,
    /// embedded in surrounding prose exactly as it would appear in a prompt.
    #[test]
    fn every_kind_is_detected_in_context() {
        let cfg = network_cfg();
        for k in SecretKind::ALL {
            let s = sample::for_kind(k);
            // BearerToken's rule needs its keyword; the others stand alone.
            let text = if k == SecretKind::BearerToken {
                format!("curl -H 'Authorization: Bearer {s}' https://api.example.org")
            } else {
                format!("the value is {s} and that is all")
            };
            let found = kinds_found(&text, &cfg);
            assert!(
                found.contains(&k),
                "{k:?} not detected in {text:?}; found {found:?}"
            );
        }
    }

    /// The Bearer rule must substitute the token, never the `Bearer ` keyword itself.
    #[test]
    fn bearer_rule_captures_only_the_token() {
        let token = sample::for_kind(SecretKind::BearerToken);
        let text = format!("Authorization: Bearer {token}");
        let m = scan(&text, &ScanConfig::default())
            .into_iter()
            .find(|m| m.kind == SecretKind::BearerToken)
            .expect("bearer token must be detected");
        assert_eq!(&text[m.start..m.end], token);
    }

    /// Brief §12: zero false positives on clean text.
    #[test]
    fn clean_text_yields_no_matches() {
        let clean = "\
Refactor the parser to handle nested arrays. The function signature is
`fn parse(input: &str) -> Result<Vec<Node>, ParseError>` and it should
return an error when the depth exceeds 32. Run `cargo test -p parser`.";
        assert_eq!(scan(clean, &network_cfg()), vec![]);
    }

    /// Brief §12: zero substitutions on the allowlist fixture. This is the test that decides
    /// whether PSK is usable inside a real coding session.
    #[test]
    fn allowlisted_classes_are_not_detected() {
        let cfg = network_cfg(); // even with the network rules ON
        let text = "\
Checkout d6cd1e2bd19e03a81132a23b2025920577f84e37 then rebase onto main.
The dev server listens on 127.0.0.1:8787 and the container on 10.0.0.5.
Docs use 192.0.2.1 and 2001:db8::1; mail alice@example.com for access.
package-lock.json pins sha512-vfNTPFNH1sBLPGDDeUXBrXXsRcMdvHtE6yHhU1cUw
and the ::1 loopback is fine.";
        let found = scan(text, &cfg);
        assert!(
            found.is_empty(),
            "allowlisted values were detected as secrets: {:?}",
            found
                .iter()
                .map(|m| (&text[m.start..m.end], m.kind))
                .collect::<Vec<_>>()
        );
    }

    /// Network rules are off unless asked for, so a loopback address in a prompt is inert and an
    /// ordinary email is left alone.
    #[test]
    fn network_rules_are_disabled_by_default() {
        let text = "ssh to 8.8.8.8 and mail bob@corp.internal";
        assert_eq!(scan(text, &ScanConfig::default()), vec![]);
        assert_eq!(
            kinds_found(text, &network_cfg()),
            vec![SecretKind::IpV4, SecretKind::Email]
                .into_iter()
                .collect::<Vec<_>>()
                .tap_sorted()
        );
    }

    /// A git SHA has the AWS-secret shape exactly. This single case is why the pure-hex exclusion
    /// exists, and it is worth its own test.
    #[test]
    fn git_sha_is_never_an_aws_secret_key() {
        let text = "git show d6cd1e2bd19e03a81132a23b2025920577f84e37";
        assert_eq!(scan(text, &ScanConfig::default()), vec![]);
    }

    /// A 16-digit order id is not a card, because Luhn says so.
    #[test]
    fn non_luhn_digit_runs_are_not_cards() {
        assert_eq!(
            scan("order 1234567890123456", &ScanConfig::default()),
            vec![]
        );
        assert!(!scan("card 4539 1488 0343 6467", &ScanConfig::default()).is_empty());
    }

    /// `sk-ant-` must not be shredded by the OpenAI rule, and vice versa.
    ///
    /// Note what this does *not* assert. An Anthropic key's 40-character tail also matches the
    /// AWS-secret rule, because it genuinely has that shape. `scan` reports raw, overlapping
    /// matches on purpose; `psk-core` resolves them by longest-match-wins. So the contract here is
    /// "the full-length match is the right kind, and any other match is strictly inside it".
    #[test]
    fn anthropic_and_openai_keys_do_not_collide() {
        for (kind, value) in [
            (
                SecretKind::AnthropicKey,
                sample::for_kind(SecretKind::AnthropicKey),
            ),
            (
                SecretKind::OpenAiKey,
                sample::for_kind(SecretKind::OpenAiKey),
            ),
        ] {
            let matches = scan(&value, &ScanConfig::default());
            let longest = matches
                .iter()
                .max_by_key(|m| m.len())
                .expect("the key must be detected");
            assert_eq!(
                longest.kind, kind,
                "longest match for {kind:?} in {matches:?}"
            );
            assert_eq!(&value[longest.start..longest.end], value);

            for m in &matches {
                assert!(
                    m.start >= longest.start && m.end <= longest.end,
                    "{:?} at {}..{} escapes the {kind:?} span",
                    m.kind,
                    m.start,
                    m.end
                );
            }
        }
    }

    /// Offsets must slice the haystack back to the exact secret.
    #[test]
    fn match_offsets_are_exact() {
        let key = sample::for_kind(SecretKind::AwsAccessKeyId);
        let text = format!("export AWS_ACCESS_KEY_ID={key}\n");
        let m = &scan(&text, &ScanConfig::default())[0];
        assert_eq!(&text[m.start..m.end], key);
    }

    /// Tiny helper so the assertion above reads in sorted order without a temporary.
    trait TapSorted {
        fn tap_sorted(self) -> Self;
    }
    impl TapSorted for Vec<SecretKind> {
        fn tap_sorted(mut self) -> Self {
            self.sort();
            self
        }
    }
}
