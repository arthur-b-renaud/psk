//! The orchestrator: run recognizers, resolve overlap, apply the guard, call the vault.

use std::collections::BTreeMap;
use std::sync::Arc;

use psk_vault::{SecretKind, Vault};

use crate::recognizer::{Match, Recognizer};

/// What one `substitute` call did. Counters only — never content (brief §8).
///
/// `BTreeMap` rather than `HashMap` so the per-kind breakdown iterates in a stable order, which
/// keeps `psk gain` output and the TUI's legend from reshuffling between runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub by_kind: BTreeMap<SecretKind, usize>,
    /// Total bytes of real secret removed from the outbound text.
    pub chars_hidden: usize,
}

impl Summary {
    pub fn total(&self) -> usize {
        self.by_kind.values().sum()
    }

    pub fn is_empty(&self) -> bool {
        self.by_kind.is_empty()
    }
}

/// Runs recognizers over text and swaps every believed secret for its fake.
pub struct Engine {
    recognizers: Vec<Box<dyn Recognizer>>,
    vault: Arc<Vault>,
}

impl Engine {
    /// The M1 engine: one regex recognizer.
    pub fn new(vault: Arc<Vault>, cfg: psk_secrets::ScanConfig) -> Self {
        Engine {
            recognizers: vec![Box::new(crate::recognizer::RegexRecognizer::new(cfg))],
            vault,
        }
    }

    /// Add a detector. The M2 seam: an NER recognizer plugs in here without the proxy noticing.
    pub fn with_recognizer(mut self, r: Box<dyn Recognizer>) -> Self {
        self.recognizers.push(r);
        self
    }

    pub fn vault(&self) -> &Arc<Vault> {
        &self.vault
    }

    /// Replace every believed secret in `text` with its deterministic fake.
    pub fn substitute(&self, text: &str) -> (String, Summary) {
        let mut candidates: Vec<Match> = self
            .recognizers
            .iter()
            .flat_map(|r| r.scan(text))
            .filter(|m| !m.is_empty())
            // The fake-recognition guard (brief §7c). An invariant, not an optimization: in
            // `restore_mode = "execution"` the resent conversation history legitimately contains
            // fakes, and after a proxy restart the maps are empty but the fakes are still fakes.
            // Substituting one would map a fake to a fake and lose the real value forever.
            .filter(|m| !self.vault.is_known_fake(m.value(text)))
            .collect();

        let accepted = resolve_overlaps(&mut candidates);

        let mut out = String::with_capacity(text.len());
        let mut summary = Summary::default();
        let mut cursor = 0usize;

        for m in &accepted {
            out.push_str(&text[cursor..m.start]);
            let real = m.value(text);
            out.push_str(&self.vault.substitute(real, m.kind));

            *summary.by_kind.entry(m.kind).or_insert(0) += 1;
            summary.chars_hidden += real.len();
            cursor = m.end;
        }
        out.push_str(&text[cursor..]);

        (out, summary)
    }

    /// Exact, whole-token restore. Delegates to the vault.
    pub fn restore(&self, text: &str) -> String {
        self.vault.restore(text)
    }
}

/// Resolve overlapping matches: **longest wins**, ties broken by kind specificity.
///
/// Overlap is normal, not exceptional. An Anthropic key's 40-character tail matches the AWS-secret
/// rule; a PEM body contains a dozen base64 blobs; a GCP service-account key matches both its own
/// rule and the generic private-key rule at the identical span.
///
/// The tie-break is `SecretKind`'s declaration order, which is `Ord` by derive. Specific kinds are
/// declared before the generics they subsume — `GcpServiceAccountKey` before `PrivateKeyBlock` —
/// so an exact-length tie picks the more specific kind, and the choice is deterministic rather
/// than dependent on recognizer iteration order.
///
/// Returns the accepted matches sorted by position, ready to splice.
fn resolve_overlaps(candidates: &mut [Match]) -> Vec<Match> {
    // Greedy: consider the strongest candidates first, keep any that does not collide with one
    // already kept. With `n` matches per request this is O(n^2) in the worst case and `n` is
    // small; a sweep with an interval tree would be premature.
    candidates.sort_by(|a, b| {
        b.len()
            .cmp(&a.len()) // longest first
            .then(a.kind.cmp(&b.kind)) // then most specific
            .then(a.start.cmp(&b.start)) // then leftmost, for determinism
    });

    let mut accepted: Vec<Match> = Vec::new();
    for &m in candidates.iter() {
        if !accepted.iter().any(|a| a.overlaps(&m)) {
            accepted.push(m);
        }
    }
    accepted.sort_by_key(|m| m.start);
    accepted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(start: usize, end: usize, kind: SecretKind) -> Match {
        Match { start, end, kind }
    }

    #[test]
    fn longest_match_wins() {
        let mut c = vec![
            m(10, 50, SecretKind::AwsSecretKey), // the tail
            m(0, 60, SecretKind::AnthropicKey),  // the whole key
        ];
        let got = resolve_overlaps(&mut c);
        assert_eq!(got, vec![m(0, 60, SecretKind::AnthropicKey)]);
    }

    #[test]
    fn equal_length_ties_break_toward_the_more_specific_kind() {
        // A GCP service-account key matches its own rule and the generic PEM rule, same span.
        let mut c = vec![
            m(0, 40, SecretKind::PrivateKeyBlock),
            m(0, 40, SecretKind::GcpServiceAccountKey),
        ];
        assert_eq!(
            resolve_overlaps(&mut c),
            vec![m(0, 40, SecretKind::GcpServiceAccountKey)]
        );

        // ...and the result must not depend on the order the recognizers reported them in.
        let mut reversed = vec![
            m(0, 40, SecretKind::GcpServiceAccountKey),
            m(0, 40, SecretKind::PrivateKeyBlock),
        ];
        assert_eq!(
            resolve_overlaps(&mut reversed),
            vec![m(0, 40, SecretKind::GcpServiceAccountKey)]
        );
    }

    #[test]
    fn disjoint_matches_all_survive_in_positional_order() {
        let mut c = vec![
            m(30, 40, SecretKind::GithubPat),
            m(0, 20, SecretKind::AwsAccessKeyId),
        ];
        let got = resolve_overlaps(&mut c);
        assert_eq!(got.len(), 2);
        assert!(
            got[0].start < got[1].start,
            "output must be sorted by position"
        );
    }

    /// Adjacent, touching spans do not overlap: `[0,10)` and `[10,20)` share no byte.
    #[test]
    fn adjacent_spans_are_not_overlapping() {
        assert!(!m(0, 10, SecretKind::Jwt).overlaps(&m(10, 20, SecretKind::Jwt)));
        assert!(m(0, 11, SecretKind::Jwt).overlaps(&m(10, 20, SecretKind::Jwt)));
    }
}
