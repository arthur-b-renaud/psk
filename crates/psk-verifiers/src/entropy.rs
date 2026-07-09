//! Shannon entropy, the gate for the high-false-positive generic rules.
//!
//! A 40-character string matching the AWS-secret-key *shape* is usually not a secret. It is a
//! base64 blob, a lockfile hash, a git SHA, or a line of minified JavaScript. Entropy separates
//! "someone typed this" from "a CSPRNG produced this" — imperfectly, which is why it is one gate
//! among several rather than the whole answer.

use std::collections::HashMap;

/// Shannon entropy of `s` in **bits per character**.
///
/// Ranges from 0.0 (every character identical) to `log2(alphabet_size)` (uniform). A random
/// base64 string sits near 5.5; a random hex string cannot exceed 4.0; `"aaaa…"` is 0.0.
///
/// Note the *per character* normalisation. Total entropy would scale with length, so a long
/// low-entropy string would out-score a short high-entropy one.
pub fn shannon_bits_per_char(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = s.chars().count() as f64;
    -counts
        .values()
        .map(|&n| {
            let p = n as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

/// The default floor for generic high-entropy rules, in bits per character.
///
/// Chosen to sit below a real base64 credential (~5.5) and a real hex-ish credential (~3.9), but
/// above English prose (~4.1 for words, but far lower for the repeated-substring blobs that
/// actually cause false positives) and above padded or patterned strings.
///
/// It is deliberately *not* high enough to reject a git SHA-1 on its own — a random hex string
/// scores ~3.9. Pure-hex exclusion, not entropy, is what kills git SHAs (brief §6b).
pub const DEFAULT_MIN_BITS_PER_CHAR: f64 = 3.0;

/// Does `s` look random enough to be a machine-generated credential?
pub fn passes_entropy_gate(s: &str, min_bits_per_char: f64) -> bool {
    shannon_bits_per_char(s) >= min_bits_per_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_string_has_zero_entropy() {
        assert_eq!(shannon_bits_per_char(&"a".repeat(40)), 0.0);
    }

    #[test]
    fn empty_string_is_zero_not_nan() {
        assert_eq!(shannon_bits_per_char(""), 0.0);
    }

    #[test]
    fn entropy_is_bounded_by_log2_of_alphabet() {
        // Four distinct characters, uniformly distributed: exactly 2 bits per character.
        assert!((shannon_bits_per_char("abcdabcdabcd") - 2.0).abs() < 1e-9);
    }

    #[test]
    fn credentials_pass_and_padding_fails() {
        let aws_shaped = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        assert!(passes_entropy_gate(aws_shaped, DEFAULT_MIN_BITS_PER_CHAR));

        assert!(!passes_entropy_gate(
            &"AAAABBBB".repeat(5),
            DEFAULT_MIN_BITS_PER_CHAR
        ));
        assert!(!passes_entropy_gate(
            &"=".repeat(40),
            DEFAULT_MIN_BITS_PER_CHAR
        ));
    }

    /// A git SHA-1 clears the entropy gate. This is the whole reason the gate is not sufficient
    /// on its own and pure-hex exclusion exists (brief §6b).
    #[test]
    fn git_sha_clears_the_entropy_gate() {
        let sha = "d6cd1e2bd19e03a81132a23b2025920577f84e37";
        assert!(
            passes_entropy_gate(sha, DEFAULT_MIN_BITS_PER_CHAR),
            "entropy alone cannot reject a git SHA; the hex rule must"
        );
    }
}
