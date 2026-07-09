//! False-positive killers: the layer between "this matched a regex" and "this is a secret".
//!
//! Brief §6b: *this decides whether the tool is usable.* A regex that matches a 40-character
//! base64 string matches half of every lockfile. Substituting those breaks the LLM's reasoning
//! about dependency files, git operations, and networking code — and the loop only tolerates false
//! positives if restore is perfect, which it is not.
//!
//! Three mechanisms, applied per kind by [`verify`]:
//!
//! 1. **Checksums** — Luhn for cards, mod-97 for IBANs. Re-exported from `psk-vault`, which needs
//!    to *forge* them as well as verify them; one implementation means a fake can never be valid
//!    by one definition and invalid by the other.
//! 2. **Entropy gate** — Shannon bits per character, for the shape-only generics.
//! 3. **Allowlists** — hard classes that are provably not secrets: git SHAs, lockfile hashes,
//!    loopback and documentation IPs, reserved domains.

pub mod allowlist;
pub mod entropy;

/// One implementation of each checksum, shared with the fake generator. `psk-vault` forges values
/// that must pass these exact functions.
pub use psk_vault::checksum::{iban_valid, luhn_valid};

use psk_vault::SecretKind;

/// Tunable thresholds. Constructed once and passed down; the proxy will read these from
/// `~/.psk/config.toml`.
#[derive(Debug, Clone, Copy)]
pub struct VerifierConfig {
    /// Shannon floor, in bits per character, for the shape-only generic rules.
    pub min_bits_per_char: f64,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        VerifierConfig {
            min_bits_per_char: entropy::DEFAULT_MIN_BITS_PER_CHAR,
        }
    }
}

/// Is `value`, which already matched the regex for `kind`, actually a secret?
///
/// Returns `false` for anything that must be left alone. Every rule that *can* have a checksum
/// goes through one before it is treated as a real secret (brief §6).
pub fn verify(kind: SecretKind, value: &str, cfg: &VerifierConfig) -> bool {
    match kind {
        // Shape-only generic. The most false-positive-prone rule in the set, so it carries every
        // gate: not a git SHA, not a lockfile hash, and high enough entropy.
        SecretKind::AwsSecretKey => {
            !allowlist::is_git_sha(value)
                && !allowlist::is_lockfile_hash(value)
                // AWS's own documentation secret key appears in thousands of tutorials.
                && !allowlist::is_published_example_key(value)
                // Beyond `[0-9a-f]`: the base64 alphabet must actually be used, or this is hex
                // wearing a base64 costume (brief §6b).
                && value.chars().any(|c| !c.is_ascii_hexdigit())
                && entropy::passes_entropy_gate(value, cfg.min_bits_per_char)
        }

        // A bare token with no distinguishing prefix. Entropy is all we have.
        SecretKind::BearerToken => {
            !allowlist::is_git_sha(value)
                && !allowlist::is_lockfile_hash(value)
                && entropy::passes_entropy_gate(value, cfg.min_bits_per_char)
        }

        // Prefixed vendor tokens. The prefix narrows the search; it is *not* the evidence.
        //
        // The gitleaks corpus refuted the earlier assumption here. `ghp_xxxxxxxx…`,
        // `AIzaaaaaaaa…`, and `AKIAXXXXXXXXXXXXXXXX` all carry a genuine vendor prefix and are all
        // placeholders. gitleaks pairs every one of these rules with an entropy threshold, and so
        // do we: the gate runs on the token *body*, after the fixed prefix, whose zero entropy
        // would otherwise drag a real key's score down.
        SecretKind::AwsAccessKeyId => {
            !allowlist::is_vendor_placeholder(value)
                && entropy::passes_entropy_gate(body_after(value, 4), cfg.min_bits_per_char)
        }
        SecretKind::GithubPat => {
            entropy::passes_entropy_gate(body_after(value, 4), cfg.min_bits_per_char)
        }
        SecretKind::GoogleApiKey => {
            !allowlist::is_published_example_key(value)
                && entropy::passes_entropy_gate(body_after(value, 4), cfg.min_bits_per_char)
        }

        SecretKind::CreditCard => {
            let digits: Vec<u8> = value.bytes().filter(u8::is_ascii_digit).collect();
            // Luhn is necessary but not sufficient: an all-zero run passes it.
            luhn_valid(&digits) && !allowlist::is_placeholder_number(&digits)
        }

        SecretKind::Iban => iban_valid(value),

        // `is_valid_ip` first: the regex matches shapes that are not addresses at all
        // (`999.999.999.999`, `1.2.3.4.5`), and `is_reserved_ip` says `false` for those.
        SecretKind::IpV4 | SecretKind::IpV6 => {
            allowlist::is_valid_ip(value) && !allowlist::is_reserved_ip(value)
        }

        SecretKind::Email => !allowlist::is_reserved_email(value),

        // The remaining kinds are carried by their *structure*, not merely a prefix, and the regex
        // already encodes it: an Anthropic key's exact 93-character body and `AA` suffix, a JWT's
        // three base64url segments, a Slack token's segment lengths, a PEM block's 64-character
        // minimum body. A further gate here would only reject real-but-unlucky credentials.
        SecretKind::AnthropicKey
        | SecretKind::OpenAiKey
        | SecretKind::GcpServiceAccountKey
        | SecretKind::SlackToken
        | SecretKind::StripeKey
        | SecretKind::Jwt
        | SecretKind::PrivateKeyBlock
        | SecretKind::SshPrivateKey => true,
    }
}

/// The token body: everything after a fixed, zero-entropy vendor prefix of `n` characters.
///
/// Measuring entropy over the whole token would count `AKIA` and `ghp_` as evidence of randomness
/// they do not have, penalising short keys.
fn body_after(value: &str, n: usize) -> &str {
    value.get(n..).unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_vault::sample;

    fn cfg() -> VerifierConfig {
        VerifierConfig::default()
    }

    /// Every representative sample must survive its own verifier, or detection is broken.
    #[test]
    fn every_sample_verifies_as_a_real_secret() {
        for k in SecretKind::ALL {
            let v = sample::for_kind(k);
            assert!(
                verify(k, &v, &cfg()),
                "{k:?} sample rejected by its verifier"
            );
        }
    }

    /// The acceptance criterion from brief §12: zero substitutions on the allowlist classes.
    #[test]
    fn allowlisted_classes_are_never_secrets() {
        let c = cfg();

        // Git SHA-1, in the rule whose shape it shares.
        assert!(!verify(
            SecretKind::AwsSecretKey,
            "d6cd1e2bd19e03a81132a23b2025920577f84e37",
            &c
        ));
        assert!(!verify(SecretKind::AwsSecretKey, &"a".repeat(40), &c)); // zero entropy too

        // Lockfile integrity hash.
        assert!(!verify(
            SecretKind::BearerToken,
            "sha512-vfNTPFNH1sBLPGDDeUXBrXXsRcMdvHtE6yHhU1cUw",
            &c
        ));

        // Loopback and documentation addresses.
        for ip in ["127.0.0.1", "10.0.0.1", "192.0.2.1"] {
            assert!(!verify(SecretKind::IpV4, ip, &c), "{ip}");
        }
        assert!(!verify(SecretKind::IpV6, "::1", &c));

        // Example domains.
        assert!(!verify(SecretKind::Email, "alice@example.com", &c));
    }

    /// The checksum gates must reject near-miss numbers, or every 16-digit order id is a card.
    #[test]
    fn checksums_reject_invalid_values() {
        let c = cfg();
        assert!(verify(SecretKind::CreditCard, "4539 1488 0343 6467", &c));
        assert!(!verify(SecretKind::CreditCard, "4539 1488 0343 6468", &c)); // one digit off
        assert!(!verify(SecretKind::CreditCard, "1234 5678 9012 3456", &c)); // an order id

        assert!(verify(SecretKind::Iban, "GB82 WEST 1234 5698 7654 32", &c));
        assert!(!verify(SecretKind::Iban, "GB82 WEST 1234 5698 7654 33", &c));
    }

    /// Routable addresses and real domains must still be substituted when the rules are enabled.
    #[test]
    fn genuinely_sensitive_network_values_still_verify() {
        let c = cfg();
        assert!(verify(SecretKind::IpV4, "8.8.8.8", &c));
        assert!(verify(SecretKind::IpV6, "2606:4700:4700::1111", &c));
        assert!(verify(SecretKind::Email, "alice@corp.internal", &c));
    }

    /// Vendor placeholders carry a real prefix and are not secrets. Assembled at runtime, like
    /// every other secret-shaped fixture in this repo — see `psk_vault::sample`.
    #[test]
    fn vendor_placeholders_and_low_entropy_bodies_are_rejected() {
        let c = cfg();

        // AWS's documented access key id. Ends with `EXAMPLE`.
        let aws_doc_key = ["AKIA", "IOSFODNN7", "EXAMPLE"].concat();
        assert!(!verify(SecretKind::AwsAccessKeyId, &aws_doc_key, &c));

        // Zero-entropy bodies behind a genuine vendor prefix. The corpus refuted the earlier
        // assumption that a prefix is sufficient evidence.
        assert!(!verify(
            SecretKind::AwsAccessKeyId,
            &format!("AKIA{}", "X".repeat(16)),
            &c
        ));
        assert!(!verify(
            SecretKind::GithubPat,
            &format!("ghp_{}", "x".repeat(36)),
            &c
        ));
        assert!(!verify(
            SecretKind::GoogleApiKey,
            &format!("AIza{}", "a".repeat(35)),
            &c
        ));

        // ...but a real key with the same prefix still verifies.
        for k in [
            SecretKind::AwsAccessKeyId,
            SecretKind::GithubPat,
            SecretKind::GoogleApiKey,
        ] {
            assert!(verify(k, &sample::for_kind(k), &c), "{k:?} sample rejected");
        }
    }

    /// Published, real-format credentials are not secrets. The allowlist stores digests, so this
    /// test reconstructs the inputs rather than reading them from the source.
    #[test]
    fn published_example_keys_are_rejected() {
        let c = cfg();

        // AWS's documentation secret access key.
        let aws_doc_secret = ["wJalrXUtnFEMI", "/K7MDENG/bPx", "RfiCYEXAMPLE", "KEY"].concat();
        assert!(allowlist::is_published_example_key(&aws_doc_secret));
        assert!(!verify(SecretKind::AwsSecretKey, &aws_doc_secret, &c));

        // One of the Firebase SDK example keys gitleaks allowlists.
        let firebase = ["AIzaSy", "abcdefghijklmnopqrstuvwxyz", "1234567"].concat();
        assert!(allowlist::is_published_example_key(&firebase));
        assert!(!verify(SecretKind::GoogleApiKey, &firebase, &c));

        // An unrelated key of the same shape is not allowlisted.
        assert!(!allowlist::is_published_example_key(&sample::for_kind(
            SecretKind::GoogleApiKey
        )));
    }

    /// `000000000000000000` is Luhn-valid: every weighted digit is zero. Luhn alone cannot reject
    /// a placeholder.
    #[test]
    fn luhn_valid_placeholder_numbers_are_not_cards() {
        let c = cfg();
        assert!(luhn_valid(b"000000000000000000"));
        assert!(!verify(SecretKind::CreditCard, "000000000000000000", &c));
        assert!(verify(
            SecretKind::CreditCard,
            &sample::for_kind(SecretKind::CreditCard),
            &c
        ));
    }

    /// The IP regexes match shapes that are not addresses. Those must not become "secrets" just
    /// because the reserved-range check cannot classify them.
    #[test]
    fn ip_shaped_non_addresses_are_not_secrets() {
        let c = cfg();
        for s in ["999.999.999.999", "1.2.3.4.5", "0.0.0.0.0"] {
            assert!(!verify(SecretKind::IpV4, s, &c), "{s} is not an address");
        }
        assert!(!verify(SecretKind::IpV6, "gggg::1", &c));
    }

    /// PSK's own fakes must never verify as real secrets. This is the vault guard's twin: even if
    /// the guard were bypassed, the verifier refuses to re-substitute a fake IP, card, or email
    /// because they live in the reserved spaces the allowlists already cover.
    #[test]
    fn psk_fakes_are_not_re_detected() {
        let c = cfg();
        let v = psk_vault::Vault::with_salt([3u8; 32]);
        for k in [SecretKind::IpV4, SecretKind::IpV6, SecretKind::Email] {
            let fake = v.substitute(&sample::for_kind(k), k);
            assert!(
                !verify(k, &fake, &c),
                "{k:?} fake {fake} re-detected as real"
            );
        }
    }
}
