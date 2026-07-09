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

        SecretKind::CreditCard => {
            let digits: Vec<u8> = value.bytes().filter(u8::is_ascii_digit).collect();
            luhn_valid(&digits)
        }

        SecretKind::Iban => iban_valid(value),

        // `is_valid_ip` first: the regex matches shapes that are not addresses at all
        // (`999.999.999.999`, `1.2.3.4.5`), and `is_reserved_ip` says `false` for those.
        SecretKind::IpV4 | SecretKind::IpV6 => {
            allowlist::is_valid_ip(value) && !allowlist::is_reserved_ip(value)
        }

        SecretKind::Email => !allowlist::is_reserved_email(value),

        // The remaining kinds carry a vendor-issued prefix (`AKIA`, `ghp_`, `sk-ant-`, `xoxb-`,
        // `-----BEGIN …`). The prefix *is* the evidence; an entropy gate on top would only reject
        // real-but-unlucky keys. A JWT's three-segment structure plays the same role.
        SecretKind::AwsAccessKeyId
        | SecretKind::GithubPat
        | SecretKind::AnthropicKey
        | SecretKind::OpenAiKey
        | SecretKind::GoogleApiKey
        | SecretKind::GcpServiceAccountKey
        | SecretKind::SlackToken
        | SecretKind::StripeKey
        | SecretKind::Jwt
        | SecretKind::PrivateKeyBlock
        | SecretKind::SshPrivateKey => true,
    }
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
