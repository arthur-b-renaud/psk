//! The secret taxonomy and, for each kind, the *shape a fake of that kind must have*.
//!
//! `SecretKind` lives in `psk-vault` rather than `psk-secrets` on purpose. A kind's only
//! structural obligation in this codebase is "what must a fake of me look like", and that is
//! the vault's job. `psk-secrets` will depend on this crate for the enum, which keeps the
//! dependency direction of the brief (§4) acyclic without inventing a `psk-types` crate.

/// The reserved marker embedded in every alphanumeric fake (brief §7b).
///
/// A human, `psk scan`, or the near-miss detector can spot an unrestored fake instantly.
/// Four characters that all live in every alphabet we generate into.
pub const MARKER: &str = "QPSK";

/// Fakes for digit-only kinds cannot carry [`MARKER`]. They live in reserved/test spaces
/// instead, which serve the same "obviously not a live value" purpose. See `CLAUDE.md`.
///
/// A well-known Visa *test* BIN. No live card is issued under it.
pub const FAKE_CARD_BIN: &str = "411111";
/// `ZZ` is not an assigned ISO 3166-1 country code, so no live IBAN can start with it.
pub const FAKE_IBAN_COUNTRY: &str = "ZZ";
/// RFC 5737 documentation range. Never routed.
pub const FAKE_IPV4_PREFIX: &str = "192.0.2.";
/// RFC 3849 documentation prefix. Never routed.
pub const FAKE_IPV6_PREFIX: &str = "2001:db8::";
/// RFC 2606 reserved domain. Never resolves.
pub const FAKE_EMAIL_DOMAIN: &str = "example.com";

/// Which characters a generated fake body may contain.
///
/// Every alphabet here contains `Q`, `P`, `S`, and `K` so [`MARKER`] can always be embedded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alphabet {
    /// `A-Z0-9` — AWS access key ids and similar shouty tokens.
    UpperAlnum,
    /// `A-Za-z0-9`.
    Base62,
    /// `A-Za-z0-9-_` — JWT segments, PEM-ish bodies.
    Base64Url,
}

impl Alphabet {
    /// Returns the character set as bytes. `&'static [u8]` because these tables outlive
    /// everything; no allocation, no lifetime plumbing.
    pub fn chars(self) -> &'static [u8] {
        const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        const B62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const B64U: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        match self {
            Alphabet::UpperAlnum => UPPER,
            Alphabet::Base62 => B62,
            Alphabet::Base64Url => B64U,
        }
    }
}

/// How a fake of a given kind is assembled.
///
/// `Token` covers every "prefix + opaque body" credential, which is most of them. The rest have
/// enough internal structure (checksums, separators, PEM armour) to need bespoke handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// Copy the real value's first `copy_prefix` characters verbatim, then fill the remaining
    /// length with generated characters, overwriting `marker_offset..+4` with [`MARKER`].
    ///
    /// Copying the prefix from the *real* value (rather than hardcoding one per kind) preserves
    /// both prefix and exact length for variable-prefix kinds like GitHub PATs, where `ghp_`,
    /// `gho_`, `ghs_` … must each survive into the fake so the LLM's reasoning stays intact.
    Token {
        copy_prefix: usize,
        alphabet: Alphabet,
        marker_offset: usize,
    },
    /// Three base64url segments. The header segment is copied verbatim (it encodes only `alg`
    /// and `typ` — no secret); payload and signature are generated.
    Jwt,
    /// `-----BEGIN <label>-----` … `-----END <label>-----`, label and body length preserved.
    Pem,
    /// Luhn-valid, [`FAKE_CARD_BIN`]-prefixed, separators of the real value preserved.
    CreditCard,
    /// mod-97-valid, [`FAKE_IBAN_COUNTRY`]-prefixed. The BBAN is alphanumeric, so it carries
    /// [`MARKER`] as well.
    Iban,
    IpV4,
    IpV6,
    Email,
}

/// Every secret kind PSK detects in M1 (brief §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SecretKind {
    AwsAccessKeyId,
    AwsSecretKey,
    GithubPat,
    AnthropicKey,
    OpenAiKey,
    GoogleApiKey,
    GcpServiceAccountKey,
    SlackToken,
    StripeKey,
    Jwt,
    BearerToken,
    PrivateKeyBlock,
    SshPrivateKey,
    CreditCard,
    Iban,
    /// Disabled by default (brief §6b).
    IpV4,
    /// Disabled by default (brief §6b).
    IpV6,
    /// Disabled by default (brief §6b).
    Email,
}

impl SecretKind {
    /// A stable byte tag mixed into the HMAC for domain separation.
    ///
    /// Without this, one string detected as two different kinds would derive the same fake, and
    /// the reverse map could not tell which format to restore. Never renumber these: the tag is
    /// part of the derivation, so changing it changes every fake for that kind.
    pub fn tag(self) -> &'static str {
        match self {
            SecretKind::AwsAccessKeyId => "aws_access_key_id",
            SecretKind::AwsSecretKey => "aws_secret_key",
            SecretKind::GithubPat => "github_pat",
            SecretKind::AnthropicKey => "anthropic_key",
            SecretKind::OpenAiKey => "openai_key",
            SecretKind::GoogleApiKey => "google_api_key",
            SecretKind::GcpServiceAccountKey => "gcp_sa_key",
            SecretKind::SlackToken => "slack_token",
            SecretKind::StripeKey => "stripe_key",
            SecretKind::Jwt => "jwt",
            SecretKind::BearerToken => "bearer_token",
            SecretKind::PrivateKeyBlock => "private_key_block",
            SecretKind::SshPrivateKey => "ssh_private_key",
            SecretKind::CreditCard => "credit_card",
            SecretKind::Iban => "iban",
            SecretKind::IpV4 => "ipv4",
            SecretKind::IpV6 => "ipv6",
            SecretKind::Email => "email",
        }
    }

    /// The fake-construction rule for this kind. A table, consulted once per derivation.
    pub fn shape(self) -> Shape {
        use Alphabet::*;
        // `copy_prefix` counts the fixed, non-secret marker characters of each credential
        // format: `AKIA`, `ghp_`, `sk-ant-`, and so on.
        match self {
            SecretKind::AwsAccessKeyId => Shape::Token {
                copy_prefix: 4, // "AKIA"
                alphabet: UpperAlnum,
                marker_offset: 0,
            },
            // No fixed prefix. The marker also guarantees the fake is not pure hex, so it can
            // never be mistaken for a git SHA-1 by our own detector (brief §6b).
            SecretKind::AwsSecretKey => Shape::Token {
                copy_prefix: 0,
                alphabet: Base62,
                marker_offset: 0,
            },
            SecretKind::GithubPat => Shape::Token {
                copy_prefix: 4, // "ghp_" | "gho_" | "ghu_" | "ghs_" | "ghr_"
                alphabet: Base62,
                marker_offset: 0,
            },
            SecretKind::AnthropicKey => Shape::Token {
                copy_prefix: 7, // "sk-ant-"
                alphabet: Base62,
                marker_offset: 0,
            },
            SecretKind::OpenAiKey => Shape::Token {
                copy_prefix: 3, // "sk-"
                alphabet: Base62,
                marker_offset: 0,
            },
            SecretKind::GoogleApiKey => Shape::Token {
                copy_prefix: 4, // "AIza"
                alphabet: Base62,
                marker_offset: 0,
            },
            SecretKind::SlackToken => Shape::Token {
                copy_prefix: 5, // "xoxb-" | "xoxa-" | "xoxp-" | "xoxr-" | "xoxs-"
                alphabet: Base62,
                marker_offset: 0,
            },
            SecretKind::StripeKey => Shape::Token {
                copy_prefix: 8, // "sk_live_" | "rk_live_"
                alphabet: Base62,
                marker_offset: 0,
            },
            SecretKind::BearerToken => Shape::Token {
                copy_prefix: 0,
                alphabet: Base64Url,
                marker_offset: 0,
            },
            SecretKind::Jwt => Shape::Jwt,
            SecretKind::GcpServiceAccountKey
            | SecretKind::PrivateKeyBlock
            | SecretKind::SshPrivateKey => Shape::Pem,
            SecretKind::CreditCard => Shape::CreditCard,
            SecretKind::Iban => Shape::Iban,
            SecretKind::IpV4 => Shape::IpV4,
            SecretKind::IpV6 => Shape::IpV6,
            SecretKind::Email => Shape::Email,
        }
    }

    /// Kinds that ship disabled (brief §6b): in agent traffic these fire constantly on loopback
    /// addresses, example domains, and documentation ranges, and a false substitution actively
    /// breaks the LLM's reasoning about networking code.
    pub fn enabled_by_default(self) -> bool {
        !matches!(
            self,
            SecretKind::IpV4 | SecretKind::IpV6 | SecretKind::Email
        )
    }

    /// Every kind, for exhaustive tests and for `psk-secrets` to iterate over.
    pub const ALL: [SecretKind; 18] = [
        SecretKind::AwsAccessKeyId,
        SecretKind::AwsSecretKey,
        SecretKind::GithubPat,
        SecretKind::AnthropicKey,
        SecretKind::OpenAiKey,
        SecretKind::GoogleApiKey,
        SecretKind::GcpServiceAccountKey,
        SecretKind::SlackToken,
        SecretKind::StripeKey,
        SecretKind::Jwt,
        SecretKind::BearerToken,
        SecretKind::PrivateKeyBlock,
        SecretKind::SshPrivateKey,
        SecretKind::CreditCard,
        SecretKind::Iban,
        SecretKind::IpV4,
        SecretKind::IpV6,
        SecretKind::Email,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_alphabet_can_hold_the_marker() {
        for a in [Alphabet::UpperAlnum, Alphabet::Base62, Alphabet::Base64Url] {
            for c in MARKER.bytes() {
                assert!(a.chars().contains(&c), "{a:?} cannot encode {}", c as char);
            }
        }
    }

    #[test]
    fn kind_tags_are_unique() {
        let mut tags: Vec<_> = SecretKind::ALL.iter().map(|k| k.tag()).collect();
        tags.sort_unstable();
        let before = tags.len();
        tags.dedup();
        assert_eq!(
            before,
            tags.len(),
            "two kinds share a domain-separation tag"
        );
    }
}
