//! The M1 rule table (brief §6).
//!
//! Rule shapes are ported from gitleaks/trufflehog. Each is a regex plus, where the format allows,
//! a validator in `psk-verifiers`. Pure-Rust `regex` only: Hyperscan needs a C toolchain and would
//! break the "`cargo install` just works everywhere" promise. See `CLAUDE.md` for the note on
//! Hyperscan as a later throughput lever.

use psk_vault::SecretKind;

/// One detection rule.
pub struct Rule {
    pub kind: SecretKind,
    /// The pattern. No lookaround or backreferences — the `regex` crate guarantees linear time by
    /// not offering them, which is exactly what we want on adversarial input.
    pub pattern: &'static str,
    /// Which capture group holds the secret itself.
    ///
    /// `0` (the whole match) for nearly everything. The `Bearer <token>` rule needs the surrounding
    /// keyword for context but must substitute only the token, so it uses group `1`.
    pub group: usize,
}

const fn rule(kind: SecretKind, pattern: &'static str) -> Rule {
    Rule {
        kind,
        pattern,
        group: 0,
    }
}

/// Ordered only for readability; overlap between rules is resolved by longest-match-wins in
/// `psk-core`, not by position in this table.
pub static RULES: &[Rule] = &[
    // ---- Cloud provider keys, all with a vendor-issued prefix -------------------------------
    // AKIA (long-term), ASIA (STS), ABIA/ACCA (service-specific). All 20 characters.
    rule(
        SecretKind::AwsAccessKeyId,
        r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b",
    ),
    rule(SecretKind::GoogleApiKey, r"\bAIza[A-Za-z0-9_-]{35}\b"),
    // ---- Vendor tokens -----------------------------------------------------------------------
    rule(SecretKind::GithubPat, r"\bgh[oprsu]_[A-Za-z0-9]{36}\b"),
    // Must be tried against the same text as OpenAI's rule; `sk-ant-` cannot match the OpenAI
    // pattern because `-` is absent from its body class, so the two never fight.
    rule(SecretKind::AnthropicKey, r"\bsk-ant-[A-Za-z0-9_-]{16,}"),
    rule(SecretKind::OpenAiKey, r"\bsk-[A-Za-z0-9]{32,}\b"),
    rule(SecretKind::SlackToken, r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    rule(SecretKind::StripeKey, r"\b[sr]k_live_[A-Za-z0-9]{16,}\b"),
    // ---- Structured credentials --------------------------------------------------------------
    // Three base64url segments. The `eyJ` anchor is `{"` base64-encoded: a JWT header always
    // starts with a JSON object, so this is far tighter than "three dot-separated blobs".
    rule(
        SecretKind::Jwt,
        r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}",
    ),
    // ---- Key material ------------------------------------------------------------------------
    // Ordered before the generic PEM rule so longest-match-wins picks the more specific kind.
    rule(
        SecretKind::SshPrivateKey,
        r"(?s)-----BEGIN OPENSSH PRIVATE KEY-----.*?-----END OPENSSH PRIVATE KEY-----",
    ),
    // A GCP service-account JSON embeds its PEM with *literal* backslash-n escapes, not newlines.
    // Matching that shape separately is what lets the fake preserve the JSON's escaping.
    rule(
        SecretKind::GcpServiceAccountKey,
        r"-----BEGIN PRIVATE KEY-----(?:\\n[A-Za-z0-9+/=]+)+\\n-----END PRIVATE KEY-----",
    ),
    rule(
        SecretKind::PrivateKeyBlock,
        r"(?s)-----BEGIN (?:RSA |EC |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----",
    ),
    // ---- Shape-only generics; these live or die on `psk-verifiers` ---------------------------
    // 40 characters of base64 alphabet. Also the shape of a git SHA-1, a truncated hash, and a
    // hundred other things — the verifier's pure-hex exclusion and entropy gate do the real work.
    rule(SecretKind::AwsSecretKey, r"\b[A-Za-z0-9/+=]{40}\b"),
    // ---- Financial, checksum-gated -----------------------------------------------------------
    // 13-19 digits with optional single spaces or dashes. Luhn decides.
    rule(SecretKind::CreditCard, r"\b\d(?:[ -]?\d){12,18}\b"),
    // Two letters, two check digits, then 11-30 alphanumerics in groups. mod-97 decides.
    rule(
        SecretKind::Iban,
        r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b",
    ),
    // ---- Disabled by default (brief §6b) ------------------------------------------------------
    rule(SecretKind::IpV4, r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    // Deliberately loose: `psk-verifiers` re-parses the match with `IpAddr::from_str`, so a shape
    // that is not an address is rejected there rather than by an unreadable regex here.
    rule(
        SecretKind::IpV6,
        r"(?:[A-Fa-f0-9]{1,4}:){2,7}(?::|[A-Fa-f0-9]{1,4})",
    ),
    rule(
        SecretKind::Email,
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    ),
];

/// `Bearer <token>` needs its keyword for context but substitutes only the token, so it is the one
/// rule with a capture group. Kept out of `RULES` above only to keep that table `const`-simple.
pub static BEARER_RULE: Rule = Rule {
    kind: SecretKind::BearerToken,
    pattern: r"(?i:bearer)\s+([A-Za-z0-9_\-.=]{20,})",
    group: 1,
};

/// Every rule, generics and all.
pub fn all() -> impl Iterator<Item = &'static Rule> {
    RULES.iter().chain(std::iter::once(&BEARER_RULE))
}
