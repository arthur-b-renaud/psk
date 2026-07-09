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

/// A rule whose secret is capture group 1, because the pattern must *consume* a delimiter it does
/// not want to substitute.
const fn rule_group1(kind: SecretKind, pattern: &'static str) -> Rule {
    Rule {
        kind,
        pattern,
        group: 1,
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
    // A Google API key may end in `-`, which is not a word character, so a trailing `\b` can never
    // match there and the key is missed. But dropping the boundary entirely makes the rule match a
    // 39-character *prefix* of a longer token, and substituting that corrupts it. Both failures
    // came from the corpus.
    //
    // The fix is an explicit right delimiter — a non-token character or end of input — consumed by
    // the pattern and excluded from the capture. `regex` has no lookahead by design (it is what
    // buys linear-time matching), so group 1 carries the secret.
    rule_group1(
        SecretKind::GoogleApiKey,
        r"\b(AIza[A-Za-z0-9_-]{35})(?:[^A-Za-z0-9_-]|$)",
    ),
    // ---- Vendor tokens -----------------------------------------------------------------------
    rule(SecretKind::GithubPat, r"\bgh[oprsu]_[A-Za-z0-9]{36}\b"),
    // The real format, not `sk-ant-` plus anything: 93 body characters and an `AA` suffix. The
    // loose version matched truncated and wrong-suffix keys that gitleaks lists as negatives.
    // `sk-ant-` cannot match the OpenAI pattern (`-` is absent from its body class), so the two
    // rules never fight.
    rule(
        SecretKind::AnthropicKey,
        r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA\b",
    ),
    rule(SecretKind::OpenAiKey, r"\bsk-[A-Za-z0-9]{32,}\b"),
    rule(
        SecretKind::StripeKey,
        r"\b[sr]k_(?:live|prod|test)_[A-Za-z0-9]{10,99}\b",
    ),
    // ---- Slack, ported from gitleaks -----------------------------------------------------------
    // Slack tokens carry *structure*, not just a prefix. A single `xox[baprs]-<anything>` rule
    // matched every `xoxb-abcdef-abcdef` placeholder in the corpus. Each variant below encodes the
    // segment shape of a real token; all map to one `SlackToken` kind because PSK does not need to
    // tell a bot token from a user token in order to hide it.
    rule(
        SecretKind::SlackToken,
        r"xoxb-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9-]*",
    ),
    rule(
        SecretKind::SlackToken,
        r"xox[pe](?:-[0-9]{10,13}){3}-[A-Za-z0-9-]{28,34}",
    ),
    rule(
        SecretKind::SlackToken,
        r"(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+",
    ),
    rule(
        SecretKind::SlackToken,
        r"xoxb-[0-9]{8,14}-[A-Za-z0-9]{18,26}",
    ),
    rule(SecretKind::SlackToken, r"xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}"),
    rule(SecretKind::SlackToken, r"xox[os]-\d+-\d+-\d+-[a-fA-F\d]+"),
    // ---- Structured credentials --------------------------------------------------------------
    // Ported from gitleaks. The `ey` anchor is `{"` base64-encoded: both the header and the payload
    // of a JWT are JSON objects, so requiring `ey` on each is far tighter than "dot-separated
    // blobs". The signature is **optional** — an `alg: none` token has an empty third segment, and
    // it still carries claims worth hiding.
    rule(
        SecretKind::Jwt,
        r"\bey[A-Za-z0-9]{17,}\.ey[A-Za-z0-9/\\_-]{17,}\.(?:[A-Za-z0-9/\\_-]{10,}={0,2})?",
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
    // Ported from gitleaks. Two things the hand-rolled version got wrong: it did not cover
    // `PGP PRIVATE KEY BLOCK`, and it happily matched an armoured block whose body was the word
    // `anything`. The `{64,}` body minimum is what makes it a key rather than a shape.
    rule(
        SecretKind::PrivateKeyBlock,
        r"(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----",
    ),
    // ---- Shape-only generics; these live or die on `psk-verifiers` ---------------------------
    // 40 characters of base64 alphabet. Also the shape of a git SHA-1, a truncated hash, and a
    // hundred other things — the verifier's pure-hex exclusion and entropy gate do the real work.
    //
    // `=` is excluded from the class on purpose. With it, the rule swallowed the assignment in
    // `csrf-token=Mj2qykJO...` and reported a span starting at `token=`. AWS secret keys are
    // exactly 40 characters of `[A-Za-z0-9/+]` with no padding.
    rule(SecretKind::AwsSecretKey, r"\b[A-Za-z0-9/+]{40}\b"),
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
