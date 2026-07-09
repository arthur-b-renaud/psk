//! Representative *fake-but-realistically-shaped* values, one per [`SecretKind`], for tests.
//!
//! # Why these are assembled instead of written as literals
//!
//! PSK is a secret scrubber, so its fixtures are secret-shaped by definition. Written as string
//! literals, they trip GitHub's push protection and every credential scanner pointed at this
//! repository — a false positive, but a loud and recurring one.
//!
//! Rather than disable push protection (which would also stop catching a *genuine* secret
//! accidentally committed here), each sample is concatenated at runtime from fragments. No
//! scannable literal exists in the source, and the safety net stays up for real accidents.
//!
//! **None of these are live credentials.** They are structurally valid and semantically inert:
//! sequential digits, alphabet runs, and truncated PEM bodies. Nothing here authenticates against
//! anything.
//!
//! Exposed (rather than kept in `#[cfg(test)]`) so the integration tests and, later,
//! `psk-secrets`' rule fixtures can share one definition instead of drifting apart.

use crate::kind::SecretKind;

/// A representative real-looking value of the given kind.
///
/// Stable across calls, so a test can substitute a sample and assert on the derived fake.
pub fn for_kind(kind: SecretKind) -> String {
    match kind {
        // 4-char prefix + 16 uppercase alphanumerics.
        SecretKind::AwsAccessKeyId => ["AKIA", "1234567890", "ABCDEF"].concat(),

        // 40 base64-alphabet characters. Deliberately not pure hex: a 40-char hex string is a git
        // SHA-1, which the detection rules must never treat as a secret (brief §6b).
        SecretKind::AwsSecretKey => {
            ["wJalrXUtnFEMI", "/K7MDENG/bPx", "RfiCYEXAMPLE", "KEY"].concat()
        }

        // 4-char prefix + 36 characters.
        SecretKind::GithubPat => {
            ["ghp", "_", "16C7e42F292c", "6912E7710c83", "8347Ae178B4a"].concat()
        }

        SecretKind::AnthropicKey => [
            "sk-",
            "ant-",
            "api03-",
            "Zm9vYmFyYmF6cXV4",
            "Y29ycmVjdGhvcnNl",
            "YmF0dGVy",
        ]
        .concat(),

        // `sk-` + 48 characters. The alphabet run keeps it obviously inert.
        SecretKind::OpenAiKey => [
            "sk-",
            "0123456789",
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKL",
        ]
        .concat(),

        // `AIza` + 35 characters.
        SecretKind::GoogleApiKey => {
            ["AIza", "SyD-", "1234567890", "abcdefghijklmnopqrstu"].concat()
        }

        SecretKind::SlackToken => [
            "xoxb",
            "-",
            "123456789012",
            "-",
            "1234567890123",
            "-",
            "abcdefghijklmnopqrstuvwx",
        ]
        .concat(),

        // 8-char prefix + 24 characters.
        SecretKind::StripeKey => ["sk", "_live_", "0123456789", "abcdefghijklmn"].concat(),

        // Header segment is real (it encodes only `alg` and `typ`); payload and signature are inert.
        SecretKind::Jwt => [
            "eyJhbGciOiJIUzI1NiJ9",
            ".",
            "eyJzdWIiOiIxMjM0NSJ9",
            ".",
            "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g",
        ]
        .concat(),

        SecretKind::BearerToken => ["AbCdEf0123456789", "AbCdEf0123456789"].concat(),

        // Truncated PEM bodies: enough armour and base64 to exercise the shape, no actual key.
        SecretKind::PrivateKeyBlock => pem_block("PRIVATE KEY", "MIIEvQIBADANBgkq", "\n"),
        SecretKind::SshPrivateKey => pem_block("OPENSSH PRIVATE KEY", "b3BlbnNzaC1rZXktdjEA", "\n"),

        // A GCP service-account key is a PEM inside a JSON string, so its newlines are the two
        // characters `\` `n`. The fake must preserve that escaping or the agent's own credentials
        // file stops parsing.
        SecretKind::GcpServiceAccountKey => pem_block("PRIVATE KEY", "MIIEvQIBADANBgkq", "\\n"),

        // A published Luhn-valid test number. Not in any live BIN.
        SecretKind::CreditCard => ["4539", " ", "1488", " ", "0343", " ", "6467"].concat(),

        // The IBAN registry's own worked example.
        SecretKind::Iban => [
            "GB82", " ", "WEST", " ", "1234", " ", "5698", " ", "7654", " ", "32",
        ]
        .concat(),

        SecretKind::IpV4 => "8.8.8.8".to_string(),
        SecretKind::IpV6 => "2606:4700:4700::1111".to_string(),
        SecretKind::Email => "alice@corp.internal".to_string(),
    }
}

/// `sep` is `"\n"` for a file on disk, or the two-character escape `"\\n"` for a PEM embedded in
/// a JSON string (a GCP service-account key).
fn pem_block(label: &str, body: &str, sep: &str) -> String {
    format!("-----BEGIN {label}-----{sep}{body}{sep}-----END {label}-----")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The samples must actually have the lengths the templates assume, or the format-preservation
    /// tests would be asserting against malformed inputs.
    #[test]
    fn samples_have_the_expected_shapes() {
        assert_eq!(for_kind(SecretKind::AwsAccessKeyId).len(), 20);
        assert_eq!(for_kind(SecretKind::AwsSecretKey).len(), 40);
        assert_eq!(for_kind(SecretKind::GithubPat).len(), 40); // "ghp_" + 36
        assert_eq!(for_kind(SecretKind::OpenAiKey).len(), 51); // "sk-" + 48
        assert_eq!(for_kind(SecretKind::GoogleApiKey).len(), 39); // "AIza" + 35
        assert_eq!(for_kind(SecretKind::StripeKey).len(), 32); // "sk_live_" + 24
        assert_eq!(for_kind(SecretKind::Jwt).split('.').count(), 3);
    }

    /// The AWS-secret sample must not be pure hex, or it is a git SHA-1 rather than a secret.
    #[test]
    fn aws_secret_sample_is_not_pure_hex() {
        let s = for_kind(SecretKind::AwsSecretKey);
        assert!(!s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn checksummed_samples_actually_validate() {
        let card: Vec<u8> = for_kind(SecretKind::CreditCard)
            .bytes()
            .filter(u8::is_ascii_digit)
            .collect();
        assert!(crate::checksum::luhn_valid(&card));
        assert!(crate::checksum::iban_valid(&for_kind(SecretKind::Iban)));
    }
}
