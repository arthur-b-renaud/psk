//! Hard allowlists: values that pattern-match a secret and are provably not one.
//!
//! Brief §6b. Coding-agent traffic is full of these. Substituting a loopback address fires on
//! every `curl 127.0.0.1` and actively breaks the LLM's reasoning about networking code;
//! substituting a git SHA breaks its reasoning about git. The loop only tolerates false positives
//! if restore is perfect, and restore is not perfect.
//!
//! Every function here answers "is this value *definitely not* a secret?". A `true` means never
//! substitute, no matter what the pattern said.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A 40-character pure-hex string is a git SHA-1, not an AWS secret key.
///
/// This is the single most important allowlist in the codebase: the AWS-secret rule matches any
/// 40-character base64-ish string, git SHAs are 40 hex characters, and agent traffic is saturated
/// with them. Entropy cannot separate the two (random hex scores ~3.9 bits/char, well over any
/// usable floor), so the alphabet must.
pub fn is_git_sha(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Subresource-integrity and lockfile hash shapes: `sha256-…`, `sha512-…`, `sha1-…`.
///
/// These appear in `package-lock.json`, `yarn.lock`, `Cargo.lock`, and every SRI attribute on the
/// web. The payload after the prefix is base64 and high-entropy, so it clears every other gate.
pub fn is_lockfile_hash(s: &str) -> bool {
    ["sha256-", "sha512-", "sha384-", "sha1-"]
        .iter()
        .any(|p| s.starts_with(p))
}

/// A vendor's documented placeholder credential.
///
/// AWS ends its documentation keys with `EXAMPLE` (`AKIAIOSFODNN7EXAMPLE`), and gitleaks
/// allowlists exactly this suffix. Seven characters is long enough that a real key ending in
/// `EXAMPLE` by chance is not worth worrying about.
pub fn is_vendor_placeholder(s: &str) -> bool {
    s.ends_with("EXAMPLE")
}

/// Credentials that are *published*, real-format, and therefore not secrets.
///
/// The canonical case is the set of Firebase example API keys committed to
/// `firebase/firebase-android-sdk` — they have the right shape and high entropy, so no gate but a
/// literal list can reject them. gitleaks maintains the same list. AWS's documentation secret key
/// is here for the same reason: it appears in thousands of tutorials.
///
/// Stored as **SHA-256 digests**, not literals, for two reasons: PSK's own source stays free of
/// strings that trip credential scanners, and the list reads as what it is — an opaque set of
/// known-public values. Provenance is in `CLAUDE.md`.
///
/// This is a per-vendor allowlist, not a general solution, and it will not scale. It exists
/// because these particular values genuinely are everywhere.
pub fn is_published_example_key(s: &str) -> bool {
    use sha2::{Digest, Sha256};

    /// Sorted, so `binary_search` works and a duplicate is obvious in review.
    const PUBLISHED: [&str; 17] = [
        "0b476bdf9acf2123d547b5ae76f1e59884d8ec9553ee0c47e9f31fd4768f3f3c",
        "2037abcaffb2b77785da716cf7ccff4ff4d00c4ea930db0167b7d71f50af7eb4",
        "27a9a42931dff7eb2f8434e20a9bce976ea364e7bee49187f19d5cfeca9c7045",
        "37f8f09bdf12c2f2eae4ead7273a62ddb0c23459cbf902892f282b57f7ed6619",
        "3a8b61d0f636b007840c0d40ba12bcf48465dc054cdc1a68704a33521d84b665",
        "3f370c9dd8225c63b5c77de1f785edc9712958f18bb612d5fa2e0ae33aeca682",
        "49f777db995e8260da7ca9ffdf0c08d66f0453e97ec967018baf2cdfe3b582d0",
        "4c98242dcadc8b29005c6b4aad526552d5ea1842149154c0694adeec75847583",
        "78314b11be2e581549ac1c4f616563fad3fdf0c3b71678f6e2299182080e0598",
        "8731261cb72d86267a32a532ebd3df429e2144e5e4ced7e13568bc9e6c8fb1b1",
        "a19f89ab3555eac10c40741f6df79ecf0935998f15569f8db9d67bce0181fff6",
        "a6c814bc555ae62c7bd8b58ec07bf559c7ed3a009976a1e0acc9cef0d4473b41",
        "dc0fcf046c61640cbd1e8b999ada3262d722c2ca4bf42dceac999020ffdbb614",
        "e4a5542bb7fd7b67e943c71ad29c34b5972c9840597e7eda53e666f44d5da0b9",
        "ea9bb1082cf95663f5faca23b8b15ef2aa0fce0a5c6df9c32dcb85b2e0a4513d",
        "eb540d2b6ee2a0a47c5779bc8a0141784c6b753840d4c6f4e2428a6e86e9e0b1",
        "f56e323494a6ffc2064e7a955908957d84f0755e5f975dabd64328d0359a8f7c",
    ];

    let digest = format!("{:x}", Sha256::digest(s.as_bytes()));
    PUBLISHED.binary_search(&digest.as_str()).is_ok()
}

/// A digit run with too few distinct digits to be a real account number.
///
/// `000000000000000000` is Luhn-valid — every weighted digit is zero, so the sum is zero, which is
/// divisible by ten. It is also a Discord snowflake placeholder, and the corpus caught us
/// substituting it as a credit card. Luhn alone cannot reject a placeholder; variety can.
pub fn is_placeholder_number(digits: &[u8]) -> bool {
    let mut seen = [false; 10];
    for &d in digits.iter().filter(|d| d.is_ascii_digit()) {
        seen[(d - b'0') as usize] = true;
    }
    seen.iter().filter(|s| **s).count() < 4
}

/// Does `s` parse as an IP address at all?
///
/// The IPv4/IPv6 regexes match shapes (`999.999.999.999`, a version string, a time range) that are
/// not addresses. [`is_reserved_ip`] answers "is this a *reserved* address", and returns `false`
/// for non-addresses — so a caller that only consults it would treat garbage as a live secret.
/// Check this first.
pub fn is_valid_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

/// Reserved, private, or documentation IP addresses (brief §6b).
///
/// Covers loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0`, `::`), RFC 1918 private ranges,
/// link-local, and the RFC 5737 / RFC 3849 documentation ranges — which are also where PSK's own
/// fake IPs live, so this doubles as the guard against re-substituting a fake.
pub fn is_reserved_ip(s: &str) -> bool {
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => is_reserved_ipv4(v4),
        Ok(IpAddr::V6(v6)) => is_reserved_ipv6(v6),
        Err(_) => false, // not an IP at all; some other rule's problem
    }
}

fn is_reserved_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_loopback()          // 127.0.0.0/8
        || ip.is_unspecified()    // 0.0.0.0
        || ip.is_private()        // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()     // 169.254/16
        || ip.is_broadcast()      // 255.255.255.255
        || ip.is_multicast()
        // RFC 5737 documentation ranges. `Ipv4Addr::is_documentation` is still unstable, so the
        // three prefixes are spelled out.
        || (a == 192 && b == 0 && c == 2)       // 192.0.2.0/24  (PSK's own fake IPv4 space)
        || (a == 198 && b == 51 && c == 100)    // 198.51.100.0/24
        || (a == 203 && b == 0 && c == 113) // 203.0.113.0/24
}

fn is_reserved_ipv6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (seg[0] & 0xffc0) == 0xfe80             // link-local fe80::/10
        || (seg[0] & 0xfe00) == 0xfc00             // unique-local fc00::/7
        || (seg[0] == 0x2001 && seg[1] == 0x0db8) // RFC 3849 2001:db8::/32 (PSK's fake IPv6 space)
}

/// Reserved and example domains (RFC 2606, RFC 6761).
///
/// `example.com` is also where PSK's own fake emails live, so this is the email-side twin of the
/// documentation-IP rule above.
pub fn is_reserved_domain(domain: &str) -> bool {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    const RESERVED_TLDS: [&str; 4] = [".test", ".invalid", ".localhost", ".example"];
    const RESERVED_DOMAINS: [&str; 3] = ["example.com", "example.org", "example.net"];

    d == "localhost"
        || RESERVED_TLDS.iter().any(|t| d.ends_with(t))
        // `ends_with` on a dot-prefixed suffix so `notexample.com` is not allowlisted.
        || RESERVED_DOMAINS
            .iter()
            .any(|r| d == *r || d.ends_with(&format!(".{r}")))
}

/// An email whose domain is reserved. `alice@example.com` is documentation, not a person.
pub fn is_reserved_email(email: &str) -> bool {
    match email.rsplit_once('@') {
        Some((_, domain)) => is_reserved_domain(domain),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_shas_and_sha256_digests_are_allowlisted() {
        assert!(is_git_sha("d6cd1e2bd19e03a81132a23b2025920577f84e37")); // 40 hex
        assert!(is_git_sha(&"a".repeat(64))); // sha256 hex
        assert!(!is_git_sha("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")); // real AWS shape
        assert!(!is_git_sha(&"a".repeat(39))); // wrong length
    }

    #[test]
    fn lockfile_hashes_are_allowlisted() {
        assert!(is_lockfile_hash(
            "sha512-vfNTPFNH/1sBLPGDDeUXBrXXsRcMdvHt+E6yHhU1c/Uw=="
        ));
        assert!(is_lockfile_hash("sha256-abc123"));
        assert!(!is_lockfile_hash("sha256abc123")); // no separator, not the SRI shape
    }

    #[test]
    fn loopback_private_and_documentation_ips_are_allowlisted() {
        for ip in [
            "127.0.0.1",
            "127.53.1.9",
            "0.0.0.0",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "192.0.2.42", // RFC 5737, and PSK's own fake space
            "198.51.100.7",
            "203.0.113.9",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "2001:db8::1", // RFC 3849, and PSK's own fake space
        ] {
            assert!(is_reserved_ip(ip), "{ip} must be allowlisted");
        }
    }

    #[test]
    fn routable_ips_are_not_allowlisted() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert!(!is_reserved_ip(ip), "{ip} must not be allowlisted");
        }
    }

    #[test]
    fn non_ip_text_is_not_treated_as_reserved() {
        assert!(!is_reserved_ip("not.an.ip.address"));
        assert!(!is_reserved_ip("999.999.999.999"));
    }

    #[test]
    fn reserved_domains_and_emails_are_allowlisted() {
        for d in [
            "example.com",
            "EXAMPLE.COM",
            "sub.example.org",
            "foo.test",
            "localhost",
        ] {
            assert!(is_reserved_domain(d), "{d} must be allowlisted");
        }
        assert!(is_reserved_email("alice@example.com"));
        assert!(is_reserved_email("qpsk-abcdefgh@example.com")); // PSK's own fake email shape
    }

    /// `notexample.com` is a real domain someone could own. The suffix match must not swallow it.
    #[test]
    fn lookalike_domains_are_not_allowlisted() {
        assert!(!is_reserved_domain("notexample.com"));
        assert!(!is_reserved_domain("example.company"));
        assert!(!is_reserved_email("bob@corp.internal"));
    }
}
