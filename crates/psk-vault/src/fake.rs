//! Deterministic, format-preserving fake generation (brief §7a, §7b).
//!
//! ```text
//! fake = format_preserve(HMAC-SHA256(salt, kind_tag || 0x00 || real_value), kind)
//! ```
//!
//! Three properties matter, in this order:
//!
//! 1. **Deterministic.** The same real value always yields the same fake under a given salt, so a
//!    restarted proxy re-derives the identical fake for a secret that reappears in the resent
//!    conversation history. Determinism also keeps Anthropic's prompt-cache prefixes
//!    byte-identical across requests; randomized fakes would silently invalidate the cache and
//!    inflate the user's token bill.
//! 2. **Format-preserving.** Same prefix, same length, same checksum validity, so the LLM's
//!    reasoning about the value is unaffected.
//! 3. **Identifiable.** Every fake carries a reserved marker (or lives in a reserved numeric
//!    space), so an unrestored fake in a diff or a config file is obvious rather than a
//!    three-hour debugging session.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::checksum::{iban_check_digits, luhn_check_digit};
use crate::kind::{
    Alphabet, FAKE_CARD_BIN, FAKE_EMAIL_DOMAIN, FAKE_IBAN_COUNTRY, FAKE_IPV4_PREFIX,
    FAKE_IPV6_PREFIX, MARKER, SecretKind, Shape,
};

type HmacSha256 = Hmac<Sha256>;

/// An unbounded, deterministic byte stream keyed by the salt and seeded by `(kind, real)`.
///
/// HMAC-SHA256 yields 32 bytes at a time; a counter appended to the seed extends it as far as a
/// PEM body needs. This is a counter-mode KDF, not a cipher: it never needs to be inverted.
struct KeyStream {
    salt: [u8; 32],
    seed: Vec<u8>,
    counter: u32,
    block: [u8; 32],
    pos: usize,
}

impl KeyStream {
    fn new(salt: &[u8; 32], kind: SecretKind, real: &str) -> Self {
        // Domain separation: the same string detected as two kinds must not derive one fake.
        // The `0x00` byte prevents ("ab", "c") and ("a", "bc") from seeding identically.
        let mut seed = Vec::with_capacity(kind.tag().len() + 1 + real.len());
        seed.extend_from_slice(kind.tag().as_bytes());
        seed.push(0x00);
        seed.extend_from_slice(real.as_bytes());
        let mut ks = KeyStream {
            salt: *salt,
            seed,
            counter: 0,
            block: [0u8; 32],
            pos: 32, // forces a refill on first use
        };
        ks.refill();
        ks
    }

    fn refill(&mut self) {
        // `new_from_slice` only fails on impossible key lengths for HMAC, which accepts any
        // length; the salt is always 32 bytes. Still, no `.unwrap()` on a fallible path that
        // user input could reach — this one cannot, and the expect documents why.
        let mut mac = HmacSha256::new_from_slice(&self.salt)
            .expect("HMAC accepts keys of any length; salt is 32 bytes");
        mac.update(&self.seed);
        mac.update(&self.counter.to_be_bytes());
        self.block = mac.finalize().into_bytes().into();
        self.counter += 1;
        self.pos = 0;
    }

    fn next_byte(&mut self) -> u8 {
        if self.pos == 32 {
            self.refill();
        }
        let b = self.block[self.pos];
        self.pos += 1;
        b
    }

    /// One character from `alphabet`.
    ///
    /// `byte % len` is very slightly biased toward the first few characters. That is irrelevant
    /// here: the fake needs to be unguessable-enough not to collide, not cryptographically
    /// uniform. Rejection sampling would buy nothing and cost determinism clarity.
    fn next_char(&mut self, alphabet: Alphabet) -> char {
        let chars = alphabet.chars();
        chars[self.next_byte() as usize % chars.len()] as char
    }

    fn next_digit(&mut self) -> u8 {
        b'0' + self.next_byte() % 10
    }

    fn next_string(&mut self, alphabet: Alphabet, len: usize) -> String {
        (0..len).map(|_| self.next_char(alphabet)).collect()
    }
}

/// The seed and the derived block are scratch space over a real secret's bytes. Wipe them.
/// (What this does *not* cover is documented in `lib.rs`.)
impl Drop for KeyStream {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.block.zeroize();
        self.salt.zeroize();
    }
}

/// Derive the fake for `real` under `kind`. Pure: same inputs, same output, always.
pub(crate) fn derive(salt: &[u8; 32], kind: SecretKind, real: &str) -> String {
    let mut ks = KeyStream::new(salt, kind, real);
    match kind.shape() {
        Shape::Token {
            copy_prefix,
            alphabet,
            marker_offset,
        } => token(&mut ks, real, copy_prefix, alphabet, marker_offset),
        Shape::Jwt => jwt(&mut ks, real),
        Shape::Pem => pem(&mut ks, real),
        Shape::CreditCard => credit_card(&mut ks, real),
        Shape::Iban => iban(&mut ks, real),
        Shape::IpV4 => ipv4(&mut ks),
        Shape::IpV6 => ipv6(&mut ks),
        Shape::Email => email(&mut ks),
    }
}

/// Overwrite `body[offset..offset+4]` with the marker, clamping so it always lands inside.
/// A body shorter than the marker simply carries none; such values are not credentials.
fn stamp_marker(body: &mut [char], offset: usize) {
    if body.len() < MARKER.len() {
        return;
    }
    let start = offset.min(body.len() - MARKER.len());
    for (i, c) in MARKER.chars().enumerate() {
        body[start + i] = c;
    }
}

/// `prefix + opaque body`, preserving the real value's exact length.
fn token(
    ks: &mut KeyStream,
    real: &str,
    copy_prefix: usize,
    alphabet: Alphabet,
    marker_offset: usize,
) -> String {
    let chars: Vec<char> = real.chars().collect();
    let split = copy_prefix.min(chars.len());
    let body_len = chars.len() - split;

    let mut body: Vec<char> = (0..body_len).map(|_| ks.next_char(alphabet)).collect();
    stamp_marker(&mut body, marker_offset);

    let mut out: String = chars[..split].iter().collect();
    out.extend(body);
    out
}

/// Three base64url segments. The header is copied verbatim: it encodes only `alg` and `typ`,
/// which are not secret, and keeping it real preserves the LLM's ability to reason about the
/// algorithm. Payload and signature are generated at their original lengths.
fn jwt(ks: &mut KeyStream, real: &str) -> String {
    let segs: Vec<&str> = real.split('.').collect();
    if segs.len() != 3 {
        // Not actually a JWT shape; fall back to an opaque token of the same length.
        return token(ks, real, 0, Alphabet::Base64Url, 0);
    }
    let mut payload: Vec<char> = (0..segs[1].chars().count())
        .map(|_| ks.next_char(Alphabet::Base64Url))
        .collect();
    stamp_marker(&mut payload, 0);
    let signature = ks.next_string(Alphabet::Base64Url, segs[2].chars().count());
    let payload: String = payload.into_iter().collect();
    format!("{}.{}.{}", segs[0], payload, signature)
}

/// `-----BEGIN <label>-----` … `-----END <label>-----`, label and body length preserved,
/// body re-wrapped at 64 characters like every PEM emitter does.
fn pem(ks: &mut KeyStream, real: &str) -> String {
    let lines: Vec<&str> = real.lines().collect();
    let begin = lines.iter().find(|l| l.contains("-----BEGIN"));
    let end = lines.iter().find(|l| l.contains("-----END"));
    let (Some(begin), Some(end)) = (begin, end) else {
        return token(ks, real, 0, Alphabet::Base64Url, 0);
    };

    // Body length = every base64 character between the armour lines.
    let body_len: usize = lines
        .iter()
        .filter(|l| !l.contains("-----"))
        .map(|l| l.trim().chars().count())
        .sum();

    let mut body: Vec<char> = (0..body_len)
        .map(|_| ks.next_char(Alphabet::Base62))
        .collect();
    stamp_marker(&mut body, 0);

    let mut out = String::with_capacity(real.len());
    out.push_str(begin.trim());
    out.push('\n');
    for chunk in body.chunks(64) {
        out.extend(chunk);
        out.push('\n');
    }
    out.push_str(end.trim());
    out
}

/// Luhn-valid, prefixed with a reserved test BIN, and the real value's separators preserved.
///
/// A digit-only format cannot carry the alphabetic marker; the reserved BIN plays that role.
fn credit_card(ks: &mut KeyStream, real: &str) -> String {
    let digit_count = real.chars().filter(char::is_ascii_digit).count();
    if !(13..=19).contains(&digit_count) {
        return token(ks, real, 0, Alphabet::Base62, 0);
    }

    let mut digits: Vec<u8> = Vec::with_capacity(digit_count);
    digits.extend_from_slice(FAKE_CARD_BIN.as_bytes());
    // Everything between the BIN and the final check digit is derived.
    for _ in 0..(digit_count - FAKE_CARD_BIN.len() - 1) {
        digits.push(ks.next_digit());
    }
    digits.push(luhn_check_digit(&digits));

    reapply_separators(real, &digits)
}

/// mod-97-valid, in an unassigned country code, with `QPSK` opening the BBAN.
fn iban(ks: &mut KeyStream, real: &str) -> String {
    let compact: Vec<char> = real.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if !(8..=34).contains(&compact.len()) {
        return token(ks, real, 0, Alphabet::Base62, 0);
    }
    let bban_len = compact.len() - 4;

    // The BBAN of an unassigned country has no mandated structure, so it can be alphanumeric
    // and carry the marker like every other alphanumeric fake.
    let mut bban: Vec<char> = (0..bban_len)
        .map(|_| ks.next_char(Alphabet::UpperAlnum))
        .collect();
    stamp_marker(&mut bban, 0);
    let bban: String = bban.into_iter().collect();

    let check = iban_check_digits(FAKE_IBAN_COUNTRY, &bban);
    let full: Vec<u8> = format!("{FAKE_IBAN_COUNTRY}{check}{bban}").into_bytes();
    reapply_separators(real, &full)
}

/// RFC 5737 documentation address. Never routed, so it is unmistakably not a real host.
fn ipv4(ks: &mut KeyStream) -> String {
    // 1..=254 keeps it a plausible host address rather than a network or broadcast address.
    format!("{FAKE_IPV4_PREFIX}{}", 1 + ks.next_byte() % 254)
}

/// RFC 3849 documentation prefix.
fn ipv6(ks: &mut KeyStream) -> String {
    format!(
        "{FAKE_IPV6_PREFIX}{:02x}{:02x}",
        ks.next_byte(),
        ks.next_byte()
    )
}

/// RFC 2606 reserved domain, with a lowercase marker in the local part.
fn email(ks: &mut KeyStream) -> String {
    let local: String = (0..8)
        .map(|_| ks.next_char(Alphabet::Base62).to_ascii_lowercase())
        .collect();
    format!(
        "{}-{local}@{FAKE_EMAIL_DOMAIN}",
        MARKER.to_ascii_lowercase()
    )
}

/// Lay `new_chars` back into the non-alphanumeric skeleton of `template`.
///
/// `4111 1111 1111 1111` in, `4111 1111 1111 1111`-shaped out — spaces and dashes where the real
/// value had them, so the fake looks like it came from the same place.
fn reapply_separators(template: &str, new_chars: &[u8]) -> String {
    let mut it = new_chars.iter();
    let mut out = String::with_capacity(template.len());
    for c in template.chars() {
        if c.is_ascii_alphanumeric() {
            match it.next() {
                Some(&b) => out.push(b as char),
                None => break,
            }
        } else {
            out.push(c);
        }
    }
    // Any surplus (the template had fewer alphanumerics than we generated) is appended so the
    // checksum stays intact. In practice the counts match by construction.
    out.extend(it.map(|&b| b as char));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::{iban_valid, luhn_valid};

    const SALT: [u8; 32] = [7u8; 32];

    #[test]
    fn aws_access_key_keeps_prefix_length_and_marker() {
        let real = crate::sample::for_kind(SecretKind::AwsAccessKeyId);
        let fake = derive(&SALT, SecretKind::AwsAccessKeyId, &real);
        assert_eq!(fake.len(), 20);
        assert!(fake.starts_with("AKIA"));
        assert!(
            fake[4..].starts_with(MARKER),
            "marker at kind offset: {fake}"
        );
        assert!(
            fake.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn github_pat_variable_prefix_survives() {
        for p in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
            let real = format!("{p}{}", "a".repeat(36));
            let fake = derive(&SALT, SecretKind::GithubPat, &real);
            assert_eq!(fake.len(), real.len());
            assert!(fake.starts_with(p), "{p} lost in {fake}");
            assert!(fake.contains(MARKER));
        }
    }

    #[test]
    fn aws_secret_key_fake_is_never_pure_hex() {
        // A pure-hex 40-char fake would be re-detected as a git SHA-1 by our own rules (§6b).
        let fake = derive(&SALT, SecretKind::AwsSecretKey, &"a".repeat(40));
        assert_eq!(fake.len(), 40);
        assert!(!fake.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(fake.contains(MARKER));
    }

    #[test]
    fn card_fake_passes_luhn_and_keeps_separators() {
        let fake = derive(&SALT, SecretKind::CreditCard, "4539 1488 0343 6467");
        let digits: Vec<u8> = fake.bytes().filter(u8::is_ascii_digit).collect();
        assert!(luhn_valid(&digits), "{fake} must be Luhn-valid");
        assert!(fake.starts_with("4111"), "reserved test BIN: {fake}");
        assert_eq!(fake.len(), "4539 1488 0343 6467".len());
        assert_eq!(fake.matches(' ').count(), 3);
    }

    #[test]
    fn iban_fake_passes_mod97_in_a_reserved_country() {
        let fake = derive(&SALT, SecretKind::Iban, "GB82 WEST 1234 5698 7654 32");
        assert!(iban_valid(&fake), "{fake} must be mod-97-valid");
        assert!(fake.starts_with("ZZ"));
        assert!(fake.contains(MARKER));
        assert_eq!(fake.len(), "GB82 WEST 1234 5698 7654 32".len());
    }

    #[test]
    fn jwt_keeps_header_and_segment_lengths() {
        let real = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g";
        let fake = derive(&SALT, SecretKind::Jwt, real);
        let (r, f): (Vec<_>, Vec<_>) = (real.split('.').collect(), fake.split('.').collect());
        assert_eq!(f.len(), 3);
        assert_eq!(f[0], r[0], "header is not secret and is copied verbatim");
        assert_eq!(f[1].len(), r[1].len());
        assert_eq!(f[2].len(), r[2].len());
        assert!(fake.contains(MARKER));
    }

    #[test]
    fn pem_keeps_armour_and_wraps_at_64() {
        let real =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
        let fake = derive(&SALT, SecretKind::PrivateKeyBlock, real);
        assert!(fake.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"));
        assert!(fake.ends_with("-----END RSA PRIVATE KEY-----"));
        assert!(fake.contains(MARKER));
        let body: String = fake.lines().filter(|l| !l.contains("-----")).collect();
        assert_eq!(body.len(), 16, "body length preserved (6 + 10 chars)");
    }

    #[test]
    fn reserved_space_kinds_land_in_documentation_ranges() {
        assert!(derive(&SALT, SecretKind::IpV4, "8.8.8.8").starts_with("192.0.2."));
        assert!(derive(&SALT, SecretKind::IpV6, "2606:4700::1111").starts_with("2001:db8::"));
        assert!(derive(&SALT, SecretKind::Email, "a@b.com").ends_with("@example.com"));
        assert!(derive(&SALT, SecretKind::Email, "a@b.com").starts_with("qpsk-"));
    }

    #[test]
    fn derivation_is_deterministic_and_salt_dependent() {
        let real = crate::sample::for_kind(SecretKind::AwsAccessKeyId);
        let a = derive(&SALT, SecretKind::AwsAccessKeyId, &real);
        let b = derive(&SALT, SecretKind::AwsAccessKeyId, &real);
        assert_eq!(a, b, "same salt + same input must give the same fake");

        let other = derive(&[9u8; 32], SecretKind::AwsAccessKeyId, &real);
        assert_ne!(a, other, "a different salt must give a different fake");
    }

    #[test]
    fn kind_is_domain_separated() {
        // One string, two kinds, two different fakes — otherwise the reverse map is ambiguous.
        let s = "sk-ant-abcdefghijklmnop";
        let a = derive(&SALT, SecretKind::AnthropicKey, s);
        let b = derive(&SALT, SecretKind::BearerToken, s);
        assert_ne!(a, b);
    }

    #[test]
    fn distinct_reals_never_collide() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..2_000 {
            let real = format!("AKIA{:016}", i);
            assert!(
                seen.insert(derive(&SALT, SecretKind::AwsAccessKeyId, &real)),
                "collision at {i}"
            );
        }
    }

    #[test]
    fn fake_never_equals_the_real_value() {
        for k in SecretKind::ALL {
            let real = crate::sample::for_kind(k);
            assert_ne!(
                derive(&SALT, k, &real),
                real,
                "{k:?} fake equals the real value"
            );
        }
    }
}
