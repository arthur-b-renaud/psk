//! Luhn and ISO 7064 mod-97 — the two checksums PSK both *verifies* (to kill false positives)
//! and *forges* (so a fake card or IBAN is checksum-valid and the LLM never comments on it).
//!
//! Roughly fifteen lines each, so they live here rather than pulling in `luhn3` + `iban` +
//! `card_validate`. `psk-verifiers` will re-export these rather than reimplement them.

/// Luhn checksum over the decimal digits of `digits`.
///
/// Takes `&[u8]` of ASCII digit *characters* (`b'0'..=b'9'`), not their numeric values.
pub fn luhn_valid(digits: &[u8]) -> bool {
    if !(13..=19).contains(&digits.len()) || !digits.iter().all(u8::is_ascii_digit) {
        return false;
    }
    luhn_sum(digits) % 10 == 0
}

/// The Luhn check digit that makes `body` (which excludes the check digit) valid.
///
/// Used to forge a valid fake card: generate `body`, append this.
pub fn luhn_check_digit(body: &[u8]) -> u8 {
    // Appending a check digit shifts every position by one, so the doubling parity flips.
    // Computing the sum of `body` with a placeholder `0` appended gives exactly the parity
    // the real check digit will see.
    let mut with_placeholder = body.to_vec();
    with_placeholder.push(b'0');
    let s = luhn_sum(&with_placeholder);
    b'0' + ((10 - (s % 10)) % 10) as u8
}

/// Sum of Luhn-weighted digits, right to left, doubling every second digit.
fn luhn_sum(digits: &[u8]) -> u32 {
    digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &b)| {
            let d = (b - b'0') as u32;
            if i % 2 == 1 {
                // Doubling can reach 18; 18 -> 1 + 8 == 9, which is `d * 2 - 9`.
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum()
}

/// ISO 13616 IBAN validity: mod-97 of the rearranged, letter-expanded number equals 1.
pub fn iban_valid(iban: &str) -> bool {
    let compact: Vec<u8> = iban
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if !(5..=34).contains(&compact.len()) || !compact.iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    // Country code and check digits must be letters then digits.
    if !compact[..2].iter().all(u8::is_ascii_alphabetic)
        || !compact[2..4].iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    mod97(&rearrange(&compact)) == 1
}

/// The two check digits that make `country` + `bban` a valid IBAN.
///
/// Used to forge a valid fake IBAN: pick a country and BBAN, then insert these at offset 2.
pub fn iban_check_digits(country: &str, bban: &str) -> String {
    // The check digits are computed as if they were `00`.
    let mut probe = Vec::with_capacity(country.len() + 2 + bban.len());
    probe.extend_from_slice(country.as_bytes());
    probe.extend_from_slice(b"00");
    probe.extend_from_slice(bban.as_bytes());
    let remainder = mod97(&rearrange(&probe));
    format!("{:02}", 98 - remainder)
}

/// Move the first four characters to the end, then expand letters: `A` -> 10 … `Z` -> 35.
fn rearrange(compact: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(compact.len() * 2);
    let mut push = |b: u8| {
        if b.is_ascii_digit() {
            out.push(b - b'0');
        } else {
            // `A` is 10, so the tens and units digits are pushed separately.
            let v = b.to_ascii_uppercase() - b'A' + 10;
            out.push(v / 10);
            out.push(v % 10);
        }
    };
    for &b in &compact[4..] {
        push(b);
    }
    for &b in &compact[..4] {
        push(b);
    }
    out
}

/// mod 97 over a sequence of single decimal digits, one digit at a time.
///
/// The number is far too large for `u128`, so it is reduced incrementally.
fn mod97(digits: &[u8]) -> u32 {
    digits
        .iter()
        .fold(0u32, |acc, &d| (acc * 10 + d as u32) % 97)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_accepts_known_test_cards() {
        assert!(luhn_valid(b"4111111111111111")); // Visa test
        assert!(luhn_valid(b"5500005555555559")); // Mastercard test
        assert!(luhn_valid(b"378282246310005")); // Amex test, 15 digits
    }

    #[test]
    fn luhn_rejects_mutations_and_bad_lengths() {
        assert!(!luhn_valid(b"4111111111111112"));
        assert!(!luhn_valid(b"411111111111")); // 12 digits
        assert!(!luhn_valid(b"41111111111111111111")); // 20 digits
        assert!(!luhn_valid(b"4111a11111111111"));
    }

    #[test]
    fn luhn_check_digit_closes_the_sum() {
        for body in [
            &b"411111111111111"[..],
            &b"55000055555555"[..],
            &b"37828224631000"[..],
        ] {
            let mut full = body.to_vec();
            full.push(luhn_check_digit(body));
            assert!(
                luhn_valid(&full),
                "check digit failed for {:?}",
                std::str::from_utf8(body)
            );
        }
    }

    #[test]
    fn iban_accepts_published_examples() {
        assert!(iban_valid("GB82 WEST 1234 5698 7654 32"));
        assert!(iban_valid("DE89370400440532013000"));
        assert!(iban_valid("FR1420041010050500013M02606"));
    }

    #[test]
    fn iban_rejects_mutations() {
        assert!(!iban_valid("GB82WEST12345698765433"));
        assert!(!iban_valid("DE89370400440532013001"));
        assert!(!iban_valid("1289370400440532013000")); // country must be letters
    }

    #[test]
    fn iban_check_digits_round_trip() {
        // Recompute the check digits of a published IBAN and get the same two digits back.
        assert_eq!(iban_check_digits("GB", "WEST12345698765432"), "82");
        assert_eq!(iban_check_digits("DE", "370400440532013000"), "89");
    }

    #[test]
    fn forged_iban_in_reserved_country_validates() {
        let bban = "QPSK1234567890";
        let cd = iban_check_digits("ZZ", bban);
        assert!(iban_valid(&format!("ZZ{cd}{bban}")));
    }
}
