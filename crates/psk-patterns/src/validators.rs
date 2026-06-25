//! Post-match validators that reduce false positives.
//! Each validator takes the raw matched text and returns true if it's valid.

/// Luhn checksum validation for credit card numbers.
pub fn validate_luhn(text: &str) -> bool {
    let digits: Vec<u8> = text.bytes().filter(|b| b.is_ascii_digit()).collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    luhn3::decimal::valid(&digits)
}

/// IBAN structural validation.
pub fn validate_iban(text: &str) -> bool {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    cleaned.parse::<iban::Iban>().is_ok()
}

/// Credit card validation using card-validate.
pub fn validate_credit_card(text: &str) -> bool {
    let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    card_validate::Validate::from(&digits).is_ok()
}

/// French INSEE number (numéro de sécurité sociale) validation.
/// Format: S AA MM DDD CCC KK
/// S = sex (1 or 2), AA = year, MM = month (01-12 or 20+ for overseas),
/// DDD = department (001-976 or 2A/2B for Corsica in digit form 99),
/// CCC = commune (001-999), KK = check key
pub fn validate_insee(text: &str) -> bool {
    let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() != 15 {
        return false;
    }

    // Sex must be 1 or 2
    let sex = digits.chars().next().unwrap();
    if sex != '1' && sex != '2' {
        return false;
    }

    // Month must be 01-12 or 20+ (for overseas)
    let month: u8 = digits[3..5].parse().unwrap_or(0);
    if month == 0 || (month > 12 && month < 20) {
        return false;
    }

    // Check key: 97 - (number formed by first 13 digits % 97)
    let number: u64 = match digits[..13].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let expected_key = 97 - (number % 97);
    let actual_key: u64 = match digits[13..15].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    expected_key == actual_key
}

/// French SIRET validation (14 digits, Luhn on full number).
pub fn validate_siret(text: &str) -> bool {
    let digits: Vec<u8> = text.bytes().filter(|b| b.is_ascii_digit()).collect();
    if digits.len() != 14 {
        return false;
    }
    luhn3::decimal::valid(&digits)
}

/// French SIREN validation (9 digits, Luhn on full number).
pub fn validate_siren(text: &str) -> bool {
    let digits: Vec<u8> = text.bytes().filter(|b| b.is_ascii_digit()).collect();
    if digits.len() != 9 {
        return false;
    }
    luhn3::decimal::valid(&digits)
}

/// Dispatch validator by name.
pub fn run_validator(name: &str, text: &str) -> bool {
    match name {
        "luhn" => validate_luhn(text),
        "iban" => validate_iban(text),
        "credit_card" => validate_credit_card(text),
        "insee" => validate_insee(text),
        "siret" => validate_siret(text),
        "siren" => validate_siren(text),
        _ => {
            tracing::warn!("Unknown validator: {}", name);
            true // Unknown validators pass by default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_valid_card() {
        assert!(validate_luhn("4111 1111 1111 1111"));
        assert!(validate_luhn("4111111111111111"));
        assert!(validate_luhn("5425233430109903"));
    }

    #[test]
    fn test_luhn_invalid_card() {
        assert!(!validate_luhn("4111 1111 1111 1112"));
        assert!(!validate_luhn("1234567890"));
    }

    #[test]
    fn test_iban_valid() {
        assert!(validate_iban("GB29 NWBK 6016 1331 9268 19"));
        assert!(validate_iban("FR76 3000 6000 0112 3456 7890 189"));
    }

    #[test]
    fn test_iban_invalid() {
        assert!(!validate_iban("GB29 NWBK 6016 1331 9268 18"));
        assert!(!validate_iban("XX00 0000"));
    }

    #[test]
    fn test_insee_valid() {
        // Example: male, born 1985, month 12, dept 75, commune 056, key
        // We'll compute: 1 85 12 75 056 xxx key
        // For a test, let's use a known valid number
        // 2 55 05 78 043 012 = 2550578043012 => 2550578043012 % 97 = ?
        let num: u64 = 2550578043012;
        let key = 97 - (num % 97);
        let insee = format!("2 55 05 78 043 012 {:02}", key);
        assert!(validate_insee(&insee));
    }

    #[test]
    fn test_siret_valid() {
        // Known valid SIRET: 732 829 320 00074 (La Poste)
        assert!(validate_siret("73282932000074"));
    }

    #[test]
    fn test_siren_valid() {
        // SIREN is first 9 digits of SIRET
        assert!(validate_siren("732829320"));
    }
}
