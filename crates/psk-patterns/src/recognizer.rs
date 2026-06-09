use crate::loader::PatternDefinition;
use crate::validators;
use psk_core::span::{EntityType, Span};
use psk_core::Recognizer;
use regex::Regex;

/// A regex-based recognizer with optional post-match validation.
pub struct RegexRecognizer {
    id: String,
    regex: Regex,
    entity: EntityType,
    confidence: f64,
    validator: Option<String>,
}

impl RegexRecognizer {
    /// Create a recognizer from a YAML pattern definition.
    pub fn from_definition(pack: &str, def: &PatternDefinition) -> anyhow::Result<Self> {
        let regex = Regex::new(&def.pattern)
            .map_err(|e| anyhow::anyhow!("Invalid regex for '{}': {}", def.name, e))?;
        let entity = parse_entity_type(&def.entity)?;

        Ok(Self {
            id: format!("regex:{}:{}", pack, def.name),
            regex,
            entity,
            confidence: def.confidence,
            validator: def.validator.clone(),
        })
    }
}

impl Recognizer for RegexRecognizer {
    fn id(&self) -> &str {
        &self.id
    }

    fn recognize(&self, text: &str) -> Vec<Span> {
        self.regex
            .find_iter(text)
            .filter_map(|m| {
                let matched = m.as_str();

                // Run validator if configured
                if let Some(ref validator_name) = self.validator {
                    if !validators::run_validator(validator_name, matched) {
                        return None;
                    }
                }

                Some(Span::new(
                    m.start(),
                    m.end(),
                    self.entity.clone(),
                    self.confidence,
                    &self.id,
                ))
            })
            .collect()
    }
}

/// Parse an entity type string from YAML into the enum.
fn parse_entity_type(s: &str) -> anyhow::Result<EntityType> {
    match s {
        // Secrets
        "AwsAccessKey" => Ok(EntityType::AwsAccessKey),
        "AwsSecretKey" => Ok(EntityType::AwsSecretKey),
        "AnthropicApiKey" => Ok(EntityType::AnthropicApiKey),
        "OpenAiApiKey" => Ok(EntityType::OpenAiApiKey),
        "GitHubToken" => Ok(EntityType::GitHubToken),
        "StripeKey" => Ok(EntityType::StripeKey),
        "GoogleApiKey" => Ok(EntityType::GoogleApiKey),
        "SlackToken" => Ok(EntityType::SlackToken),
        "Jwt" => Ok(EntityType::Jwt),
        "BearerToken" => Ok(EntityType::BearerToken),
        "GenericSecret" => Ok(EntityType::GenericSecret),
        "SshPrivateKey" => Ok(EntityType::SshPrivateKey),
        // Contact
        "Email" => Ok(EntityType::Email),
        "PhoneInternational" => Ok(EntityType::PhoneInternational),
        "PhoneFr" => Ok(EntityType::PhoneFr),
        "PhoneUs" => Ok(EntityType::PhoneUs),
        // Financial
        "CreditCard" => Ok(EntityType::CreditCard),
        "Iban" => Ok(EntityType::Iban),
        "Bic" => Ok(EntityType::Bic),
        "FrRib" => Ok(EntityType::FrRib),
        // Identity
        "UsSsn" => Ok(EntityType::UsSsn),
        "FrInsee" => Ok(EntityType::FrInsee),
        "FrSiret" => Ok(EntityType::FrSiret),
        "FrSiren" => Ok(EntityType::FrSiren),
        "EsNif" => Ok(EntityType::EsNif),
        "UkNin" => Ok(EntityType::UkNin),
        // Network
        "Ipv4" => Ok(EntityType::Ipv4),
        "Ipv6" => Ok(EntityType::Ipv6),
        "MacAddress" => Ok(EntityType::MacAddress),
        "UrlWithAuth" => Ok(EntityType::UrlWithAuth),
        // Generic
        "Uuid" => Ok(EntityType::Uuid),
        "Base64Blob" => Ok(EntityType::Base64Blob),
        "HexBlob" => Ok(EntityType::HexBlob),
        // NER
        "Person" => Ok(EntityType::Person),
        "Organization" => Ok(EntityType::Organization),
        "Address" => Ok(EntityType::Address),
        "Location" => Ok(EntityType::Location),
        // Custom
        other => Ok(EntityType::Custom(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::PatternDefinition;

    fn make_def(name: &str, entity: &str, pattern: &str) -> PatternDefinition {
        PatternDefinition {
            name: name.to_string(),
            entity: entity.to_string(),
            pattern: pattern.to_string(),
            confidence: 0.95,
            validator: None,
            description: None,
        }
    }

    #[test]
    fn test_email_recognizer() {
        let def = make_def(
            "email",
            "Email",
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        );
        let r = RegexRecognizer::from_definition("contact", &def).unwrap();
        let spans = r.recognize("Send to john@example.com please");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity, EntityType::Email);
        assert_eq!(&"Send to john@example.com please"[spans[0].start..spans[0].end], "john@example.com");
    }

    #[test]
    fn test_aws_key_recognizer() {
        let def = make_def("aws_access_key", "AwsAccessKey", r"AKIA[0-9A-Z]{16}");
        let r = RegexRecognizer::from_definition("secrets", &def).unwrap();
        let spans = r.recognize("key: AKIAIOSFODNN7EXAMPLE");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].entity, EntityType::AwsAccessKey);
    }

    #[test]
    fn test_credit_card_with_luhn_validator() {
        let def = PatternDefinition {
            name: "visa".to_string(),
            entity: "CreditCard".to_string(),
            pattern: r"4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}".to_string(),
            confidence: 0.95,
            validator: Some("luhn".to_string()),
            description: None,
        };
        let r = RegexRecognizer::from_definition("financial", &def).unwrap();

        // Valid Luhn
        let spans = r.recognize("card: 4111111111111111");
        assert_eq!(spans.len(), 1);

        // Invalid Luhn
        let spans = r.recognize("card: 4111111111111112");
        assert_eq!(spans.len(), 0);
    }

    #[test]
    fn test_no_match() {
        let def = make_def("email", "Email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}");
        let r = RegexRecognizer::from_definition("contact", &def).unwrap();
        let spans = r.recognize("No emails here!");
        assert!(spans.is_empty());
    }
}
