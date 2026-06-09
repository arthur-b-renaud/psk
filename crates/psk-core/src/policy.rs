use crate::span::EntityType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// What to do with a detected entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionAction {
    /// Replace with a tag like `[EMAIL]`, `[API_KEY]`.
    Replace,
    /// Mask partially: `j***@e***.com`.
    Mask,
    /// Replace with a deterministic hash (reversible with the salt).
    Hash,
}

impl Default for RedactionAction {
    fn default() -> Self {
        RedactionAction::Replace
    }
}

/// Redaction policy: maps entity types to actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionPolicy {
    /// Default action for entity types not explicitly configured.
    #[serde(default)]
    pub default_action: RedactionAction,
    /// Per-entity overrides.
    #[serde(default)]
    pub overrides: HashMap<String, RedactionAction>,
    /// Salt for hash-based redaction.
    #[serde(default = "default_salt")]
    pub hash_salt: String,
}

fn default_salt() -> String {
    "psk-default-salt".to_string()
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            default_action: RedactionAction::Replace,
            overrides: HashMap::new(),
            hash_salt: default_salt(),
        }
    }
}

impl RedactionPolicy {
    /// Get the action for a given entity type.
    pub fn action_for(&self, entity: &EntityType) -> &RedactionAction {
        let key = entity.to_string();
        self.overrides.get(&key).unwrap_or(&self.default_action)
    }

    /// Apply the redaction action to a matched text span.
    pub fn redact(&self, entity: &EntityType, matched_text: &str) -> String {
        match self.action_for(entity) {
            RedactionAction::Replace => {
                format!("[{}]", entity)
            }
            RedactionAction::Mask => Self::mask_text(entity, matched_text),
            RedactionAction::Hash => self.hash_text(matched_text),
        }
    }

    fn mask_text(entity: &EntityType, text: &str) -> String {
        match entity {
            EntityType::Email => {
                // j***@e***.com
                if let Some((local, domain)) = text.split_once('@') {
                    let masked_local = Self::mask_part(local);
                    let masked_domain = Self::mask_part(domain);
                    format!("{}@{}", masked_local, masked_domain)
                } else {
                    Self::mask_generic(text)
                }
            }
            EntityType::CreditCard => {
                // ****-****-****-6467
                let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 4 {
                    let last4 = &digits[digits.len() - 4..];
                    format!("****-****-****-{}", last4)
                } else {
                    Self::mask_generic(text)
                }
            }
            EntityType::PhoneFr | EntityType::PhoneUs | EntityType::PhoneInternational => {
                // ***-***-**78
                let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 2 {
                    let last2 = &digits[digits.len() - 2..];
                    format!("***-***-**{}", last2)
                } else {
                    Self::mask_generic(text)
                }
            }
            _ => Self::mask_generic(text),
        }
    }

    fn mask_part(s: &str) -> String {
        let mut chars = s.chars();
        if let Some(first) = chars.next() {
            let rest_len = chars.count();
            format!("{}{}", first, "*".repeat(rest_len.min(5)))
        } else {
            "***".to_string()
        }
    }

    fn mask_generic(text: &str) -> String {
        let len = text.len();
        if len <= 4 {
            "*".repeat(len)
        } else {
            let visible = &text[..2];
            format!("{}{}**", visible, "*".repeat((len - 4).min(10)))
        }
    }

    fn hash_text(&self, text: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.hash_salt.as_bytes());
        hasher.update(text.as_bytes());
        let result = hasher.finalize();
        format!("[HASH:{}]", hex::encode(&result[..8]))
    }
}

// Inline hex encoding to avoid another dependency.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_action() {
        let policy = RedactionPolicy::default();
        let result = policy.redact(&EntityType::Email, "test@example.com");
        assert_eq!(result, "[EMAIL]");
    }

    #[test]
    fn test_mask_email() {
        let mut policy = RedactionPolicy::default();
        policy
            .overrides
            .insert("EMAIL".to_string(), RedactionAction::Mask);
        let result = policy.redact(&EntityType::Email, "john@example.com");
        assert_eq!(result, "j***@e*****");
    }

    #[test]
    fn test_mask_credit_card() {
        let mut policy = RedactionPolicy::default();
        policy
            .overrides
            .insert("CREDIT_CARD".to_string(), RedactionAction::Mask);
        let result = policy.redact(&EntityType::CreditCard, "4532 1488 0343 6467");
        assert_eq!(result, "****-****-****-6467");
    }

    #[test]
    fn test_hash_action() {
        let mut policy = RedactionPolicy::default();
        policy.default_action = RedactionAction::Hash;
        let result = policy.redact(&EntityType::Email, "test@example.com");
        assert!(result.starts_with("[HASH:"));
        assert!(result.ends_with(']'));
        // Deterministic
        let result2 = policy.redact(&EntityType::Email, "test@example.com");
        assert_eq!(result, result2);
    }
}
