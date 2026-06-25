use serde::{Deserialize, Serialize};
use std::fmt;

/// The type of entity detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    // Secrets
    AwsAccessKey,
    AwsSecretKey,
    AwsSessionToken,
    AnthropicApiKey,
    OpenAiApiKey,
    GitHubToken,
    GitlabToken,
    StripeKey,
    GoogleApiKey,
    GcpServiceAccountKey,
    SlackToken,
    SlackWebhook,
    TwilioKey,
    SendgridKey,
    MailgunKey,
    NpmToken,
    PypiToken,
    HuggingfaceToken,
    DigitaloceanToken,
    CloudflareToken,
    DatadogKey,
    SentryDsn,
    DiscordToken,
    TelegramBotToken,
    ShopifyToken,
    Jwt,
    BearerToken,
    GenericSecret,
    SshPrivateKey,
    PgpPrivateKey,
    ConnectionString,

    // Contact
    Email,
    PhoneInternational,
    PhoneFr,
    PhoneUs,

    // Financial
    CreditCard,
    Iban,
    Bic,
    FrRib,

    // Identity
    UsSsn,
    FrInsee,
    FrSiret,
    FrSiren,
    EsNif,
    UkNin,

    // Network
    Ipv4,
    Ipv6,
    MacAddress,
    UrlWithAuth,

    // Generic
    Uuid,
    Base64Blob,
    HexBlob,

    // User-defined
    Custom(String),
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntityType::Custom(name) => write!(f, "{}", name),
            other => {
                // Convert enum variant to SCREAMING_SNAKE_CASE for display
                let s = format!("{:?}", other);
                let mut result = String::new();
                for (i, ch) in s.chars().enumerate() {
                    if ch.is_uppercase() && i > 0 {
                        result.push('_');
                    }
                    result.push(ch.to_ascii_uppercase());
                }
                write!(f, "{}", result)
            }
        }
    }
}

/// A detected span within the input text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    /// Byte offset start (inclusive).
    pub start: usize,
    /// Byte offset end (exclusive).
    pub end: usize,
    /// The type of entity detected.
    pub entity: EntityType,
    /// Confidence score (0.0 to 1.0). Regex matches default to 1.0.
    pub confidence: f64,
    /// Which recognizer produced this span.
    pub recognizer_id: String,
}

impl Span {
    pub fn new(
        start: usize,
        end: usize,
        entity: EntityType,
        confidence: f64,
        recognizer_id: impl Into<String>,
    ) -> Self {
        Self {
            start,
            end,
            entity,
            confidence,
            recognizer_id: recognizer_id.into(),
        }
    }

    /// The length of the matched text in bytes.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether this span is empty.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Check if this span overlaps with another.
    pub fn overlaps(&self, other: &Span) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Extract the matched text from the original input.
    pub fn extract<'a>(&self, text: &'a str) -> &'a str {
        &text[self.start..self.end]
    }
}
