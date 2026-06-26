use psk_core::{Pipeline, Span};
use serde_json::Value;

/// Scrub PII/secrets from an Anthropic API request body.
///
/// Walks the **entire** request — every message's content plus the system prompt — not just the
/// last turn. Coding agents resend the full conversation history each request from their own
/// un-redacted local copy, so scrubbing only the latest message would leak earlier-turn secrets on
/// resend. Deterministic vault tokenization makes re-scrubbing already-tokenized text a no-op, so
/// this is cheap and idempotent.
pub fn scrub_anthropic_request(body: &mut Value, pipeline: &Pipeline) -> Vec<Span> {
    let mut all_spans = Vec::new();

    if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for message in messages.iter_mut() {
            all_spans.extend(scrub_message_content(message, pipeline));
        }
    }

    // Anthropic `system` is either a string or an array of text blocks.
    if let Some(system) = body.get_mut("system") {
        all_spans.extend(scrub_value(system, pipeline));
    }

    all_spans
}

/// Scrub PII/secrets from an OpenAI (chat-completions) API request body. Walks every message,
/// including the `system` role message. See [`scrub_anthropic_request`] for why the whole body is
/// processed.
pub fn scrub_openai_request(body: &mut Value, pipeline: &Pipeline) -> Vec<Span> {
    let mut all_spans = Vec::new();

    if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for message in messages.iter_mut() {
            all_spans.extend(scrub_message_content(message, pipeline));
        }
    }

    all_spans
}

/// Scrub PII/secrets from a Gemini (`generateContent`) API request body. Walks
/// `contents[*].parts[*].text` and `system_instruction.parts[*].text`.
pub fn scrub_gemini_request(body: &mut Value, pipeline: &Pipeline) -> Vec<Span> {
    let mut all_spans = Vec::new();

    if let Some(contents) = body.get_mut("contents").and_then(|c| c.as_array_mut()) {
        for content in contents.iter_mut() {
            all_spans.extend(scrub_gemini_parts(content, pipeline));
        }
    }

    // System instruction (snake_case per REST, camelCase per some SDKs).
    for key in ["system_instruction", "systemInstruction"] {
        if let Some(sys) = body.get_mut(key) {
            all_spans.extend(scrub_gemini_parts(sys, pipeline));
        }
    }

    all_spans
}

/// Scrub the `parts[*].text` of a Gemini `Content` object.
fn scrub_gemini_parts(content: &mut Value, pipeline: &Pipeline) -> Vec<Span> {
    let mut all_spans = Vec::new();
    if let Some(parts) = content.get_mut("parts").and_then(|p| p.as_array_mut()) {
        for part in parts.iter_mut() {
            if let Some(Value::String(text)) = part.get_mut("text") {
                let (redacted, spans) = pipeline.redact(text);
                if !spans.is_empty() {
                    *text = redacted;
                    all_spans.extend(spans);
                }
            }
        }
    }
    all_spans
}

/// Scrub content within a single message object.
fn scrub_message_content(message: &mut Value, pipeline: &Pipeline) -> Vec<Span> {
    let mut all_spans = Vec::new();

    match message.get_mut("content") {
        // String content: "content": "some text"
        Some(Value::String(text)) => {
            let (redacted, spans) = pipeline.redact(text);
            if !spans.is_empty() {
                *text = redacted;
                all_spans.extend(spans);
            }
        }
        // Array content: "content": [{"type": "text", "text": "some text"}, ...]
        Some(Value::Array(blocks)) => {
            for block in blocks.iter_mut() {
                if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                    if let Some(Value::String(text)) = block.get_mut("text") {
                        let (redacted, spans) = pipeline.redact(text);
                        if !spans.is_empty() {
                            *text = redacted;
                            all_spans.extend(spans);
                        }
                    }
                }
            }
        }
        _ => {}
    }

    all_spans
}

/// Scrub a generic JSON value (used for system prompts).
fn scrub_value(value: &mut Value, pipeline: &Pipeline) -> Vec<Span> {
    match value {
        Value::String(text) => {
            let (redacted, spans) = pipeline.redact(text);
            if !spans.is_empty() {
                *text = redacted;
            }
            spans
        }
        Value::Array(arr) => arr
            .iter_mut()
            .flat_map(|v| scrub_value(v, pipeline))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_core::span::EntityType;
    use psk_core::{Recognizer, RedactionPolicy};
    use serde_json::json;

    struct FakeEmailRecognizer;
    impl Recognizer for FakeEmailRecognizer {
        fn id(&self) -> &str {
            "test:email"
        }
        fn recognize(&self, text: &str) -> Vec<psk_core::Span> {
            let pattern =
                regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
            pattern
                .find_iter(text)
                .map(|m| psk_core::Span::new(m.start(), m.end(), EntityType::Email, 1.0, "test"))
                .collect()
        }
    }

    /// Matches `SECRET<digits>` and tags it as a (reversible) secret.
    struct FakeSecretRecognizer;
    impl Recognizer for FakeSecretRecognizer {
        fn id(&self) -> &str {
            "test:secret"
        }
        fn recognize(&self, text: &str) -> Vec<psk_core::Span> {
            let pattern = regex::Regex::new(r"SECRET\d+").unwrap();
            pattern
                .find_iter(text)
                .map(|m| {
                    psk_core::Span::new(m.start(), m.end(), EntityType::GenericSecret, 1.0, "test")
                })
                .collect()
        }
    }

    fn test_pipeline() -> Pipeline {
        let mut p = Pipeline::new(RedactionPolicy::default());
        p.add_recognizer(Box::new(FakeEmailRecognizer));
        p
    }

    #[test]
    fn test_egress_tokenizes_secret_and_vault_restores() {
        // The full loop: a secret is tokenized on egress (provider never sees it), and the vault
        // restores the real value — exactly what the PreToolUse restore hook relies on.
        use psk_core::Vault;
        use std::sync::Arc;

        let vault = Arc::new(Vault::new());
        let mut pipeline = Pipeline::new(RedactionPolicy::default()).with_vault(vault.clone());
        pipeline.add_recognizer(Box::new(FakeSecretRecognizer));

        let mut body = json!({
            "messages": [
                {"role": "user", "content": "deploy with SECRET12345 now"}
            ]
        });
        let spans = scrub_anthropic_request(&mut body, &pipeline);
        assert_eq!(spans.len(), 1);

        let sent = body["messages"][0]["content"].as_str().unwrap();
        assert!(!sent.contains("SECRET12345"), "raw secret must not leave");
        assert!(sent.contains("__PSK_"), "secret should be tokenized");
        // The hook restores the real value locally.
        assert_eq!(vault.detokenize(sent), "deploy with SECRET12345 now");
    }

    #[test]
    fn test_scrub_anthropic_string_content() {
        let pipeline = test_pipeline();
        let mut body = json!({
            "messages": [
                {"role": "user", "content": "Email me at john@secret.com"}
            ]
        });
        let spans = scrub_anthropic_request(&mut body, &pipeline);
        assert_eq!(spans.len(), 1);
        assert_eq!(
            body["messages"][0]["content"].as_str().unwrap(),
            "Email me at [EMAIL]"
        );
    }

    #[test]
    fn test_scrub_anthropic_array_content() {
        let pipeline = test_pipeline();
        let mut body = json!({
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "Contact john@secret.com"}
                ]}
            ]
        });
        let spans = scrub_anthropic_request(&mut body, &pipeline);
        assert_eq!(spans.len(), 1);
        assert_eq!(
            body["messages"][0]["content"][0]["text"].as_str().unwrap(),
            "Contact [EMAIL]"
        );
    }

    #[test]
    fn test_scrub_no_secrets() {
        let pipeline = test_pipeline();
        let mut body = json!({
            "messages": [
                {"role": "user", "content": "Hello world"}
            ]
        });
        let spans = scrub_anthropic_request(&mut body, &pipeline);
        assert!(spans.is_empty());
        assert_eq!(
            body["messages"][0]["content"].as_str().unwrap(),
            "Hello world"
        );
    }

    #[test]
    fn test_scrub_whole_history_not_just_last() {
        // Regression: an earlier-turn message must also be scrubbed, since clients resend full
        // history each request from their own un-redacted copy.
        let pipeline = test_pipeline();
        let mut body = json!({
            "messages": [
                {"role": "user", "content": "first turn from old@secret.com"},
                {"role": "assistant", "content": "ok"},
                {"role": "user", "content": "second turn"}
            ]
        });
        let spans = scrub_anthropic_request(&mut body, &pipeline);
        assert_eq!(spans.len(), 1);
        assert_eq!(
            body["messages"][0]["content"].as_str().unwrap(),
            "first turn from [EMAIL]"
        );
    }

    #[test]
    fn test_scrub_gemini_parts() {
        let pipeline = test_pipeline();
        let mut body = json!({
            "contents": [
                {"role": "user", "parts": [{"text": "ping me at dev@secret.com"}]}
            ],
            "system_instruction": {"parts": [{"text": "admin is boss@secret.com"}]}
        });
        let spans = scrub_gemini_request(&mut body, &pipeline);
        assert_eq!(spans.len(), 2);
        assert_eq!(
            body["contents"][0]["parts"][0]["text"].as_str().unwrap(),
            "ping me at [EMAIL]"
        );
        assert_eq!(
            body["system_instruction"]["parts"][0]["text"]
                .as_str()
                .unwrap(),
            "admin is [EMAIL]"
        );
    }
}
