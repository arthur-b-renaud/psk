use psk_core::{Pipeline, Span};
use serde_json::Value;

/// Scrub PII/secrets from an Anthropic API request body.
/// Only processes the last user message and the last tool result
/// to avoid re-scanning the entire conversation history.
pub fn scrub_anthropic_request(body: &mut Value, pipeline: &Pipeline) -> Vec<Span> {
    let mut all_spans = Vec::new();

    if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        // Process last user message
        if let Some(last_user_idx) = messages
            .iter()
            .rposition(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        {
            let spans = scrub_message_content(&mut messages[last_user_idx], pipeline);
            all_spans.extend(spans);
        }

        // Process last tool_result message
        if let Some(last_tool_idx) = messages
            .iter()
            .rposition(|m| m.get("role").and_then(|r| r.as_str()) == Some("tool"))
        {
            let spans = scrub_message_content(&mut messages[last_tool_idx], pipeline);
            all_spans.extend(spans);
        }
    }

    // Also scrub the system prompt if present
    if let Some(system) = body.get_mut("system") {
        let spans = scrub_value(system, pipeline);
        all_spans.extend(spans);
    }

    all_spans
}

/// Scrub PII/secrets from an OpenAI API request body.
pub fn scrub_openai_request(body: &mut Value, pipeline: &Pipeline) -> Vec<Span> {
    let mut all_spans = Vec::new();

    if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        // Process last user message
        if let Some(last_user_idx) = messages
            .iter()
            .rposition(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        {
            let spans = scrub_message_content(&mut messages[last_user_idx], pipeline);
            all_spans.extend(spans);
        }

        // Process last tool message
        if let Some(last_tool_idx) = messages
            .iter()
            .rposition(|m| m.get("role").and_then(|r| r.as_str()) == Some("tool"))
        {
            let spans = scrub_message_content(&mut messages[last_tool_idx], pipeline);
            all_spans.extend(spans);
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
    use psk_core::{RedactionPolicy, Recognizer};
    use serde_json::json;

    struct FakeEmailRecognizer;
    impl Recognizer for FakeEmailRecognizer {
        fn id(&self) -> &str {
            "test:email"
        }
        fn recognize(&self, text: &str) -> Vec<psk_core::Span> {
            let pattern = regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
                .unwrap();
            pattern
                .find_iter(text)
                .map(|m| psk_core::Span::new(m.start(), m.end(), EntityType::Email, 1.0, "test"))
                .collect()
        }
    }

    fn test_pipeline() -> Pipeline {
        let mut p = Pipeline::new(RedactionPolicy::default());
        p.add_recognizer(Box::new(FakeEmailRecognizer));
        p
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
}
