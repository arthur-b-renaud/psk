//! Substitution surfaces (brief §8a) — every place a secret can hide in a Messages API request.
//!
//! "The prompt" is the smallest leak channel. The dominant exfiltration path in agent traffic is
//! **tool output**: the agent runs `cat .env`, reads `settings.py`, greps for credentials, and
//! that content travels upstream inside a `tool_result` block. Missing that surface would make
//! PSK theatre.
//!
//! Covered, explicitly:
//!
//! - `system`, as a string and as a block array;
//! - `messages[].content`, as a string;
//! - `messages[].content[]` blocks of type `text` and `thinking`;
//! - `tool_result` blocks, whose `content` is a string *or* an array of blocks — the big one;
//! - `tool_use` input blocks echoed back in history, whose `input` is arbitrary JSON.
//!
//! Everything else is left byte-identical. In particular `cache_control` markers are never
//! touched: rewriting them would silently invalidate Anthropic's prompt cache and inflate the
//! user's token bill (brief §7a).

use psk_core::{Engine, Summary};
use serde_json::Value;

/// Substitute every secret across all surfaces of a Messages API request body, in place.
///
/// Returns the merged [`Summary`] of what was hidden.
pub fn substitute_request(engine: &Engine, body: &mut Value) -> Summary {
    let mut total = Summary::default();

    if let Some(system) = body.get_mut("system") {
        substitute_text_or_blocks(engine, system, &mut total);
    }

    if let Some(Value::Array(messages)) = body.get_mut("messages") {
        for message in messages {
            if let Some(content) = message.get_mut("content") {
                substitute_message_content(engine, content, &mut total);
            }
        }
    }

    total
}

/// `content` is either a plain string or an array of content blocks.
fn substitute_message_content(engine: &Engine, content: &mut Value, total: &mut Summary) {
    match content {
        Value::String(_) => substitute_string(engine, content, total),
        Value::Array(blocks) => {
            for block in blocks {
                substitute_block(engine, block, total);
            }
        }
        _ => {}
    }
}

/// One content block, dispatched on its `type`.
fn substitute_block(engine: &Engine, block: &mut Value, total: &mut Summary) {
    let Some(kind) = block.get("type").and_then(Value::as_str).map(str::to_owned) else {
        return;
    };

    match kind.as_str() {
        "text" => {
            if let Some(v) = block.get_mut("text") {
                substitute_string(engine, v, total);
            }
        }
        // Thinking blocks are resent in history and are displayed to the user. They are text.
        "thinking" => {
            if let Some(v) = block.get_mut("thinking") {
                substitute_string(engine, v, total);
            }
        }
        // The big one. `content` here is a string or an array of blocks, recursively.
        "tool_result" => {
            if let Some(v) = block.get_mut("content") {
                substitute_message_content(engine, v, total);
            }
        }
        // Arbitrary tool arguments echoed back in history. A `Write` call's `content` field, a
        // `Bash` call's `command` — any string anywhere under `input` can carry a secret, so every
        // string is scanned rather than a hand-maintained list of field names.
        "tool_use" => {
            if let Some(v) = block.get_mut("input") {
                substitute_every_string(engine, v, total);
            }
        }
        _ => {}
    }
}

/// `system` accepts both a bare string and an array of text blocks.
fn substitute_text_or_blocks(engine: &Engine, v: &mut Value, total: &mut Summary) {
    match v {
        Value::String(_) => substitute_string(engine, v, total),
        Value::Array(blocks) => {
            for block in blocks {
                substitute_block(engine, block, total);
            }
        }
        _ => {}
    }
}

/// Recursively substitute every string in an arbitrary JSON value.
///
/// Object **keys** are never rewritten — a key is a field name, not user data, and changing one
/// would break the tool's schema.
fn substitute_every_string(engine: &Engine, v: &mut Value, total: &mut Summary) {
    match v {
        Value::String(_) => substitute_string(engine, v, total),
        Value::Array(items) => {
            for item in items {
                substitute_every_string(engine, item, total);
            }
        }
        Value::Object(map) => {
            for (_key, val) in map.iter_mut() {
                substitute_every_string(engine, val, total);
            }
        }
        _ => {}
    }
}

/// The leaf. Replaces the string's contents with the substituted text.
fn substitute_string(engine: &Engine, v: &mut Value, total: &mut Summary) {
    let Value::String(s) = v else { return };
    // Cheap guard: the engine allocates a fresh String on every call, and most strings in a
    // request (roles, ids, model names) contain nothing.
    if s.is_empty() {
        return;
    }
    let (out, summary) = engine.substitute(s);
    merge(total, summary);
    *s = out;
}

fn merge(into: &mut Summary, from: Summary) {
    for (kind, n) in from.by_kind {
        *into.by_kind.entry(kind).or_insert(0) += n;
    }
    into.chars_hidden += from.chars_hidden;
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_core::{ScanConfig, SecretKind, Vault};
    use psk_vault::sample;
    use serde_json::json;
    use std::sync::Arc;

    fn engine() -> Engine {
        Engine::new(Arc::new(Vault::with_salt([9u8; 32])), ScanConfig::default())
    }

    fn aws() -> String {
        sample::for_kind(SecretKind::AwsAccessKeyId)
    }

    fn ghp() -> String {
        sample::for_kind(SecretKind::GithubPat)
    }

    /// Serialise and assert the real secret is nowhere in the outbound bytes.
    fn assert_absent(body: &Value, secret: &str) {
        let s = serde_json::to_string(body).unwrap();
        assert!(!s.contains(secret), "secret leaked in {s}");
    }

    #[test]
    fn plain_string_content_is_substituted() {
        let e = engine();
        let mut body = json!({"messages": [{"role": "user", "content": format!("key {}", aws())}]});
        let summary = substitute_request(&e, &mut body);
        assert_eq!(summary.total(), 1);
        assert_absent(&body, &aws());
    }

    #[test]
    fn text_blocks_are_substituted() {
        let e = engine();
        let mut body = json!({
            "messages": [{
                "role": "user",
                "content": [{"type": "text", "text": format!("key {}", aws())}]
            }]
        });
        assert_eq!(substitute_request(&e, &mut body).total(), 1);
        assert_absent(&body, &aws());
    }

    #[test]
    fn system_field_is_substituted_as_string_and_as_blocks() {
        let e = engine();

        let mut as_string = json!({"system": format!("deploy with {}", aws()), "messages": []});
        assert_eq!(substitute_request(&e, &mut as_string).total(), 1);
        assert_absent(&as_string, &aws());

        let mut as_blocks = json!({
            "system": [{"type": "text", "text": format!("deploy with {}", aws())}],
            "messages": []
        });
        assert_eq!(substitute_request(&e, &mut as_blocks).total(), 1);
        assert_absent(&as_blocks, &aws());
    }

    /// The acceptance criterion of brief §12: a `.env` file inside a `tool_result` block, and a
    /// secret in the `system` field, both fully substituted before forwarding.
    #[test]
    fn dotenv_inside_a_tool_result_and_a_secret_in_system_are_substituted() {
        let e = engine();
        let dotenv = format!("AWS_ACCESS_KEY_ID={}\nGITHUB_TOKEN={}\n", aws(), ghp());

        let mut body = json!({
            "model": "claude-opus-4-8",
            "system": format!("The deploy key is {}", aws()),
            "messages": [
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "tu_1", "name": "Bash",
                     "input": {"command": "cat .env"}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "tu_1", "content": dotenv}
                ]}
            ]
        });

        let summary = substitute_request(&e, &mut body);
        assert!(
            summary.total() >= 3,
            "system + two .env values: {summary:?}"
        );
        assert_absent(&body, &aws());
        assert_absent(&body, &ghp());

        // Structure survives.
        assert_eq!(body["model"], "claude-opus-4-8");
        assert_eq!(
            body["messages"][0]["content"][0]["input"]["command"],
            "cat .env"
        );
        assert_eq!(body["messages"][1]["content"][0]["tool_use_id"], "tu_1");
    }

    /// `tool_result.content` also comes as an array of blocks.
    #[test]
    fn tool_result_with_array_content_is_substituted() {
        let e = engine();
        let mut body = json!({
            "messages": [{"role": "user", "content": [{
                "type": "tool_result",
                "tool_use_id": "tu_1",
                "content": [{"type": "text", "text": format!("found {}", aws())}]
            }]}]
        });
        assert_eq!(substitute_request(&e, &mut body).total(), 1);
        assert_absent(&body, &aws());
    }

    /// A `Write` tool call carries the file body in `input.content`. Any string under `input` may
    /// hold a secret, so all of them are scanned.
    #[test]
    fn tool_use_input_is_substituted_recursively() {
        let e = engine();
        let mut body = json!({
            "messages": [{"role": "assistant", "content": [{
                "type": "tool_use", "id": "tu_2", "name": "Write",
                "input": {
                    "file_path": "/app/.env",
                    "content": format!("AWS_ACCESS_KEY_ID={}", aws()),
                    "nested": {"deep": [format!("also {}", ghp())]}
                }
            }]}]
        });
        let summary = substitute_request(&e, &mut body);
        assert_eq!(summary.total(), 2);
        assert_absent(&body, &aws());
        assert_absent(&body, &ghp());
        assert_eq!(
            body["messages"][0]["content"][0]["input"]["file_path"],
            "/app/.env"
        );
    }

    #[test]
    fn thinking_blocks_are_substituted() {
        let e = engine();
        let mut body = json!({
            "messages": [{"role": "assistant", "content": [
                {"type": "thinking", "thinking": format!("the key is {}", aws()), "signature": "x"}
            ]}]
        });
        assert_eq!(substitute_request(&e, &mut body).total(), 1);
        assert_absent(&body, &aws());
    }

    /// §7a: `cache_control` blocks pass through untouched, or every cached prefix is invalidated
    /// and the user pays for it in tokens.
    #[test]
    fn cache_control_markers_survive_untouched() {
        let e = engine();
        let mut body = json!({
            "system": [{
                "type": "text",
                "text": format!("deploy with {}", aws()),
                "cache_control": {"type": "ephemeral"}
            }],
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "text",
                    "text": "hello",
                    "cache_control": {"type": "ephemeral", "ttl": "1h"}
                }]
            }]
        });
        substitute_request(&e, &mut body);

        assert_eq!(
            body["system"][0]["cache_control"],
            json!({"type": "ephemeral"})
        );
        assert_eq!(
            body["messages"][0]["content"][0]["cache_control"],
            json!({"type": "ephemeral", "ttl": "1h"})
        );
    }

    /// Object keys are field names, not user data. Rewriting one would break the tool schema.
    #[test]
    fn object_keys_are_never_rewritten() {
        let e = engine();
        let mut body = json!({
            "messages": [{"role": "assistant", "content": [{
                "type": "tool_use", "id": "t", "name": "X",
                "input": {aws(): "value"}
            }]}]
        });
        substitute_request(&e, &mut body);
        assert!(
            body["messages"][0]["content"][0]["input"]
                .as_object()
                .unwrap()
                .contains_key(&aws())
        );
    }

    /// A request with no secrets must come out byte-identical.
    #[test]
    fn clean_request_is_unchanged() {
        let e = engine();
        let original = json!({
            "model": "claude-opus-4-8",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "refactor the parser"}]
        });
        let mut body = original.clone();
        let summary = substitute_request(&e, &mut body);
        assert!(summary.is_empty());
        assert_eq!(body, original);
    }

    /// The guard, at the request level: a history full of fakes is a no-op.
    #[test]
    fn resent_history_of_fakes_is_not_re_substituted() {
        let e = engine();
        let mut body = json!({"messages": [{"role": "user", "content": format!("key {}", aws())}]});
        substitute_request(&e, &mut body);
        let after_first = body.clone();

        let summary = substitute_request(&e, &mut body);
        assert_eq!(summary.total(), 0, "fakes were re-substituted");
        assert_eq!(body, after_first);
    }
}
