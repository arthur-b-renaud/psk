//! Turning the captured request body into something a human can read.
//!
//! `rewritten_text` is the whole outbound request, serialised **compact** by the proxy — one
//! enormous line. Rendered raw it is unreadable. [`pretty`] re-indents it; [`pretty_folded`]
//! additionally collapses the "technical" subtrees (tool definitions, schemas, tool calls) that
//! dominate a Claude Code request and bury the parts a human actually reads. The colouring is done
//! by the renderer. Kept pure and here (not in `render`) so it can be tested without a terminal.

use serde_json::Value;

/// Below this many characters of pretty-printed JSON a node is never folded: collapsing something
/// that already fits in a line or two saves nothing and hides context.
const FOLD_MIN_CHARS: usize = 400;

/// Pretty-print `text` if it is JSON; otherwise return it unchanged.
///
/// The body is almost always a JSON Messages-API request, but PSK forwards non-JSON bodies
/// untouched (see the proxy's `forward`), so the inspector must survive a non-JSON `rewritten_text`
/// too — it simply shows it as-is.
pub fn pretty(text: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(value) => serde_json::to_string_pretty(&value).unwrap_or_else(|_| text.to_string()),
        Err(_) => text.to_string(),
    }
}

/// Like [`pretty`], but with the technical subtrees folded to a one-line summary:
///
/// - each entry of the request's top-level `tools` array (a Claude Code request carries dozens of
///   tools whose descriptions run to kilobytes),
/// - any `input_schema` value,
/// - `tool_use` / `tool_result` content blocks anywhere in the message history,
/// - the top-level `system` prompt (and, if it is an array, each of its blocks).
///
/// Two overrides keep the fold honest. Small nodes ([`FOLD_MIN_CHARS`]) are never folded — there
/// is nothing to save. And a subtree containing `marker` (a substituted secret) is never folded:
/// the pane exists to show what was hidden, so a fold must not hide the evidence. Only the
/// marker-free siblings collapse around it.
///
/// Non-JSON text passes through unchanged, exactly as in [`pretty`].
pub fn pretty_folded(text: &str, marker: &str) -> String {
    match serde_json::from_str::<Value>(text) {
        Ok(value) => {
            let mut out = String::new();
            write_value(&value, 0, Slot::Root, marker, &mut out);
            out
        }
        Err(_) => text.to_string(),
    }
}

/// Where a node sits in its parent — what the positional fold rules key on.
#[derive(Clone, Copy)]
enum Slot<'a> {
    Root,
    /// An object member under this key. `top_level` distinguishes the request's own `system` from
    /// a key of the same name buried inside a message.
    Member {
        key: &'a str,
        top_level: bool,
    },
    /// An array element: the key its array lives under (if any), and whether that array is a
    /// top-level field of the request — so `tools[*]` means the request's tool list, not some
    /// nested `"tools"` inside a prompt.
    Elem {
        array_key: Option<&'a str>,
        top_level: bool,
    },
}

/// Is this node one of the technical shapes that folds by default?
fn is_technical(v: &Value, slot: Slot) -> bool {
    match slot {
        Slot::Elem {
            array_key: Some("tools" | "system"),
            top_level: true,
        } => true,
        Slot::Member {
            key: "input_schema",
            ..
        } => true,
        Slot::Member {
            key: "system",
            top_level: true,
        } => true,
        // Positional rules aside, a tool call or its result is technical wherever it appears.
        _ => matches!(
            v.get("type").and_then(Value::as_str),
            Some("tool_use" | "tool_result")
        ),
    }
}

/// The one-line summary replacing a folded subtree, or `None` when the node must stay open
/// (too small to be worth folding, or carrying a substituted secret).
fn fold(v: &Value, marker: &str) -> Option<String> {
    let pretty = serde_json::to_string_pretty(v).ok()?;
    if pretty.len() < FOLD_MIN_CHARS || pretty.contains(marker) {
        return None;
    }

    // The identifying bits a reader still wants on the folded line: which tool, which block type.
    let mut head = String::new();
    for key in ["type", "name"] {
        if let Some(s) = v.get(key).and_then(Value::as_str) {
            head.push_str(&format!("\"{key}\": \"{s}\", "));
        }
    }

    let size = human_chars(pretty.len());
    Some(match v {
        Value::Array(_) => format!("[ … {size} folded ]"),
        Value::Object(_) => format!("{{ {head}… {size} folded }}"),
        _ => format!("\"… {size} folded\""),
    })
}

fn human_chars(n: usize) -> String {
    if n < 1000 {
        format!("{n} chars")
    } else {
        format!("{:.1}k chars", n as f64 / 1000.0)
    }
}

/// Recursive pretty-printer. `indent` is the node's own indentation level (root = 0); output
/// matches `serde_json::to_string_pretty` byte for byte wherever nothing folds, so the folded and
/// full views line up visually.
fn write_value(v: &Value, indent: usize, slot: Slot, marker: &str, out: &mut String) {
    if is_technical(v, slot)
        && let Some(summary) = fold(v, marker)
    {
        out.push_str(&summary);
        return;
    }

    match v {
        Value::Object(map) if !map.is_empty() => {
            out.push_str("{\n");
            let last = map.len() - 1;
            for (i, (key, val)) in map.iter().enumerate() {
                push_indent(out, indent + 1);
                // serde escapes the key for us (quotes included). Serialising a string to JSON
                // cannot fail; the fallback exists so no user input can reach an unwrap.
                out.push_str(&serde_json::to_string(key).unwrap_or_else(|_| format!("\"{key}\"")));
                out.push_str(": ");
                let child = Slot::Member {
                    key,
                    top_level: indent == 0,
                };
                write_value(val, indent + 1, child, marker, out);
                if i < last {
                    out.push(',');
                }
                out.push('\n');
            }
            push_indent(out, indent);
            out.push('}');
        }
        Value::Array(arr) if !arr.is_empty() => {
            let (array_key, top_level) = match slot {
                Slot::Member { key, top_level } => (Some(key), top_level),
                _ => (None, false),
            };
            out.push_str("[\n");
            let last = arr.len() - 1;
            for (i, val) in arr.iter().enumerate() {
                push_indent(out, indent + 1);
                let child = Slot::Elem {
                    array_key,
                    top_level,
                };
                write_value(val, indent + 1, child, marker, out);
                if i < last {
                    out.push(',');
                }
                out.push('\n');
            }
            push_indent(out, indent);
            out.push(']');
        }
        // Scalars and empty containers: the compact form is already the pretty form.
        _ => out.push_str(&serde_json::to_string(v).unwrap_or_default()),
    }
}

fn push_indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // The real marker constant, not a string literal: PSK's own near-miss hook (rightly) refuses
    // to write a file that embeds marker residue.
    use psk_proxy::MARKER;

    #[test]
    fn compact_json_is_expanded_onto_many_lines() {
        let compact = r#"{"model":"claude","messages":[{"role":"user","content":"hi"}]}"#;
        let out = pretty(compact);
        assert!(out.contains("\n"), "pretty output must span multiple lines");
        assert!(out.contains("\"model\": \"claude\""));
        // The single giant line is gone.
        assert!(out.lines().count() > 3);
    }

    #[test]
    fn non_json_is_returned_unchanged() {
        assert_eq!(pretty("not json at all"), "not json at all");
        assert_eq!(pretty(""), "");
        assert_eq!(pretty_folded("not json at all", MARKER), "not json at all");
    }

    #[test]
    fn a_secret_shaped_string_survives_round_trip() {
        // Whatever the value, pretty-printing must not alter it — only the layout changes.
        let compact = r#"{"key":"AKIAIOSFODNN7EXAMPLE"}"#;
        let out = pretty(compact);
        assert!(out.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    // -- folding ---------------------------------------------------------------------------------

    /// A request shaped like Claude Code's: huge tool definitions, a huge system prompt, a short
    /// conversation.
    fn claude_code_request() -> String {
        let desc = "very long tool description ".repeat(40);
        let sys = "you are a coding agent ".repeat(40);
        serde_json::json!({
            "model": "claude",
            "system": [{ "type": "text", "text": sys }],
            "tools": [
                { "name": "Bash", "description": desc,
                  "input_schema": { "type": "object", "properties": { "command": { "type": "string" } } } },
                { "name": "Read", "description": desc,
                  "input_schema": { "type": "object", "properties": { "file_path": { "type": "string" } } } }
            ],
            "messages": [{ "role": "user", "content": "deploy the app please" }]
        })
        .to_string()
    }

    #[test]
    fn tool_definitions_fold_to_one_line_each_keeping_the_name() {
        let out = pretty_folded(&claude_code_request(), MARKER);
        assert!(
            !out.contains("very long tool description"),
            "descriptions are hidden:\n{out}"
        );
        assert!(
            out.contains(r#"{ "name": "Bash", … "#),
            "tool name survives:\n{out}"
        );
        assert!(out.contains(r#"{ "name": "Read", … "#));
        assert!(out.contains("folded"));
    }

    #[test]
    fn the_system_prompt_folds_but_the_conversation_does_not() {
        let out = pretty_folded(&claude_code_request(), MARKER);
        assert!(
            !out.contains("you are a coding agent"),
            "system prompt hidden"
        );
        assert!(
            out.contains("deploy the app please"),
            "the user's message stays readable:\n{out}"
        );
    }

    #[test]
    fn tool_calls_and_results_in_the_history_fold() {
        let long = "line of output ".repeat(50);
        let body = serde_json::json!({
            "messages": [
                { "role": "assistant", "content": [
                    { "type": "tool_use", "id": "toolu_1", "name": "Bash",
                      "input": { "command": long } } ] },
                { "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "toolu_1", "content": long } ] }
            ]
        })
        .to_string();
        let out = pretty_folded(&body, MARKER);
        assert!(
            !out.contains("line of output"),
            "call payloads hidden:\n{out}"
        );
        assert!(out.contains(r#""type": "tool_use", "name": "Bash""#));
        assert!(out.contains(r#""type": "tool_result""#));
    }

    #[test]
    fn a_subtree_carrying_a_substituted_secret_is_never_folded() {
        // The fold exists for readability; it must not hide the one thing the pane is for.
        let fake = format!("{MARKER}abcd1234efgh");
        let padding = "padding ".repeat(60);
        let body = serde_json::json!({
            "messages": [{ "role": "assistant", "content": [
                { "type": "tool_use", "id": "t1", "name": "Bash",
                  "input": { "command": format!("export KEY={fake} # {padding}") } } ] }]
        })
        .to_string();
        let out = pretty_folded(&body, MARKER);
        assert!(out.contains(&fake), "the marked fake stays visible:\n{out}");
        assert!(
            !out.contains(" folded }"),
            "nothing on the marker's path folded"
        );
    }

    #[test]
    fn small_technical_nodes_stay_open() {
        // Folding a call that already fits on a couple of lines would only cost information.
        let body = serde_json::json!({
            "messages": [{ "role": "assistant", "content": [
                { "type": "tool_use", "id": "t1", "name": "Read",
                  "input": { "file_path": "/etc/hosts" } } ] }]
        })
        .to_string();
        let out = pretty_folded(&body, MARKER);
        assert!(out.contains("/etc/hosts"));
        assert!(!out.contains("folded"));
    }

    #[test]
    fn folded_output_matches_pretty_when_nothing_is_technical() {
        // The custom writer must agree with serde's pretty format byte for byte, so the folded
        // and full views of the same request line up.
        let body = r#"{"a":1,"b":[1,2],"c":{"d":"e"},"empty":{},"none":null,"list":[]}"#;
        assert_eq!(pretty_folded(body, MARKER), pretty(body));
    }

    #[test]
    fn a_nested_tools_key_is_not_mistaken_for_the_request_tool_list() {
        // Only the *top-level* tools array folds positionally; a "tools" array inside a message
        // is conversation content. (Long strings inside it are still shown.)
        let long = "content the user pasted ".repeat(30);
        let body = serde_json::json!({
            "messages": [{ "role": "user", "content": { "tools": [{ "note": long }] } }]
        })
        .to_string();
        let out = pretty_folded(&body, MARKER);
        assert!(
            out.contains("content the user pasted"),
            "not folded:\n{out}"
        );
    }
}
