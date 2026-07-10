//! Turning the captured request body into something a human can read.
//!
//! `rewritten_text` is the whole outbound request, serialised **compact** by the proxy — one
//! enormous line. Rendered raw it is unreadable. [`pretty`] re-indents it; the colouring is done by
//! the renderer. Kept pure and here (not in `render`) so it can be tested without a terminal.

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

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn a_secret_shaped_string_survives_round_trip() {
        // Whatever the value, pretty-printing must not alter it — only the layout changes.
        let compact = r#"{"key":"AKIAIOSFODNN7EXAMPLE"}"#;
        let out = pretty(compact);
        assert!(out.contains("AKIAIOSFODNN7EXAMPLE"));
    }
}
