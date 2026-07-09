//! Inbound SSE restore, for `restore_mode = "full"` only (brief §8).
//!
//! # Why this is harder than `text.replace(fake, real)`
//!
//! Two layers of fragmentation sit between us and a fake.
//!
//! 1. **HTTP chunks split SSE events.** A chunk boundary can fall anywhere, including inside the
//!    `data:` JSON. So bytes are buffered until a complete `\n\n`-terminated event is available.
//! 2. **SSE events split the text itself.** The model streams a few characters per
//!    `content_block_delta`, so a fake is routinely spread across several events. Restoring each
//!    delta in isolation would never match one.
//!
//! The fix for (2) is a hold-back window: after restoring, retain the longest suffix that could
//! still *grow into* a fake, and prepend it to the next delta. `Vault::pending_fake_prefix_len`
//! computes that exactly, so in the overwhelmingly common case it is zero and the delta is
//! forwarded whole, with no added latency.
//!
//! # Why restore happens inside the JSON, not on the raw bytes
//!
//! A real secret can contain characters that are illegal raw inside a JSON string — a PEM private
//! key is full of newlines. Substituting on the raw SSE bytes would splice those in unescaped and
//! produce a response the agent cannot parse. So each event's `data:` payload is parsed, the text
//! field is restored, and the JSON is re-serialised, which escapes correctly by construction.

use std::sync::Arc;

use psk_vault::Vault;
use serde_json::Value;

/// Streaming SSE transformer. Feed it response bytes, get back bytes to forward.
pub struct SseRestorer {
    vault: Arc<Vault>,
    /// Bytes of an incomplete SSE event, carried across HTTP chunks.
    raw: String,
    /// Restored text held back because it might still be the start of a fake.
    pending: String,
    /// `index` of the content block the pending text belongs to, so a flush can address it.
    pending_index: Value,
    /// Which delta field the pending text came from: `text` or `thinking`.
    pending_field: &'static str,
}

impl SseRestorer {
    pub fn new(vault: Arc<Vault>) -> Self {
        SseRestorer {
            vault,
            raw: String::new(),
            pending: String::new(),
            pending_index: Value::from(0),
            pending_field: "text",
        }
    }

    /// Consume a chunk of the upstream response, returning the bytes to forward downstream.
    ///
    /// Any trailing partial event stays buffered until [`SseRestorer::finish`].
    pub fn push(&mut self, chunk: &str) -> String {
        self.raw.push_str(chunk);
        let mut out = String::new();

        // SSE events are separated by a blank line.
        while let Some(idx) = self.raw.find("\n\n") {
            let event: String = self.raw.drain(..idx + 2).collect();
            out.push_str(&self.transform_event(&event));
        }
        out
    }

    /// Flush whatever is left when the upstream stream ends.
    ///
    /// A well-formed stream ends on a `content_block_stop` with nothing pending. If text is still
    /// held back, it is emitted as a **synthetic delta event**, not as bare bytes: appending raw
    /// text after the last event would corrupt the stream and the agent would drop it.
    pub fn finish(&mut self) -> String {
        let mut out = self.flush_pending();
        out.push_str(&std::mem::take(&mut self.raw));
        out
    }

    /// Emit the held-back text as a delta event of the same shape it came from. Empty when there
    /// is nothing pending, which is the normal case.
    fn flush_pending(&mut self) -> String {
        if self.pending.is_empty() {
            return String::new();
        }
        // Nothing more can arrive for this block, so the tail cannot grow into a fake.
        let text = std::mem::take(&mut self.pending);
        let delta = serde_json::json!({
            "type": "content_block_delta",
            "index": self.pending_index,
            "delta": {"type": delta_type_for(self.pending_field), self.pending_field: text}
        });
        format!(
            "event: content_block_delta\ndata: {}\n\n",
            serde_json::to_string(&delta).expect("value is serializable")
        )
    }

    /// Rewrite one complete SSE event.
    fn transform_event(&mut self, event: &str) -> String {
        let Some(data) = data_payload(event) else {
            return event.to_string(); // comment, ping, or an event without a data line
        };
        let Ok(mut json) = serde_json::from_str::<Value>(data) else {
            return event.to_string(); // not JSON; forward untouched rather than guess
        };

        match json.get("type").and_then(Value::as_str) {
            Some("content_block_delta") => {
                if let Some(field) = delta_text_field(&json)
                    && let Some(text) = json["delta"][field].as_str()
                {
                    self.pending_index = json.get("index").cloned().unwrap_or(Value::from(0));
                    self.pending_field = field;
                    let emitted = self.restore_delta(text);
                    json["delta"][field] = Value::String(emitted);
                    return reserialize(event, &json);
                }
                event.to_string()
            }
            // The block is ending, so whatever is held back can never grow into a fake. Emit it as
            // one final delta before the stop event, keeping the stream well-formed.
            Some("content_block_stop") => {
                let mut out = self.flush_pending();
                out.push_str(event);
                out
            }
            _ => event.to_string(),
        }
    }

    /// Restore `text`, returning what is safe to emit now and stashing the rest.
    fn restore_delta(&mut self, text: &str) -> String {
        let mut combined = std::mem::take(&mut self.pending);
        combined.push_str(text);

        let restored = self.vault.restore(&combined);

        // How much of the tail could still become a fake once more characters arrive?
        let hold = self.vault.pending_fake_prefix_len(&restored);
        let split = restored.len() - hold;
        // `pending_fake_prefix_len` already respects char boundaries, but a defensive check costs
        // nothing and turns a would-be panic into "emit it all".
        if !restored.is_char_boundary(split) {
            return restored;
        }

        self.pending = restored[split..].to_string();
        restored[..split].to_string()
    }
}

/// Which field of a `content_block_delta` carries displayable text.
///
/// Both `text_delta` and `thinking_delta` are shown to the user, so both are restored (brief §8).
/// `input_json_delta` is deliberately excluded: it streams partial JSON for a tool call, and the
/// `PreToolUse` hook restores that at the execution boundary where it belongs.
fn delta_text_field(json: &Value) -> Option<&'static str> {
    match json.get("delta")?.get("type")?.as_str()? {
        "text_delta" => Some("text"),
        "thinking_delta" => Some("thinking"),
        _ => None,
    }
}

/// The delta `type` that carries a given field, for synthesising a flush event.
fn delta_type_for(field: &str) -> &'static str {
    match field {
        "thinking" => "thinking_delta",
        _ => "text_delta",
    }
}

/// The `data:` payload of an SSE event, if it has one.
fn data_payload(event: &str) -> Option<&str> {
    event
        .lines()
        .find_map(|l| l.strip_prefix("data:").map(str::trim_start))
}

/// Rebuild the event, replacing only its `data:` line and preserving `event:` and any other field.
///
/// `event` arrives with its terminating `\n\n`. Iterating `lines()` would yield a spurious empty
/// final line, so the terminator is stripped first and re-added once.
fn reserialize(event: &str, json: &Value) -> String {
    let encoded = serde_json::to_string(json).expect("value came from JSON; it re-serializes");
    let body = event.strip_suffix("\n\n").unwrap_or(event);

    let mut out = String::with_capacity(body.len() + encoded.len() + 2);
    for line in body.split('\n') {
        if line.starts_with("data:") {
            out.push_str("data: ");
            out.push_str(&encoded);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out.push('\n'); // the blank line terminating the event
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_vault::{SecretKind, sample};

    /// A vault holding one AWS key, plus the fake it minted.
    fn vault_with_fake() -> (Arc<Vault>, String, String) {
        let v = Arc::new(Vault::with_salt([5u8; 32]));
        let real = sample::for_kind(SecretKind::AwsAccessKeyId);
        let fake = v.substitute(&real, SecretKind::AwsAccessKeyId);
        (v, real, fake)
    }

    fn delta_event(text: &str) -> String {
        let json = serde_json::json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": text}
        });
        format!("event: content_block_delta\ndata: {json}\n\n")
    }

    /// Collect the `text` of every text delta in a stream of events.
    fn collect_text(sse: &str) -> String {
        let mut out = String::new();
        for event in sse.split("\n\n") {
            if let Some(data) = data_payload(event)
                && let Ok(j) = serde_json::from_str::<Value>(data)
                && let Some(t) = j["delta"]["text"].as_str()
            {
                out.push_str(t);
            }
        }
        out
    }

    #[test]
    fn a_fake_inside_one_delta_is_restored() {
        let (v, real, fake) = vault_with_fake();
        let mut r = SseRestorer::new(v);
        let out = r.push(&delta_event(&format!("the key is {fake}")));
        assert_eq!(collect_text(&out), format!("the key is {real}"));
    }

    /// The headline case from brief §12: a fake split across two SSE chunks.
    #[test]
    fn a_fake_split_across_two_chunks_is_restored() {
        let (v, real, fake) = vault_with_fake();
        let mut r = SseRestorer::new(v);

        let (head, tail) = fake.split_at(9);
        let mut out = r.push(&delta_event(&format!("key {head}")));
        out.push_str(&r.push(&delta_event(&format!("{tail} done"))));
        out.push_str(&r.finish());

        assert_eq!(collect_text(&out), format!("key {real} done"));
    }

    /// Split at every possible offset. If the hold-back window is off by one anywhere, this finds
    /// it — and an unrestored fake reaching the user is exactly the failure that matters.
    #[test]
    fn a_fake_split_at_every_offset_is_restored() {
        let (v, real, fake) = vault_with_fake();
        for at in 1..fake.len() {
            let mut r = SseRestorer::new(Arc::clone(&v));
            let mut out = r.push(&delta_event(&fake[..at]));
            out.push_str(&r.push(&delta_event(&fake[at..])));
            out.push_str(&r.finish());
            assert_eq!(collect_text(&out), real, "split at {at}");
        }
    }

    /// One character per delta, the way the model actually streams.
    #[test]
    fn a_fake_streamed_one_character_at_a_time_is_restored() {
        let (v, real, fake) = vault_with_fake();
        let mut r = SseRestorer::new(v);
        let mut out = String::new();
        for c in fake.chars() {
            out.push_str(&r.push(&delta_event(&c.to_string())));
        }
        out.push_str(&r.finish());
        assert_eq!(collect_text(&out), real);
    }

    /// An HTTP chunk boundary falling inside an SSE event must not corrupt it.
    #[test]
    fn an_event_split_across_http_chunks_is_reassembled() {
        let (v, real, fake) = vault_with_fake();
        let mut r = SseRestorer::new(v);

        let event = delta_event(&format!("key {fake}"));
        let (a, b) = event.split_at(event.len() / 2);
        let mut out = r.push(a);
        assert_eq!(out, "", "no complete event yet, nothing may be forwarded");
        out.push_str(&r.push(b));

        assert_eq!(collect_text(&out), format!("key {real}"));
    }

    #[test]
    fn thinking_deltas_are_restored_too() {
        let (v, real, fake) = vault_with_fake();
        let mut r = SseRestorer::new(v);
        let json = serde_json::json!({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "thinking_delta", "thinking": format!("uses {fake}")}
        });
        let out = r.push(&format!("event: content_block_delta\ndata: {json}\n\n"));

        let data = data_payload(&out).unwrap();
        let parsed: Value = serde_json::from_str(data).unwrap();
        assert_eq!(parsed["delta"]["thinking"], format!("uses {real}"));
    }

    /// Held-back text must be flushed before the block closes, or the tail is lost.
    #[test]
    fn pending_text_is_flushed_at_content_block_stop() {
        let (v, _real, fake) = vault_with_fake();
        let mut r = SseRestorer::new(v);

        // Ends mid-fake, so the tail is held back...
        let partial = &fake[..8];
        let mut out = r.push(&delta_event(&format!("x{partial}")));
        assert!(
            !collect_text(&out).contains(partial),
            "tail must be held back"
        );

        // ...and released when the block ends.
        out.push_str(&r.push(
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        ));
        assert_eq!(collect_text(&out), format!("x{partial}"));
        assert!(out.contains("content_block_stop"));
    }

    /// A restored PEM key is full of newlines. Splicing it into raw SSE bytes would produce
    /// unparseable JSON; restoring inside the parsed value escapes it correctly.
    ///
    /// Note the flush: the restored PEM *ends* with `-----`, which is a valid prefix of the PEM
    /// fake, so the hold-back window legitimately retains it until the stream ends.
    #[test]
    fn a_restored_multiline_secret_stays_valid_json() {
        let v = Arc::new(Vault::with_salt([5u8; 32]));
        let real = sample::for_kind(SecretKind::PrivateKeyBlock);
        assert!(real.contains('\n'));
        let fake = v.substitute(&real, SecretKind::PrivateKeyBlock);

        let mut r = SseRestorer::new(v);
        let mut out = r.push(&delta_event(&fake));
        out.push_str(&r.finish());

        assert_eq!(collect_text(&out), real);

        // Every `data:` line remains one line of valid JSON: the newlines are escaped, not raw.
        for event in out.split("\n\n").filter(|e| !e.trim().is_empty()) {
            let data = data_payload(event).expect("event has a data line");
            serde_json::from_str::<Value>(data).expect("data line must remain valid JSON");
            assert!(
                !data.contains('\n'),
                "raw newline leaked into the data line"
            );
        }
    }

    /// Held-back text must never be emitted as bare bytes outside an event: the agent's SSE parser
    /// would discard it and the tail of the secret would be silently lost.
    #[test]
    fn flushed_text_is_emitted_as_a_well_formed_event() {
        let (v, _real, fake) = vault_with_fake();
        let mut r = SseRestorer::new(v);

        let mut out = r.push(&delta_event(&fake[..8])); // ends mid-fake, tail held back
        out.push_str(&r.finish());

        for event in out.split("\n\n").filter(|e| !e.trim().is_empty()) {
            assert!(
                event.starts_with("event: "),
                "stray bytes outside an event: {event:?}"
            );
            assert!(
                data_payload(event).is_some(),
                "event without a data line: {event:?}"
            );
        }
        assert_eq!(collect_text(&out), fake[..8]);
    }

    /// A thinking delta held back and then flushed must be flushed as a *thinking* delta, or the
    /// agent renders the tail of its own reasoning as assistant output.
    #[test]
    fn a_flushed_thinking_delta_keeps_its_type() {
        let (v, _real, fake) = vault_with_fake();
        let mut r = SseRestorer::new(v);

        let json = serde_json::json!({
            "type": "content_block_delta", "index": 3,
            "delta": {"type": "thinking_delta", "thinking": fake[..8].to_string()}
        });
        let mut out = r.push(&format!("event: content_block_delta\ndata: {json}\n\n"));
        out.push_str(&r.finish());

        let events: Vec<&str> = out.split("\n\n").filter(|e| !e.trim().is_empty()).collect();
        let flushed = events.last().expect("a flush event must exist");
        let parsed: Value = serde_json::from_str(data_payload(flushed).unwrap()).unwrap();
        assert_eq!(parsed["delta"]["type"], "thinking_delta");
        assert_eq!(parsed["index"], 3, "the flush must address the right block");
    }

    /// Events we do not understand are forwarded byte-identical.
    #[test]
    fn unknown_events_pass_through_untouched() {
        let (v, _, _) = vault_with_fake();
        let mut r = SseRestorer::new(v);
        for event in [
            ": ping\n\n",
            "event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
            "event: weird\ndata: not json at all\n\n",
        ] {
            assert_eq!(r.push(event), event, "{event:?} was modified");
        }
    }

    /// With nothing minted, the restorer is a pure pass-through: `execution` mode never
    /// constructs one, but a `full`-mode stream before the first substitution must not stall.
    #[test]
    fn an_empty_vault_forwards_everything_immediately() {
        let v = Arc::new(Vault::with_salt([5u8; 32]));
        let mut r = SseRestorer::new(v);
        let event = delta_event("hello world");
        assert_eq!(r.push(&event), event);
    }
}
