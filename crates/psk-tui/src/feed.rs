//! The SSE client: the proxy's `GET /events` stream, parsed into [`Event`]s.
//!
//! The TUI is read-only — it never touches traffic, so it can attach and detach at any time
//! without affecting the proxy (brief §9). This runs on a background thread and hands parsed events
//! to the UI thread over a channel; the UI thread never blocks on the network.

use std::io::BufRead;
use std::sync::mpsc::Sender;

use psk_proxy::events::Event;

/// A message from the feed thread to the UI thread.
pub enum FeedMsg {
    /// A parsed request event.
    Event(Box<Event>),
    /// The stream ended or the proxy went away. The UI shows a hint but keeps running (the buffer
    /// it already has is still worth inspecting).
    Disconnected,
}

/// Parse an SSE byte stream, sending each complete `data:` event as an [`Event`].
///
/// Split out from the network so it can be tested over any `BufRead` — a real HTTP body in
/// production, a `&[u8]` in tests. Returns when the reader is exhausted.
pub fn read_sse<R: BufRead>(reader: R, tx: &Sender<FeedMsg>) {
    // SSE lines: `data: <json>`, events terminated by a blank line. Anthropic-style event streams
    // may spread `data:` across lines, but the proxy emits one `data:` line per event, so a
    // per-line parse is sufficient and simplest.
    let mut data = String::new();
    for line in reader.lines() {
        let Ok(line) = line else { break };

        if let Some(rest) = line.strip_prefix("data:") {
            data.push_str(rest.trim_start());
        } else if line.is_empty() {
            // End of one event.
            if !data.is_empty() {
                if let Ok(event) = serde_json::from_str::<Event>(&data) {
                    if tx.send(FeedMsg::Event(Box::new(event))).is_err() {
                        return; // UI thread gone; stop.
                    }
                }
                data.clear();
            }
        }
        // Other SSE fields (`event:`, `id:`, `:comment`) are ignored.
    }
    let _ = tx.send(FeedMsg::Disconnected);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn event_json(id: u64, url: &str) -> String {
        // One physical line: an SSE `data:` payload cannot contain a raw newline.
        format!(
            concat!(
                r#"{{"id":{},"timestamp":1,"upstream_url":"{}","model":"m","#,
                r#""entity_counts_by_kind":{{}},"chars_hidden":0,"latency_ms":5,"#,
                r#""rewritten_text":"hi"}}"#
            ),
            id, url
        )
    }

    #[test]
    fn parses_events_separated_by_blank_lines() {
        let stream = format!(
            "data: {}\n\ndata: {}\n\n",
            event_json(1, "https://api.anthropic.com"),
            event_json(2, "https://api.openai.com")
        );
        let (tx, rx) = mpsc::channel();
        read_sse(stream.as_bytes(), &tx);

        let ids: Vec<u64> = rx
            .try_iter()
            .filter_map(|m| match m {
                FeedMsg::Event(e) => Some(e.id),
                FeedMsg::Disconnected => None,
            })
            .collect();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn a_disconnect_is_signalled_at_end_of_stream() {
        let (tx, rx) = mpsc::channel();
        read_sse(&b""[..], &tx);
        assert!(matches!(rx.recv().unwrap(), FeedMsg::Disconnected));
    }

    #[test]
    fn comment_and_event_lines_are_ignored() {
        let stream = format!(
            ": keep-alive\nevent: message\ndata: {}\n\n",
            event_json(7, "u")
        );
        let (tx, rx) = mpsc::channel();
        read_sse(stream.as_bytes(), &tx);
        match rx.recv().unwrap() {
            FeedMsg::Event(e) => assert_eq!(e.id, 7),
            FeedMsg::Disconnected => panic!("expected an event"),
        }
    }

    #[test]
    fn malformed_json_is_skipped_not_fatal() {
        let stream = format!("data: not json\n\ndata: {}\n\n", event_json(3, "u"));
        let (tx, rx) = mpsc::channel();
        read_sse(stream.as_bytes(), &tx);
        let ids: Vec<u64> = rx
            .try_iter()
            .filter_map(|m| match m {
                FeedMsg::Event(e) => Some(e.id),
                _ => None,
            })
            .collect();
        assert_eq!(ids, vec![3], "one bad event does not kill the stream");
    }
}
