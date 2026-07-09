//! The inspector's event stream (brief §8, §9).
//!
//! One event per request, published on a `tokio::sync::broadcast` channel and kept in a bounded
//! in-memory ring buffer. `psk top` is an SSE client of `GET /events`.
//!
//! # The safety property
//!
//! An event carries **metadata plus the rewritten (safe) text only**. The original text — the one
//! with real secrets in it — is never broadcast. It is stashed beside the ring buffer and served
//! only when an operator explicitly asks for one request by id, at `GET /events/{id}/original`.
//!
//! Nothing here touches disk. Closing the proxy drops every original.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use psk_core::Summary;
use serde::Serialize;
use tokio::sync::broadcast;

/// What the TUI sees. No original text, by construction: there is no field for it.
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub id: u64,
    /// Milliseconds since the Unix epoch.
    pub timestamp: u64,
    pub upstream_url: String,
    pub model: String,
    pub entity_counts_by_kind: std::collections::BTreeMap<String, usize>,
    pub chars_hidden: usize,
    pub latency_ms: u64,
    /// The **substituted** text, safe to display and safe to put on the wire.
    pub rewritten_text: String,
}

pub struct EventBus {
    tx: broadcast::Sender<Event>,
    ring: Mutex<VecDeque<Event>>,
    /// `id -> original text`. Bounded in lockstep with the ring, so an id served by `/events` is
    /// the same set of ids revealable at `/events/{id}/original`.
    originals: Mutex<HashMap<u64, String>>,
    capacity: usize,
    next_id: AtomicU64,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity.max(1));
        EventBus {
            tx,
            ring: Mutex::new(VecDeque::with_capacity(capacity)),
            originals: Mutex::new(HashMap::new()),
            capacity,
            next_id: AtomicU64::new(1),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// Record one request. `original` is stashed, never broadcast.
    pub fn publish(
        &self,
        upstream_url: String,
        model: String,
        summary: &Summary,
        latency_ms: u64,
        original: String,
        rewritten_text: String,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let event = Event {
            id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            upstream_url,
            model,
            entity_counts_by_kind: summary
                .by_kind
                .iter()
                .map(|(k, n)| (format!("{k:?}"), *n))
                .collect(),
            chars_hidden: summary.chars_hidden,
            latency_ms,
            rewritten_text,
        };

        {
            let mut ring = self.ring.lock().unwrap_or_else(|p| p.into_inner());
            let mut originals = self.originals.lock().unwrap_or_else(|p| p.into_inner());

            ring.push_back(event.clone());
            originals.insert(id, original);

            // Evict together, so the two collections never disagree about which ids exist.
            while ring.len() > self.capacity {
                if let Some(old) = ring.pop_front() {
                    originals.remove(&old.id);
                }
            }
        }

        // `send` fails only when nobody is subscribed, which is the normal case (no TUI attached).
        let _ = self.tx.send(event);
        id
    }

    /// The recent events, oldest first. Metadata and rewritten text only.
    pub fn recent(&self) -> Vec<Event> {
        self.ring
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// The original, real-secret-bearing text of one request. Served only on explicit request.
    pub fn original(&self, id: u64) -> Option<String> {
        self.originals
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publish(bus: &EventBus, original: &str, rewritten: &str) -> u64 {
        bus.publish(
            "https://api.anthropic.com/v1/messages".into(),
            "claude-opus-4-8".into(),
            &Summary::default(),
            12,
            original.into(),
            rewritten.into(),
        )
    }

    /// The safety property: a serialised event has no field that could carry the original.
    #[test]
    fn originals_are_never_broadcast() {
        let bus = EventBus::new(10);
        let id = publish(&bus, "real AKIA-secret", "fake");

        let json = serde_json::to_string(&bus.recent()[0]).unwrap();
        assert!(
            !json.contains("real AKIA-secret"),
            "original leaked into the event: {json}"
        );
        assert!(json.contains("fake"));

        // But it is retrievable per-id, on purpose.
        assert_eq!(bus.original(id).as_deref(), Some("real AKIA-secret"));
    }

    #[test]
    fn the_ring_is_bounded_and_evicts_originals_with_it() {
        let bus = EventBus::new(2);
        let first = publish(&bus, "one", "1");
        publish(&bus, "two", "2");
        publish(&bus, "three", "3");

        assert_eq!(bus.recent().len(), 2, "ring must stay bounded");
        assert_eq!(
            bus.original(first),
            None,
            "an evicted event must not leave its original behind"
        );
        // The two survivors keep theirs.
        let ids: Vec<u64> = bus.recent().iter().map(|e| e.id).collect();
        assert!(ids.iter().all(|id| bus.original(*id).is_some()));
    }

    #[test]
    fn ids_are_unique_and_ascending() {
        let bus = EventBus::new(10);
        let a = publish(&bus, "a", "a");
        let b = publish(&bus, "b", "b");
        assert!(b > a);
    }

    #[tokio::test]
    async fn subscribers_receive_published_events() {
        let bus = EventBus::new(10);
        let mut rx = bus.subscribe();
        publish(&bus, "secret", "safe");

        let event = rx.recv().await.expect("subscriber receives the event");
        assert_eq!(event.rewritten_text, "safe");
        assert_eq!(event.model, "claude-opus-4-8");
    }

    /// Publishing with no subscriber attached is the normal case and must not error.
    #[test]
    fn publishing_without_subscribers_is_fine() {
        let bus = EventBus::new(10);
        publish(&bus, "x", "y");
        assert_eq!(bus.recent().len(), 1);
    }
}
