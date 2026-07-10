//! The inspector's state and its pure reducers.
//!
//! Everything here is terminal-free and deterministic: feed it events and key presses, read back
//! what should be on screen. The ratatui rendering and the SSE/keyboard I/O live in the driver
//! (`lib.rs`) and are the only untested surface.
//!
//! Nothing here touches disk. The event buffer is bounded; revealed originals are held in memory
//! for the session and dropped on quit (brief §9).

use std::collections::VecDeque;

use psk_proxy::events::Event;

/// What the detail pane is showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// The request list.
    List,
    /// One request's rewritten (safe) text, with the substituted spans highlighted.
    Detail,
    /// The original text of the open request, revealed on demand and diffed against the rewritten
    /// version. `String` is the fetched original — it lives only in memory, only after an explicit
    /// keypress (brief §9).
    Reveal(String),
}

/// What a key press asks the driver to do that the app cannot do itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Nothing further; the app already handled it.
    None,
    /// Quit the inspector.
    Quit,
    /// Fetch `GET /events/{id}/original` and hand it back via [`App::revealed`]. The driver owns
    /// the HTTP call so the app stays pure and testable.
    RevealOriginal(u64),
}

/// The inspector.
pub struct App {
    /// Newest first. Bounded; the oldest are dropped, exactly as the proxy's ring buffer is.
    events: VecDeque<Event>,
    cap: usize,
    /// The **id** of the selected request, not an index. Tracking the id rather than a position is
    /// what lets a paused cursor stay on its request as new rows push in above it, and survive a
    /// filter change that reorders the list. `None` when the list is empty.
    selected_id: Option<u64>,
    paused: bool,
    group_by_url: bool,
    /// Case-insensitive substring filter on the upstream URL.
    filter: String,
    /// Whether keystrokes are currently editing [`App::filter`] rather than navigating.
    filtering: bool,
    mode: Mode,
    /// Vertical scroll offset of the detail/reveal pane, in lines. Reset whenever a different
    /// request is opened. Clamped to the content by the renderer.
    detail_scroll: u16,
    /// Near-misses blocked at the hook. Not on the event stream (it carries no secrets and no hook
    /// data); the driver reads it from `stats.json` and pushes it in.
    pub near_misses_blocked: u64,
}

impl App {
    pub fn new(cap: usize) -> Self {
        App {
            events: VecDeque::with_capacity(cap.min(1024)),
            cap: cap.max(1),
            selected_id: None,
            paused: false,
            group_by_url: false,
            filter: String::new(),
            filtering: false,
            mode: Mode::List,
            detail_scroll: 0,
            near_misses_blocked: 0,
        }
    }

    // -- ingest --------------------------------------------------------------------------------

    /// A new request event arrived from the proxy.
    ///
    /// Buffered even while paused — pause freezes the *selection*, not the feed, so nothing is
    /// missed. When live, the selection stays pinned to the newest row.
    pub fn push(&mut self, event: Event) {
        let id = event.id;
        self.events.push_front(event);
        while self.events.len() > self.cap {
            self.events.pop_back();
        }
        // Follow the newest request when live and browsing the list, or when nothing was selected
        // yet. Otherwise (paused, or a request open) the selection is tracked by id, so it stays
        // put — but make sure that id still exists after an eviction.
        let live = !self.paused && self.mode == Mode::List;
        if live || self.selected_id.is_none() {
            self.selected_id = Some(id);
        } else {
            self.ensure_selection_visible();
        }
    }

    // -- the visible slice ---------------------------------------------------------------------

    /// The events matching the current filter, newest first. When grouped, entries are ordered so
    /// all rows sharing an upstream URL are adjacent (newest group first, newest row first within).
    pub fn visible(&self) -> Vec<&Event> {
        let needle = self.filter.to_ascii_lowercase();
        let mut rows: Vec<&Event> = self
            .events
            .iter()
            .filter(|e| needle.is_empty() || e.upstream_url.to_ascii_lowercase().contains(&needle))
            .collect();

        if self.group_by_url {
            // Stable within a group (preserves newest-first); groups ordered by first appearance,
            // which is already newest-first because `rows` is.
            let mut order: Vec<String> = Vec::new();
            for e in &rows {
                if !order.contains(&e.upstream_url) {
                    order.push(e.upstream_url.clone());
                }
            }
            rows.sort_by_key(|e| order.iter().position(|u| u == &e.upstream_url).unwrap_or(0));
        }
        rows
    }

    pub fn selected_event(&self) -> Option<&Event> {
        let id = self.selected_id?;
        self.visible().into_iter().find(|e| e.id == id)
    }

    /// The selected row's position in the visible list, for the renderer's highlight and scroll.
    pub fn selected_index(&self) -> Option<usize> {
        let id = self.selected_id?;
        self.visible().iter().position(|e| e.id == id)
    }

    /// If the tracked id has fallen out of the visible list (evicted, or filtered away), snap the
    /// selection to the nearest still-visible row so the cursor is never pointing at nothing.
    fn ensure_selection_visible(&mut self) {
        if self.selected_event().is_some() {
            return;
        }
        self.selected_id = self.visible().first().map(|e| e.id);
    }

    // -- keys ----------------------------------------------------------------------------------

    /// Handle a logical key. Returns an [`Effect`] the driver must carry out (quit, fetch).
    ///
    /// `Key` is this crate's own enum so the app does not depend on crossterm, keeping it testable.
    pub fn on_key(&mut self, key: Key) -> Effect {
        // While typing a filter, most keys are text; only Enter/Esc leave the mode.
        if self.filtering {
            return self.on_filter_key(key);
        }

        match key {
            Key::Quit => return Effect::Quit,
            // Up/Down navigate the list, but scroll the pane once a request is open.
            Key::Up => self.nav_or_scroll(-1),
            Key::Down => self.nav_or_scroll(1),
            Key::PageUp => self.nav_or_scroll(-10),
            Key::PageDown => self.nav_or_scroll(10),
            Key::Home => {
                if self.mode == Mode::List {
                    self.selected_id = self.visible().first().map(|e| e.id);
                } else {
                    self.detail_scroll = 0;
                }
            }
            Key::End => {
                if self.mode == Mode::List {
                    self.selected_id = self.visible().last().map(|e| e.id);
                } else {
                    // Renderer clamps to the real bottom; MAX means "as far as it goes".
                    self.detail_scroll = u16::MAX;
                }
            }
            Key::Enter => {
                if self.selected_event().is_some() {
                    self.mode = Mode::Detail;
                    self.detail_scroll = 0;
                }
            }
            Key::Reveal => {
                // Only meaningful with a request open. Ask the driver to fetch its original.
                if self.mode != Mode::List
                    && let Some(id) = self.selected_event().map(|e| e.id)
                {
                    return Effect::RevealOriginal(id);
                }
            }
            Key::Escape => self.collapse(),
            Key::Group => self.group_by_url = !self.group_by_url,
            Key::Pause => self.paused = !self.paused,
            Key::Filter => self.filtering = true,
            Key::Char(_) | Key::Backspace => {}
        }
        Effect::None
    }

    /// In the list, move the selection; in the detail/reveal pane, scroll it.
    fn nav_or_scroll(&mut self, delta: i16) {
        if self.mode == Mode::List {
            self.move_selection(delta as isize);
        } else {
            self.detail_scroll = self.detail_scroll.saturating_add_signed(delta);
        }
    }

    fn on_filter_key(&mut self, key: Key) -> Effect {
        match key {
            Key::Enter | Key::Escape => self.filtering = false,
            Key::Backspace => {
                self.filter.pop();
            }
            Key::Char(c) => self.filter.push(c),
            _ => {}
        }
        // A changed filter can hide the selected row; snap to a visible one.
        self.ensure_selection_visible();
        Effect::None
    }

    /// The driver calls this with the fetched original after a [`Effect::RevealOriginal`].
    pub fn revealed(&mut self, original: String) {
        // Ignore a stale reveal that arrived after the user already collapsed the pane.
        if self.mode != Mode::List {
            self.mode = Mode::Reveal(original);
            self.detail_scroll = 0;
        }
    }

    fn collapse(&mut self) {
        self.mode = match self.mode {
            // Reveal collapses back to the safe view; Detail collapses back to the list.
            Mode::Reveal(_) => Mode::Detail,
            _ => Mode::List,
        };
    }

    fn move_selection(&mut self, delta: isize) {
        let visible = self.visible();
        if visible.is_empty() {
            self.selected_id = None;
            return;
        }
        let current = self.selected_index().unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, visible.len() as isize - 1) as usize;
        self.selected_id = Some(visible[next].id);
        self.detail_scroll = 0;
    }

    // -- header aggregates (computed from the buffer; no separate counters to drift) ------------

    pub fn header(&self) -> Header {
        let prompts = self.events.len();
        let entities: usize = self
            .events
            .iter()
            .map(|e| e.entity_counts_by_kind.values().sum::<usize>())
            .sum();
        let chars: usize = self.events.iter().map(|e| e.chars_hidden).sum();

        let mut latencies: Vec<u64> = self.events.iter().map(|e| e.latency_ms).collect();
        latencies.sort_unstable();
        let avg = if latencies.is_empty() {
            0
        } else {
            latencies.iter().sum::<u64>() / latencies.len() as u64
        };
        let p95 = percentile(&latencies, 95);

        // Per-kind totals across the buffer, in a stable order for a legend that does not reshuffle.
        let mut by_kind: std::collections::BTreeMap<String, usize> = Default::default();
        for e in &self.events {
            for (k, n) in &e.entity_counts_by_kind {
                *by_kind.entry(k.clone()).or_insert(0) += *n;
            }
        }

        Header {
            prompts,
            entities,
            chars_hidden: chars,
            near_misses_blocked: self.near_misses_blocked,
            avg_latency_ms: avg,
            p95_latency_ms: p95,
            by_kind,
        }
    }

    // -- accessors for the renderer ------------------------------------------------------------

    pub fn mode(&self) -> &Mode {
        &self.mode
    }
    /// The detail/reveal pane's scroll offset, in lines. The renderer clamps it to the content.
    pub fn detail_scroll(&self) -> u16 {
        self.detail_scroll
    }
    /// The selected row's index in the visible list, or 0 when the list is empty.
    pub fn selected(&self) -> usize {
        self.selected_index().unwrap_or(0)
    }
    pub fn paused(&self) -> bool {
        self.paused
    }
    pub fn grouped(&self) -> bool {
        self.group_by_url
    }
    pub fn is_filtering(&self) -> bool {
        self.filtering
    }
    pub fn filter(&self) -> &str {
        &self.filter
    }
}

/// A logical key. Independent of crossterm so `App` stays free of terminal types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Enter,
    Escape,
    Reveal,
    Group,
    Pause,
    Filter,
    Quit,
    Backspace,
    Char(char),
}

/// The header line's aggregates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub prompts: usize,
    pub entities: usize,
    pub chars_hidden: usize,
    pub near_misses_blocked: u64,
    pub avg_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub by_kind: std::collections::BTreeMap<String, usize>,
}

/// Nearest-rank percentile of a **sorted** slice.
fn percentile(sorted: &[u64], p: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    // Nearest-rank: rank = ceil(p/100 * n), 1-indexed.
    let rank = ((p * sorted.len()).div_ceil(100)).max(1);
    sorted[(rank - 1).min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: u64, url: &str, entities: usize, chars: usize, latency: u64) -> Event {
        let mut by_kind = std::collections::BTreeMap::new();
        if entities > 0 {
            by_kind.insert("AwsAccessKeyId".to_string(), entities);
        }
        Event {
            id,
            timestamp: 1_000 + id,
            upstream_url: url.to_string(),
            model: "claude-opus-4-8".to_string(),
            entity_counts_by_kind: by_kind,
            chars_hidden: chars,
            latency_ms: latency,
            rewritten_text: format!("request {id} to {url}"),
        }
    }

    #[test]
    fn newest_event_is_selected_when_live() {
        let mut app = App::new(10);
        app.push(event(1, "https://api.anthropic.com/v1/messages", 1, 20, 10));
        app.push(event(2, "https://api.anthropic.com/v1/messages", 2, 40, 20));
        assert_eq!(app.selected_event().unwrap().id, 2, "live feed pins newest");
    }

    #[test]
    fn the_buffer_is_bounded() {
        let mut app = App::new(2);
        for i in 1..=5 {
            app.push(event(i, "u", 0, 0, 0));
        }
        assert_eq!(app.visible().len(), 2);
        assert_eq!(app.visible()[0].id, 5, "newest kept");
        assert_eq!(app.visible()[1].id, 4);
    }

    #[test]
    fn pause_freezes_the_selection_but_not_the_feed() {
        let mut app = App::new(10);
        app.push(event(1, "u", 0, 0, 0));
        app.push(event(2, "u", 0, 0, 0)); // selected id 2 at index 0
        app.on_key(Key::Down); // select index 1 (id 1)
        assert_eq!(app.selected_event().unwrap().id, 1);

        app.on_key(Key::Pause);
        app.push(event(3, "u", 0, 0, 0)); // arrives at front; feed keeps flowing
        // The cursor still points at id 1, now one row lower, not snapped to the new top.
        assert_eq!(
            app.selected_event().unwrap().id,
            1,
            "paused cursor stays on its request"
        );
        assert_eq!(app.visible().len(), 3, "the event was still buffered");
    }

    #[test]
    fn filter_narrows_by_upstream_url_case_insensitively() {
        let mut app = App::new(10);
        app.push(event(1, "https://api.anthropic.com/v1/messages", 0, 0, 0));
        app.push(event(2, "https://api.openai.com/v1/chat", 0, 0, 0));

        app.on_key(Key::Filter);
        assert!(app.is_filtering());
        for c in "ANTHROPIC".chars() {
            app.on_key(Key::Char(c));
        }
        app.on_key(Key::Enter);
        assert!(!app.is_filtering());

        let vis = app.visible();
        assert_eq!(vis.len(), 1);
        assert!(vis[0].upstream_url.contains("anthropic"));
    }

    #[test]
    fn a_filter_that_empties_the_list_does_not_leave_a_dangling_selection() {
        let mut app = App::new(10);
        app.push(event(1, "anthropic", 0, 0, 0));
        app.on_key(Key::Filter);
        for c in "zzz".chars() {
            app.on_key(Key::Char(c));
        }
        assert_eq!(app.visible().len(), 0);
        assert_eq!(app.selected_event(), None, "no panic, no stale index");
    }

    #[test]
    fn grouping_puts_same_url_rows_together() {
        let mut app = App::new(10);
        app.push(event(1, "A", 0, 0, 0));
        app.push(event(2, "B", 0, 0, 0));
        app.push(event(3, "A", 0, 0, 0));
        app.on_key(Key::Group);
        let urls: Vec<&str> = app
            .visible()
            .iter()
            .map(|e| e.upstream_url.as_str())
            .collect();
        // Both A's adjacent, both B's adjacent.
        assert!(
            urls == ["A", "A", "B"] || urls == ["B", "A", "A"],
            "grouped: {urls:?}"
        );
    }

    #[test]
    fn enter_opens_detail_and_reveal_asks_the_driver_to_fetch() {
        let mut app = App::new(10);
        app.push(event(7, "u", 1, 20, 10));
        assert_eq!(app.on_key(Key::Enter), Effect::None);
        assert_eq!(*app.mode(), Mode::Detail);

        // Reveal in detail mode returns the fetch effect for this id.
        assert_eq!(app.on_key(Key::Reveal), Effect::RevealOriginal(7));

        app.revealed("the real secret text".to_string());
        assert_eq!(
            *app.mode(),
            Mode::Reveal("the real secret text".to_string())
        );
    }

    #[test]
    fn reveal_is_a_no_op_from_the_list() {
        let mut app = App::new(10);
        app.push(event(1, "u", 0, 0, 0));
        // In the list (not detail), `r` does nothing: originals are only fetched with a request open.
        assert_eq!(app.on_key(Key::Reveal), Effect::None);
        assert_eq!(*app.mode(), Mode::List);
    }

    #[test]
    fn escape_collapses_reveal_to_detail_then_detail_to_list() {
        let mut app = App::new(10);
        app.push(event(1, "u", 0, 0, 0));
        app.on_key(Key::Enter);
        app.on_key(Key::Reveal);
        app.revealed("real".into());
        assert!(matches!(app.mode(), Mode::Reveal(_)));

        app.on_key(Key::Escape);
        assert_eq!(*app.mode(), Mode::Detail, "reveal -> detail");
        app.on_key(Key::Escape);
        assert_eq!(*app.mode(), Mode::List, "detail -> list");
    }

    #[test]
    fn header_aggregates_the_buffer() {
        let mut app = App::new(10);
        app.push(event(1, "u", 2, 40, 10));
        app.push(event(2, "u", 3, 60, 30));
        app.push(event(3, "u", 1, 20, 20));
        app.near_misses_blocked = 4;

        let h = app.header();
        assert_eq!(h.prompts, 3);
        assert_eq!(h.entities, 6);
        assert_eq!(h.chars_hidden, 120);
        assert_eq!(h.avg_latency_ms, 20); // (10+30+20)/3
        assert_eq!(h.near_misses_blocked, 4);
        assert_eq!(h.by_kind.get("AwsAccessKeyId"), Some(&6));
    }

    #[test]
    fn p95_is_nearest_rank() {
        let sorted: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&sorted, 95), 95);
        assert_eq!(percentile(&sorted, 100), 100);
        assert_eq!(percentile(&[], 95), 0);
        assert_eq!(percentile(&[42], 95), 42);
    }

    #[test]
    fn quit_key_asks_to_quit() {
        let mut app = App::new(10);
        assert_eq!(app.on_key(Key::Quit), Effect::Quit);
    }

    #[test]
    fn arrows_scroll_the_detail_pane_without_moving_the_selection() {
        let mut app = App::new(10);
        app.push(event(1, "u", 0, 0, 0));
        app.push(event(2, "u", 0, 0, 0));
        app.on_key(Key::Enter); // open detail on the selected (newest) request
        assert_eq!(*app.mode(), Mode::Detail);
        assert_eq!(app.detail_scroll(), 0, "opens at the top");

        app.on_key(Key::Down);
        app.on_key(Key::Down);
        assert_eq!(app.detail_scroll(), 2, "Down scrolls the pane in detail mode");
        assert_eq!(app.selected_event().unwrap().id, 2, "selection is untouched");

        app.on_key(Key::Up);
        assert_eq!(app.detail_scroll(), 1);
        app.on_key(Key::Home);
        assert_eq!(app.detail_scroll(), 0);
        app.on_key(Key::End);
        assert_eq!(app.detail_scroll(), u16::MAX, "End asks for the bottom; render clamps it");
    }

    #[test]
    fn scroll_resets_when_a_different_request_is_opened() {
        let mut app = App::new(10);
        app.push(event(1, "u", 0, 0, 0));
        app.push(event(2, "u", 0, 0, 0));
        app.on_key(Key::Enter);
        app.on_key(Key::Down); // scrolled into request 2
        assert_eq!(app.detail_scroll(), 1);
        app.on_key(Key::Escape); // back to the list
        app.on_key(Key::Up); // select the other request — scroll resets
        assert_eq!(app.detail_scroll(), 0);
    }

    #[test]
    fn up_and_down_still_navigate_the_list() {
        let mut app = App::new(10);
        app.push(event(1, "u", 0, 0, 0));
        app.push(event(2, "u", 0, 0, 0));
        // In the list, Down moves the selection (it does not scroll a pane).
        app.on_key(Key::Down);
        assert_eq!(app.selected_event().unwrap().id, 1);
        assert_eq!(app.detail_scroll(), 0);
    }

    /// The reveal never survives to disk and never enters the event buffer: it lives only in the
    /// `Mode::Reveal` payload, which is dropped on collapse.
    #[test]
    fn revealed_original_is_dropped_on_collapse() {
        let mut app = App::new(10);
        app.push(event(1, "u", 0, 0, 0));
        app.on_key(Key::Enter);
        app.on_key(Key::Reveal);
        app.revealed("SECRET".into());
        app.on_key(Key::Escape); // back to Detail
        assert_eq!(*app.mode(), Mode::Detail);
        // Nothing in the buffer carries the revealed text.
        assert!(
            app.events
                .iter()
                .all(|e| !e.rewritten_text.contains("SECRET"))
        );
    }
}
