//! `psk top` — the terminal inspector (brief §9).
//!
//! Watches the proxy's localhost `GET /events` stream and renders it live. Read-only: it never
//! touches traffic, so it attaches and detaches at will. Nothing is written to disk; the event
//! buffer and any revealed original live only in memory and vanish on quit.
//!
//! The interesting logic (state, filtering, the diff, SSE parsing) lives in [`app`], [`diff`], and
//! [`feed`] and is unit-tested. This module is the terminal/HTTP driver — the untested shell.

pub mod app;
pub mod diff;
pub mod feed;
pub mod jsonfmt;
pub mod render;

use std::io::BufReader;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::event::{self, Event as CtEvent, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use app::{App, Effect, Key};
use feed::FeedMsg;

/// Launch the inspector against the proxy described by `config`.
///
/// If the proxy is not running, prints a one-line hint and returns `Ok(())` — a missing proxy is
/// not an error, just nothing to watch (brief §9).
pub fn run(config: &psk_proxy::Config) -> Result<()> {
    let base = format!("http://{}", config.bind);
    // No *total* timeout: `GET /events` is a long-lived stream, and a request-wide timeout would
    // silently sever it (that was the "psk top stops updating after a few seconds" bug). Bound only
    // the connect, so a proxy that is not running still fails fast; the one-shot requests below add
    // their own per-request read timeout.
    let http = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()
        .expect("client builds");

    // Cheap liveness check before taking over the terminal.
    if http
        .get(format!("{base}/health"))
        .timeout(Duration::from_secs(5))
        .send()
        .is_err()
    {
        println!(
            "psk top: no proxy answering at {base}.\n\
             Start one with `psk proxy`, then run `psk top` again."
        );
        return Ok(());
    }

    // Background thread streams SSE events into the channel; the UI thread never blocks on IO.
    let (tx, rx) = mpsc::channel();
    {
        let url = format!("{base}/events");
        let http = http.clone();
        std::thread::spawn(move || match http.get(&url).send() {
            Ok(resp) => feed::read_sse(BufReader::new(resp), &tx),
            Err(_) => {
                let _ = tx.send(FeedMsg::Disconnected);
            }
        });
    }

    let mut app = App::new(config.event_buffer);
    let mut terminal = enter_terminal().context("entering the alternate screen")?;

    let result = event_loop(&mut terminal, &mut app, &rx, &http, &base);

    restore_terminal(&mut terminal).context("restoring the terminal")?;
    result
}

type Term = Terminal<CrosstermBackend<std::io::Stdout>>;

fn event_loop(
    terminal: &mut Term,
    app: &mut App,
    rx: &mpsc::Receiver<FeedMsg>,
    http: &reqwest::blocking::Client,
    base: &str,
) -> Result<()> {
    let tick = Duration::from_millis(200);
    let mut last_stats = Instant::now();
    load_near_misses(app); // seed the counter once at startup

    loop {
        terminal.draw(|f| render::draw(f, app))?;

        // Drain whatever the feed thread has produced.
        while let Ok(msg) = rx.try_recv() {
            match msg {
                FeedMsg::Event(e) => app.push(*e),
                // Keep the buffer we already have; the proxy may come back and the feed thread
                // ends, but what we captured is still worth inspecting.
                FeedMsg::Disconnected => {}
            }
        }

        // The near-miss counter is not on the event stream (events carry no hook data), so refresh
        // it from stats.json every couple of seconds.
        if last_stats.elapsed() > Duration::from_secs(2) {
            load_near_misses(app);
            last_stats = Instant::now();
        }

        // Poll for a key, with a timeout so the feed keeps draining even when idle.
        if event::poll(tick)?
            && let CtEvent::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && let Some(logical) = map_key(key.code, app.is_filtering())
        {
            match app.on_key(logical) {
                Effect::Quit => return Ok(()),
                Effect::RevealOriginal(id) => {
                    // Fetch the one original, on demand, never cached to disk.
                    if let Ok(resp) = http
                        .get(format!("{base}/events/{id}/original"))
                        .timeout(Duration::from_secs(10))
                        .send()
                        && resp.status().is_success()
                        && let Ok(text) = resp.text()
                    {
                        app.revealed(text);
                    }
                }
                Effect::None => {}
            }
        }
    }
}

/// Read `near_misses_blocked` from `~/.psk/stats.json`. Best-effort: the counter is a nicety, and a
/// missing or malformed file simply leaves it at its last value.
fn load_near_misses(app: &mut App) {
    if let Ok(home) = psk_vault::salt::psk_home()
        && let Ok(text) = std::fs::read_to_string(home.join("stats.json"))
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(n) = v
            .get("near_misses_blocked")
            .and_then(serde_json::Value::as_u64)
    {
        app.near_misses_blocked = n;
    }
}

/// Map a crossterm key to the app's logical key. In filter mode, printable characters are text.
fn map_key(code: KeyCode, filtering: bool) -> Option<Key> {
    Some(match code {
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Escape,
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Char(c) if filtering => Key::Char(c),
        KeyCode::Char('q') => Key::Quit,
        KeyCode::Char('r') => Key::Reveal,
        KeyCode::Char('x') => Key::Expand,
        KeyCode::Char('g') => Key::Group,
        KeyCode::Char(' ') => Key::Pause,
        KeyCode::Char('/') => Key::Filter,
        KeyCode::Char(_) => return None,
        _ => return None,
    })
}

fn enter_terminal() -> Result<Term> {
    enable_raw_mode()?;
    let mut out = std::io::stdout();
    crossterm::execute!(out, EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(out))?)
}

fn restore_terminal(terminal: &mut Term) -> Result<()> {
    disable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_keys_map_outside_filter_mode() {
        assert_eq!(map_key(KeyCode::Char('q'), false), Some(Key::Quit));
        assert_eq!(map_key(KeyCode::Char('r'), false), Some(Key::Reveal));
        assert_eq!(map_key(KeyCode::Char('x'), false), Some(Key::Expand));
        assert_eq!(map_key(KeyCode::Char(' '), false), Some(Key::Pause));
        assert_eq!(map_key(KeyCode::Char('/'), false), Some(Key::Filter));
        assert_eq!(map_key(KeyCode::Char('z'), false), None);
        // Scroll keys for the detail pane.
        assert_eq!(map_key(KeyCode::PageDown, false), Some(Key::PageDown));
        assert_eq!(map_key(KeyCode::Home, false), Some(Key::Home));
        assert_eq!(map_key(KeyCode::End, false), Some(Key::End));
    }

    #[test]
    fn printable_keys_are_text_in_filter_mode() {
        // In filter mode `q` is a letter to type, not the quit command.
        assert_eq!(map_key(KeyCode::Char('q'), true), Some(Key::Char('q')));
        assert_eq!(map_key(KeyCode::Char('/'), true), Some(Key::Char('/')));
        // Enter/Esc still leave the mode.
        assert_eq!(map_key(KeyCode::Enter, true), Some(Key::Enter));
        assert_eq!(map_key(KeyCode::Esc, true), Some(Key::Escape));
    }
}
