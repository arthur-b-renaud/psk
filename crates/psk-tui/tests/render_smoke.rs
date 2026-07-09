//! Render smoke tests: drive the real ratatui renderer against a `TestBackend` (an in-memory
//! terminal) so the drawing code is exercised without a TTY. Asserts on the rendered text buffer.

use psk_proxy::events::Event;
use psk_tui::app::{App, Key};
use ratatui::Terminal;
use ratatui::backend::TestBackend;

fn event(id: u64, url: &str, rewritten: &str) -> Event {
    let mut by_kind = std::collections::BTreeMap::new();
    by_kind.insert("AwsAccessKeyId".to_string(), 1);
    Event {
        id,
        timestamp: 1000 + id,
        upstream_url: url.to_string(),
        model: "claude-opus-4-8".to_string(),
        entity_counts_by_kind: by_kind,
        chars_hidden: 20,
        latency_ms: 12,
        rewritten_text: rewritten.to_string(),
    }
}

/// Render `app` into an 80x24 test terminal and return the screen as one string.
fn render_to_string(app: &App) -> String {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| psk_tui::render::draw(f, app)).unwrap();

    let buffer = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            out.push_str(buffer[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

#[test]
fn the_list_view_shows_the_header_and_a_request_row() {
    let mut app = App::new(10);
    app.push(event(
        1,
        "https://api.anthropic.com/v1/messages",
        "deploy AKIAQPSKFAKE0000000",
    ));

    let screen = render_to_string(&app);
    assert!(screen.contains("PSK"), "header title present");
    assert!(screen.contains("prompts 1"), "header aggregates present");
    assert!(
        screen.contains("api.anthropic.com/v1/messages"),
        "request row host/path"
    );
    assert!(screen.contains("q quit"), "key hints present");
}

#[test]
fn detail_view_shows_rewritten_text() {
    let mut app = App::new(10);
    app.push(event(5, "u", "the key is AKIAQPSKFAKE0000000 done"));
    app.on_key(Key::Enter);

    let screen = render_to_string(&app);
    assert!(screen.contains("rewritten"), "detail title says rewritten");
    assert!(screen.contains("AKIAQPSKFAKE0000000"), "the fake is shown");
    assert!(screen.contains("r reveal original"), "reveal hint present");
}

#[test]
fn reveal_view_diffs_original_against_rewritten() {
    let mut app = App::new(10);
    app.push(event(9, "u", "key = AKIAQPSKFAKE0000000"));
    app.on_key(Key::Enter);
    app.on_key(Key::Reveal);
    app.revealed("key = AKIA1234567890REALKEY".to_string());

    let screen = render_to_string(&app);
    assert!(
        screen.contains("REVEALED"),
        "title warns real values are shown"
    );
    assert!(
        screen.contains("AKIA1234567890REALKEY"),
        "the real value is in the diff"
    );
    assert!(
        screen.contains("fake") && screen.contains("real"),
        "diff labels both sides"
    );
}

#[test]
fn a_paused_grouped_filtered_list_labels_its_state() {
    let mut app = App::new(10);
    app.push(event(1, "https://api.anthropic.com", "x"));
    app.on_key(Key::Pause);
    app.on_key(Key::Group);

    let screen = render_to_string(&app);
    assert!(screen.contains("[PAUSED]"));
    assert!(screen.contains("[grouped]"));
}

#[test]
fn empty_state_renders_without_panicking() {
    let app = App::new(10);
    let screen = render_to_string(&app);
    assert!(screen.contains("PSK"), "header still drawn with no events");
    assert!(screen.contains("prompts 0"));
}
