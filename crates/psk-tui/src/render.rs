//! ratatui rendering. The one untested surface — it draws; the state it draws from is tested in
//! `app`. Kept declarative: read `App`, emit widgets, no logic beyond turning text into styled
//! spans.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use psk_proxy::MARKER;
use psk_proxy::events::Event;

use crate::app::{App, Mode};
use crate::diff::{DiffLine, diff};
use crate::jsonfmt;

// The palette, named once so the whole view stays consistent.
const KEY: Color = Color::Cyan; // JSON object keys
const STRING: Color = Color::Green; // JSON string values
const NUMBER: Color = Color::Yellow; // JSON numbers
const LITERAL: Color = Color::Blue; // true / false / null
const PUNCT: Color = Color::DarkGray; // braces, colons, commas
const FAKE: Color = Color::Magenta; // a substituted (marker-bearing) value
const REAL: Color = Color::Red; // a revealed real secret

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // header
            Constraint::Min(6),    // list / detail
            Constraint::Length(1), // key hints
        ])
        .split(f.area());

    draw_header(f, chunks[0], app);

    match app.mode() {
        Mode::List => draw_list(f, chunks[1], app),
        Mode::Detail => draw_detail(f, chunks[1], app, None),
        Mode::Reveal(original) => draw_detail(f, chunks[1], app, Some(original)),
    }

    draw_hints(f, chunks[2], app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let h = app.header();
    let dim = Style::default().fg(PUNCT);
    let label = |s: &str| Span::styled(s.to_string(), dim);
    let value = |n: usize, c: Color| {
        Span::styled(
            n.to_string(),
            Style::default().fg(c).add_modifier(Modifier::BOLD),
        )
    };

    // The per-kind legend, coloured like the fakes it counts.
    let mut legend: Vec<Span> = Vec::new();
    for (k, n) in &h.by_kind {
        legend.push(Span::raw(" "));
        legend.push(Span::styled(format!("{k}:{n}"), Style::default().fg(FAKE)));
    }

    let near_miss_color = if h.near_misses_blocked > 0 {
        REAL
    } else {
        PUNCT
    };

    let body = vec![
        Line::from(vec![
            Span::styled("PSK", Style::default().fg(KEY).add_modifier(Modifier::BOLD)),
            Span::styled(" inspector", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" — what left this machine", dim),
        ]),
        Line::from(vec![
            label("prompts "),
            value(h.prompts, Color::White),
            label("   secrets hidden "),
            value(h.entities, STRING),
            label("   chars "),
            value(h.chars_hidden, STRING),
            label("   near-misses blocked "),
            Span::styled(
                h.near_misses_blocked.to_string(),
                Style::default()
                    .fg(near_miss_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(
            [
                vec![
                    label("latency "),
                    Span::raw(format!("{}ms avg", h.avg_latency_ms)),
                    label("  "),
                    Span::raw(format!("{}ms p95", h.p95_latency_ms)),
                    label("   "),
                ],
                legend,
            ]
            .concat(),
        ),
    ];
    f.render_widget(
        Paragraph::new(body).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn draw_list(f: &mut Frame, area: Rect, app: &App) {
    let rows: Vec<ListItem> = app.visible().iter().map(|e| list_row(e)).collect();

    let mut title = vec![
        Span::styled(
            " Requests ",
            Style::default().fg(KEY).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("({}) ", app.visible().len()),
            Style::default().fg(PUNCT),
        ),
    ];
    if app.paused() {
        title.push(Span::styled(
            "[PAUSED] ",
            Style::default().fg(NUMBER).add_modifier(Modifier::BOLD),
        ));
    }
    if app.grouped() {
        title.push(Span::styled("[grouped] ", Style::default().fg(PUNCT)));
    }
    if !app.filter().is_empty() {
        title.push(Span::styled(
            format!("[/{}] ", app.filter()),
            Style::default().fg(STRING),
        ));
    }

    let mut state = ListState::default();
    state.select(Some(app.selected()));
    f.render_stateful_widget(
        List::new(rows)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Line::from(title)),
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> "),
        area,
        &mut state,
    );
}

/// One request as a coloured row. Rows that actually hid something stand out in green.
fn list_row(e: &Event) -> ListItem<'static> {
    let entities: usize = e.entity_counts_by_kind.values().sum();
    let ent_style = if entities > 0 {
        Style::default().fg(STRING).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(PUNCT)
    };
    let dim = Style::default().fg(PUNCT);

    ListItem::new(Line::from(vec![
        Span::styled(format!("{:>6}", e.id), Style::default().fg(KEY)),
        Span::raw("  "),
        Span::raw(format!("{:<40}", truncate(&host_path(&e.upstream_url), 40))),
        Span::raw("  "),
        Span::styled(format!("{:<18}", truncate(&e.model, 18)), dim),
        Span::raw("  "),
        Span::styled(format!("{:>3} secrets", entities), ent_style),
        Span::raw("  "),
        Span::styled(format!("{:>5} chars", e.chars_hidden), dim),
        Span::raw("  "),
        Span::styled(format!("{:>4}ms", e.latency_ms), dim),
    ]))
}

fn draw_detail(f: &mut Frame, area: Rect, app: &App, original: Option<&str>) {
    let Some(event) = app.selected_event() else {
        f.render_widget(
            Paragraph::new("no request selected").block(Block::default().borders(Borders::ALL)),
            area,
        );
        return;
    };

    let lines: Vec<Line> = match original {
        // Reveal: diff the original against the rewritten. Real values are on screen only now,
        // only for this request, and never persisted. Always the full form — the diff is
        // positional, and folding could collapse the two sides differently.
        Some(orig) => reveal_lines(&event.rewritten_text, orig),
        // Safe view: the rewritten body, pretty-printed and syntax-highlighted, with technical
        // subtrees folded unless the user expanded them.
        None => detail_lines(&event.rewritten_text, app.expanded()),
    };

    let entities: usize = event.entity_counts_by_kind.values().sum();
    let title = if original.is_some() {
        Line::from(vec![
            Span::styled(
                format!(" Request #{} ", event.id),
                Style::default().fg(KEY).add_modifier(Modifier::BOLD),
            ),
            Span::styled("· ", Style::default().fg(PUNCT)),
            Span::styled(
                "REVEALED",
                Style::default().fg(REAL).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" — real values, local only ", Style::default().fg(PUNCT)),
        ])
    } else {
        let view = if app.expanded() {
            "· full "
        } else {
            "· folded "
        };
        Line::from(vec![
            Span::styled(
                format!(" Request #{} ", event.id),
                Style::default().fg(KEY).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("· {} ", event.model), Style::default().fg(PUNCT)),
            Span::styled(format!("· {entities} hidden "), Style::default().fg(STRING)),
            Span::styled(
                "· rewritten (what the provider saw) ",
                Style::default().fg(PUNCT),
            ),
            Span::styled(view, Style::default().fg(PUNCT)),
        ])
    };

    // Clamp the scroll so the pane cannot scroll into empty space (End sets u16::MAX).
    let max_scroll = lines.len().saturating_sub(1) as u16;
    let scroll = app.detail_scroll().min(max_scroll);

    f.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        area,
    );
}

/// The rewritten body, pretty-printed and coloured. Folded by default: tool definitions, schemas,
/// and calls collapse to one-line summaries — but a subtree carrying a substituted secret never
/// folds (see `jsonfmt::pretty_folded`), so nothing the pane exists to show is hidden. Falls back
/// to plain fake-highlighting if the body is not JSON (PSK forwards non-JSON bodies untouched).
fn detail_lines(text: &str, expanded: bool) -> Vec<Line<'static>> {
    if is_json(text) {
        let pretty = if expanded {
            jsonfmt::pretty(text)
        } else {
            jsonfmt::pretty_folded(text, MARKER)
        };
        pretty.lines().map(highlight_json_line).collect()
    } else {
        text.lines().map(highlight_plain).collect()
    }
}

/// The reveal diff, over the pretty-printed forms so a single substituted value shows up as one
/// changed line surrounded by identical, syntax-highlighted context.
fn reveal_lines(rewritten: &str, original: &str) -> Vec<Line<'static>> {
    let json = is_json(rewritten);
    let pretty_rw = jsonfmt::pretty(rewritten);
    let pretty_orig = jsonfmt::pretty(original);

    diff(&pretty_rw, &pretty_orig)
        .into_iter()
        .map(|d| match d {
            DiffLine::Same(s) => {
                if json {
                    highlight_json_line(&s)
                } else {
                    highlight_plain(&s)
                }
            }
            // The fake the provider saw — yellow gutter, then the line's own colouring.
            DiffLine::Rewritten(s) => {
                let mut spans = vec![Span::styled(
                    "  fake  ",
                    Style::default().fg(NUMBER).add_modifier(Modifier::BOLD),
                )];
                let trimmed = s.trim_start();
                let mut body = if json {
                    highlight_json_line(trimmed)
                } else {
                    highlight_plain(trimmed)
                };
                spans.append(&mut body.spans);
                Line::from(spans)
            }
            // The real value — red gutter and red text, so it is unmistakable.
            DiffLine::Original(s) => Line::from(vec![
                Span::styled(
                    "  real  ",
                    Style::default().fg(REAL).add_modifier(Modifier::BOLD),
                ),
                Span::styled(s.trim_start().to_string(), Style::default().fg(REAL)),
            ]),
        })
        .collect()
}

fn is_json(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text).is_ok()
}

/// Colour one line of pretty-printed JSON. Pretty output is regular: a key is always the first
/// string on its line and is followed by a colon, which is what tells a key from a bare string value.
fn highlight_json_line(line: &str) -> Line<'static> {
    let indent_len = line.len() - line.trim_start().len();
    let (indent, rest) = line.split_at(indent_len);

    let mut spans: Vec<Span> = Vec::new();
    if !indent.is_empty() {
        spans.push(Span::raw(indent.to_string()));
    }
    if rest.is_empty() {
        return Line::from(spans);
    }

    // Key line: `"key": <value>`.
    if rest.starts_with('"') {
        let end = scan_json_string(rest);
        if rest.is_char_boundary(end) {
            let after = rest[end..].trim_start();
            if let Some(value) = after.strip_prefix(':') {
                spans.push(Span::styled(
                    rest[..end].to_string(),
                    Style::default().fg(KEY),
                ));
                spans.push(Span::styled(": ".to_string(), Style::default().fg(PUNCT)));
                value_spans(value.trim_start(), &mut spans);
                return Line::from(spans);
            }
        }
    }

    // Otherwise the whole remainder is a value or a structural token.
    value_spans(rest, &mut spans);
    Line::from(spans)
}

/// Push the spans for a JSON value fragment, which may carry a trailing comma.
fn value_spans(s: &str, spans: &mut Vec<Span<'static>>) {
    if s.is_empty() {
        return;
    }
    let (core, comma) = match s.strip_suffix(',') {
        Some(rest) => (rest.trim_end(), true),
        None => (s, false),
    };

    match core.chars().next() {
        Some('"') => string_value_spans(core, spans),
        Some('{') | Some('}') | Some('[') | Some(']') => {
            spans.push(Span::styled(core.to_string(), Style::default().fg(PUNCT)));
        }
        Some('t') | Some('f') | Some('n') => {
            spans.push(Span::styled(core.to_string(), Style::default().fg(LITERAL)));
        }
        Some(_) => {
            // A number (or anything else we did not special-case).
            spans.push(Span::styled(core.to_string(), Style::default().fg(NUMBER)));
        }
        None => {}
    }
    if comma {
        spans.push(Span::styled(",".to_string(), Style::default().fg(PUNCT)));
    }
}

/// A `"…"` string value: green, but any marker-bearing token inside it (a substituted secret) is
/// bold magenta so it stands out even in the middle of prompt text.
fn string_value_spans(quoted: &str, spans: &mut Vec<Span<'static>>) {
    let green = Style::default().fg(STRING);
    let end = scan_json_string(quoted);
    if end < 2 || !quoted.is_char_boundary(end) {
        spans.push(Span::styled(quoted.to_string(), green));
        return;
    }
    let inner = &quoted[1..end - 1];

    spans.push(Span::styled("\"".to_string(), green));
    for (i, tok) in inner.split(' ').enumerate() {
        if i > 0 {
            spans.push(Span::styled(" ".to_string(), green));
        }
        if tok.contains(MARKER) {
            spans.push(Span::styled(
                tok.to_string(),
                Style::default().fg(FAKE).add_modifier(Modifier::BOLD),
            ));
        } else if !tok.is_empty() {
            spans.push(Span::styled(tok.to_string(), green));
        }
    }
    spans.push(Span::styled("\"".to_string(), green));

    // Anything after the closing quote (unusual for a pure value) is punctuation.
    if end < quoted.len() {
        spans.push(Span::styled(
            quoted[end..].to_string(),
            Style::default().fg(PUNCT),
        ));
    }
}

/// Non-JSON fallback: split on spaces and light up marker-bearing tokens, nothing more.
fn highlight_plain(line: &str) -> Line<'static> {
    let mut spans = Vec::new();
    for (i, tok) in line.split(' ').enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        if tok.contains(MARKER) {
            spans.push(Span::styled(
                tok.to_string(),
                Style::default().fg(FAKE).add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::raw(tok.to_string()));
        }
    }
    Line::from(spans)
}

/// Given `s` starting with `"`, return the byte index just past the closing quote, honouring
/// backslash escapes. Returns `s.len()` if unterminated.
fn scan_json_string(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut i = 1; // past the opening quote
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2, // skip the escaped byte (JSON escapes are ASCII)
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    s.len()
}

fn draw_hints(f: &mut Frame, area: Rect, app: &App) {
    let hint = if app.is_filtering() {
        "filter: type to match upstream URL · Enter/Esc done".to_string()
    } else {
        match app.mode() {
            Mode::List => "↑↓ move · Enter open · g group · space pause · / filter · q quit".into(),
            Mode::Detail => {
                let x = if app.expanded() { "x fold" } else { "x expand" };
                format!("↑↓/PgUp/PgDn scroll · {x} · r reveal original · Esc back · q quit")
            }
            Mode::Reveal(_) => "↑↓ scroll · Esc back to safe view · q quit".into(),
        }
    };
    f.render_widget(Paragraph::new(hint).style(Style::default().fg(PUNCT)), area);
}

/// `https://api.anthropic.com/v1/messages?beta=true` -> `api.anthropic.com/v1/messages`.
fn host_path(url: &str) -> String {
    let no_scheme = url.split("://").nth(1).unwrap_or(url);
    no_scheme.split('?').next().unwrap_or(no_scheme).to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}\u{2026}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_path_strips_scheme_and_query() {
        assert_eq!(
            host_path("https://api.anthropic.com/v1/messages?beta=true"),
            "api.anthropic.com/v1/messages"
        );
    }

    #[test]
    fn truncate_adds_an_ellipsis() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 5), "hell\u{2026}");
    }

    #[test]
    fn scan_json_string_handles_escaped_quotes() {
        // "a\"b" — the escaped quote is not the end.
        let s = r#""a\"b" rest"#;
        let end = scan_json_string(s);
        assert_eq!(&s[..end], r#""a\"b""#);
    }

    #[test]
    fn a_key_line_splits_into_key_and_value() {
        let line = highlight_json_line(r#"  "model": "claude","#);
        // First non-indent span is the key, styled in the key colour.
        let key_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("model"))
            .unwrap();
        assert_eq!(key_span.style.fg, Some(KEY));
        // The value keeps the string colour.
        let val_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("claude"))
            .unwrap();
        assert_eq!(val_span.style.fg, Some(STRING));
    }

    #[test]
    fn a_marker_token_inside_a_string_value_is_flagged() {
        // A substituted secret embedded in prompt text must pop even mid-string.
        let fake = format!("{MARKER}abcd1234");
        let line = highlight_json_line(&format!(r#"  "content": "deploy {fake} now""#));
        let flagged = line
            .spans
            .iter()
            .find(|s| s.content.contains(&fake))
            .unwrap();
        assert_eq!(flagged.style.fg, Some(FAKE));
    }

    #[test]
    fn the_folded_detail_view_hides_tool_descriptions_and_x_brings_them_back() {
        let desc = "an awfully long tool description ".repeat(30);
        let body = serde_json::json!({
            "model": "claude",
            "tools": [{ "name": "Bash", "description": desc,
                        "input_schema": { "type": "object" } }],
            "messages": [{ "role": "user", "content": "hello" }]
        })
        .to_string();

        let text_of = |lines: &[Line]| -> String {
            lines
                .iter()
                .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
                .collect()
        };

        let folded = detail_lines(&body, false);
        let full = detail_lines(&body, true);
        assert!(folded.len() < full.len(), "folding shortens the pane");
        assert!(!text_of(&folded).contains("awfully long tool description"));
        assert!(
            text_of(&folded).contains("hello"),
            "the conversation survives"
        );
        assert!(text_of(&full).contains("awfully long tool description"));
    }
}
