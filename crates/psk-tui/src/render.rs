//! ratatui rendering. The one untested surface — it draws; the state it draws from is tested in
//! `app`. Kept declarative: read `App`, emit widgets, no logic.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use psk_proxy::MARKER;

use crate::app::{App, Mode};
use crate::diff::{DiffLine, diff};

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // header
            Constraint::Min(6),    // list
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
    let kinds: Vec<String> = h.by_kind.iter().map(|(k, n)| format!("{k}:{n}")).collect();

    let body = vec![
        Line::from(vec![
            Span::styled(
                "PSK",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  inspector — what left this machine"),
        ]),
        Line::from(format!(
            "prompts {}   entities {}   chars hidden {}   near-misses blocked {}",
            h.prompts, h.entities, h.chars_hidden, h.near_misses_blocked
        )),
        Line::from(format!(
            "latency avg {}ms  p95 {}ms   [{}]",
            h.avg_latency_ms,
            h.p95_latency_ms,
            kinds.join("  ")
        )),
    ];
    f.render_widget(
        Paragraph::new(body).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn draw_list(f: &mut Frame, area: Rect, app: &App) {
    let rows: Vec<ListItem> = app
        .visible()
        .iter()
        .map(|e| {
            let entities: usize = e.entity_counts_by_kind.values().sum();
            ListItem::new(format!(
                "{:>6}  {:<40}  {:<18}  ent {:>3}  chars {:>5}  {:>4}ms",
                e.id,
                truncate(&host_path(&e.upstream_url), 40),
                truncate(&e.model, 18),
                entities,
                e.chars_hidden,
                e.latency_ms,
            ))
        })
        .collect();

    let title = format!(
        " requests{}{}{} ",
        if app.paused() { " [PAUSED]" } else { "" },
        if app.grouped() { " [grouped]" } else { "" },
        if app.filter().is_empty() {
            String::new()
        } else {
            format!(" [/{}]", app.filter())
        },
    );

    let mut state = ListState::default();
    state.select(Some(app.selected()));
    f.render_stateful_widget(
        List::new(rows)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> "),
        area,
        &mut state,
    );
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
        // only for this request, and never persisted.
        Some(orig) => diff(&event.rewritten_text, orig)
            .into_iter()
            .map(|d| match d {
                DiffLine::Same(s) => Line::from(s),
                DiffLine::Rewritten(s) => Line::from(vec![
                    Span::styled("fake ", Style::default().fg(Color::Yellow)),
                    Span::raw(s),
                ]),
                DiffLine::Original(s) => Line::from(vec![
                    Span::styled(
                        "real ",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(s, Style::default().fg(Color::Red)),
                ]),
            })
            .collect(),
        // Safe view: the rewritten text, with marker-bearing fakes highlighted.
        None => event.rewritten_text.lines().map(highlight_fakes).collect(),
    };

    let title = if original.is_some() {
        format!(" request {} — REVEALED (real values shown) ", event.id)
    } else {
        format!(" request {} — rewritten (what the provider saw) ", event.id)
    };

    f.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Highlight any whitespace-delimited token carrying the PSK marker, so the substituted spans in
/// the rewritten text stand out.
fn highlight_fakes(line: &str) -> Line<'static> {
    let mut spans = Vec::new();
    for (i, tok) in line.split(' ').enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        if tok.contains(MARKER) {
            spans.push(Span::styled(
                tok.to_string(),
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::raw(tok.to_string()));
        }
    }
    Line::from(spans)
}

fn draw_hints(f: &mut Frame, area: Rect, app: &App) {
    let hint = if app.is_filtering() {
        "filter: type to match upstream URL · Enter/Esc done".to_string()
    } else {
        match app.mode() {
            Mode::List => "↑↓ move · Enter open · g group · space pause · / filter · q quit".into(),
            Mode::Detail => "r reveal original · Esc back · q quit".into(),
            Mode::Reveal(_) => "Esc back to safe view · q quit".into(),
        }
    };
    f.render_widget(
        Paragraph::new(hint).style(Style::default().fg(Color::DarkGray)),
        area,
    );
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
}
