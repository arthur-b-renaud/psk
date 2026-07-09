//! A minimal line diff for the reveal pane: original vs rewritten.
//!
//! Not a general diff library — just enough to render "here is what the real value was" against
//! the fake the provider saw. Line-oriented, because a substituted secret sits inside a line and
//! the surrounding lines are identical.

/// One line of the diff view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffLine {
    /// Identical in both.
    Same(String),
    /// The rewritten (safe) form — what the provider saw.
    Rewritten(String),
    /// The original (real) form — what actually runs locally.
    Original(String),
}

/// Diff `rewritten` against `original`, line by line.
///
/// Lines equal in both are `Same`. Where they differ, the rewritten line is shown first (it is the
/// safe one), then the original, so the reader sees fake-then-real in reading order. This is a
/// positional diff, not a longest-common-subsequence one: substitution preserves line count and
/// structure, so aligned lines line up.
pub fn diff(rewritten: &str, original: &str) -> Vec<DiffLine> {
    let r: Vec<&str> = rewritten.lines().collect();
    let o: Vec<&str> = original.lines().collect();
    let mut out = Vec::with_capacity(r.len().max(o.len()));

    for i in 0..r.len().max(o.len()) {
        match (r.get(i), o.get(i)) {
            (Some(rl), Some(ol)) if rl == ol => out.push(DiffLine::Same((*rl).to_string())),
            (Some(rl), Some(ol)) => {
                out.push(DiffLine::Rewritten((*rl).to_string()));
                out.push(DiffLine::Original((*ol).to_string()));
            }
            // Uneven line counts (rare, but a multi-line PEM restore can change wrapping): show
            // whichever side has the extra line, labelled honestly.
            (Some(rl), None) => out.push(DiffLine::Rewritten((*rl).to_string())),
            (None, Some(ol)) => out.push(DiffLine::Original((*ol).to_string())),
            (None, None) => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_lines_are_same() {
        let d = diff("a\nb\nc", "a\nb\nc");
        assert_eq!(
            d,
            vec![
                DiffLine::Same("a".into()),
                DiffLine::Same("b".into()),
                DiffLine::Same("c".into())
            ]
        );
    }

    #[test]
    fn a_changed_line_shows_rewritten_then_original() {
        let d = diff("key = AKIAQPSKFAKE", "key = AKIA1234REAL");
        assert_eq!(
            d,
            vec![
                DiffLine::Rewritten("key = AKIAQPSKFAKE".into()),
                DiffLine::Original("key = AKIA1234REAL".into()),
            ]
        );
    }

    #[test]
    fn only_the_differing_line_is_split() {
        let d = diff(
            "host: db\nkey = FAKE\nport: 5432",
            "host: db\nkey = REAL\nport: 5432",
        );
        assert_eq!(d.len(), 4); // same, rewritten, original, same
        assert_eq!(d[0], DiffLine::Same("host: db".into()));
        assert_eq!(d[3], DiffLine::Same("port: 5432".into()));
    }

    #[test]
    fn uneven_line_counts_do_not_panic() {
        let d = diff("a", "a\nb\nc");
        assert!(d.contains(&DiffLine::Same("a".into())));
        assert!(d.contains(&DiffLine::Original("b".into())));
        assert!(d.contains(&DiffLine::Original("c".into())));
    }
}
