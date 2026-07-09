//! Exact, whole-token restore over the set of known fakes.
//!
//! The naive implementation is `for (fake, real) in map { text = text.replace(fake, real) }`,
//! which walks the haystack once per fake. A single Aho-Corasick automaton walks it once for all
//! of them (brief §5). The automaton is rebuilt only when a new fake is minted, so a long
//! conversation pays for it a handful of times, not once per request.

use aho_corasick::{AhoCorasick, MatchKind};

/// The compiled automaton plus the replacement table it indexes into.
///
/// `patterns[i]` is a fake and `replacements[i]` is its real value. Aho-Corasick reports the
/// pattern id of each match, which indexes `replacements` directly.
pub(crate) struct Restorer {
    ac: AhoCorasick,
    replacements: Vec<String>,
}

impl Restorer {
    /// Build from `(fake, real)` pairs. Returns `None` when there is nothing to restore, which
    /// saves constructing an automaton over an empty pattern set.
    pub(crate) fn build<'a, I>(pairs: I) -> Option<Restorer>
    where
        I: Iterator<Item = (&'a str, &'a str)>,
    {
        let (patterns, replacements): (Vec<&str>, Vec<String>) =
            pairs.map(|(f, r)| (f, r.to_string())).unzip();
        if patterns.is_empty() {
            return None;
        }
        // LeftmostLongest: if one fake is a prefix of another (a truncated PEM body, say), the
        // longer one wins, so restore is never left holding half a token.
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .expect("pattern set is small and well-formed");
        Some(Restorer { ac, replacements })
    }

    pub(crate) fn restore(&self, text: &str) -> String {
        self.ac.replace_all(text, &self.replacements)
    }
}
