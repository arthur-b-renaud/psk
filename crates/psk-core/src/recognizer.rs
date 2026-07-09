//! The `Recognizer` seam (brief §5).
//!
//! A *trait* is Rust's interface: any type implementing it can be used wherever a `Recognizer` is
//! expected. The regex layer is one implementation; another detector could be a second. The proxy
//! and the engine only ever see this trait, so adding a detector never touches them.

use psk_vault::SecretKind;

/// A detected span. Byte offsets into the scanned text, always on UTF-8 boundaries.
///
/// The brief writes this as `Match { start, end, kind, value: &str }`. The borrowed `value` is
/// dropped here: it would tie every `Match` to the lifetime of the haystack, which forces a
/// lifetime parameter through `Recognizer`, `Engine`, and every implementation, in exchange for a
/// slice the caller can recover with `&text[m.start..m.end]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    pub start: usize,
    pub end: usize,
    pub kind: SecretKind,
}

impl Match {
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// The matched text. Panics only if `text` is not the haystack this match came from.
    pub fn value<'t>(&self, text: &'t str) -> &'t str {
        &text[self.start..self.end]
    }

    /// Does this match share any byte with `other`?
    pub fn overlaps(&self, other: &Match) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Anything that can find secrets in text.
///
/// `Send + Sync` because the proxy shares one engine across Claude Code's parallel background
/// requests (brief §8).
pub trait Recognizer: Send + Sync {
    fn scan(&self, text: &str) -> Vec<Match>;
}

/// The M1 regex recognizer, wrapping `psk-secrets`.
pub struct RegexRecognizer {
    cfg: psk_secrets::ScanConfig,
}

impl RegexRecognizer {
    pub fn new(cfg: psk_secrets::ScanConfig) -> Self {
        RegexRecognizer { cfg }
    }
}

impl Default for RegexRecognizer {
    fn default() -> Self {
        RegexRecognizer::new(psk_secrets::ScanConfig::default())
    }
}

impl Recognizer for RegexRecognizer {
    fn scan(&self, text: &str) -> Vec<Match> {
        psk_secrets::scan(text, &self.cfg)
            .into_iter()
            .map(|m| Match {
                start: m.start,
                end: m.end,
                kind: m.kind,
            })
            .collect()
    }
}
