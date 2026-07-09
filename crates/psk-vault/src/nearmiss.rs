//! Near-miss detection (brief §8b) — used at the execution boundary only.
//!
//! The LLM sometimes echoes an *altered* fake: it uppercases it, truncates it, re-wraps a PEM
//! body across different line lengths. Exact restore misses it, and the result is a
//! plausible-looking, checksum-valid fake written silently into a real config file. That is
//! worse than not running PSK at all.
//!
//! So at the `PreToolUse` hook, after exact restore, whatever *still* looks like a fake is a
//! near miss and the hook blocks loudly. Everywhere else (the proxy stream, `psk scan`) restore
//! stays exact — the execution boundary is the only place where "almost" becomes damage, so it
//! is the only place that pays the cost of this scan.

use crate::kind::{FAKE_CARD_BIN, FAKE_IBAN_COUNTRY, MARKER};

/// The length of the fake-identifying window used by [`NearMissReason::TruncatedPrefix`].
///
/// Below this, a coincidental collision with ordinary text becomes plausible and the hook would
/// block the agent for nothing.
pub const MIN_PREFIX_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NearMissReason {
    /// Same characters as a known fake, different casing.
    CaseMangled,
    /// Starts with at least [`MIN_PREFIX_LEN`] characters of a known fake, then diverges.
    TruncatedPrefix,
    /// Carries the reserved marker (or sits in a reserved fake space) but matches no known fake.
    /// Typically a fake minted by an earlier proxy process, or one the LLM rewrote entirely.
    MarkerResidue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearMiss {
    pub reason: NearMissReason,
    /// The mangled text as it appears in the tool input, for the block message.
    pub suspect: String,
    /// The known fake it resembles, when one could be identified.
    pub resembles: Option<String>,
}

/// Scan `text` (already exact-restored) for anything that still looks like a fake.
///
/// `fakes` is the vault's known-fake set. Returns the first hit; the hook only needs one reason
/// to block.
pub(crate) fn detect(text: &str, fakes: &[String]) -> Option<NearMiss> {
    let lower = text.to_ascii_lowercase();

    for fake in fakes {
        // An exact match is not a near miss — exact restore already had its chance, and a fake
        // that survives it verbatim means the caller chose not to restore this span.
        if text.contains(fake.as_str()) {
            continue;
        }
        let fake_lower = fake.to_ascii_lowercase();
        if let Some(at) = lower.find(&fake_lower) {
            return Some(NearMiss {
                reason: NearMissReason::CaseMangled,
                suspect: text[at..at + fake.len()].to_string(),
                resembles: Some(fake.clone()),
            });
        }
        if let Some(window) = signature_window(fake)
            && let Some(at) = text.find(window)
        {
            return Some(NearMiss {
                reason: NearMissReason::TruncatedPrefix,
                suspect: token_around(text, at),
                resembles: Some(fake.clone()),
            });
        }
    }

    // Nothing matched a *known* fake. A marker or reserved-space residue still means a fake got
    // here from somewhere — a previous proxy process, most likely — and must not be executed.
    if let Some(at) = lower.find(&MARKER.to_ascii_lowercase()) {
        return Some(NearMiss {
            reason: NearMissReason::MarkerResidue,
            suspect: token_around(text, at),
            resembles: None,
        });
    }
    first_reserved_residue(text).map(|suspect| NearMiss {
        reason: NearMissReason::MarkerResidue,
        suspect,
        resembles: None,
    })
}

/// The `MIN_PREFIX_LEN` characters of `fake` starting at its marker.
///
/// Anchoring at the marker rather than at offset 0 is what keeps this rule usable. A PEM fake
/// begins `-----BEGIN PRIVATE KEY-----`, which every *real* private key on earth also begins
/// with: matching on the fake's first twelve characters would block the agent on any legitimate
/// key file it wrote. The marker sits at the head of the generated body, so the window always
/// straddles high-entropy, fake-specific characters.
///
/// Returns `None` for the digit-only and network kinds, which carry no marker. Those are covered
/// by [`first_reserved_residue`] instead.
fn signature_window(fake: &str) -> Option<&str> {
    // Case-insensitive search, because the email fake lowercases its marker.
    let at = fake
        .to_ascii_lowercase()
        .find(&MARKER.to_ascii_lowercase())?;
    // `get` rather than slicing: fakes are ASCII by construction, but this returns `None` instead
    // of panicking if that ever stops being true.
    fake.get(at..at + MIN_PREFIX_LEN)
}

/// The first reserved-space residue in `text`, for the digit-only kinds that cannot carry the
/// alphabetic marker.
///
/// Deliberately conservative. A bare `192.0.2.x` or `user@example.com` in a tool input is far
/// more likely to be documentation the user actually meant than an unrestored fake, so the IP and
/// email spaces are *not* treated as residues — blocking on them would make the hook unusable.
/// Only the card BIN and the unassigned IBAN country are, and only when the value also passes its
/// checksum, which arbitrary text does not.
fn first_reserved_residue(text: &str) -> Option<String> {
    text.split(|c: char| c.is_whitespace() || c == '"' || c == ',')
        .find(|tok| {
            let compact: Vec<u8> = tok.bytes().filter(u8::is_ascii_alphanumeric).collect();
            let s = String::from_utf8_lossy(&compact);
            (s.starts_with(FAKE_CARD_BIN) && crate::checksum::luhn_valid(&compact))
                || (s.starts_with(FAKE_IBAN_COUNTRY) && crate::checksum::iban_valid(&s))
        })
        .map(str::to_string)
}

/// The whitespace-delimited token containing byte offset `at`, for a useful block message.
fn token_around(text: &str, at: usize) -> String {
    let start = text[..at].rfind(char::is_whitespace).map_or(0, |i| i + 1);
    let end = text[at..]
        .find(char::is_whitespace)
        .map_or(text.len(), |i| at + i);
    text[start..end].to_string()
}
