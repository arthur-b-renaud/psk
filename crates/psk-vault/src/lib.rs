//! The PSK vault: a bijective `real <-> fake` map with deterministic, format-preserving fake
//! generation and exact restore.
//!
//! # What this crate guarantees
//!
//! - [`Vault::substitute`] is **deterministic**: the same real value under the same salt always
//!   derives the same fake, in this process and in every future one.
//! - [`Vault::restore`] is an **exact, whole-token** inverse of `substitute`.
//! - [`Vault::is_known_fake`] recognises a fake *even if this process never minted it*, which is
//!   what makes proxy restarts a non-event (see `salt.rs`).
//!
//! # Memory hygiene, scoped honestly (brief §7d)
//!
//! Read this before assuming PSK protects secrets in memory. It mostly does not, and pretending
//! otherwise would be worse than saying nothing.
//!
//! **What `zeroize` covers here:**
//! - The HMAC key stream's seed, derived block, and salt copy (`fake::KeyStream`'s `Drop`).
//!   These are transient scratch space holding a copy of the real secret's bytes.
//! - The vault's maps on `Drop`, best-effort (see below).
//!
//! **What it does not, and cannot, cover:**
//! - Real secrets live in plain heap `String`s inside `fwd`/`rev` for the entire session. That is
//!   the accepted, deliberate residency of real values: the vault cannot restore what it does not
//!   remember. Every incoming request buffer also holds them.
//! - `String` and `HashMap` reallocate as they grow. A `String` that outgrew its capacity leaves
//!   its old bytes behind on the heap, unreferenced and unwiped. `Drop` cannot reach those.
//! - Nothing here prevents the OS from paging the vault to swap, or from including it in a core
//!   dump.
//!
//! In short: `zeroize` narrows the window in which a *transient copy* of a secret sits in freed
//! memory. It does not make PSK's process memory safe to dump. A security tool with a false sense
//! of memory hygiene is worse than one with none.

pub mod checksum;
mod fake;
pub mod kind;
mod nearmiss;
mod restore;
pub mod salt;
pub mod sample;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use zeroize::Zeroize;

pub use kind::{MARKER, SecretKind};
pub use nearmiss::{MIN_PREFIX_LEN, NearMiss, NearMissReason};

use kind::{
    FAKE_CARD_BIN, FAKE_EMAIL_DOMAIN, FAKE_IBAN_COUNTRY, FAKE_IPV4_PREFIX, FAKE_IPV6_PREFIX,
};
use restore::Restorer;

/// Errors this crate can return. `thiserror` for a library crate, per the brief's conventions.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("cannot locate the PSK home directory: neither PSK_HOME nor HOME is set")]
    NoHome,
    #[error(
        "salt at {path} is {len} bytes, expected 32; refusing to mint a new one (that would invalidate every fake in the live conversation)"
    )]
    CorruptSalt { path: PathBuf, len: usize },
    #[error("could not gather randomness for a new salt: {0}")]
    Random(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// The guarded interior. Kept behind one `RwLock` so the map and its derived automaton mutate
/// together — a reader can never observe a fake in `rev` that the `Restorer` lacks.
#[derive(Default)]
struct Inner {
    /// `real -> fake`. Memoized so repeated substitutions of one secret skip the HMAC (brief §7b)
    /// and, more importantly, keep coreference intact for the LLM.
    fwd: HashMap<String, String>,
    /// `fake -> real`, the restore direction.
    rev: HashMap<String, String>,
    /// Rebuilt lazily, and only when `rev` gains an entry.
    restorer: Option<Restorer>,
}

impl Inner {
    fn ensure_restorer(&mut self) {
        if self.restorer.is_none() {
            self.restorer = Restorer::build(self.rev.iter().map(|(f, r)| (f.as_str(), r.as_str())));
        }
    }
}

/// The session vault.
///
/// `Send + Sync` by construction: Claude Code issues parallel background requests (subagents,
/// title generation) and the proxy shares one vault across all of them (brief §8).
pub struct Vault {
    salt: [u8; 32],
    inner: RwLock<Inner>,
}

impl Vault {
    /// Open the vault backed by the salt at `$PSK_HOME/salt` (default `~/.psk/salt`), creating
    /// the salt on first run.
    pub fn open() -> Result<Self, VaultError> {
        let dir = salt::psk_home()?;
        let salt = salt::load_or_create(&dir)?;
        Ok(Vault::with_salt(salt))
    }

    /// Build a vault over an explicit salt. Used by tests and by callers that manage the salt
    /// themselves.
    pub fn with_salt(salt: [u8; 32]) -> Self {
        Vault {
            salt,
            inner: RwLock::new(Inner::default()),
        }
    }

    /// Return the fake for `real`, minting and remembering it on first sight.
    ///
    /// Idempotent and deterministic. Takes `&self`, not `&mut self`, so the proxy can share one
    /// vault across concurrent requests behind an `Arc`.
    pub fn substitute(&self, real: &str, kind: SecretKind) -> String {
        // Fast path: a read lock suffices for a value we have already seen, which is the common
        // case once a conversation gets going and the history is resent each turn.
        if let Ok(inner) = self.inner.read()
            && let Some(existing) = inner.fwd.get(real)
        {
            return existing.clone(); // clone: the caller owns its fake, the map keeps its own.
        }

        // Derive outside the write lock. HMAC over a PEM block is not free, and holding the lock
        // across it would serialize every concurrent request behind one derivation.
        let mut derived = fake::derive(&self.salt, kind, real);

        // Safety net. A fake equal to its real value would make `restore` a no-op and send the
        // real secret upstream. `derive` never does this — the marker alone prevents it — but the
        // invariant matters too much to leave entirely to the generator.
        if derived == real {
            let tail = MARKER.len().min(derived.len());
            derived = format!("{MARKER}{}", &derived[tail..]);
        }

        let mut inner = match self.inner.write() {
            Ok(g) => g,
            // A poisoned lock means another thread panicked mid-substitution. We only ever insert,
            // so the maps are structurally sound; recovering beats taking the process down and
            // losing every mapping in the live conversation.
            Err(poisoned) => poisoned.into_inner(),
        };
        // Another thread may have raced us to the same secret between the two locks. Both derived
        // the same fake (determinism), so `entry` simply keeps whichever landed first.
        let fake = inner.fwd.entry(real.to_string()).or_insert(derived).clone();
        if inner.rev.insert(fake.clone(), real.to_string()).is_none() {
            inner.restorer = None; // the automaton no longer covers every fake
        }
        fake
    }

    /// Replace every known fake in `text` with its real value. Exact, whole-token, single pass.
    pub fn restore(&self, text: &str) -> String {
        // A write lock because the automaton may need rebuilding. Restore runs once per tool call
        // (the hook) or once per stream chunk, not in a hot inner loop, so this is not a
        // contention problem worth an `RwLock`-upgrade dance.
        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.ensure_restorer();
        match &inner.restorer {
            Some(r) => r.restore(text),
            None => text.to_string(), // nothing minted yet
        }
    }

    /// The anti-cascade guard (brief §7c). `Engine::substitute` must drop any candidate match
    /// this accepts, *before* substituting it.
    ///
    /// It accepts more than the values this process minted, on purpose:
    ///
    /// - In `restore_mode = "execution"`, the resent conversation history legitimately contains
    ///   fakes. Re-substituting one would map a fake to a fake and lose the real value forever.
    /// - After a proxy restart the maps are empty but the salt is not, so the history's fakes are
    ///   still fakes. The marker and the reserved spaces are what recognise them.
    pub fn is_known_fake(&self, s: &str) -> bool {
        if let Ok(inner) = self.inner.read()
            && inner.rev.contains_key(s)
        {
            return true;
        }
        carries_marker(s) || in_reserved_space(s)
    }

    /// Look for a *mangled* fake in `text` (brief §8b). Call this only at the execution boundary,
    /// after [`Vault::restore`] has had its exact pass.
    pub fn near_miss(&self, text: &str) -> Option<NearMiss> {
        let fakes: Vec<String> = match self.inner.read() {
            Ok(inner) => inner.rev.keys().cloned().collect(),
            Err(p) => p.into_inner().rev.keys().cloned().collect(),
        };
        nearmiss::detect(text, &fakes)
    }

    /// The length of the longest suffix of `s` that is a **proper prefix** of some known fake.
    ///
    /// This is the SSE restorer's hold-back length (brief §8). A fake can be split across two
    /// streamed deltas, so the restorer must retain a trailing window until it knows the window
    /// cannot grow into a fake.
    ///
    /// Answering "how many trailing bytes could still become a fake?" *exactly* is what keeps
    /// streaming responsive: the naive alternative — always hold back `longest_fake_len` bytes —
    /// would stall the stream by the length of a PEM block on every single delta. In practice this
    /// returns 0, so the delta is forwarded whole and immediately.
    ///
    /// Returns 0 when nothing has been minted, or when no suffix could extend into a fake.
    pub fn pending_fake_prefix_len(&self, s: &str) -> usize {
        let inner = match self.inner.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut best = 0usize;
        for fake in inner.rev.keys() {
            // A *proper* prefix: a complete fake at the tail was already handled by `restore`,
            // so `fake.len()` itself is excluded.
            let max_k = s.len().min(fake.len().saturating_sub(1));
            // Only look for something longer than the best we already have.
            for k in (best + 1..=max_k).rev() {
                let tail_start = s.len() - k;
                if s.is_char_boundary(tail_start)
                    && fake.as_bytes()[..k] == s.as_bytes()[tail_start..]
                {
                    best = k;
                    break;
                }
            }
        }
        best
    }

    /// Number of distinct secrets currently mapped. For `psk gain`: counters only, never content.
    pub fn len(&self) -> usize {
        self.inner.read().map(|i| i.fwd.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Case-insensitive, so a fake the LLM uppercased is still recognised as a fake and never
/// re-substituted. The near-miss detector, not this guard, is what complains about the mangling.
fn carries_marker(s: &str) -> bool {
    s.to_ascii_lowercase()
        .contains(&MARKER.to_ascii_lowercase())
}

/// The digit-only and network kinds carry no alphabetic marker; they live in reserved spaces
/// instead, which serve the same "this is not a live value" purpose (brief §7b).
fn in_reserved_space(s: &str) -> bool {
    let compact: Vec<u8> = s.bytes().filter(u8::is_ascii_alphanumeric).collect();
    let compact_str = String::from_utf8_lossy(&compact);

    // The checksum requirement is what keeps this from firing on ordinary text: an arbitrary
    // string starting `411111` is not Luhn-valid, and one starting `ZZ` is not mod-97-valid.
    if compact_str.starts_with(FAKE_CARD_BIN) && checksum::luhn_valid(&compact) {
        return true;
    }
    if compact_str.starts_with(FAKE_IBAN_COUNTRY) && checksum::iban_valid(&compact_str) {
        return true;
    }
    s.starts_with(FAKE_IPV4_PREFIX)
        || s.starts_with(FAKE_IPV6_PREFIX)
        || s.ends_with(FAKE_EMAIL_DOMAIN)
}

/// Best-effort wipe of the real values the vault necessarily held. See the honesty block at the
/// top of this file for what this achieves and what it does not.
impl Drop for Vault {
    fn drop(&mut self) {
        self.salt.zeroize();
        if let Ok(mut inner) = self.inner.write() {
            for (mut k, mut v) in inner.fwd.drain() {
                k.zeroize();
                v.zeroize();
            }
            for (mut k, mut v) in inner.rev.drain() {
                k.zeroize();
                v.zeroize();
            }
        }
    }
}
