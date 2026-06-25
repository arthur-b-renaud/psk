//! Reversible-tokenization vault.
//!
//! When a secret is redacted with [`crate::RedactionAction::Tokenize`], the vault swaps it for a
//! stable, opaque token (`__PSK_<hex>__`) and remembers the mapping. Outbound provider traffic
//! only ever sees the token; the original value can be restored later — e.g. by the Claude Code
//! `PreToolUse` restore hook when the agent writes the value back into a local file.
//!
//! Security model: the vault lives only in the running daemon's memory and dies with it
//! (session-scoped, never persisted to disk). The token itself is just a handle — it reveals
//! nothing about the secret, and restoration is impossible without this in-memory map. The salt is
//! minted per session so tokens are not stable across daemon restarts.

use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Matches any PSK token. `8,` allows longer tokens minted to dodge a rare collision.
static TOKEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"__PSK_[0-9a-f]{8,}__").unwrap());

#[derive(Default)]
struct VaultInner {
    /// secret -> token (for deterministic reuse within a session)
    fwd: HashMap<String, String>,
    /// token -> secret (for restoration)
    rev: HashMap<String, String>,
}

/// In-memory, session-scoped store mapping tokens to their original secret values.
pub struct Vault {
    salt: [u8; 16],
    inner: RwLock<VaultInner>,
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl Vault {
    /// Create an empty vault with a freshly minted per-session salt.
    pub fn new() -> Self {
        Self {
            salt: mint_salt(),
            inner: RwLock::new(VaultInner::default()),
        }
    }

    /// Whether this text contains at least one PSK token.
    pub fn contains_token(text: &str) -> bool {
        TOKEN_RE.is_match(text)
    }

    /// Replace `secret` with a stable token, recording the mapping. Identical secrets map to the
    /// same token within a session, so re-scrubbing already-tokenized conversation history is a
    /// no-op.
    pub fn tokenize(&self, entity: &str, secret: &str) -> String {
        // Fast path: already seen this secret.
        if let Some(tok) = self.inner.read().unwrap().fwd.get(secret) {
            return tok.clone();
        }

        let mut inner = self.inner.write().unwrap();
        // Re-check under the write lock (another thread may have inserted it).
        if let Some(tok) = inner.fwd.get(secret) {
            return tok.clone();
        }

        // Derive a token from the salted hash of (entity, secret). Probe with a longer hex prefix
        // on the rare event the short token already maps to a *different* secret.
        let digest = self.digest_hex(entity, secret);
        let mut len = 8;
        let token = loop {
            let candidate = format!("__PSK_{}__", &digest[..len]);
            match inner.rev.get(&candidate) {
                Some(existing) if existing != secret => {
                    len += 4;
                    if len > digest.len() {
                        // Astronomically unlikely; fall back to a length-tagged token.
                        break format!("__PSK_{}{:x}__", digest, inner.rev.len());
                    }
                }
                _ => break candidate,
            }
        };

        inner.fwd.insert(secret.to_string(), token.clone());
        inner.rev.insert(token.clone(), secret.to_string());
        token
    }

    /// Restore every known token in `text` to its original secret. Unknown tokens (e.g. from a
    /// previous daemon session) are left untouched.
    pub fn detokenize(&self, text: &str) -> String {
        if !TOKEN_RE.is_match(text) {
            return text.to_string();
        }
        let inner = self.inner.read().unwrap();
        TOKEN_RE
            .replace_all(text, |caps: &regex::Captures| {
                let tok = &caps[0];
                inner
                    .rev
                    .get(tok)
                    .cloned()
                    .unwrap_or_else(|| tok.to_string())
            })
            .into_owned()
    }

    /// Number of distinct secrets currently held.
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().rev.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn digest_hex(&self, entity: &str, secret: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.salt);
        hasher.update(entity.as_bytes());
        hasher.update(b":");
        hasher.update(secret.as_bytes());
        let out = hasher.finalize();
        out.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Mint a per-session salt. Not used as a cryptographic key (the token is only a handle — the vault
/// map is the sole path back to a secret), so a time/pid-derived seed is sufficient to keep tokens
/// distinct across sessions and free of cross-secret collisions.
fn mint_salt() -> [u8; 16] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(pid.to_le_bytes());
    let out = hasher.finalize();
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&out[..16]);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_secret() {
        let v = Vault::new();
        let tok = v.tokenize("OPENAI_API_KEY", "sk-proj-abc123");
        assert!(tok.starts_with("__PSK_"));
        assert!(tok.ends_with("__"));
        assert_ne!(tok, "sk-proj-abc123");
        assert_eq!(v.detokenize(&tok), "sk-proj-abc123");
    }

    #[test]
    fn same_secret_same_token() {
        let v = Vault::new();
        let a = v.tokenize("X", "shhh");
        let b = v.tokenize("X", "shhh");
        assert_eq!(a, b);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detokenize_restores_within_surrounding_text() {
        let v = Vault::new();
        let tok = v.tokenize("AWS", "AKIAIOSFODNN7EXAMPLE");
        let line = format!("AWS_KEY={}\n", tok);
        assert_eq!(v.detokenize(&line), "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n");
    }

    #[test]
    fn unknown_tokens_pass_through() {
        let v = Vault::new();
        // Looks like a token but was never minted by this vault.
        assert_eq!(v.detokenize("__PSK_deadbeef__"), "__PSK_deadbeef__");
    }

    #[test]
    fn detokenize_is_noop_without_tokens() {
        let v = Vault::new();
        assert_eq!(
            v.detokenize("plain text, no tokens"),
            "plain text, no tokens"
        );
    }
}
