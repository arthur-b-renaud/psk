//! Counters, flushed to `~/.psk/stats.json`. What `psk gain` reads.
//!
//! **Counters only, never content.** This is the one PSK file that grows, and the disk ban (brief
//! §14) says nothing about a prompt or a response may ever be written to it. Not a fragment, not a
//! hash of one.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use psk_core::{SecretKind, Summary};
use serde::{Deserialize, Serialize};

/// The serialised shape of `stats.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub prompts_scanned: u64,
    /// Keyed by the `Debug` name of the kind, so the file stays readable and survives a reordering
    /// of the enum.
    pub entities_substituted: BTreeMap<String, u64>,
    pub chars_hidden: u64,
    pub fakes_restored: u64,
    /// Requests where a fake reached the hook but no known fake matched exactly.
    pub fakes_never_restored: u64,
    pub near_misses_blocked: u64,
    pub avg_latency_ms: u64,
    /// Internal: `avg_latency_ms` is derived from these, but keeping them makes the average
    /// resumable across restarts instead of resetting to the first request's latency.
    latency_total_ms: u64,
    latency_samples: u64,
}

/// Live counters. `Send + Sync`; the proxy shares one across all requests.
#[derive(Default)]
pub struct Stats {
    inner: Mutex<StatsSnapshot>,
}

impl Stats {
    pub fn new() -> Self {
        Stats::default()
    }

    /// Seed from a previous run so `psk gain` reports lifetime totals, not per-process ones.
    pub fn load(dir: &Path) -> Self {
        let path = dir.join("stats.json");
        let snapshot = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Stats {
            inner: Mutex::new(snapshot),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, StatsSnapshot> {
        // Counters are not worth crashing over: a poisoned lock still has a valid snapshot,
        // because every mutation below is a simple increment.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn record_request(&self, summary: &Summary, latency_ms: u64) {
        let mut s = self.lock();
        s.prompts_scanned += 1;
        for (kind, n) in &summary.by_kind {
            *s.entities_substituted
                .entry(format!("{kind:?}"))
                .or_insert(0) += *n as u64;
        }
        s.chars_hidden += summary.chars_hidden as u64;
        s.latency_total_ms += latency_ms;
        s.latency_samples += 1;
        s.avg_latency_ms = s.latency_total_ms / s.latency_samples.max(1);
    }

    pub fn record_restored(&self, n: u64) {
        self.lock().fakes_restored += n;
    }

    pub fn record_near_miss(&self) {
        self.lock().near_misses_blocked += 1;
    }

    pub fn record_unrestored(&self) {
        self.lock().fakes_never_restored += 1;
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        self.lock().clone()
    }

    /// Write `stats.json` atomically: a crash mid-write must not leave a truncated file that the
    /// next `Stats::load` silently parses as zeroes.
    pub fn flush(&self, dir: &Path) -> std::io::Result<()> {
        let snapshot = self.snapshot();
        let json = serde_json::to_string_pretty(&snapshot)?;
        let tmp = dir.join("stats.json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(tmp, dir.join("stats.json"))
    }

    /// The count of entities, for the per-kind check in tests and `psk gain`.
    pub fn kind_count(&self, kind: SecretKind) -> u64 {
        self.lock()
            .entities_substituted
            .get(&format!("{kind:?}"))
            .copied()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary_of(kind: SecretKind, n: usize, chars: usize) -> Summary {
        let mut s = Summary::default();
        s.by_kind.insert(kind, n);
        s.chars_hidden = chars;
        s
    }

    #[test]
    fn counters_accumulate_per_kind() {
        let s = Stats::new();
        s.record_request(&summary_of(SecretKind::AwsAccessKeyId, 2, 40), 10);
        s.record_request(&summary_of(SecretKind::AwsAccessKeyId, 1, 20), 20);

        let snap = s.snapshot();
        assert_eq!(snap.prompts_scanned, 2);
        assert_eq!(s.kind_count(SecretKind::AwsAccessKeyId), 3);
        assert_eq!(snap.chars_hidden, 60);
        assert_eq!(snap.avg_latency_ms, 15);
    }

    /// The average must survive a restart rather than resetting to the next request's latency.
    #[test]
    fn averages_resume_across_a_reload() {
        let dir = std::env::temp_dir().join(format!("psk-stats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let s = Stats::new();
        s.record_request(&summary_of(SecretKind::GithubPat, 1, 10), 100);
        s.record_request(&summary_of(SecretKind::GithubPat, 1, 10), 200);
        s.flush(&dir).unwrap();

        let reloaded = Stats::load(&dir);
        reloaded.record_request(&summary_of(SecretKind::GithubPat, 1, 10), 300);

        let snap = reloaded.snapshot();
        assert_eq!(snap.prompts_scanned, 3);
        assert_eq!(snap.avg_latency_ms, 200, "(100+200+300)/3");
        assert_eq!(reloaded.kind_count(SecretKind::GithubPat), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The disk ban: whatever ends up in `stats.json` must contain no prompt content.
    #[test]
    fn the_snapshot_serialises_only_counters() {
        let s = Stats::new();
        s.record_request(&summary_of(SecretKind::AwsSecretKey, 1, 40), 5);
        s.record_near_miss();

        let json = serde_json::to_string(&s.snapshot()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        for (_key, value) in parsed.as_object().unwrap() {
            // Every leaf is a number or a map of numbers. No strings, so no content.
            let numeric = value.is_u64()
                || value
                    .as_object()
                    .is_some_and(|m| m.values().all(serde_json::Value::is_u64));
            assert!(numeric, "non-numeric value in stats.json: {value}");
        }
    }
}
