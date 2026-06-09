use crate::span::Span;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// Counters-only statistics. Never stores prompt content.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Stats {
    pub prompts_scanned: u64,
    pub total_entities_redacted: u64,
    pub entities_by_type: HashMap<String, u64>,
    pub total_chars_hidden: u64,
    /// Cumulative redaction latency in microseconds.
    pub total_latency_us: u64,
    /// Last updated timestamp.
    pub last_updated: Option<String>,
}

/// Thread-safe stats collector that persists to `~/.psk/stats.json`.
pub struct StatsCollector {
    inner: Mutex<Stats>,
}

impl StatsCollector {
    pub fn new() -> Self {
        let stats = Self::load().unwrap_or_default();
        Self {
            inner: Mutex::new(stats),
        }
    }

    /// Record a scan with detected spans.
    pub fn record_scan(&self, spans: &[Span]) {
        self.record_scan_with_latency(spans, 0);
    }

    /// Record a scan with detected spans and latency in microseconds.
    pub fn record_scan_with_latency(&self, spans: &[Span], latency_us: u64) {
        let mut stats = self.inner.lock().unwrap();
        stats.prompts_scanned += 1;
        stats.total_entities_redacted += spans.len() as u64;
        stats.total_latency_us += latency_us;
        stats.last_updated = Some(Utc::now().to_rfc3339());

        for span in spans {
            let key = span.entity.to_string();
            stats.total_chars_hidden += span.len() as u64;
            *stats.entities_by_type.entry(key).or_insert(0) += 1;
        }

        // Best-effort persist
        let _ = Self::save(&stats);
    }

    /// Get a snapshot of current stats.
    pub fn snapshot(&self) -> Stats {
        let stats = self.inner.lock().unwrap();
        // Manually clone since Stats doesn't derive Clone
        Stats {
            prompts_scanned: stats.prompts_scanned,
            total_entities_redacted: stats.total_entities_redacted,
            entities_by_type: stats.entities_by_type.clone(),
            total_chars_hidden: stats.total_chars_hidden,
            total_latency_us: stats.total_latency_us,
            last_updated: stats.last_updated.clone(),
        }
    }

    fn stats_path() -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".psk").join("stats.json"))
    }

    fn load() -> Option<Stats> {
        let path = Self::stats_path()?;
        let data = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }

    fn save(stats: &Stats) -> anyhow::Result<()> {
        if let Some(path) = Self::stats_path() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let data = serde_json::to_string_pretty(stats)?;
            std::fs::write(path, data)?;
        }
        Ok(())
    }
}

impl Default for StatsCollector {
    fn default() -> Self {
        Self::new()
    }
}
