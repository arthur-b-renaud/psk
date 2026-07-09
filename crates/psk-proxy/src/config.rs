//! `~/.psk/config.toml`.

use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Where fakes are turned back into real secrets (brief §2b).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RestoreMode {
    /// **Default.** The proxy substitutes outbound only and never restores the response. Restore
    /// happens exclusively at the `PreToolUse` hook, the instant before a tool executes.
    ///
    /// Real secrets therefore never reach Claude Code's transcripts (`~/.claude/projects/*.jsonl`)
    /// or the terminal scrollback. The user sees fakes on screen, which is the feature: what you
    /// see is what the provider saw.
    #[default]
    Execution,
    /// The proxy also restores fakes in the streamed SSE response, for agents with no hook
    /// mechanism. **The agent then persists real secrets to its own local transcripts.**
    Full,
}

impl RestoreMode {
    pub fn restores_response(self) -> bool {
        self == RestoreMode::Full
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub bind: SocketAddr,
    /// The real provider. Overridable so tests can point at a mock upstream.
    pub upstream: String,
    pub restore_mode: RestoreMode,
    /// IP and email rules ship disabled (brief §6b).
    pub enable_network_rules: bool,
    /// How many requests the inspector's in-memory ring buffer keeps. Content, never disk.
    pub event_buffer: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind: ([127, 0, 0, 1], 8787).into(), // localhost only, always
            upstream: "https://api.anthropic.com".to_string(),
            restore_mode: RestoreMode::default(),
            enable_network_rules: false,
            event_buffer: 500,
        }
    }
}

impl Config {
    /// Read `<psk_home>/config.toml`, falling back to defaults when it does not exist.
    ///
    /// A malformed config is an error rather than a silent fallback: defaulting `restore_mode`
    /// back to `execution` because of a typo would be a surprising downgrade, and defaulting it to
    /// `full` would be a surprising leak.
    pub fn load(dir: &Path) -> Result<Config, ConfigError> {
        let path = dir.join("config.toml");
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).map_err(|e| ConfigError::Parse {
                path: path.display().to_string(),
                source: e,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(ConfigError::Io(e)),
        }
    }

    pub fn scan_config(&self) -> psk_core::ScanConfig {
        psk_core::ScanConfig {
            enable_network_rules: self.enable_network_rules,
            ..Default::default()
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not parse {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_is_the_default_restore_mode() {
        let c = Config::default();
        assert_eq!(c.restore_mode, RestoreMode::Execution);
        assert!(!c.restore_mode.restores_response());
        assert!(!c.enable_network_rules, "network rules ship disabled");
        assert!(
            c.bind.ip().is_loopback(),
            "the proxy must bind localhost only"
        );
    }

    #[test]
    fn missing_config_file_yields_defaults() {
        let dir = std::env::temp_dir().join("psk-config-absent");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            Config::load(&dir).unwrap().restore_mode,
            RestoreMode::Execution
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_mode_round_trips_through_toml() {
        let parsed: Config = toml::from_str("restore_mode = \"full\"").unwrap();
        assert_eq!(parsed.restore_mode, RestoreMode::Full);
        assert!(parsed.restore_mode.restores_response());
        // Unspecified fields keep their defaults.
        assert_eq!(parsed.upstream, "https://api.anthropic.com");
    }

    /// A typo must not silently pick a mode the user did not ask for, in either direction.
    #[test]
    fn a_malformed_config_is_an_error() {
        assert!(toml::from_str::<Config>("restore_mode = \"excution\"").is_err());
    }
}
