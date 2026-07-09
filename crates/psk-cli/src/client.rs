//! The blocking HTTP client the short-lived `psk hook` and `psk scan` processes use to reach the
//! running proxy's `/restore` endpoint, so hook and proxy share one live vault.

use psk_proxy::hook::{NearMiss, RestoreClient, RestoreUnavailable, Restored};
use serde_json::Value;

/// A restore client backed by the proxy over localhost HTTP.
pub struct HttpRestore {
    client: reqwest::blocking::Client,
    restore_url: String,
    health_url: String,
}

impl HttpRestore {
    /// Point at a proxy bound to `addr` (e.g. `127.0.0.1:8787`).
    pub fn new(addr: &std::net::SocketAddr) -> Self {
        HttpRestore {
            // A tight timeout: the hook is in the critical path of every tool call, and a hung
            // proxy must degrade to fail-open quickly rather than stall the agent.
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("a blocking client with a timeout always builds"),
            restore_url: format!("http://{addr}/restore"),
            health_url: format!("http://{addr}/health"),
        }
    }

    /// Is the proxy answering? Used by `psk scan` to decide whether to run in full or degraded mode.
    pub fn is_up(&self) -> bool {
        self.client
            .get(&self.health_url)
            .send()
            .is_ok_and(|r| r.status().is_success())
    }
}

impl RestoreClient for HttpRestore {
    fn restore(&self, text: &str) -> Result<Restored, RestoreUnavailable> {
        // Any transport failure is the fail-open signal. The `?`-less mapping keeps "proxy down"
        // strictly separate from "restored, but suspicious" — conflating them would either block
        // the agent when PSK is merely absent, or leak a near miss when it is present.
        let resp = self
            .client
            .post(&self.restore_url)
            .json(&text)
            .send()
            .map_err(|_| RestoreUnavailable)?;
        if !resp.status().is_success() {
            return Err(RestoreUnavailable);
        }
        let body: Value = resp.json().map_err(|_| RestoreUnavailable)?;

        let restored = body
            .get("restored")
            .and_then(Value::as_str)
            .ok_or(RestoreUnavailable)?
            .to_string();

        let near_miss = body
            .get("near_miss")
            .filter(|v| !v.is_null())
            .map(|nm| NearMiss {
                reason: nm
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                suspect: nm
                    .get("suspect")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                field: String::new(), // the field name is added by the hook layer, not the proxy
            });

        Ok(Restored {
            text: restored,
            near_miss,
        })
    }
}
