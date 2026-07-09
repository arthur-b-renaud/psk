//! The `PreToolUse` restore hook (brief §8b): restore loudly, fail open quietly.
//!
//! This runs as a short-lived process Claude Code spawns before every `Bash`/`Edit`/`Write`. It is
//! the **primary** restore point in `restore_mode = "execution"` (the proxy never restores the
//! response there) and the safety net in `full` mode.
//!
//! Two rules, and conflating them would break the tool:
//!
//! - **Fail open on infrastructure.** If the proxy is down, pass the input through unchanged and
//!   exit 0. Never block the agent because PSK is not running.
//! - **Fail closed on detection.** If a restored field still *looks* like a fake — a near miss —
//!   block (exit 2) with a diagnostic. A mangled, checksum-valid fake written into a real config
//!   file is worse than no tool at all.
//!
//! This module is pure logic over a restore client; the wire format with Claude Code lives in the
//! CLI, and the transport lives behind [`RestoreClient`]. Both are swapped for fakes in tests.

use serde_json::Value;

/// The restore side of the proxy, as the hook needs it. A trait so tests inject a fake vault
/// without a running server, and the CLI injects the real HTTP client.
pub trait RestoreClient {
    /// Restore `text`, returning the restored string and any near-miss diagnostic. `Err` means the
    /// proxy is unreachable — the caller must then fail *open*.
    fn restore(&self, text: &str) -> Result<Restored, RestoreUnavailable>;
}

/// A restored string plus the near-miss verdict the proxy computed over it.
#[derive(Debug, Clone)]
pub struct Restored {
    pub text: String,
    pub near_miss: Option<NearMiss>,
}

/// The proxy could not be reached. Distinct from "restored, but suspicious": this is the fail-open
/// condition, and it must never be confused with a near miss.
#[derive(Debug, Clone)]
pub struct RestoreUnavailable;

/// A mangled fake caught at the execution boundary. Enough to name the offending field and value.
#[derive(Debug, Clone)]
pub struct NearMiss {
    pub reason: String,
    pub suspect: String,
    pub field: String,
}

/// The hook's decision. The CLI turns each variant into a specific Claude Code wire response.
///
/// The three variants map to three distinct responses because the wire protocol distinguishes
/// them (contract verified against the Claude Code hooks reference):
///
/// - `Rewrite` → exit 0 with `hookSpecificOutput.updatedInput` **and**
///   `permissionDecision: "allow"`. `updatedInput` replaces `tool_input` wholesale, so it carries
///   every field, not a patch. Omitting `"allow"` silently drops the rewrite — the single most
///   dangerous mistake here, since the tool would then run on the fake.
/// - `PassThrough` → exit 0 with **empty stdout**. Nothing changed, so there is nothing to apply,
///   and emitting `updatedInput` would need a newer CLI for no benefit. This is also the
///   fail-open response when the proxy is down.
/// - `Block` → exit 2 with the message on stderr. Universal across CLI versions, and what the
///   brief specifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// A field was restored. Emit the full input as `updatedInput`.
    Rewrite { tool_input: Value },
    /// Run the tool unchanged: nothing needed restoring, the tool is not one PSK handles, or the
    /// proxy is down (fail open).
    PassThrough,
    /// Block the tool. Exit 2, message to the agent.
    Block { message: String },
}

/// Which string fields of each tool's input carry values worth restoring.
///
/// A deliberately small, explicit list rather than "every string": the hook must restore what the
/// tool will *act on*, and a `Write` to `file_path` is a path, not content. Restoring the wrong
/// field is how you corrupt a filename.
fn fields_for(tool: &str) -> &'static [&'static str] {
    match tool {
        // The command line the shell will run.
        "Bash" => &["command"],
        // `Write` persists `content` to `file_path`; only the content is data.
        "Write" => &["content"],
        // `Edit`/`MultiEdit` replace `old_string` with `new_string`. A fake can appear in either:
        // the model may target a line that (in the fakes it sees) contains one, and the
        // replacement it writes may contain one too.
        "Edit" | "MultiEdit" => &["old_string", "new_string"],
        _ => &[],
    }
}

/// Decide what to do with one `PreToolUse` invocation.
///
/// `tool` is the tool name; `tool_input` is its input object. Returns the (possibly rewritten)
/// input to run, or a block.
pub fn decide(client: &impl RestoreClient, tool: &str, tool_input: &Value) -> Decision {
    let fields = fields_for(tool);
    if fields.is_empty() {
        // A tool PSK does not restore (Read, Grep, a custom tool). Nothing to do.
        return Decision::PassThrough;
    }

    let mut restored_input = tool_input.clone();
    let mut changed = false;

    for field in fields {
        let Some(original) = tool_input.get(*field).and_then(Value::as_str) else {
            continue; // field absent or not a string; nothing to restore
        };

        match client.restore(original) {
            Ok(r) => {
                // Fail closed: a near miss on the boundary is exactly the case that must not slip
                // through. Block before writing the mangled value anywhere.
                if let Some(nm) = r.near_miss {
                    return Decision::Block {
                        message: block_message(tool, field, &nm),
                    };
                }
                if r.text != original {
                    restored_input[*field] = Value::String(r.text);
                    changed = true;
                }
            }
            // Fail open: the proxy is down. Passing the input through unchanged is correct — in
            // `execution` mode the field still holds a fake, which is inert, not a real secret.
            Err(RestoreUnavailable) => return Decision::PassThrough,
        }
    }

    if changed {
        Decision::Rewrite {
            tool_input: restored_input,
        }
    } else {
        // No fake was present. Emit nothing rather than a no-op `updatedInput`.
        Decision::PassThrough
    }
}

fn block_message(tool: &str, field: &str, nm: &NearMiss) -> String {
    format!(
        "psk: blocked {tool} — the `{field}` field contains what looks like an altered PSK fake \
         ({reason}): {suspect:?}. Exact restore could not turn it back into the real value, and \
         writing a mangled fake into a real target is worse than not running. Re-request the \
         value from the model verbatim, or run `psk scan` on the field to inspect it.",
        reason = nm.reason,
        suspect = nm.suspect,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A scripted restore client: maps known fakes to reals, flags configured near-misses, or
    /// reports itself down.
    struct FakeProxy {
        down: bool,
        map: Vec<(&'static str, &'static str)>,
        near_miss_on: Option<&'static str>,
    }

    impl FakeProxy {
        fn up() -> Self {
            FakeProxy {
                down: false,
                map: vec![("AKIAQPSK0000000000FAKE", "AKIA1234567890ABCDEF")],
                near_miss_on: None,
            }
        }
    }

    impl RestoreClient for FakeProxy {
        fn restore(&self, text: &str) -> Result<Restored, RestoreUnavailable> {
            if self.down {
                return Err(RestoreUnavailable);
            }
            if let Some(needle) = self.near_miss_on
                && text.contains(needle)
            {
                return Ok(Restored {
                    text: text.to_string(),
                    near_miss: Some(NearMiss {
                        reason: "CaseMangled".into(),
                        suspect: needle.to_string(),
                        field: String::new(),
                    }),
                });
            }
            let mut out = text.to_string();
            for (fake, real) in &self.map {
                out = out.replace(fake, real);
            }
            Ok(Restored {
                text: out,
                near_miss: None,
            })
        }
    }

    fn rewritten(d: Decision) -> Value {
        match d {
            Decision::Rewrite { tool_input } => tool_input,
            other => panic!("expected Rewrite, got {other:?}"),
        }
    }

    #[test]
    fn bash_command_is_restored() {
        let input = json!({"command": "aws configure set key AKIAQPSK0000000000FAKE"});
        let out = rewritten(decide(&FakeProxy::up(), "Bash", &input));
        assert_eq!(out["command"], "aws configure set key AKIA1234567890ABCDEF");
    }

    #[test]
    fn write_restores_content_but_never_the_path() {
        let input = json!({
            "file_path": "/etc/AKIAQPSK0000000000FAKE.conf",
            "content": "key = AKIAQPSK0000000000FAKE"
        });
        let out = rewritten(decide(&FakeProxy::up(), "Write", &input));
        assert_eq!(out["content"], "key = AKIA1234567890ABCDEF");
        // The path is left exactly as the model wrote it. Restoring it would rename the file.
        assert_eq!(out["file_path"], "/etc/AKIAQPSK0000000000FAKE.conf");
    }

    #[test]
    fn edit_restores_both_sides() {
        let input = json!({
            "old_string": "old AKIAQPSK0000000000FAKE",
            "new_string": "new AKIAQPSK0000000000FAKE"
        });
        let out = rewritten(decide(&FakeProxy::up(), "Edit", &input));
        assert_eq!(out["old_string"], "old AKIA1234567890ABCDEF");
        assert_eq!(out["new_string"], "new AKIA1234567890ABCDEF");
    }

    #[test]
    fn unhandled_tools_pass_through() {
        let input = json!({"file_path": "/etc/passwd", "pattern": "AKIAQPSK0000000000FAKE"});
        assert_eq!(
            decide(&FakeProxy::up(), "Grep", &input),
            Decision::PassThrough
        );
    }

    /// The infrastructure fail-open path (brief §8b). Proxy down → run unchanged, never block.
    #[test]
    fn a_down_proxy_passes_through_and_does_not_block() {
        let mut proxy = FakeProxy::up();
        proxy.down = true;
        let input = json!({"command": "echo AKIAQPSK0000000000FAKE"});
        // Pass-through: the CLI emits empty stdout, so the tool runs with the original input.
        assert_eq!(decide(&proxy, "Bash", &input), Decision::PassThrough);
    }

    /// The detection fail-closed path (brief §8b). A near miss → block with a diagnostic naming the
    /// field and the suspect.
    #[test]
    fn a_near_miss_blocks_with_a_diagnostic() {
        let mut proxy = FakeProxy::up();
        proxy.near_miss_on = Some("akiaqpsk0000000000fake"); // case-mangled
        let input = json!({"command": "echo akiaqpsk0000000000fake"});
        match decide(&proxy, "Bash", &input) {
            Decision::Block { message } => {
                assert!(message.contains("Bash"));
                assert!(message.contains("command"), "must name the field");
                assert!(
                    message.contains("akiaqpsk0000000000fake"),
                    "must name the suspect"
                );
            }
            other => panic!("a near miss must block, got {other:?}"),
        }
    }

    /// Down-proxy and near-miss are different conditions. A near miss must block even though a
    /// down proxy passes through — never conflate them.
    #[test]
    fn a_near_miss_is_not_softened_into_pass_through() {
        let mut proxy = FakeProxy::up();
        proxy.near_miss_on = Some("mangled");
        assert!(matches!(
            decide(&proxy, "Write", &json!({"content": "x mangled y"})),
            Decision::Block { .. }
        ));
    }

    /// No fake present → pass through with empty stdout, not a no-op `updatedInput`. This keeps the
    /// hook free of the `updatedInput` CLI-version dependency on the overwhelmingly common path.
    #[test]
    fn a_field_with_no_fake_passes_through() {
        let input = json!({"command": "cargo build --release"});
        assert_eq!(
            decide(&FakeProxy::up(), "Bash", &input),
            Decision::PassThrough
        );
    }
}
