//! The `psk` binary. Thin shells over the library crates; the logic lives there and is tested
//! there. `anyhow` at this boundary (brief §13), `thiserror` in the libraries.

mod client;

use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use psk_proxy::hook::{Decision, RestoreClient, decide};
use serde_json::{Value, json};

#[derive(Parser)]
#[command(name = "psk", version, about = "PSK — Prompt Secret Killer")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Detect secrets in stdin (or a file) and preview the substitution.
    Scan {
        /// Read this file instead of stdin.
        file: Option<PathBuf>,
    },
    /// Start the local reverse proxy. Prints the ANTHROPIC_BASE_URL line to export.
    Proxy,
    /// The PreToolUse restore handler. Reads Claude Code's hook JSON on stdin.
    Hook,
    /// Install PSK's PreToolUse hook into ~/.claude/settings.json.
    Init,
    /// Remove PSK's PreToolUse hook from ~/.claude/settings.json.
    Uninit,
    /// Print token-savings counters from ~/.psk/stats.json.
    Gain,
    /// Run detection against the built-in fixtures and, if present, the external corpus.
    Test,
    /// Launch the inspector TUI (not yet implemented).
    Top,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("psk: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<std::process::ExitCode> {
    match command {
        Command::Scan { file } => cmd_scan(file),
        Command::Proxy => cmd_proxy(),
        Command::Hook => cmd_hook(),
        Command::Init => cmd_init(),
        Command::Uninit => cmd_uninit(),
        Command::Gain => cmd_gain(),
        Command::Test => cmd_test(),
        Command::Top => cmd_top(),
    }
}

const OK: std::process::ExitCode = std::process::ExitCode::SUCCESS;

/// Load the proxy config from `~/.psk`, so every subcommand agrees on bind address and mode.
fn load_config() -> Result<psk_proxy::Config> {
    let home = psk_vault::salt::psk_home().context("locating ~/.psk")?;
    psk_proxy::Config::load(&home).context("reading ~/.psk/config.toml")
}

// --- init / uninit ----------------------------------------------------------------------------

fn cmd_init() -> Result<std::process::ExitCode> {
    let path = psk_init::default_settings_path()?;
    let outcome = psk_init::init(&path).with_context(|| format!("editing {}", path.display()))?;
    match outcome {
        psk_init::Outcome::Added => println!(
            "psk: installed the PreToolUse hook ({}) in {}",
            psk_init::HOOK_COMMAND,
            path.display()
        ),
        psk_init::Outcome::AlreadyPresent => {
            println!(
                "psk: the PreToolUse hook is already installed in {}",
                path.display()
            )
        }
        _ => unreachable!("init returns Added or AlreadyPresent"),
    }
    Ok(OK)
}

fn cmd_uninit() -> Result<std::process::ExitCode> {
    let path = psk_init::default_settings_path()?;
    let outcome = psk_init::uninit(&path).with_context(|| format!("editing {}", path.display()))?;
    match outcome {
        psk_init::Outcome::Removed => {
            println!("psk: removed the PreToolUse hook from {}", path.display())
        }
        psk_init::Outcome::Absent => {
            println!("psk: no PSK hook was installed in {}", path.display())
        }
        _ => unreachable!("uninit returns Removed or Absent"),
    }
    Ok(OK)
}

// --- proxy ------------------------------------------------------------------------------------

fn cmd_proxy() -> Result<std::process::ExitCode> {
    let config = load_config()?;
    let home = psk_vault::salt::psk_home()?;
    let vault = std::sync::Arc::new(psk_vault::Vault::open().context("opening the vault")?);

    let bind = config.bind;
    let mode = config.restore_mode;
    let state = std::sync::Arc::new(psk_proxy::ProxyState::new(vault, config, home));

    println!("psk proxy — restore_mode = {mode:?}");
    println!("point your agent at it:\n");
    println!("    export ANTHROPIC_BASE_URL=http://{bind}\n");
    if mode == psk_proxy::RestoreMode::Execution {
        println!("execution mode: run `psk init` so the hook restores secrets at tool time.");
    }

    // A dedicated runtime rather than #[tokio::main], so cold startup of the *other* subcommands
    // (gain, init, hook) pays nothing for tokio.
    let rt = tokio::runtime::Runtime::new().context("starting the async runtime")?;
    rt.block_on(psk_proxy::serve(state))
        .context("serving the proxy")?;
    Ok(OK)
}

// --- hook -------------------------------------------------------------------------------------

fn cmd_hook() -> Result<std::process::ExitCode> {
    // Read Claude Code's PreToolUse JSON from stdin.
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading hook input")?;
    let input: Value = serde_json::from_str(&buf).context("hook stdin is not JSON")?;

    let tool = input.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let tool_input = input.get("tool_input").cloned().unwrap_or(Value::Null);

    let config = load_config()?;
    let restore = client::HttpRestore::new(&config.bind);

    emit_decision(decide(&restore, tool, &tool_input))
}

/// Turn a [`Decision`] into Claude Code's PreToolUse wire response.
///
/// The three responses are exactly the contract verified against the hooks reference:
/// - rewrite: `hookSpecificOutput.updatedInput` **with** `permissionDecision: "allow"`, exit 0;
/// - pass-through: empty stdout, exit 0;
/// - block: message on stderr, exit 2.
fn emit_decision(decision: Decision) -> Result<std::process::ExitCode> {
    match decision {
        Decision::Rewrite { tool_input } => {
            // `updatedInput` replaces `tool_input` wholesale, and MUST be paired with
            // `permissionDecision: "allow"` or the rewrite is silently dropped — which would send
            // the fake into the tool.
            let out = json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "updatedInput": tool_input
                }
            });
            println!("{out}");
            Ok(OK)
        }
        // Nothing to change: empty stdout runs the tool with its original input, and avoids the
        // `updatedInput` CLI-version dependency on the common path.
        Decision::PassThrough => Ok(OK),
        // Exit 2 blocks the tool and surfaces stderr to the agent (brief §8b).
        Decision::Block { message } => {
            eprintln!("{message}");
            Ok(std::process::ExitCode::from(2))
        }
    }
}

// --- scan -------------------------------------------------------------------------------------

fn cmd_scan(file: Option<PathBuf>) -> Result<std::process::ExitCode> {
    let text = match &file {
        Some(p) => {
            std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?
        }
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading stdin")?;
            buf
        }
    };

    let config = load_config()?;
    let vault = std::sync::Arc::new(psk_vault::Vault::open().context("opening the vault")?);
    let engine = psk_core::Engine::new(std::sync::Arc::clone(&vault), config.scan_config());

    let (substituted, summary) = engine.substitute(&text);

    if summary.is_empty() {
        println!("no secrets detected.");
    } else {
        println!("detected {} entities:", summary.total());
        for (kind, n) in &summary.by_kind {
            println!("  {kind:?}: {n}");
        }
        println!("\n--- substituted (what the provider would see) ---\n{substituted}");
    }

    // Flag known fakes / near-misses. Full fidelity needs the proxy's live vault; degrade to
    // marker-based detection when it is down (brief §10).
    let restore = client::HttpRestore::new(&config.bind);
    if restore.is_up() {
        if let Ok(r) = restore.restore(&text) {
            if let Some(nm) = r.near_miss {
                println!(
                    "\n\u{26a0} near-miss fake ({}): {:?}",
                    nm.reason, nm.suspect
                );
            }
            if r.text != text {
                println!("\n(input already contained known fakes; the proxy can restore them.)");
            }
        }
    } else if text.contains(psk_vault::MARKER) {
        println!(
            "\n\u{26a0} the input contains the PSK marker {:?} — it may hold unrestored fakes. \
             Start `psk proxy` for exact detection.",
            psk_vault::MARKER
        );
    }

    Ok(OK)
}

// --- gain -------------------------------------------------------------------------------------

fn cmd_gain() -> Result<std::process::ExitCode> {
    let home = psk_vault::salt::psk_home()?;
    let path = home.join("stats.json");

    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("psk: no stats yet. Run `psk proxy` and send some traffic through it.");
            return Ok(OK);
        }
        Err(e) => return Err(e).context(format!("reading {}", path.display())),
    };
    let s: Value = serde_json::from_str(&text).context("parsing stats.json")?;

    let n = |k: &str| s.get(k).and_then(Value::as_u64).unwrap_or(0);
    println!("PSK — token savings");
    println!("  prompts scanned      {}", n("prompts_scanned"));
    println!("  entities substituted {}", n("chars_hidden"));
    if let Some(by_kind) = s.get("entities_substituted").and_then(Value::as_object) {
        for (kind, count) in by_kind {
            println!("    {kind:24} {}", count.as_u64().unwrap_or(0));
        }
    }
    println!("  chars hidden         {}", n("chars_hidden"));
    println!("  fakes restored       {}", n("fakes_restored"));
    println!("  fakes never restored {}", n("fakes_never_restored"));
    println!("  near-misses blocked  {}", n("near_misses_blocked"));
    println!("  avg latency (ms)     {}", n("avg_latency_ms"));
    Ok(OK)
}

// --- test -------------------------------------------------------------------------------------

fn cmd_test() -> Result<std::process::ExitCode> {
    use psk_core::SecretKind;

    let cfg = psk_secrets_scan_config();
    let mut failures = 0usize;

    // Built-in fixtures: every kind's representative sample must be detected as that kind.
    println!("fixtures:");
    for k in SecretKind::ALL {
        let sample = psk_vault::sample::for_kind(k);
        // The Bearer rule keys on its keyword, so a bare token cannot match by design. Present it
        // the way it actually appears in traffic, exactly as the unit tests do.
        let text = if k == SecretKind::BearerToken {
            format!("Authorization: Bearer {sample}")
        } else {
            sample
        };
        let found = psk_secrets::scan(&text, &cfg)
            .into_iter()
            .any(|m| m.kind == k);
        // Network kinds ship disabled, so they are expected to be absent under the default config.
        let expected = k.enabled_by_default();
        let ok = found == expected;
        if !ok {
            failures += 1;
        }
        println!(
            "  {} {k:?}{}",
            if ok { "\u{2713}" } else { "\u{2717}" },
            if expected {
                ""
            } else {
                " (disabled by default)"
            }
        );
    }

    // External corpus, if it has been fetched.
    let corpus =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/manifest.jsonl");
    if corpus.exists() {
        println!(
            "\ncorpus: present at {} — run `cargo test -p psk-secrets --test corpus` for precision/recall.",
            corpus.display()
        );
    } else {
        println!(
            "\ncorpus: not fetched (run ./scripts/fetch-corpus.sh). Skipping the external gate."
        );
    }

    if failures == 0 {
        println!("\nall fixtures passed.");
        Ok(OK)
    } else {
        println!("\n{failures} fixture(s) failed.");
        Ok(std::process::ExitCode::FAILURE)
    }
}

fn psk_secrets_scan_config() -> psk_secrets::ScanConfig {
    psk_secrets::ScanConfig::default()
}

// --- top --------------------------------------------------------------------------------------

fn cmd_top() -> Result<std::process::ExitCode> {
    let config = load_config()?;
    psk_tui::run(&config).context("running the inspector")?;
    Ok(OK)
}
