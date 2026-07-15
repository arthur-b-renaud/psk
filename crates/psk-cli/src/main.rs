//! The `psk` binary. Thin shells over the library crates; the logic lives there and is tested
//! there. `anyhow` at this boundary (brief §13), `thiserror` in the libraries.

mod client;
mod run;
mod shim;

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
    /// Launch `claude` through the proxy: starts it if needed, then execs claude. This is what the
    /// installed `~/.psk/bin/claude` shim calls; everything after `run` is passed to claude.
    Run {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
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
    /// Launch the live inspector TUI (watches the proxy's event feed).
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
        Command::Run { rest } => run::cmd_run(rest),
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

/// The env var Claude Code reads to route requests through the proxy. Earlier versions of `psk
/// init` wrote it into `settings.json`; that was a landmine — a static URL pointing at a proxy that
/// might be down, breaking `claude` (`CLAUDE.md` §4). The base URL is now set per-process by the
/// `claude` shim (`run.rs`), and `psk init` only *removes* any stale settings.json copy.
const BASE_URL_VAR: &str = "ANTHROPIC_BASE_URL";

fn cmd_init() -> Result<std::process::ExitCode> {
    let path = psk_init::default_settings_path()?;

    let hook = psk_init::init(&path).with_context(|| format!("editing {}", path.display()))?;
    match hook {
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

    // Migrate away from the old settings.json landmine: remove env.ANTHROPIC_BASE_URL if it is
    // still ours (guarded, so a user-repointed URL is left alone). This is what un-breaks anyone
    // who ran the previous `psk init` and then didn't leave a proxy running.
    let base_url = format!("http://{}", load_config()?.bind);
    let env = psk_init::unset_env(&path, BASE_URL_VAR, &base_url)
        .with_context(|| format!("editing {}", path.display()))?;
    if let psk_init::EnvOutcome::Removed = env {
        println!("psk: removed the old {BASE_URL_VAR} from settings (now set by the claude shim)");
    }

    // Install the transparent `claude` shim, so typing `claude` routes through `psk run`.
    let home = psk_vault::salt::psk_home().context("locating ~/.psk")?;
    let exe = std::env::current_exe().context("finding the psk executable")?;
    let shim = shim::install(&home, &exe)
        .with_context(|| format!("installing the claude shim under {}", home.display()))?;
    match shim {
        shim::ShimOutcome::Installed => {
            println!("psk: installed the claude shim at {}", shim::shim_path(&home).display())
        }
        shim::ShimOutcome::Unchanged => println!(
            "psk: the claude shim is already installed at {}",
            shim::shim_path(&home).display()
        ),
        _ => unreachable!("install returns Installed or Unchanged"),
    }

    if shim::bin_dir_on_path(&home) {
        println!("\nDone. Run `claude` as usual — it routes through the proxy, which starts on demand.");
    } else {
        println!(
            "\nOne-time setup: put the shim on your PATH, then restart your shell:\n\
             \n    export PATH=\"{}:$PATH\"\n\
             \nAdd that line to your shell rc (~/.bashrc, ~/.zshrc, …). Then run `claude` as usual —\n\
             it routes through the proxy, which starts on demand.",
            shim::bin_dir(&home).display()
        );
    }
    Ok(OK)
}

fn cmd_uninit() -> Result<std::process::ExitCode> {
    let path = psk_init::default_settings_path()?;
    let base_url = format!("http://{}", load_config()?.bind);

    let hook = psk_init::uninit(&path).with_context(|| format!("editing {}", path.display()))?;
    match hook {
        psk_init::Outcome::Removed => {
            println!("psk: removed the PreToolUse hook from {}", path.display())
        }
        psk_init::Outcome::Absent => {
            println!("psk: no PSK hook was installed in {}", path.display())
        }
        _ => unreachable!("uninit returns Removed or Absent"),
    }

    let env = psk_init::unset_env(&path, BASE_URL_VAR, &base_url)
        .with_context(|| format!("editing {}", path.display()))?;
    match env {
        psk_init::EnvOutcome::Removed => {
            println!("psk: unset {BASE_URL_VAR}; Claude Code now talks to the provider directly")
        }
        // Absent covers both "we never set it" and "the user re-pointed it themselves"; in the
        // latter case leaving it be is the correct, non-clobbering behaviour.
        psk_init::EnvOutcome::Absent => {}
        _ => unreachable!("unset_env returns Removed or Absent"),
    }

    // Remove the transparent `claude` shim.
    let home = psk_vault::salt::psk_home().context("locating ~/.psk")?;
    match shim::uninstall(&home).with_context(|| format!("removing the claude shim under {}", home.display()))? {
        shim::ShimOutcome::Removed => {
            println!("psk: removed the claude shim at {}", shim::shim_path(&home).display())
        }
        shim::ShimOutcome::Absent => {}
        _ => unreachable!("uninstall returns Removed or Absent"),
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

    println!("psk proxy is running on http://{bind}  (restore_mode = {mode:?})\n");
    if psk_init::is_installed(&psk_init::default_settings_path()?).unwrap_or(false) {
        println!("  `psk init` has wired Claude Code to PSK. Normally you don't run this by hand —\n");
        println!("  the `claude` shim starts a proxy on demand. This one will be reused if it's up.\n");
    } else {
        println!("  Run `psk init` to install the PreToolUse hook and the `claude` shim,\n");
        println!("  which start a proxy like this one automatically.\n");
    }
    // The last line before it blocks: the mistake to prevent is Ctrl-C'ing this, thinking the
    // command finished. Say plainly that it keeps running here.
    println!("Leave this terminal open — the proxy runs here. Press Ctrl-C to stop.");
    // Flush now: the process then blocks in `serve` forever, and piped/redirected stdout is
    // block-buffered, so without this the banner would never appear in `psk proxy > log`.
    use std::io::Write as _;
    let _ = std::io::stdout().flush();

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
