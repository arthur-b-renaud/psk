use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use psk_core::{Pipeline, RedactionPolicy, Vault};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "psk",
    version,
    about = "Prompt Secret Killer — scrub PII and secrets from LLM prompts"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Auto-detect agents and configure proxy routing + hooks
    Install {
        /// Target a specific agent instead of auto-detecting
        #[arg(long)]
        agent: Option<String>,
        /// Proxy port (default: 7878)
        #[arg(long, default_value = "7878")]
        port: u16,
    },
    /// Remove hooks and env vars (keeps config + stats)
    Uninstall,
    /// Start the proxy daemon
    Start {
        /// Port to listen on
        #[arg(long, default_value = "7878")]
        port: u16,
        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,
    },
    /// Stop the proxy daemon
    Stop,
    /// Show daemon status
    Status,
    /// Scan stdin for PII/secrets and output redacted text
    Scan {
        /// Output JSON with span details instead of redacted text
        #[arg(long)]
        json: bool,
    },
    /// Restore real values from PSK tokens (Claude Code PreToolUse hook). Reads hook JSON on stdin.
    Restore {
        /// Run in hook mode (emit a PreToolUse hookSpecificOutput response)
        #[arg(long)]
        hook: bool,
        /// Daemon port to query for detokenization
        #[arg(long, default_value = "7878")]
        port: u16,
        /// Shared auth token for the daemon's detokenize endpoint
        #[arg(long, default_value = "")]
        auth: String,
    },
    /// Show redaction statistics
    Gain {
        /// Show per-command history
        #[arg(long)]
        history: bool,
    },
    /// List loaded patterns
    Patterns,
    /// Run fixture tests and report precision/recall
    Test,
    /// Show version
    Version,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "psk=info".parse().unwrap()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Install { agent, port } => cmd_install(agent, port),
        Commands::Uninstall => cmd_uninstall(),
        Commands::Start { port, foreground } => cmd_start(port, foreground),
        Commands::Stop => cmd_stop(),
        Commands::Status => cmd_status(),
        Commands::Scan { json } => cmd_scan(json),
        Commands::Restore { hook, port, auth } => cmd_restore(hook, port, auth),
        Commands::Gain { history } => cmd_gain(history),
        Commands::Patterns => cmd_patterns(),
        Commands::Test => cmd_test(),
        Commands::Version => cmd_version(),
    }
}

// ---------------------------------------------------------------------------
// ~/.psk runtime files
// ---------------------------------------------------------------------------

fn psk_dir() -> Result<PathBuf> {
    let dir = dirs::home_dir()
        .context("Cannot find home directory")?
        .join(".psk");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn pid_path() -> Result<PathBuf> {
    Ok(psk_dir()?.join("psk.pid"))
}
fn port_path() -> Result<PathBuf> {
    Ok(psk_dir()?.join("psk.port"))
}
fn log_path() -> Result<PathBuf> {
    Ok(psk_dir()?.join("psk.log"))
}
fn auth_token_path() -> Result<PathBuf> {
    Ok(psk_dir()?.join("auth.token"))
}

/// Load the daemon auth token, creating one on first use. Shared between `psk start` (daemon),
/// `psk install` (embeds it in the hook command), and `psk restore` (the hook).
fn get_or_create_auth_token() -> Result<String> {
    let path = auth_token_path()?;
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let mut hasher = Sha256::new();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    hasher.update(nanos.to_le_bytes());
    hasher.update((std::process::id() as u128).to_le_bytes());
    hasher.update(b"psk-auth");
    let token: String = hasher
        .finalize()
        .iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect();
    std::fs::write(&path, &token)?;
    set_owner_only(&path);
    Ok(token)
}

/// Best-effort `chmod 600` on Unix (the token / vault-adjacent files are sensitive).
fn set_owner_only(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

fn build_pipeline(vault: Option<Arc<Vault>>) -> Pipeline {
    let policy = load_policy();
    let mut pipeline = Pipeline::new(policy);
    if let Some(v) = vault {
        pipeline = pipeline.with_vault(v);
    }

    for recognizer in psk_patterns::builtin_recognizers() {
        pipeline.add_recognizer(recognizer);
    }

    if let Some(home) = dirs::home_dir() {
        let custom_dir = home.join(".psk").join("patterns");
        if custom_dir.exists() {
            for recognizer in psk_patterns::load_recognizers_from_dir(&custom_dir) {
                pipeline.add_recognizer(recognizer);
            }
        }
    }

    pipeline
}

fn load_policy() -> RedactionPolicy {
    if let Some(home) = dirs::home_dir() {
        let config_path = home.join(".psk").join("config.toml");
        if config_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&config_path) {
                // TODO: add TOML config support
                let _ = data;
            }
        }
    }
    RedactionPolicy::default()
}

// ---------------------------------------------------------------------------
// install / uninstall
// ---------------------------------------------------------------------------

fn cmd_install(agent: Option<String>, port: u16) -> Result<()> {
    let agents_to_install: Vec<String> = if let Some(agent) = agent {
        vec![agent]
    } else {
        detect_installed_agents()
    };

    if agents_to_install.is_empty() {
        println!("No supported agents detected.");
        println!("Supported agents: claude-code, cursor, antigravity");
        println!("\nYou can still use PSK in pipe mode: echo 'text' | psk scan");
        println!("Or start the proxy: psk start");
        return Ok(());
    }

    let auth = get_or_create_auth_token()?;

    for agent_name in &agents_to_install {
        match agent_name.as_str() {
            "claude-code" => {
                psk_hook::claude_code::install(port, &auth)?;
                println!("✓ claude-code: routed via proxy + PreToolUse restore hook installed.");
            }
            "cursor" => print_cursor_instructions(port),
            "antigravity" => install_antigravity(port)?,
            other => println!("  {} — not supported yet.", other),
        }
    }

    println!("\nNext: start the daemon with  psk start  (required — the token vault lives there).");
    println!("Check stats anytime with  psk gain");
    Ok(())
}

fn print_cursor_instructions(port: u16) {
    println!("• cursor (best-effort): set Settings → Models → \"Override OpenAI Base URL\" to:");
    println!("      http://127.0.0.1:{}/v1", port);
    println!("  then put any non-empty key in the \"OpenAI API Key\" field.");
    println!("  NOTE: only Cursor's chat/plan panel honors this — Composer / apply / autocomplete");
    println!("  bypass the override, so agent traffic is NOT fully covered. No local restore hook");
    println!(
        "  exists for Cursor, so PSK tokens may appear in its chat (secrets still never leave"
    );
    println!("  the machine in cleartext).");
}

fn install_antigravity(port: u16) -> Result<()> {
    println!("• antigravity (experimental): point its model endpoint at the proxy:");
    println!("      http://127.0.0.1:{}", port);
    if let Some(home) = dirs::home_dir() {
        let cfg = home.join(".config").join("antigravity").join("config.toml");
        if !cfg.exists() {
            println!("  (no ~/.config/antigravity/config.toml found — set the base URL once the IDE creates it.)");
        } else {
            println!(
                "  add an `api_base`/base-URL entry pointing at the above in {}.",
                cfg.display()
            );
        }
    }
    println!("  NOTE: Antigravity custom-endpoint support is unstable upstream; coverage is best-effort.");
    Ok(())
}

fn cmd_uninstall() -> Result<()> {
    if psk_hook::claude_code::is_installed() {
        psk_hook::claude_code::uninstall()?;
        println!("  Removed Claude Code base-URL override + restore hook");
    }
    println!("PSK uninstalled. Config and stats preserved in ~/.psk/");
    Ok(())
}

// ---------------------------------------------------------------------------
// daemon lifecycle
// ---------------------------------------------------------------------------

fn cmd_start(port: u16, foreground: bool) -> Result<()> {
    if !foreground {
        // User-facing path: guard against a double-start, then spawn the detached daemon.
        if let Some(pid) = running_pid() {
            println!("PSK proxy already running (pid {}).", pid);
            return Ok(());
        }
        return daemonize(port);
    }

    // Foreground: this IS the daemon process (either `--foreground` directly or the spawned child).
    let vault = Arc::new(Vault::new());
    let auth = get_or_create_auth_token()?;
    let pipeline = build_pipeline(Some(vault.clone()));
    let bind_addr = format!("127.0.0.1:{}", port);

    std::fs::write(pid_path()?, std::process::id().to_string())?;
    std::fs::write(port_path()?, port.to_string())?;

    println!("PSK proxy listening on {}", bind_addr);
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(psk_proxy::start_proxy(&bind_addr, pipeline, vault, auth));
    // Clean up pid file on exit.
    let _ = std::fs::remove_file(pid_path()?);
    result
}

/// Spawn a detached background copy of ourselves running `start --foreground`.
fn daemonize(port: u16) -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let exe = std::env::current_exe()?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path()?)?;

    let mut cmd = Command::new(exe);
    cmd.arg("start")
        .arg("--port")
        .arg(port.to_string())
        .arg("--foreground")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);

    // Detach into a new session so the daemon survives the launching shell.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    // The child writes its own pid/port file on startup (so it doesn't mistake the parent-written
    // pid for an already-running instance and exit).
    let child = cmd.spawn().context("Failed to spawn proxy daemon")?;
    println!(
        "PSK proxy starting in background (pid {}, port {}).",
        child.id(),
        port
    );
    println!("Logs: {}", log_path()?.display());
    Ok(())
}

/// The pid of a live daemon, if one is recorded and the process exists.
fn running_pid() -> Option<i32> {
    let pid: i32 = std::fs::read_to_string(pid_path().ok()?)
        .ok()?
        .trim()
        .parse()
        .ok()?;
    // kill(pid, 0) probes existence without sending a signal.
    if unsafe { libc::kill(pid, 0) } == 0 {
        Some(pid)
    } else {
        None
    }
}

fn cmd_stop() -> Result<()> {
    match running_pid() {
        Some(pid) => {
            let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
            let _ = std::fs::remove_file(pid_path()?);
            if rc == 0 {
                println!("Stopped PSK proxy (pid {}).", pid);
            } else {
                println!("Sent SIGTERM to pid {} (it may already be gone).", pid);
            }
        }
        None => println!("PSK proxy is not running."),
    }
    Ok(())
}

fn cmd_status() -> Result<()> {
    match running_pid() {
        Some(pid) => {
            let port = std::fs::read_to_string(port_path()?)
                .ok()
                .and_then(|s| s.trim().parse::<u16>().ok())
                .unwrap_or(7878);
            let healthy = check_health(port);
            println!(
                "PSK proxy: running (pid {}, port {}) — {}",
                pid,
                port,
                if healthy { "healthy" } else { "not responding" }
            );
        }
        None => println!("PSK proxy: not running."),
    }
    Ok(())
}

fn check_health(port: u16) -> bool {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return false,
    };
    rt.block_on(async {
        reqwest::Client::new()
            .get(format!("http://127.0.0.1:{}/health", port))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    })
}

// ---------------------------------------------------------------------------
// scan / restore
// ---------------------------------------------------------------------------

fn cmd_scan(json_output: bool) -> Result<()> {
    // No vault in one-shot scan mode: tokenize degrades to irreversible replacement.
    let pipeline = build_pipeline(None);
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    if json_output {
        let (redacted, spans) = pipeline.redact(&input);
        let output = json!({
            "original_length": input.len(),
            "redacted": redacted,
            "entities": spans.iter().map(|s| {
                json!({
                    "type": s.entity.to_string(),
                    "start": s.start,
                    "end": s.end,
                    "text": s.extract(&input),
                    "confidence": s.confidence,
                    "recognizer": s.recognizer_id,
                })
            }).collect::<Vec<_>>()
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let (redacted, spans) = pipeline.redact(&input);
        if spans.is_empty() {
            eprintln!("No entities found.");
        } else {
            eprintln!("Found {} entities:", spans.len());
            for span in &spans {
                eprintln!(
                    "  {} ({:.0}%) → {}",
                    span.entity,
                    span.confidence * 100.0,
                    span.extract(&input)
                );
            }
            eprintln!();
        }
        print!("{}", redacted);
    }

    Ok(())
}

/// PreToolUse restore hook: replace PSK tokens in the tool input with their real values, so the
/// file written / command run locally contains the real secret (provider traffic never did).
fn cmd_restore(hook: bool, port: u16, auth: String) -> Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    if !hook {
        // Plain mode: detokenize stdin and print it.
        let restored = detokenize_via_daemon(port, &auth, &input).unwrap_or(input);
        print!("{}", restored);
        return Ok(());
    }

    let hook_input: Value = serde_json::from_str(&input).unwrap_or_else(|_| json!({}));
    let tool_name = hook_input
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let mut tool_input = hook_input
        .get("tool_input")
        .cloned()
        .unwrap_or_else(|| json!({}));

    // Fields that may carry restorable values, per tool.
    let mut changed = false;
    let fields: &[&str] = match tool_name {
        "Write" => &["content"],
        "Edit" => &["old_string", "new_string"],
        "Bash" => &["command"],
        "NotebookEdit" => &["new_source"],
        _ => &[],
    };
    for f in fields {
        changed |= restore_field(&mut tool_input, f, port, &auth);
    }
    // MultiEdit: an array of {old_string, new_string} edits.
    if tool_name == "MultiEdit" {
        if let Some(edits) = tool_input.get_mut("edits").and_then(|e| e.as_array_mut()) {
            for edit in edits.iter_mut() {
                changed |= restore_field(edit, "old_string", port, &auth);
                changed |= restore_field(edit, "new_string", port, &auth);
            }
        }
    }

    if changed {
        let response = json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "psk: restored real value(s) from token(s)",
                "updatedInput": tool_input,
            }
        });
        println!("{}", serde_json::to_string(&response)?);
    }
    // No change → emit nothing and exit 0: the tool proceeds unmodified.
    Ok(())
}

/// Detokenize one string field of `obj` in place. Returns whether it changed.
fn restore_field(obj: &mut Value, field: &str, port: u16, auth: &str) -> bool {
    let Some(s) = obj.get(field).and_then(|v| v.as_str()) else {
        return false;
    };
    if !s.contains("__PSK_") {
        return false; // fast path: no token, no daemon round-trip
    }
    match detokenize_via_daemon(port, auth, s) {
        Ok(restored) if restored != s => {
            obj[field] = json!(restored);
            true
        }
        _ => false,
    }
}

fn detokenize_via_daemon(port: u16, auth: &str, text: &str) -> Result<String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let resp = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{}/psk/detokenize", port))
            .json(&json!({ "text": text, "auth": auth }))
            .send()
            .await?
            .error_for_status()?;
        let body: Value = resp.json().await?;
        Ok(body
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or(text)
            .to_string())
    })
}

// ---------------------------------------------------------------------------
// gain / patterns / test / version
// ---------------------------------------------------------------------------

fn cmd_gain(_history: bool) -> Result<()> {
    let stats = psk_core::StatsCollector::new().snapshot();

    println!();
    println!("  PSK \u{2014} Prompt Secret Killer");
    println!("  \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");
    println!("  Prompts scanned     {:>8}", stats.prompts_scanned);
    println!("  Entities redacted   {:>8}", stats.total_entities_redacted);

    let mut sorted: Vec<_> = stats.entities_by_type.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (entity, count) in &sorted {
        println!("  \u{251c}\u{2500} {:18} {:>6}", entity, count);
    }

    if stats.prompts_scanned > 0 {
        let avg_entities = stats.total_entities_redacted as f64 / stats.prompts_scanned as f64;
        let avg_latency_ms = if stats.total_latency_us > 0 {
            stats.total_latency_us as f64 / stats.prompts_scanned as f64 / 1000.0
        } else {
            0.0
        };
        println!();
        println!("  Redaction rate     {:>6.1} entities/prompt", avg_entities);
        println!("  Avg latency        {:>6.1} ms/prompt", avg_latency_ms);
    }
    println!("  Total chars hidden {:>8}", stats.total_chars_hidden);
    println!();

    Ok(())
}

fn cmd_patterns() -> Result<()> {
    let recognizers = psk_patterns::builtin_recognizers();
    println!("{} patterns loaded", recognizers.len());

    let mut packs: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for r in &recognizers {
        let parts: Vec<&str> = r.id().splitn(3, ':').collect();
        if parts.len() == 3 {
            packs
                .entry(parts[1].to_string())
                .or_default()
                .push(parts[2].to_string());
        }
    }

    for (pack, patterns) in &packs {
        println!("  {} ({}): {}", pack, patterns.len(), patterns.join(", "));
    }

    Ok(())
}

fn cmd_test() -> Result<()> {
    let pipeline = build_pipeline(None);
    let fixtures_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");

    if !fixtures_dir.exists() {
        println!("No fixtures directory found at {}", fixtures_dir.display());
        return Ok(());
    }

    let mut total = 0;
    let mut passed = 0;

    for entry in std::fs::read_dir(&fixtures_dir)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("txt") {
            continue;
        }

        let content = std::fs::read_to_string(&path)?;
        let (_, spans) = pipeline.redact(&content);
        total += 1;

        if !spans.is_empty() {
            passed += 1;
            println!(
                "  \u{2713} {} — {} entities found",
                path.file_name().unwrap().to_string_lossy(),
                spans.len()
            );
        } else {
            println!(
                "  \u{2717} {} — no entities found",
                path.file_name().unwrap().to_string_lossy()
            );
        }
    }

    println!();
    if total > 0 {
        println!(
            "  {}/{} fixtures passed ({:.0}%)",
            passed,
            total,
            passed as f64 / total as f64 * 100.0
        );
    } else {
        println!("  No fixture files found.");
    }

    Ok(())
}

fn cmd_version() -> Result<()> {
    println!("psk {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

fn detect_installed_agents() -> Vec<String> {
    let mut agents = Vec::new();

    if let Some(home) = dirs::home_dir() {
        if home.join(".claude").exists() {
            agents.push("claude-code".to_string());
        }
        if home.join(".cursor").exists() {
            agents.push("cursor".to_string());
        }
        if home.join(".config").join("antigravity").exists() {
            agents.push("antigravity".to_string());
        }
    }

    agents
}
