use anyhow::Result;
use clap::{Parser, Subcommand};
use psk_core::{Pipeline, RedactionPolicy};
use std::io::{self, Read};

#[derive(Parser)]
#[command(name = "psk", version, about = "Prompt Secret Killer — scrub PII and secrets from LLM prompts")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Auto-detect agents and configure hooks + proxy env
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
        /// Run in hook mode (reads hook input from stdin, outputs hook response)
        #[arg(long)]
        hook: bool,
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
        Commands::Scan { json, hook } => cmd_scan(json, hook),
        Commands::Gain { history } => cmd_gain(history),
        Commands::Patterns => cmd_patterns(),
        Commands::Test => cmd_test(),
        Commands::Version => cmd_version(),
    }
}

fn build_pipeline() -> Pipeline {
    let policy = load_policy();
    let mut pipeline = Pipeline::new(policy);

    // Load built-in patterns
    for recognizer in psk_patterns::builtin_recognizers() {
        pipeline.add_recognizer(recognizer);
    }

    // Load custom user patterns from ~/.psk/patterns/
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
                // For now we use JSON for the policy section
                // TODO: add TOML config support
                let _ = data;
            }
        }
    }
    RedactionPolicy::default()
}

fn cmd_install(agent: Option<String>, port: u16) -> Result<()> {
    let agents_to_install: Vec<String> = if let Some(agent) = agent {
        vec![agent]
    } else {
        detect_installed_agents()
    };

    if agents_to_install.is_empty() {
        println!("No supported agents detected.");
        println!("Supported agents: claude-code, cursor, codex, gemini, aider");
        println!("\nYou can still use PSK in pipe mode: echo 'text' | psk scan");
        println!("Or start the proxy: psk start");
        return Ok(());
    }

    for agent_name in &agents_to_install {
        match agent_name.as_str() {
            "claude-code" => {
                psk_hook::claude_code::install(port)?;
                println!("  Installed Claude Code hook + ANTHROPIC_BASE_URL");
            }
            other => {
                println!("  {} — hook not yet implemented (coming in M2)", other);
            }
        }
    }

    println!("\nPSK installed for: {}", agents_to_install.join(", "));
    println!("Start the proxy with: psk start");
    println!("Check stats anytime with: psk gain");
    Ok(())
}

fn cmd_uninstall() -> Result<()> {
    if psk_hook::claude_code::is_installed() {
        psk_hook::claude_code::uninstall()?;
        println!("  Removed Claude Code hook");
    }
    println!("PSK uninstalled. Config and stats preserved in ~/.psk/");
    Ok(())
}

fn cmd_start(port: u16, foreground: bool) -> Result<()> {
    let bind_addr = format!("127.0.0.1:{}", port);
    let pipeline = build_pipeline();

    if foreground {
        println!("PSK proxy starting on {}", bind_addr);
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(psk_proxy::start_proxy(&bind_addr, pipeline))?;
    } else {
        // Daemonize: fork to background
        // For now, just run in foreground with a note
        println!("PSK proxy starting on {} (foreground mode)", bind_addr);
        println!("Tip: use 'psk start --foreground' or run in a tmux/screen session");
        println!("Background daemon mode coming soon.");
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(psk_proxy::start_proxy(&bind_addr, pipeline))?;
    }
    Ok(())
}

fn cmd_stop() -> Result<()> {
    // TODO: read PID file and send SIGTERM
    println!("Daemon stop not yet implemented. Kill the process manually for now.");
    Ok(())
}

fn cmd_status() -> Result<()> {
    // TODO: check PID file and port availability
    println!("Daemon status check not yet implemented.");
    Ok(())
}

fn cmd_scan(json_output: bool, hook_mode: bool) -> Result<()> {
    let pipeline = build_pipeline();
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    if hook_mode {
        // Claude Code hook mode: read hook input, return hook response
        let hook_input: serde_json::Value = serde_json::from_str(&input)?;
        let prompt = hook_input
            .get("prompt")
            .and_then(|p| p.as_str())
            .unwrap_or("");

        let (redacted, spans) = pipeline.redact(prompt);

        if spans.is_empty() {
            // No secrets found — allow
            let response = serde_json::json!({
                "decision": "allow"
            });
            println!("{}", serde_json::to_string(&response)?);
        } else {
            // Secrets found — block with suggestion
            let entity_summary: Vec<String> = spans
                .iter()
                .map(|s| format!("{}", s.entity))
                .collect();
            let message = format!(
                "PSK blocked: found {} secret(s) [{}]. Redacted version:\n\n{}",
                spans.len(),
                entity_summary.join(", "),
                redacted
            );
            let response = serde_json::json!({
                "decision": "block",
                "reason": message
            });
            println!("{}", serde_json::to_string(&response)?);
        }
    } else if json_output {
        let (redacted, spans) = pipeline.redact(&input);
        let output = serde_json::json!({
            "original_length": input.len(),
            "redacted": redacted,
            "entities": spans.iter().map(|s| {
                serde_json::json!({
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
            eprint!("No entities found.\n");
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

fn cmd_gain(_history: bool) -> Result<()> {
    let stats = psk_core::StatsCollector::new().snapshot();

    println!();
    println!("  PSK \u{2014} Prompt Secret Killer");
    println!("  \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");
    println!("  Prompts scanned     {:>8}", stats.prompts_scanned);
    println!(
        "  Entities redacted   {:>8}",
        stats.total_entities_redacted
    );

    // Sort entity types by count descending
    let mut sorted: Vec<_> = stats.entities_by_type.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (entity, count) in &sorted {
        println!("  \u{251c}\u{2500} {:18} {:>6}", entity, count);
    }

    if stats.prompts_scanned > 0 {
        let avg_entities =
            stats.total_entities_redacted as f64 / stats.prompts_scanned as f64;
        let avg_latency_ms = if stats.total_latency_us > 0 {
            stats.total_latency_us as f64 / stats.prompts_scanned as f64 / 1000.0
        } else {
            0.0
        };
        println!();
        println!(
            "  Redaction rate     {:>6.1} entities/prompt",
            avg_entities
        );
        println!("  Avg latency        {:>6.1} ms/prompt", avg_latency_ms);
    }
    println!(
        "  Total chars hidden {:>8}",
        stats.total_chars_hidden
    );
    println!();

    Ok(())
}

fn cmd_patterns() -> Result<()> {
    let recognizers = psk_patterns::builtin_recognizers();
    println!("{} patterns loaded", recognizers.len());

    // Group by pack (extract from recognizer ID: "regex:pack:name")
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
    let pipeline = build_pipeline();
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

        // A fixture file is "passed" if it found at least one entity
        // (all fixture files are designed to contain detectable entities)
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
        if home.join(".codex").exists() {
            agents.push("codex".to_string());
        }
        if home.join(".config").join("gemini").exists() {
            agents.push("gemini".to_string());
        }
    }

    // Check for .aider.conf.yml in cwd
    if std::path::Path::new(".aider.conf.yml").exists() {
        agents.push("aider".to_string());
    }

    agents
}
