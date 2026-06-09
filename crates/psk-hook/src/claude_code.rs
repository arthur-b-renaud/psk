use anyhow::{Context, Result};
use serde_json::Value;
use std::path::PathBuf;

const PSK_HOOK_MARKER: &str = "psk-prompt-guard";

/// Install the PSK UserPromptSubmit hook into Claude Code settings.
/// Also injects ANTHROPIC_BASE_URL into the user's shell rc file.
pub fn install(proxy_port: u16) -> Result<()> {
    install_hook()?;
    install_env_var(proxy_port)?;
    Ok(())
}

/// Remove PSK hooks from Claude Code settings and shell rc.
pub fn uninstall() -> Result<()> {
    uninstall_hook()?;
    uninstall_env_var()?;
    Ok(())
}

/// Check if PSK is already installed for Claude Code.
pub fn is_installed() -> bool {
    if let Some(settings) = load_settings() {
        if let Some(hooks) = settings.get("hooks") {
            if let Some(Value::Array(arr)) = hooks.get("UserPromptSubmit") {
                return arr
                    .iter()
                    .any(|h| h.get("id").and_then(|v| v.as_str()) == Some(PSK_HOOK_MARKER));
            }
        }
    }
    false
}

fn settings_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".claude").join("settings.json"))
}

fn load_settings() -> Option<Value> {
    let path = settings_path()?;
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn install_hook() -> Result<()> {
    let path = settings_path().context("Cannot find home directory")?;

    let mut settings = if path.exists() {
        let data = std::fs::read_to_string(&path)?;
        serde_json::from_str::<Value>(&data).unwrap_or_else(|_| Value::Object(Default::default()))
    } else {
        Value::Object(Default::default())
    };

    // Ensure hooks.UserPromptSubmit exists as an array
    let hooks = settings
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| Value::Object(Default::default()));
    let user_prompt_hooks = hooks
        .as_object_mut()
        .unwrap()
        .entry("UserPromptSubmit")
        .or_insert_with(|| Value::Array(Vec::new()));

    if let Value::Array(arr) = user_prompt_hooks {
        // Remove existing PSK hook if present
        arr.retain(|h| h.get("id").and_then(|v| v.as_str()) != Some(PSK_HOOK_MARKER));

        // Add the PSK hook
        let hook = serde_json::json!({
            "id": PSK_HOOK_MARKER,
            "type": "command",
            "command": "psk scan --hook",
            "description": "PSK: scan prompt for PII and secrets before submission",
            "timeout": 5000
        });
        arr.push(hook);
    }

    // Write back
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&path, data)?;

    tracing::info!("Installed PSK hook in {}", path.display());
    Ok(())
}

fn uninstall_hook() -> Result<()> {
    let path = match settings_path() {
        Some(p) if p.exists() => p,
        _ => return Ok(()),
    };

    let data = std::fs::read_to_string(&path)?;
    let mut settings: Value = serde_json::from_str(&data)?;

    if let Some(hooks) = settings.get_mut("hooks") {
        if let Some(Value::Array(arr)) = hooks.get_mut("UserPromptSubmit") {
            arr.retain(|h| h.get("id").and_then(|v| v.as_str()) != Some(PSK_HOOK_MARKER));
        }
    }

    let data = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&path, data)?;
    tracing::info!("Removed PSK hook from {}", path.display());
    Ok(())
}

fn shell_rc_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    // Prefer .zshrc on macOS, .bashrc elsewhere
    let candidates = [".zshrc", ".bashrc", ".profile"];
    for name in &candidates {
        let p = home.join(name);
        if p.exists() {
            return Some(p);
        }
    }
    // Default to .bashrc
    Some(home.join(".bashrc"))
}

const ENV_MARKER_START: &str = "# >>> psk >>>";
const ENV_MARKER_END: &str = "# <<< psk <<<";

fn install_env_var(proxy_port: u16) -> Result<()> {
    let rc_path = shell_rc_path().context("Cannot find shell rc file")?;

    let mut contents = if rc_path.exists() {
        std::fs::read_to_string(&rc_path)?
    } else {
        String::new()
    };

    // Remove existing PSK block
    if let (Some(start), Some(end)) = (
        contents.find(ENV_MARKER_START),
        contents.find(ENV_MARKER_END),
    ) {
        let block_end = end + ENV_MARKER_END.len();
        // Also remove trailing newline if present
        let block_end = if contents[block_end..].starts_with('\n') {
            block_end + 1
        } else {
            block_end
        };
        contents.replace_range(start..block_end, "");
    }

    // Append new block
    let block = format!(
        "\n{}\nexport ANTHROPIC_BASE_URL=\"http://127.0.0.1:{}\"\n{}\n",
        ENV_MARKER_START, proxy_port, ENV_MARKER_END
    );
    contents.push_str(&block);

    std::fs::write(&rc_path, contents)?;
    tracing::info!(
        "Set ANTHROPIC_BASE_URL in {} (port {})",
        rc_path.display(),
        proxy_port
    );
    Ok(())
}

fn uninstall_env_var() -> Result<()> {
    let rc_path = match shell_rc_path() {
        Some(p) if p.exists() => p,
        _ => return Ok(()),
    };

    let mut contents = std::fs::read_to_string(&rc_path)?;

    if let (Some(start), Some(end)) = (
        contents.find(ENV_MARKER_START),
        contents.find(ENV_MARKER_END),
    ) {
        let block_end = end + ENV_MARKER_END.len();
        let block_end = if contents[block_end..].starts_with('\n') {
            block_end + 1
        } else {
            block_end
        };
        contents.replace_range(start..block_end, "");
        std::fs::write(&rc_path, contents)?;
        tracing::info!("Removed ANTHROPIC_BASE_URL from {}", rc_path.display());
    }

    Ok(())
}
