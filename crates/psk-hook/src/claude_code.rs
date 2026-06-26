use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::PathBuf;

/// Substring identifying the PSK restore hook command (used for idempotent install/uninstall).
const RESTORE_CMD_MARKER: &str = "psk restore --hook";
/// Tools whose input may carry secret values that must be restored before they touch the machine.
const PRETOOLUSE_MATCHER: &str = "Write|Edit|MultiEdit|Bash";

/// Wire PSK into Claude Code:
/// 1. route API traffic through the local proxy (`ANTHROPIC_BASE_URL` in settings.json + shell rc),
/// 2. install a `PreToolUse` hook that restores real values from PSK tokens into local writes/commands.
pub fn install(proxy_port: u16, auth_token: &str) -> Result<()> {
    let mut settings = load_or_default_settings()?;
    set_base_url(&mut settings, proxy_port);
    set_restore_hook(&mut settings, proxy_port, auth_token);
    write_settings(&settings)?;
    // Shell rc fallback (covers terminals launched before settings.json env is read).
    install_env_var(proxy_port)?;
    Ok(())
}

/// Remove PSK base-URL override and restore hook from Claude Code.
pub fn uninstall() -> Result<()> {
    if let Some(path) = settings_path() {
        if path.exists() {
            let mut settings = load_or_default_settings()?;
            remove_base_url(&mut settings);
            remove_restore_hook(&mut settings);
            write_settings(&settings)?;
        }
    }
    uninstall_env_var()?;
    Ok(())
}

/// Whether the PSK restore hook is present in Claude Code settings.
pub fn is_installed() -> bool {
    let Some(settings) = load_settings() else {
        return false;
    };
    settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().any(is_psk_restore_entry))
        .unwrap_or(false)
}

fn settings_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".claude").join("settings.json"))
}

fn load_settings() -> Option<Value> {
    let path = settings_path()?;
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn load_or_default_settings() -> Result<Value> {
    let path = settings_path().context("Cannot find home directory")?;
    if path.exists() {
        let data = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str::<Value>(&data).unwrap_or_else(|_| json!({})))
    } else {
        Ok(json!({}))
    }
}

fn write_settings(settings: &Value) -> Result<()> {
    let path = settings_path().context("Cannot find home directory")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(settings)?)?;
    tracing::info!("Updated Claude Code settings at {}", path.display());
    Ok(())
}

fn set_base_url(settings: &mut Value, port: u16) {
    let obj = settings.as_object_mut().expect("settings is an object");
    let env = obj
        .entry("env")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("env is an object");
    env.insert(
        "ANTHROPIC_BASE_URL".to_string(),
        json!(format!("http://127.0.0.1:{}", port)),
    );
}

fn remove_base_url(settings: &mut Value) {
    if let Some(env) = settings.get_mut("env").and_then(|e| e.as_object_mut()) {
        env.remove("ANTHROPIC_BASE_URL");
    }
}

fn is_psk_restore_entry(entry: &Value) -> bool {
    entry
        .get("hooks")
        .and_then(|h| h.as_array())
        .map(|hooks| {
            hooks.iter().any(|h| {
                h.get("command")
                    .and_then(|c| c.as_str())
                    .map(|c| c.contains(RESTORE_CMD_MARKER))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn set_restore_hook(settings: &mut Value, port: u16, auth_token: &str) {
    let obj = settings.as_object_mut().expect("settings is an object");
    let hooks = obj
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("hooks is an object");
    let pre = hooks
        .entry("PreToolUse")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("PreToolUse is an array");

    // Drop any prior PSK entry, then add the current one.
    pre.retain(|e| !is_psk_restore_entry(e));
    pre.push(json!({
        "matcher": PRETOOLUSE_MATCHER,
        "hooks": [{
            "type": "command",
            "command": format!("psk restore --hook --port {} --auth {}", port, auth_token),
            "timeout": 10000
        }]
    }));
}

fn remove_restore_hook(settings: &mut Value) {
    if let Some(pre) = settings
        .get_mut("hooks")
        .and_then(|h| h.get_mut("PreToolUse"))
        .and_then(|v| v.as_array_mut())
    {
        pre.retain(|e| !is_psk_restore_entry(e));
    }
}

fn shell_rc_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let candidates = [".zshrc", ".bashrc", ".profile"];
    for name in &candidates {
        let p = home.join(name);
        if p.exists() {
            return Some(p);
        }
    }
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
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_round_trips() {
        let mut s = json!({});
        set_base_url(&mut s, 7878);
        assert_eq!(s["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:7878");
        remove_base_url(&mut s);
        assert!(s["env"].get("ANTHROPIC_BASE_URL").is_none());
    }

    #[test]
    fn restore_hook_is_idempotent_and_removable() {
        let mut s = json!({});
        set_restore_hook(&mut s, 7878, "tok");
        set_restore_hook(&mut s, 7878, "tok"); // second install must not duplicate
        let pre = s["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0]["matcher"], PRETOOLUSE_MATCHER);
        assert!(pre[0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("psk restore --hook --port 7878 --auth tok"));

        remove_restore_hook(&mut s);
        assert!(s["hooks"]["PreToolUse"].as_array().unwrap().is_empty());
    }

    #[test]
    fn preserves_unrelated_hooks() {
        let mut s = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Read", "hooks": [{"type":"command","command":"other-tool"}] }
            ]}
        });
        set_restore_hook(&mut s, 1234, "x");
        remove_restore_hook(&mut s);
        let pre = s["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0]["matcher"], "Read");
    }
}
