//! `psk run [claude-args…]` — the launcher behind the transparent `claude` shim (`shim.rs`).
//!
//! It guarantees the proxy is listening *before* `claude` is exec'd, then points that one child at
//! it via `ANTHROPIC_BASE_URL` in its environment — never in `~/.claude/settings.json`. This is the
//! fix for the settings.json landmine: the base URL now exists only when, and only for as long as,
//! the proxy is actually up. If the proxy cannot be brought up, `claude` still runs — unprotected
//! but never blocked (`CLAUDE.md` §4, fail-open).
//!
//! Flow: health-check → (spawn the proxy detached + wait, if down) → resolve the *real* `claude`
//! (skipping our own shim) → exec it with the base URL in its env.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};

use crate::client::HttpRestore;

/// The env var Claude Code reads to route requests through the proxy.
const BASE_URL_VAR: &str = "ANTHROPIC_BASE_URL";

/// How long to wait for a freshly spawned proxy to start answering `/health` before giving up and
/// running `claude` unprotected. ~3s: generous for a localhost bind, short enough not to stall.
const STARTUP_POLLS: u32 = 30;
const STARTUP_INTERVAL: Duration = Duration::from_millis(100);

/// Entry point for the `Run` subcommand. `rest` is forwarded to `claude` verbatim.
pub fn cmd_run(rest: Vec<String>) -> Result<std::process::ExitCode> {
    let config = crate::load_config()?;
    let bind = config.bind;
    let home = psk_vault::salt::psk_home().context("locating ~/.psk")?;
    let base_url = format!("http://{bind}");

    let up = ensure_proxy(&bind, &home);
    if !up {
        // A warning, not a failure: the whole point is that we still launch. Goes to stderr so it
        // does not pollute anything reading claude's stdout.
        eprintln!(
            "psk: proxy at {bind} is not reachable — launching claude WITHOUT secret protection.\n\
             psk: start it yourself with `psk proxy`, or check {}.",
            home.join("proxy.log").display()
        );
    }

    let claude = resolve_claude(&home)?;
    exec_claude(&claude, &rest, &base_url, up, &home)
}

/// Return true if the proxy is answering. If it is not, spawn it detached and poll until it comes
/// up (or the startup budget expires).
fn ensure_proxy(bind: &std::net::SocketAddr, home: &Path) -> bool {
    let client = HttpRestore::new(bind);
    if client.is_up() {
        return true;
    }

    if let Err(e) = spawn_proxy_detached(home) {
        eprintln!("psk: could not start the proxy: {e:#}");
        return false;
    }

    for _ in 0..STARTUP_POLLS {
        std::thread::sleep(STARTUP_INTERVAL);
        if client.is_up() {
            return true;
        }
    }
    false
}

/// Spawn `psk proxy` as a detached background process: a new session (so a Ctrl-C in the
/// foreground `claude` process group does not also kill the proxy), stdio pointed at
/// `<home>/proxy.log`, and never waited on — it outlives this launcher and is shared by every later
/// session.
fn spawn_proxy_detached(home: &Path) -> Result<()> {
    let exe = std::env::current_exe().context("finding the psk executable")?;

    let log_path = home.join("proxy.log");
    // The proxy's own dir may not exist yet on a very first run; the proxy will create ~/.psk for
    // the salt, but the log open happens first, so ensure the dir here.
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening {}", log_path.display()))?;
    let log_err = log.try_clone().context("duplicating the proxy log handle")?;

    let mut cmd = Command::new(exe);
    cmd.arg("proxy")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log_err));
    detach(&mut cmd);

    cmd.spawn().context("spawning `psk proxy`")?;
    // Deliberately drop the child handle without waiting: we want it to keep running.
    Ok(())
}

/// Put the spawned proxy in its own session so terminal signals sent to the foreground process
/// group (claude) do not reach it.
#[cfg(unix)]
fn detach(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: `setsid` is async-signal-safe and touches no shared state in the forked child; this
    // is exactly the pattern `pre_exec` exists for.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn detach(_cmd: &mut Command) {}

/// Find the real `claude` on `PATH`, skipping our shim so we do not exec ourselves in a loop.
fn resolve_claude(home: &Path) -> Result<PathBuf> {
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let bin_dir = crate::shim::bin_dir(home);
    find_claude(&path_var, &bin_dir, is_executable_file).ok_or_else(|| {
        anyhow!(
            "could not find a `claude` executable on PATH (excluding the psk shim at {}). \
             Is Claude Code installed?",
            crate::shim::shim_path(home).display()
        )
    })
}

/// Pure `PATH` walk, with the executable check injected so it is unit-testable without a real
/// `claude` on disk. Returns the first `claude` in a directory other than the shim dir.
fn find_claude<F: Fn(&Path) -> bool>(
    path_var: &OsStr,
    bin_dir: &Path,
    is_exec: F,
) -> Option<PathBuf> {
    std::env::split_paths(path_var)
        .filter(|dir| dir != bin_dir)
        .map(|dir| dir.join("claude"))
        .find(|candidate| is_exec(candidate))
}

/// `PATH` with the shim dir removed, so any `claude` the child re-execs cannot bounce back through
/// the shim. Protection still reaches such a child via the inherited `ANTHROPIC_BASE_URL`.
fn sanitized_path(path_var: &OsStr, bin_dir: &Path) -> OsString {
    let kept: Vec<PathBuf> = std::env::split_paths(path_var)
        .filter(|dir| dir != bin_dir)
        .collect();
    std::env::join_paths(kept).unwrap_or_else(|_| path_var.to_os_string())
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // `metadata` follows symlinks, so a symlinked `claude` (the common npm install shape) counts,
    // and a broken symlink errors out and is skipped.
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Replace this process with `claude`. On success it never returns; the returned error is always a
/// failure to launch.
fn exec_claude(
    claude: &Path,
    rest: &[String],
    base_url: &str,
    up: bool,
    home: &Path,
) -> Result<std::process::ExitCode> {
    let mut cmd = Command::new(claude);
    cmd.args(rest);

    // Strip the shim dir from the child's PATH (see `sanitized_path`).
    let bin_dir = crate::shim::bin_dir(home);
    if let Some(path_var) = std::env::var_os("PATH") {
        cmd.env("PATH", sanitized_path(&path_var, &bin_dir));
    }

    // Point claude at the proxy, or actively protect it from a stale pointer:
    //  - up            → set our base URL (overriding any inherited one; the user asked for PSK).
    //  - down + our URL inherited → REMOVE it. It would send claude at a proxy we just found dead,
    //    reintroducing the very landmine this shim exists to kill.
    //  - down + a different URL inherited → leave it: it may be a third-party gateway, not ours.
    if up {
        cmd.env(BASE_URL_VAR, base_url);
    } else if std::env::var(BASE_URL_VAR).is_ok_and(|v| v == base_url) {
        cmd.env_remove(BASE_URL_VAR);
    }

    run_to_completion(cmd, claude)
}

#[cfg(unix)]
fn run_to_completion(mut cmd: Command, claude: &Path) -> Result<std::process::ExitCode> {
    use std::os::unix::process::CommandExt;
    // `exec` replaces the image, so signals and the exit code pass straight through to claude.
    let err = cmd.exec();
    Err(anyhow::Error::new(err).context(format!("failed to exec {}", claude.display())))
}

#[cfg(not(unix))]
fn run_to_completion(mut cmd: Command, claude: &Path) -> Result<std::process::ExitCode> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to run {}", claude.display()))?;
    let code = status.code().unwrap_or(1);
    Ok(std::process::ExitCode::from(code as u8))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path_of(dirs: &[&str]) -> OsString {
        std::env::join_paths(dirs.iter().map(Path::new)).unwrap()
    }

    #[test]
    fn find_claude_skips_the_shim_dir() {
        let path = path_of(&["/home/u/.psk/bin", "/usr/local/bin", "/usr/bin"]);
        let bin_dir = Path::new("/home/u/.psk/bin");
        // Pretend every candidate is executable; the shim dir must still be skipped.
        let found = find_claude(&path, bin_dir, |_| true);
        assert_eq!(found, Some(PathBuf::from("/usr/local/bin/claude")));
    }

    #[test]
    fn find_claude_returns_first_executable_match() {
        let path = path_of(&["/a", "/b", "/c"]);
        let bin_dir = Path::new("/home/u/.psk/bin");
        // Only /b/claude is "executable".
        let found = find_claude(&path, bin_dir, |p| p == Path::new("/b/claude"));
        assert_eq!(found, Some(PathBuf::from("/b/claude")));
    }

    #[test]
    fn find_claude_none_when_only_the_shim_exists() {
        let path = path_of(&["/home/u/.psk/bin"]);
        let bin_dir = Path::new("/home/u/.psk/bin");
        assert_eq!(find_claude(&path, bin_dir, |_| true), None);
    }

    #[test]
    fn sanitized_path_drops_only_the_shim_dir() {
        let path = path_of(&["/home/u/.psk/bin", "/usr/local/bin", "/usr/bin"]);
        let bin_dir = Path::new("/home/u/.psk/bin");
        let out = sanitized_path(&path, bin_dir);
        let dirs: Vec<PathBuf> = std::env::split_paths(&out).collect();
        assert_eq!(dirs, vec![PathBuf::from("/usr/local/bin"), PathBuf::from("/usr/bin")]);
    }
}
