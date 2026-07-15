//! `psk hook` end to end, driving the compiled binary the way Claude Code does: hook JSON on
//! stdin, response on stdout, exit code as the signal.
//!
//! The wire format is the part that cannot be unit-tested — it is the contract with Claude Code —
//! so it is exercised here against the real binary. The restore *logic* is unit-tested in
//! `psk-proxy::hook`.

use std::io::Write;
use std::process::{Command, Stdio};

/// Run `psk hook` with `stdin`, in an isolated `PSK_HOME` (so no proxy is reachable — the
/// fail-open path). Returns (exit code, stdout, stderr).
fn run_hook(stdin: &str) -> (i32, String, String) {
    let bin = env!("CARGO_BIN_EXE_psk");
    // Unique per call: the tests run in parallel in one process, so a PID-only path would be shared
    // and one test's cleanup could delete another's config mid-run (a real race that flaked here).
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let seq = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let home = std::env::temp_dir().join(format!("psk-hookcli-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    // Point at a port nothing is listening on, so restore fails and the hook must fail open.
    std::fs::write(home.join("config.toml"), "bind = \"127.0.0.1:1\"\n").unwrap();

    let mut child = Command::new(bin)
        .arg("hook")
        .env("PSK_HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn psk hook");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();

    let _ = std::fs::remove_dir_all(&home);
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// With the proxy down, the hook must pass input through: exit 0, empty stdout. This is the
/// fail-open guarantee (brief §8b) — never block the agent because PSK is not running.
#[test]
fn proxy_down_fails_open_with_empty_stdout() {
    let (code, stdout, _stderr) =
        run_hook(r#"{"tool_name":"Bash","tool_input":{"command":"echo AKIAQPSK0000000000FK"}}"#);
    assert_eq!(code, 0, "must not block when the proxy is down");
    assert!(
        stdout.trim().is_empty(),
        "pass-through emits nothing, got: {stdout:?}"
    );
}

/// A tool PSK does not restore is passed through even when everything is up.
#[test]
fn unhandled_tool_passes_through() {
    let (code, stdout, _e) = run_hook(r#"{"tool_name":"Read","tool_input":{"file_path":"/x"}}"#);
    assert_eq!(code, 0);
    assert!(stdout.trim().is_empty());
}

/// Malformed stdin is a hook error. It must not crash into "tool runs with who-knows-what"; a
/// non-zero exit with a message is the right failure.
#[test]
fn malformed_stdin_is_a_clean_error() {
    let (code, stdout, stderr) = run_hook("{ not json");
    assert_ne!(code, 0, "malformed input must not silently succeed");
    assert!(stdout.trim().is_empty());
    assert!(stderr.contains("psk:"), "should explain itself: {stderr:?}");
}
