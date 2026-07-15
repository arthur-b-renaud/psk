//! The transparent `claude` shim: `~/.psk/bin/claude`, a tiny wrapper that re-invokes `psk run` so
//! that typing `claude` routes through the proxy launcher (see `run.rs`).
//!
//! Why a shim instead of `env.ANTHROPIC_BASE_URL` in `~/.claude/settings.json`: that env var is
//! static, but the proxy's liveness is not. A settings.json base URL pointing at a down proxy
//! breaks every `claude` invocation — the exact opposite of PSK's fail-open contract (`CLAUDE.md`
//! §4). The shim moves the base URL out of settings and into a per-process env set *only when the
//! proxy is confirmed up*, so a down proxy can never block the agent.
//!
//! This lives in `psk-cli`, not `psk-init`, on purpose: `psk-init` is a pure `settings.json`
//! editor (`CLAUDE.md` §7c) and knows nothing of `~/.psk`. The shim is a `~/.psk` artifact, so the
//! CLI — which already resolves `psk_home()` — owns it.

use std::io;
use std::path::{Path, PathBuf};

/// The basename installed onto `PATH`. Must match the binary the user actually types.
const SHIM_NAME: &str = "claude";

/// What `install` / `uninstall` did, so `psk init` / `psk uninit` can print an honest line.
#[derive(Debug, PartialEq, Eq)]
pub enum ShimOutcome {
    /// The shim was created, or its contents were brought up to date.
    Installed,
    /// The shim already existed with exactly the right contents.
    Unchanged,
    /// The shim file was present and has been removed.
    Removed,
    /// There was nothing to remove.
    Absent,
}

/// `<home>/bin` — the directory the user puts on `PATH`.
pub fn bin_dir(home: &Path) -> PathBuf {
    home.join("bin")
}

/// `<home>/bin/claude` — the shim itself.
pub fn shim_path(home: &Path) -> PathBuf {
    bin_dir(home).join(SHIM_NAME)
}

/// The script body. `psk_exe` is pinned as an **absolute** path (from `current_exe()`) so the shim
/// does not itself depend on `psk` being on `PATH` — and `exec` so signals and the exit code pass
/// straight through to `claude`.
fn shim_contents(psk_exe: &Path) -> String {
    // `"$@"` forwards claude's args verbatim; `--` guards against an arg that looks like a psk flag.
    format!(
        "#!/bin/sh\n# Installed by `psk init`. Routes `claude` through the PSK proxy launcher.\nexec {} run -- \"$@\"\n",
        shell_quote(&psk_exe.to_string_lossy())
    )
}

/// Single-quote a path for `/bin/sh`, so a space or other metacharacter in the install path cannot
/// break the shim. `'` inside is closed, escaped, and reopened: `it's` → `'it'\''s'`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Install (or refresh) `<home>/bin/claude`. Idempotent: re-running with the same `psk_exe` is a
/// no-op that returns `Unchanged`.
pub fn install(home: &Path, psk_exe: &Path) -> io::Result<ShimOutcome> {
    let dir = bin_dir(home);
    create_dir_private(&dir)?;

    let path = shim_path(home);
    let contents = shim_contents(psk_exe);

    // If it already matches, don't rewrite — keeps `psk init` a true no-op on repeat runs.
    if let Ok(existing) = std::fs::read_to_string(&path) {
        if existing == contents {
            return Ok(ShimOutcome::Unchanged);
        }
    }

    write_executable(&path, &contents)?;
    Ok(ShimOutcome::Installed)
}

/// Remove the shim, and the `bin` dir if it is now empty. Leaves a non-empty `bin` (the user may
/// keep other tools there) and never errors on a missing file.
pub fn uninstall(home: &Path) -> io::Result<ShimOutcome> {
    let path = shim_path(home);
    match std::fs::remove_file(&path) {
        Ok(()) => {
            // Best-effort: an empty dir is tidy to drop, a populated one must stay. `remove_dir`
            // fails on a non-empty dir, which we deliberately ignore.
            let _ = std::fs::remove_dir(bin_dir(home));
            Ok(ShimOutcome::Removed)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(ShimOutcome::Absent),
        Err(e) => Err(e),
    }
}

/// Is `<home>/bin` already on `$PATH`? Drives whether `psk init` prints the one-time PATH guidance.
pub fn bin_dir_on_path(home: &Path) -> bool {
    let target = bin_dir(home);
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|p| p == target))
        .unwrap_or(false)
}

/// Create `dir` with mode `0700`, matching how the vault protects `~/.psk` (`salt.rs`): the shim
/// dir sits beside the salt and should be no more permissive.
fn create_dir_private(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    set_mode(dir, 0o700)
}

/// Write `contents` to `path` atomically (temp + rename, like `psk_init::write`) and mark it
/// executable — a shim the shell cannot execute is silently useless.
fn write_executable(path: &Path, contents: &str) -> io::Result<()> {
    let tmp = path.with_extension("psk-tmp");
    std::fs::write(&tmp, contents)?;
    set_mode(&tmp, 0o755)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

// The shim is a `/bin/sh` script and only meaningful on Unix. On other targets the mode is a no-op;
// `psk init` still creates the file, but the launcher path is Unix-only by design.
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway `~/.psk` under the system temp dir, cleaned on drop. Mirrors the `PSK_HOME`
    /// idiom used across the crate so a test never touches a developer's real `~/.psk`.
    struct TempHome(PathBuf);
    impl TempHome {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("psk-shim-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            TempHome(p)
        }
    }
    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn install_writes_an_executable_shim_that_calls_psk_run() {
        let home = TempHome::new("install");
        let exe = Path::new("/opt/psk/bin/psk");

        assert_eq!(install(&home.0, exe).unwrap(), ShimOutcome::Installed);

        let path = shim_path(&home.0);
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.starts_with("#!/bin/sh"));
        // The absolute psk path is pinned, quoted, and invoked as `run`.
        assert!(body.contains("exec '/opt/psk/bin/psk' run -- \"$@\""), "body was: {body}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
    }

    #[test]
    fn install_is_idempotent() {
        let home = TempHome::new("idempotent");
        let exe = Path::new("/opt/psk/bin/psk");
        assert_eq!(install(&home.0, exe).unwrap(), ShimOutcome::Installed);
        assert_eq!(install(&home.0, exe).unwrap(), ShimOutcome::Unchanged);
    }

    #[test]
    fn install_refreshes_a_stale_shim() {
        let home = TempHome::new("stale");
        install(&home.0, Path::new("/old/psk")).unwrap();
        // A moved binary must update the pinned path, not be left dangling.
        assert_eq!(install(&home.0, Path::new("/new/psk")).unwrap(), ShimOutcome::Installed);
        let body = std::fs::read_to_string(shim_path(&home.0)).unwrap();
        assert!(body.contains("'/new/psk'"));
        assert!(!body.contains("'/old/psk'"));
    }

    #[test]
    fn uninstall_removes_the_shim_and_the_empty_bin_dir() {
        let home = TempHome::new("uninstall");
        install(&home.0, Path::new("/opt/psk/bin/psk")).unwrap();

        assert_eq!(uninstall(&home.0).unwrap(), ShimOutcome::Removed);
        assert!(!shim_path(&home.0).exists());
        assert!(!bin_dir(&home.0).exists(), "empty bin dir should be pruned");

        // Second uninstall is a clean no-op.
        assert_eq!(uninstall(&home.0).unwrap(), ShimOutcome::Absent);
    }

    #[test]
    fn uninstall_keeps_a_populated_bin_dir() {
        let home = TempHome::new("populated");
        install(&home.0, Path::new("/opt/psk/bin/psk")).unwrap();
        // A sibling tool the user put there must survive.
        std::fs::write(bin_dir(&home.0).join("other"), b"x").unwrap();

        assert_eq!(uninstall(&home.0).unwrap(), ShimOutcome::Removed);
        assert!(bin_dir(&home.0).exists());
        assert!(bin_dir(&home.0).join("other").exists());
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("/it's/psk"), "'/it'\\''s/psk'");
    }
}
