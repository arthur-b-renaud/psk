//! The persisted salt (brief §7a).
//!
//! Claude Code resends the full conversation history on every request. If the proxy restarted
//! with a fresh random salt, the history would contain fakes the new vault has never seen — and
//! those fakes pattern-match as real secrets, so they would be substituted *again*, cascading
//! into a corrupted mapping. A salt that survives restart makes the fake derivation reproducible,
//! so a restarted proxy re-derives identical fakes and rebuilds its mapping on the fly.
//!
//! A salt is a key, not content. Persisting it does not violate PSK's "no prompt or response
//! content on disk, ever" rule (brief §14).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::VaultError;

pub const SALT_LEN: usize = 32;

/// Where PSK keeps the salt (and, later, `stats.json`).
///
/// `PSK_HOME` overrides the default so tests never touch the developer's real `~/.psk`.
pub fn psk_home() -> Result<PathBuf, VaultError> {
    if let Some(dir) = std::env::var_os("PSK_HOME") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME").ok_or(VaultError::NoHome)?;
    Ok(Path::new(&home).join(".psk"))
}

/// Load the salt from `<psk_home>/salt`, creating it on first run.
///
/// Returns the same 32 bytes on every subsequent call, which is the whole point.
pub fn load_or_create(dir: &Path) -> Result<[u8; SALT_LEN], VaultError> {
    create_dir_private(dir)?;
    let path = dir.join("salt");

    match fs::read(&path) {
        Ok(bytes) if bytes.len() == SALT_LEN => {
            let mut salt = [0u8; SALT_LEN];
            salt.copy_from_slice(&bytes);
            return Ok(salt);
        }
        // A truncated or oversized salt file is corruption, not a reason to silently mint a new
        // one: a new salt would invalidate every fake in the live conversation history.
        Ok(bytes) => {
            return Err(VaultError::CorruptSalt {
                path: path.clone(),
                len: bytes.len(),
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(VaultError::Io(e)),
    }

    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| VaultError::Random(e.to_string()))?;

    // Write to a unique temp file, fsync, then rename. `rename` is atomic within a directory,
    // so two processes racing on first run both end up seeing one consistent salt — and the
    // loser detects it by re-reading below rather than clobbering the winner's file.
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    write_private(&tmp, &salt)?;
    match fs::hard_link(&tmp, &path) {
        Ok(()) => {
            let _ = fs::remove_file(&tmp);
            Ok(salt)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another process won the race. Adopt its salt; ours never leaves this function.
            let _ = fs::remove_file(&tmp);
            let bytes = fs::read(&path)?;
            if bytes.len() != SALT_LEN {
                return Err(VaultError::CorruptSalt {
                    path,
                    len: bytes.len(),
                });
            }
            salt.copy_from_slice(&bytes);
            Ok(salt)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(VaultError::Io(e))
        }
    }
}

/// `mkdir -p` with mode 0700 on the final component.
fn create_dir_private(dir: &Path) -> Result<(), VaultError> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    set_mode(dir, 0o700)
}

/// Create `path` with mode 0600 *before* any bytes reach it, fsync, close.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Set the mode in the `open(2)` call itself: a chmod afterwards leaves a window in
        // which the salt is world-readable.
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), VaultError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), VaultError> {
    Ok(()) // Windows packaging is out of scope for M1.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory that removes itself. Avoids a `tempfile` dependency for two tests.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("psk-salt-test-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn creates_then_reuses_the_same_salt() {
        let d = TempDir::new("reuse");
        let first = load_or_create(&d.0).unwrap();
        let second = load_or_create(&d.0).unwrap();
        assert_eq!(first, second, "salt must be stable across calls");
        assert_ne!(first, [0u8; SALT_LEN], "salt must not be all zeroes");
    }

    #[cfg(unix)]
    #[test]
    fn salt_file_is_0600_inside_a_0700_dir() {
        use std::os::unix::fs::PermissionsExt;
        let d = TempDir::new("perms");
        load_or_create(&d.0).unwrap();
        let dir_mode = fs::metadata(&d.0).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(d.0.join("salt")).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "psk home must not be group/world readable");
        assert_eq!(file_mode, 0o600, "salt must not be group/world readable");
    }

    #[test]
    fn corrupt_salt_is_an_error_not_a_silent_regeneration() {
        let d = TempDir::new("corrupt");
        load_or_create(&d.0).unwrap();
        fs::write(d.0.join("salt"), b"short").unwrap();
        assert!(matches!(
            load_or_create(&d.0),
            Err(VaultError::CorruptSalt { .. })
        ));
    }
}
