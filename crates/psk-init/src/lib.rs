//! `psk init` / `psk uninit`: manage PSK's `PreToolUse` hook entry in `~/.claude/settings.json`.
//!
//! The hook is what restores real secrets at the execution boundary (brief §2b, §8b). Without it,
//! `restore_mode = "execution"` would send fakes into `Bash`/`Edit`/`Write` — the tool would run on
//! the fake value, which is wrong.
//!
//! Both operations are **idempotent** and report exactly what they changed, because editing a
//! user's Claude Code settings behind their back is exactly the kind of thing that should be
//! legible. Every other key in `settings.json` is preserved byte-for-byte in structure; only the
//! one hook entry is added or removed.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

/// The tools whose input PSK restores. Anything that writes to disk or executes a command.
pub const MATCHER: &str = "Edit|Write|Bash";

/// The command Claude Code runs for the hook. `psk` must be on `PATH`.
pub const HOOK_COMMAND: &str = "psk hook";

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("cannot locate the Claude settings directory: HOME is not set")]
    NoHome,
    #[error("{path} is not valid JSON: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
    #[error(
        "{path} has an unexpected shape at `{pointer}`: expected {expected}, so PSK will not edit it by hand"
    )]
    Shape {
        path: String,
        pointer: String,
        expected: &'static str,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// What an `init`/`uninit` did, for a legible one-line report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The hook was added.
    Added,
    /// The hook was already present, byte-identical; nothing changed.
    AlreadyPresent,
    /// The hook was removed.
    Removed,
    /// No PSK hook was there to remove; nothing changed.
    Absent,
}

impl Outcome {
    /// Did this operation modify the file on disk?
    pub fn changed(self) -> bool {
        matches!(self, Outcome::Added | Outcome::Removed)
    }
}

/// The default settings path, `~/.claude/settings.json`.
pub fn default_settings_path() -> Result<PathBuf, InitError> {
    let home = std::env::var_os("HOME").ok_or(InitError::NoHome)?;
    Ok(Path::new(&home).join(".claude").join("settings.json"))
}

/// Add PSK's `PreToolUse` hook to `path`, creating the file (and its parent) if absent.
pub fn init(path: &Path) -> Result<Outcome, InitError> {
    let mut root = read_or_empty(path)?;
    let hooks = object_at(&mut root, "hooks", path)?;
    let entries = array_at(hooks, "PreToolUse", path)?;

    if entries.iter().any(is_psk_entry) {
        return Ok(Outcome::AlreadyPresent);
    }
    entries.push(psk_entry());
    write(path, &root)?;
    Ok(Outcome::Added)
}

/// Remove PSK's `PreToolUse` hook from `path`. A missing file is simply "absent".
pub fn uninit(path: &Path) -> Result<Outcome, InitError> {
    let mut root = match read(path)? {
        Some(v) => v,
        None => return Ok(Outcome::Absent),
    };

    // Navigate defensively: a user may have removed `hooks` entirely, and that is not an error.
    let Some(entries) = root
        .get_mut("hooks")
        .and_then(|h| h.get_mut("PreToolUse"))
        .and_then(Value::as_array_mut)
    else {
        return Ok(Outcome::Absent);
    };

    let before = entries.len();
    entries.retain(|e| !is_psk_entry(e));
    if entries.len() == before {
        return Ok(Outcome::Absent);
    }

    // Leave the surrounding structure tidy: an emptied `PreToolUse`, and an emptied `hooks`, are
    // removed so `uninit` returns the file to something close to its pre-`init` shape.
    prune_empty(&mut root);
    write(path, &root)?;
    Ok(Outcome::Removed)
}

/// Is the PSK hook currently installed in `path`?
pub fn is_installed(path: &Path) -> Result<bool, InitError> {
    Ok(read(path)?
        .and_then(|root| {
            root.get("hooks")
                .and_then(|h| h.get("PreToolUse"))
                .and_then(Value::as_array)
                .map(|entries| entries.iter().any(is_psk_entry))
        })
        .unwrap_or(false))
}

/// The hook entry PSK installs. Claude Code's shape: a matcher plus a list of hook commands.
fn psk_entry() -> Value {
    json!({
        "matcher": MATCHER,
        "hooks": [{ "type": "command", "command": HOOK_COMMAND }]
    })
}

/// Recognise a PSK entry by its command, not by exact equality — so a user who added their own
/// `matcher` tweak is still recognised, and `init` stays idempotent against it.
fn is_psk_entry(entry: &Value) -> bool {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|hooks| {
            hooks
                .iter()
                .any(|h| h.get("command").and_then(Value::as_str) == Some(HOOK_COMMAND))
        })
}

// -- JSON navigation that refuses to clobber an unexpected shape -------------------------------

/// Borrow `root[key]` as an object, creating an empty one if the key is absent. Errors if the key
/// exists but is not an object, rather than overwriting whatever the user had there.
fn object_at<'a>(
    root: &'a mut Value,
    key: &'static str,
    path: &Path,
) -> Result<&'a mut Value, InitError> {
    let obj = root.as_object_mut().ok_or_else(|| InitError::Shape {
        path: path.display().to_string(),
        pointer: "/".into(),
        expected: "a JSON object at the top level",
    })?;
    let entry = obj.entry(key).or_insert_with(|| Value::Object(Map::new()));
    if !entry.is_object() {
        return Err(InitError::Shape {
            path: path.display().to_string(),
            pointer: format!("/{key}"),
            expected: "an object",
        });
    }
    Ok(entry)
}

/// Borrow `obj[key]` as an array, creating an empty one if absent.
fn array_at<'a>(
    obj: &'a mut Value,
    key: &'static str,
    path: &Path,
) -> Result<&'a mut Vec<Value>, InitError> {
    let map = obj.as_object_mut().expect("caller passed an object");
    let entry = map.entry(key).or_insert_with(|| Value::Array(Vec::new()));
    entry.as_array_mut().ok_or_else(|| InitError::Shape {
        path: path.display().to_string(),
        pointer: format!("/hooks/{key}"),
        expected: "an array",
    })
}

/// Drop an empty `PreToolUse` array and, if that leaves `hooks` empty, drop `hooks` too.
fn prune_empty(root: &mut Value) {
    let Some(obj) = root.as_object_mut() else {
        return;
    };
    if let Some(hooks) = obj.get_mut("hooks").and_then(Value::as_object_mut) {
        if hooks
            .get("PreToolUse")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            hooks.remove("PreToolUse");
        }
        if hooks.is_empty() {
            obj.remove("hooks");
        }
    }
}

// -- file IO -----------------------------------------------------------------------------------

fn read(path: &Path) -> Result<Option<Value>, InitError> {
    match std::fs::read_to_string(path) {
        Ok(text) if text.trim().is_empty() => Ok(Some(Value::Object(Map::new()))),
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|source| InitError::Parse {
                path: path.display().to_string(),
                source,
            }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(InitError::Io(e)),
    }
}

fn read_or_empty(path: &Path) -> Result<Value, InitError> {
    Ok(read(path)?.unwrap_or_else(|| Value::Object(Map::new())))
}

/// Write atomically: a crash mid-write must not truncate the user's settings.
fn write(path: &Path, value: &Value) -> Result<(), InitError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Pretty-printed with a trailing newline, matching how Claude Code writes the file, so a diff
    // against the user's editor stays minimal.
    let mut json = serde_json::to_string_pretty(value).expect("Value re-serializes");
    json.push('\n');

    let tmp = path.with_extension("json.psk-tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempFile(PathBuf);
    impl TempFile {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir()
                .join(format!("psk-init-{tag}-{}", std::process::id()))
                .join("settings.json");
            let _ = std::fs::remove_dir_all(p.parent().unwrap());
            TempFile(p)
        }
        fn read(&self) -> Value {
            serde_json::from_str(&std::fs::read_to_string(&self.0).unwrap()).unwrap()
        }
        fn put(&self, v: &Value) {
            std::fs::create_dir_all(self.0.parent().unwrap()).unwrap();
            std::fs::write(&self.0, serde_json::to_string_pretty(v).unwrap()).unwrap();
        }
    }
    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
        }
    }

    #[test]
    fn init_creates_the_file_when_absent() {
        let f = TempFile::new("create");
        assert_eq!(init(&f.0).unwrap(), Outcome::Added);
        assert!(is_installed(&f.0).unwrap());
        assert_eq!(
            f.read()["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            HOOK_COMMAND
        );
        assert_eq!(f.read()["hooks"]["PreToolUse"][0]["matcher"], MATCHER);
    }

    #[test]
    fn init_is_idempotent() {
        let f = TempFile::new("idem");
        assert_eq!(init(&f.0).unwrap(), Outcome::Added);
        assert_eq!(init(&f.0).unwrap(), Outcome::AlreadyPresent);
        // Exactly one entry, no duplicate.
        assert_eq!(f.read()["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn init_preserves_unrelated_settings_and_other_hooks() {
        let f = TempFile::new("preserve");
        f.put(&json!({
            "model": "opus",
            "permissions": {"allow": ["Bash(ls:*)"]},
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Read", "hooks": [{"type": "command", "command": "other-tool"}]}
                ],
                "Stop": [{"matcher": "", "hooks": [{"type": "command", "command": "notify"}]}]
            }
        }));
        assert_eq!(init(&f.0).unwrap(), Outcome::Added);

        let v = f.read();
        assert_eq!(v["model"], "opus");
        assert_eq!(v["permissions"]["allow"][0], "Bash(ls:*)");
        assert_eq!(v["hooks"]["Stop"][0]["hooks"][0]["command"], "notify");
        // The user's own PreToolUse hook survives alongside ours.
        let pre = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2);
        assert!(pre.iter().any(|e| e["hooks"][0]["command"] == "other-tool"));
        assert!(pre.iter().any(is_psk_entry));
    }

    #[test]
    fn uninit_removes_only_the_psk_hook() {
        let f = TempFile::new("uninit");
        f.put(&json!({
            "hooks": {"PreToolUse": [
                {"matcher": "Read", "hooks": [{"type": "command", "command": "other-tool"}]}
            ]}
        }));
        init(&f.0).unwrap();
        assert_eq!(uninit(&f.0).unwrap(), Outcome::Removed);

        let pre = f.read()["hooks"]["PreToolUse"].as_array().unwrap().clone();
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0]["hooks"][0]["command"], "other-tool");
        assert!(!is_installed(&f.0).unwrap());
    }

    #[test]
    fn uninit_prunes_empty_containers_it_created() {
        let f = TempFile::new("prune");
        init(&f.0).unwrap(); // creates hooks.PreToolUse with only our entry
        assert_eq!(uninit(&f.0).unwrap(), Outcome::Removed);
        // Nothing of ours, and no empty scaffolding left behind.
        assert_eq!(f.read().get("hooks"), None);
    }

    #[test]
    fn uninit_on_a_missing_file_is_absent_not_an_error() {
        let f = TempFile::new("missing");
        assert_eq!(uninit(&f.0).unwrap(), Outcome::Absent);
    }

    #[test]
    fn uninit_twice_is_idempotent() {
        let f = TempFile::new("uninit-idem");
        init(&f.0).unwrap();
        assert_eq!(uninit(&f.0).unwrap(), Outcome::Removed);
        assert_eq!(uninit(&f.0).unwrap(), Outcome::Absent);
    }

    #[test]
    fn a_wrongly_typed_hooks_field_is_an_error_not_a_clobber() {
        let f = TempFile::new("badshape");
        f.put(&json!({"hooks": "not an object"}));
        assert!(matches!(init(&f.0), Err(InitError::Shape { .. })));
        // The user's file is untouched.
        assert_eq!(f.read()["hooks"], "not an object");
    }

    #[test]
    fn malformed_json_is_reported_not_overwritten() {
        let f = TempFile::new("malformed");
        std::fs::create_dir_all(f.0.parent().unwrap()).unwrap();
        std::fs::write(&f.0, "{ not json").unwrap();
        assert!(matches!(init(&f.0), Err(InitError::Parse { .. })));
    }
}
