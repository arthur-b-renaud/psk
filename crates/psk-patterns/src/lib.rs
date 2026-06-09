pub mod loader;
pub mod recognizer;
pub mod validators;

pub use recognizer::RegexRecognizer;

use psk_core::Recognizer;
use std::path::Path;

/// Load all built-in pattern packs and return a list of recognizers.
pub fn builtin_recognizers() -> Vec<Box<dyn Recognizer>> {
    let patterns_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../patterns");
    load_recognizers_from_dir(&patterns_dir)
}

/// Load recognizers from all YAML files in a directory.
pub fn load_recognizers_from_dir(dir: &Path) -> Vec<Box<dyn Recognizer>> {
    let mut recognizers: Vec<Box<dyn Recognizer>> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                match loader::load_pattern_file(&path) {
                    Ok(defs) => {
                        let pack_name = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown");
                        for def in defs {
                            match RegexRecognizer::from_definition(pack_name, &def) {
                                Ok(r) => recognizers.push(Box::new(r)),
                                Err(e) => {
                                    tracing::warn!(
                                        "Skipping pattern '{}' in {}: {}",
                                        def.name,
                                        path.display(),
                                        e
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load pattern file {}: {}", path.display(), e);
                    }
                }
            }
        }
    }

    recognizers
}
