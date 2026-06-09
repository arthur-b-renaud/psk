//! ML/NER layer: GLiNER ONNX entity detection (`organization`/`person`/`location`/`address`).
//!
//! Built on the pure-Rust `gline-rs` inference engine (see `CLAUDE.md`). This crate is a stub
//! for now; the full implementation lands behind the `gliner` cargo feature so regex-only builds
//! compile without ONNX.

/// Whether the GLiNER runtime is compiled in and a model is loadable.
/// Always `false` until the `gliner` feature implementation lands.
pub fn available() -> bool {
    cfg!(feature = "gliner")
}
