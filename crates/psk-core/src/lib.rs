//! `psk-core` — text in, substituted text plus vault operations out.
//!
//! This is the only crate that knows how detection, verification, and the vault fit together:
//!
//! ```text
//! recognizers -> overlap resolution -> fake-recognition guard -> vault.substitute
//! ```
//!
//! The proxy, the CLI, and the hook all go through [`Engine`]. New detectors arrive as new
//! [`Recognizer`] implementations and nothing downstream changes.

pub mod engine;
pub mod recognizer;

pub use engine::{Engine, Summary};
pub use psk_secrets::ScanConfig;
pub use psk_vault::{SecretKind, Vault, VaultError};
pub use psk_verifiers::VerifierConfig;
pub use recognizer::{Match, Recognizer, RegexRecognizer};
