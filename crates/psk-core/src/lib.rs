pub mod pipeline;
pub mod policy;
pub mod span;
pub mod stats;

pub use pipeline::Pipeline;
pub use policy::{RedactionAction, RedactionPolicy};
pub use span::{EntityType, Span};
pub use stats::StatsCollector;

/// A recognizer detects entities in text and returns spans.
pub trait Recognizer: Send + Sync {
    /// Unique identifier for this recognizer (e.g., "regex:email", "ner:person").
    fn id(&self) -> &str;

    /// Scan `text` and return all detected spans.
    fn recognize(&self, text: &str) -> Vec<Span>;
}
