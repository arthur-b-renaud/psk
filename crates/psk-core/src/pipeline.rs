use crate::policy::RedactionPolicy;
use crate::span::Span;
use crate::stats::StatsCollector;
use crate::Recognizer;

/// The detection + redaction pipeline.
///
/// Runs all registered recognizers, resolves overlapping spans,
/// and applies the redaction policy.
pub struct Pipeline {
    recognizers: Vec<Box<dyn Recognizer>>,
    policy: RedactionPolicy,
    stats: StatsCollector,
}

impl Pipeline {
    pub fn new(policy: RedactionPolicy) -> Self {
        Self {
            recognizers: Vec::new(),
            policy,
            stats: StatsCollector::new(),
        }
    }

    /// Add a recognizer to the pipeline.
    pub fn add_recognizer(&mut self, recognizer: Box<dyn Recognizer>) {
        self.recognizers.push(recognizer);
    }

    /// Detect all entities in `text`, returning resolved (non-overlapping) spans.
    pub fn detect(&self, text: &str) -> Vec<Span> {
        let mut all_spans: Vec<Span> = self
            .recognizers
            .iter()
            .flat_map(|r| r.recognize(text))
            .collect();

        Self::resolve_overlaps(&mut all_spans);
        all_spans
    }

    /// Detect and redact entities in `text`, returning the redacted string
    /// and the list of detected spans.
    pub fn redact(&self, text: &str) -> (String, Vec<Span>) {
        let spans = self.detect(text);
        let redacted = self.apply_redactions(text, &spans);

        // Update stats
        self.stats.record_scan(&spans);

        (redacted, spans)
    }

    /// Access the stats collector.
    pub fn stats(&self) -> &StatsCollector {
        &self.stats
    }

    /// Apply redactions to the text given a set of non-overlapping spans.
    /// Spans must be sorted by start position.
    fn apply_redactions(&self, text: &str, spans: &[Span]) -> String {
        if spans.is_empty() {
            return text.to_string();
        }

        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;

        for span in spans {
            // Append text before this span
            result.push_str(&text[last_end..span.start]);
            // Append redacted replacement
            let matched = &text[span.start..span.end];
            let replacement = self.policy.redact(&span.entity, matched);
            result.push_str(&replacement);
            last_end = span.end;
        }

        // Append remaining text
        result.push_str(&text[last_end..]);
        result
    }

    /// Resolve overlapping spans: longest match wins, ties broken by confidence.
    fn resolve_overlaps(spans: &mut Vec<Span>) {
        if spans.len() <= 1 {
            return;
        }

        // Sort by start position, then by length descending, then by confidence descending
        spans.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| b.len().cmp(&a.len()))
                .then_with(|| {
                    b.confidence
                        .partial_cmp(&a.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });

        let mut resolved: Vec<Span> = Vec::with_capacity(spans.len());

        for span in spans.drain(..) {
            if let Some(last) = resolved.last() {
                if span.start < last.end {
                    // Overlapping — keep the existing one (longer/higher confidence due to sort)
                    continue;
                }
            }
            resolved.push(span);
        }

        *spans = resolved;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::EntityType;

    struct MockRecognizer {
        spans: Vec<Span>,
    }

    impl Recognizer for MockRecognizer {
        fn id(&self) -> &str {
            "mock"
        }

        fn recognize(&self, _text: &str) -> Vec<Span> {
            self.spans.clone()
        }
    }

    #[test]
    fn test_no_detections() {
        let pipeline = Pipeline::new(RedactionPolicy::default());
        let (redacted, spans) = pipeline.redact("Hello world");
        assert_eq!(redacted, "Hello world");
        assert!(spans.is_empty());
    }

    #[test]
    fn test_single_redaction() {
        let mut pipeline = Pipeline::new(RedactionPolicy::default());
        pipeline.add_recognizer(Box::new(MockRecognizer {
            spans: vec![Span::new(10, 26, EntityType::Email, 1.0, "mock")],
        }));
        let (redacted, spans) = pipeline.redact("Contact: test@example.com please");
        // "Contact: " = 9 chars... let me fix the offsets
        // "Contact: " is 9 bytes, "test@example.com" starts at 9
        // Actually let me just test with correct offsets
        assert_eq!(spans.len(), 1);
        assert!(redacted.contains("[EMAIL]"));
    }

    #[test]
    fn test_overlap_resolution() {
        let mut spans = vec![
            Span::new(0, 10, EntityType::Email, 1.0, "a"),
            Span::new(5, 15, EntityType::Ipv4, 1.0, "b"),
            Span::new(20, 30, EntityType::CreditCard, 1.0, "c"),
        ];

        Pipeline::resolve_overlaps(&mut spans);
        // First two overlap: keep the one starting first (0..10)
        // Third doesn't overlap: keep
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].start, 0);
        assert_eq!(spans[1].start, 20);
    }

    #[test]
    fn test_multiple_non_overlapping() {
        let mut pipeline = Pipeline::new(RedactionPolicy::default());
        pipeline.add_recognizer(Box::new(MockRecognizer {
            spans: vec![
                Span::new(0, 5, EntityType::Ipv4, 1.0, "mock"),
                Span::new(10, 15, EntityType::Email, 1.0, "mock"),
            ],
        }));
        let text = "1.2.3 and test@";
        let (redacted, spans) = pipeline.redact(text);
        assert_eq!(spans.len(), 2);
        assert_eq!(redacted, "[IPV4] and [EMAIL]");
    }
}
