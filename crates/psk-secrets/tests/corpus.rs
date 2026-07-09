//! The external-corpus gate (brief §12).
//!
//! Self-graded fixtures prove nothing to an open-source audience. This scores PSK's detection
//! against a **third-party** labelled corpus extracted from gitleaks (MIT), whose false positives
//! were curated by people with no stake in making our numbers look good.
//!
//! The corpus lives in its own repository and is **not** required to build or test PSK:
//!
//! ```sh
//! ./scripts/fetch-corpus.sh                                   # clones into corpus/
//! PSK_REQUIRE_CORPUS=1 cargo test -p psk-secrets --test corpus
//! ```
//!
//! Without `corpus/`, this test prints a hint and passes, so `cargo test` stays hermetic and
//! offline for anyone who just cloned the repo. CI sets `PSK_REQUIRE_CORPUS=1`, so the floor is
//! always enforced somewhere.

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::Engine as _;
use psk_secrets::{ScanConfig, scan};
use psk_vault::SecretKind;

/// The precision floor for the M1 rule kinds, from the brief. Deliberately not 1.0: a self-graded
/// 100% would mean the corpus had been tuned to the code.
const PRECISION_FLOOR: f64 = 0.95;

struct Row {
    source_rule: String,
    label: String,
    kind: Option<SecretKind>,
    value: String,
    /// gitleaks' `fps` are *per-rule* negatives, not "this is not a secret". Where a rule's
    /// negatives contain a valid instance of a sibling rule mapping to the same (coarser) PSK
    /// kind, detecting it is correct behaviour and the row is excluded. The reason travels with
    /// the data, in the manifest.
    exclude_from_fp: bool,
}

fn kind_from_str(s: &str) -> Option<SecretKind> {
    SecretKind::ALL
        .iter()
        .copied()
        .find(|k| format!("{k:?}") == s)
}

fn corpus_path() -> PathBuf {
    if let Ok(dir) = std::env::var("PSK_CORPUS_DIR") {
        return PathBuf::from(dir).join("manifest.jsonl");
    }
    // `crates/psk-secrets` -> workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("corpus/manifest.jsonl")
}

fn load() -> Option<Vec<Row>> {
    let path = corpus_path();
    let text = std::fs::read_to_string(&path).ok()?;

    let mut rows = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("corpus row must be JSON");
        let b64 = v["value_b64"].as_str().expect("value_b64");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("value_b64 must be valid base64");
        rows.push(Row {
            source_rule: v["source_rule"].as_str().unwrap_or_default().to_string(),
            label: v["label"].as_str().unwrap_or_default().to_string(),
            kind: v["kind"].as_str().and_then(kind_from_str),
            value: String::from_utf8(bytes).expect("corpus values are UTF-8"),
            exclude_from_fp: v["exclude_from_fp"].as_bool().unwrap_or(false),
        });
    }
    Some(rows)
}

/// Truncate for a readable failure message. Never print a whole PEM block into CI logs.
fn snippet(s: &str) -> String {
    let one_line: String = s
        .chars()
        .map(|c| if c == '\n' { '\u{23ce}' } else { c })
        .collect();
    if one_line.chars().count() <= 60 {
        one_line
    } else {
        format!("{}…", one_line.chars().take(60).collect::<String>())
    }
}

#[test]
fn precision_and_recall_against_the_gitleaks_corpus() {
    let Some(rows) = load() else {
        let required = std::env::var("PSK_REQUIRE_CORPUS").is_ok_and(|v| v == "1");
        assert!(
            !required,
            "PSK_REQUIRE_CORPUS=1 but no corpus at {}. Run ./scripts/fetch-corpus.sh",
            corpus_path().display()
        );
        eprintln!(
            "corpus absent at {} — skipping the external gate.\n\
             Run ./scripts/fetch-corpus.sh to enable it.",
            corpus_path().display()
        );
        return;
    };

    // The shipping configuration. Network rules stay off, exactly as a user would run it.
    let cfg = ScanConfig::default();

    let mut detected_tp = 0usize;
    let mut total_tp = 0usize;
    let mut detected_fp = 0usize;

    let mut recall_by_kind: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    // `kind -> (true positives detected, false positives detected)`
    let mut precision_by_kind: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut tp_misses: Vec<String> = Vec::new();
    let mut fp_hits: Vec<String> = Vec::new();
    let mut collateral: Vec<String> = Vec::new();

    for row in &rows {
        let matches = scan(&row.value, &cfg);

        match (row.label.as_str(), row.kind) {
            // A true positive of a rule we implement: we must find it, as the right kind.
            ("tp", Some(kind)) => {
                total_tp += 1;
                let entry = recall_by_kind.entry(format!("{kind:?}")).or_insert((0, 0));
                entry.1 += 1;

                if matches.iter().any(|m| m.kind == kind) {
                    detected_tp += 1;
                    entry.0 += 1;
                    precision_by_kind.entry(format!("{kind:?}")).or_default().0 += 1;
                } else {
                    tp_misses.push(format!(
                        "  MISS {kind:?} [{}] {}",
                        row.source_rule,
                        snippet(&row.value)
                    ));
                }
            }
            // A true positive of a rule we do not implement: excluded from both metrics. Counting
            // it as a miss would penalise us for scope we never claimed.
            ("tp", None) => {}

            // A negative of a rule we implement. The rule-level contract: *our detector for this
            // kind* must not fire. A detection of some other kind is not evidence about this rule.
            ("fp", Some(kind)) if !row.exclude_from_fp => {
                if let Some(m) = matches.iter().find(|m| m.kind == kind) {
                    detected_fp += 1;
                    precision_by_kind.entry(format!("{kind:?}")).or_default().1 += 1;
                    fp_hits.push(format!(
                        "  FP {kind:?} in [{}] {} :: matched {:?}",
                        row.source_rule,
                        snippet(&row.value),
                        snippet(&row.value[m.start..m.end])
                    ));
                }
            }
            // A negative of a rule we do not implement. Detecting something here is *usually* a
            // real false positive, but not always: `curl-auth-header`'s negatives contain a
            // genuine JWT, and finding it is correct. Reported, never gated — a noisy signal must
            // not be allowed to fail the build, and must not be silently discarded either.
            ("fp", None) => {
                if let Some(m) = matches.first() {
                    collateral.push(format!(
                        "  {:?} in [{}] {} :: matched {:?}",
                        m.kind,
                        row.source_rule,
                        snippet(&row.value),
                        snippet(&row.value[m.start..m.end])
                    ));
                }
            }
            _ => {}
        }
    }

    let precision = if detected_tp + detected_fp == 0 {
        1.0
    } else {
        detected_tp as f64 / (detected_tp + detected_fp) as f64
    };
    let recall = if total_tp == 0 {
        1.0
    } else {
        detected_tp as f64 / total_tp as f64
    };

    eprintln!("\n=== gitleaks corpus ({} rows) ===", rows.len());
    eprintln!("precision {precision:.4}  (floor {PRECISION_FLOOR}, rule-level, M1 kinds)");
    eprintln!("recall    {recall:.4}  ({detected_tp}/{total_tp} mapped true positives)");
    eprintln!("false positives: {detected_fp}");
    eprintln!("\nper kind:");
    for (kind, (hit, total)) in &recall_by_kind {
        let (tp, fp) = precision_by_kind.get(kind).copied().unwrap_or((0, 0));
        let p = if tp + fp == 0 {
            1.0
        } else {
            tp as f64 / (tp + fp) as f64
        };
        eprintln!("  {kind:24} recall {hit:3}/{total:<3}  precision {p:.4} ({fp} fp)");
    }
    if !tp_misses.is_empty() {
        eprintln!("\nmissed true positives:");
        for m in &tp_misses {
            eprintln!("{m}");
        }
    }
    if !fp_hits.is_empty() {
        eprintln!("\nfalse positives (gated):");
        for f in &fp_hits {
            eprintln!("{f}");
        }
    }
    if !collateral.is_empty() {
        eprintln!(
            "\ncollateral detections on negatives of rules we do not implement \
             ({} rows, not gated):",
            collateral.len()
        );
        for c in &collateral {
            eprintln!("{c}");
        }
    }
    eprintln!();

    // The floor is enforced **per kind**, not only on the pooled total.
    //
    // Pooling hides regressions. `AwsAccessKeyId` contributes 1 true positive to a pool of 71, so
    // reintroducing both of its false positives still scores 71/73 = 0.973 overall — comfortably
    // above the floor, and completely broken. A gate that cannot fail proves nothing.
    let mut below: Vec<String> = Vec::new();
    for (kind, (tp, fp)) in &precision_by_kind {
        if tp + fp == 0 {
            continue;
        }
        let p = *tp as f64 / (tp + fp) as f64;
        if p < PRECISION_FLOOR {
            below.push(format!("{kind} {p:.4} ({tp} tp, {fp} fp)"));
        }
    }
    assert!(
        below.is_empty(),
        "per-kind precision below the {PRECISION_FLOOR} floor: {}",
        below.join("; ")
    );

    assert!(
        precision >= PRECISION_FLOOR,
        "overall precision {precision:.4} is below the {PRECISION_FLOOR} floor: \
         {detected_fp} false positives against {detected_tp} true positives"
    );
}
