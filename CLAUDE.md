# CLAUDE.md :: psk-pii-ml (gline-rs NER component)

Scope: this file governs the **ML / NER layer only** (`psk-pii-ml`), built on the pure-Rust
`gline-rs` inference engine. It does **not** cover the Hyperscan regex layer (`psk-secrets`),
the structured-PII regex layer (`psk-pii`), or the client-name gazetteer (planned, see "Out of
scope"). Those bundle in later and are easy to wire once this layer is measured and stable.

Read this before touching anything under `crates/psk-pii-ml/`, `models/`, `data/`, or `bench/`.

---

## Mission and priority order

The enterprise goal is to stop **client and company identities** plus personal PII from reaching
external LLM providers. Risk is asymmetric:

- A **false positive** (masking a non-sensitive word) is harmless noise.
- A **false negative** (a client name reaching the provider) is the exact failure we prevent.

Therefore this layer is tuned for **recall over precision**, with `ORGANIZATION` as the top-value
entity. Concretely:

- Lower the confidence threshold to favor recall.
- Track `ORG` recall as the headline metric, not aggregate F1.
- NER only earns its footprint on the **unstructured** slice: `PERSON`, `ORGANIZATION`,
  `LOCATION` / `ADDRESS`. Everything structured (emails, IPs, IBANs, cards, SSNs) and all secrets
  stay in the regex layers; do not route them through the model.

Keep the **label set narrow** (4 to 6 labels). A small label space is the single biggest lever for
CPU latency and memory. Do not load a 60-class catalogue we do not use.

---

## Runtime: gline-rs

`gline-rs` runs GLiNER ONNX models in pure, safe Rust on top of ONNX Runtime (via the `orp` / `ort`
crates), with `tokenizers` for the BPE step. No Python at inference. Single in-process binary.

Two pipeline modes; the mode **must match the checkpoint**:

- `TokenMode` (TokenPipeline): token-classification GLiNER variants (e.g. multitask models).
- `SpanMode` (SpanPipeline): span-scoring GLiNER models (most PII checkpoints).

Pick the mode from the model card. A mismatch produces silently wrong output, so assert it in tests.

`Cargo.toml` (verify latest on crates.io before pinning):

```toml
[dependencies]
gline-rs = "1"   # confirm current major/minor on crates.io
```

Reference call (the real API surface):

```rust
use gline_rs::{GLiNER, TextInput, Parameters, RuntimeParameters};
use gline_rs::pipeline::SpanMode; // or TokenMode, matching the checkpoint

let model = GLiNER::<SpanMode>::new(
    Parameters::default(),
    RuntimeParameters::default(), // thread / device config lives here + in ort session options
    "models/gliner-pii-edge/tokenizer.json",
    "models/gliner-pii-edge/onnx/model.onnx",
)?;

let labels = ["organization", "person", "location", "address"];
let input = TextInput::from_str(
    &["Engagement with Société Générale led by Jean Dupont in La Défense."],
    &labels,
)?;

let output = model.inference(input)?; // spans + confidence per entity
```

Load the model **once** and share it (`Arc<RwLock<Option<Model>>>`, lazy-init on first call),
behind a `gliner` cargo feature flag so the crate compiles without ONNX for regex-only builds.
This matches the daemon design: weights loaded once, socket round-trip per prompt.

Starting checkpoints (all Apache-2.0, ONNX available, CPU-friendly):

- `knowledgator/gliner-pii-edge-v1.0` : edge-optimized, UINT8 ONNX, lowest latency / footprint. **Default.**
- `knowledgator/gliner-pii-small-v1.0` : FP16 + UINT8 ONNX, quantization-aware.
- `urchade/gliner_multi_pii-v1` : broad 60+ type coverage, use as accuracy ceiling reference.

Download:

```bash
huggingface-cli download knowledgator/gliner-pii-edge-v1.0 \
  --local-dir models/gliner-pii-edge
# confirm models/gliner-pii-edge/onnx/model.onnx and tokenizer.json exist
```

---

## 1. Training and validation datasets

### Sources

Public PII corpora (ai4privacy series, token-classification format on Hugging Face):

- `ai4privacy/pii-masking-openpii-1m` : current flagship, 1.4M samples, 23 languages, 19 classes. Primary.
- `ai4privacy/pii-masking-openpii-1.5m` : 1.6M samples, 30 languages, Asia Pacific extension. Use for language breadth.
- `ai4privacy/pii-masking-300k` : OpenPII-220k + FinPII-80k. The **FinPII** subset adds finance / insurance classes, relevant to consulting clients in those sectors.
- `ai4privacy/pii-masking-200k` (54 classes) and `pii-masking-400k` (63 classes): use only to mine extra class variety.

```python
from datasets import load_dataset
ds = load_dataset("ai4privacy/pii-masking-openpii-1m")
```

### Critical caveat

These corpora are **personal-PII heavy**. `ORGANIZATION` is a coarse, under-represented class and is
exactly our top target. Public data alone will under-perform on client-name recall. You must augment.

### eXalt augmentation (mandatory)

Generate synthetic consulting / dev prompts that embed organization names the way they actually leak:
in stack traces, configs, meeting notes, slide text, commit messages, ticket descriptions. Inject a
roster of realistic client-style company names (and aliases / abbreviations / legal-form variants:
"Société Générale" / "Soc Gen" / "SocGen" / "SG SA"). Generate this set on the DGX Spark with a local
LLM. Do **not** use real client data to build training fixtures; use synthetic look-alikes.

### Label mapping

Map every source label down to the narrow PSK set in `data/label_map.json`. Collapse the long
ai4privacy taxonomy into `{ORGANIZATION, PERSON, LOCATION, ADDRESS}` (plus any unstructured class
proven necessary by eval). Anything structured maps to `O` here (handled by regex layers).

### Splits and layout

```
data/
  raw/          # untouched HF downloads
  processed/    # converted to GLiNER span format + label_map applied
  eval/         # held-out, real-shaped consulting prompts (NEVER trained on)
  label_map.json
```

- Stratify train/val by entity type so `ORG` is not starved.
- The `eval/` set is the gate: realistic consulting prompts, hand-checked, frozen. Report all
  headline numbers against it. Treat any leakage of `eval/` into training as a build-breaking bug.

---

## 2. Speed and performance experiments

### Metrics (all reported per experiment)

- Latency: p50 / p95 / p99 per prompt (not just mean).
- Throughput: prompts/sec, single thread and N threads.
- Memory: peak RSS, model size on disk.
- Accuracy: precision / recall / F1 **per entity**, with `ORGANIZATION` recall as the headline.

### Harness

- `criterion` for micro-benchmarks under `bench/`.
- A `bench` binary that runs the full `eval/` corpus end to end and emits a CSV row per config.
- Pin CPU governor / disable turbo where possible for stable numbers; record hardware in the row.

### Variables to sweep

- Model: `gliner-pii-edge` vs `small` vs `multi_pii` (accuracy ceiling).
- Quantization: FP16 vs INT8 vs UINT8.
- Pipeline mode: `TokenMode` vs `SpanMode` (per checkpoint).
- Sequence handling: window size (384 / 512 tokens), overlap, batch size.
- Threads: `ort` intra-op / inter-op (set via `RuntimeParameters` and ort session options).
- Scope rule under test: NER on **new content only** (fresh user turn + fresh tool output);
  the regex layers stay full-prompt. Confirm this keeps p95 inside budget on 100k-token contexts.

### Targets

- p95 end to end **under 30 to 50 ms** with the daemon (model preloaded), scoped to new content.
- Peak RSS small enough to sit alongside an agent without complaint (target single-digit hundreds of MB max; lower with UINT8).
- `ORGANIZATION` recall on `eval/` above the agreed gate (set the number once the first baseline lands).

### Output

Commit a results table to `bench/RESULTS.md` per run: config, latency percentiles, RSS, per-entity
P/R/F1. This table is the decision record for whether to ship the off-the-shelf model or retrain.

```bash
cargo bench -p psk-pii-ml                 # criterion micro-benches
cargo run -p psk-pii-ml --bin bench --release -- --corpus data/eval --model models/gliner-pii-edge
```

---

## 3. Retraining / distillation pipeline

### Gate: do not retrain by default

Retrain **only** if the off-the-shelf model fails the `eval/` recall gate, or if you need to shrink
below the edge checkpoint. Adoption first; training is the fallback, not the starting point.

### Approach

Specialize a small GLiNER to the narrow label set and the consulting / dev distribution. Two teacher
options for label generation, both run on the DGX Spark:

- **Soft-label distillation:** use `gliner-pii-base` (or `multi_pii`) as teacher over the augmented corpus.
- **LLM-as-annotator:** run a local LLM to label the synthetic consulting prompts, then fine-tune.

Student: fine-tune `gliner-pii-edge` / `small` on the narrow labels using the Python `gliner` library
(training entrypoint in the upstream gliner repo). Keep it an **encoder** (token/span tagger), not a
generative model; generative-to-CPU is the wrong shape for this task.

### Steps

1. Build / refresh the augmented dataset (public + eXalt synthetic) -> `data/processed/`.
2. Fine-tune student on the narrow label set (Spark). Log seed, config, dataset hash to `runs/<id>/`.
3. Quantize (INT8 / UINT8).
4. Export to ONNX (gliner `save_pretrained` + the conversion tooling in the gliner / gline-rs examples).
5. Verify Rust parity: run the same prompts through `gline-rs` and the Python reference; assert spans
   and labels match within tolerance, and that `TokenMode` vs `SpanMode` is correct for the new export.
6. Drop into `models/<name>/`, re-run section 2, append to `bench/RESULTS.md`.
7. Ship only if it beats the incumbent on `ORGANIZATION` recall at equal-or-better latency.

### Reproducibility

- Every run pins: dataset hash, label_map version, base checkpoint, seed, quant settings.
- Artifacts and metrics land under `runs/<id>/`. No run, no ship.

---

## Out of scope (handled elsewhere, do not implement here)

- Secrets and structured PII: regex + validators in `psk-secrets` / `psk-pii`.
- **Client-name gazetteer:** deterministic exact + fuzzy match (`aho-corasick` / `fst`) against the
  client roster. This is the real guarantee for known clients; NER is the backstop for unknown orgs.
  It bundles in after this layer is measured. Do not bolt it onto the model.

## Agent guardrails

- No network calls at inference. Model files are local; no runtime downloads.
- Model loads once (daemon), shared read-only across requests.
- Keep the `gliner` feature flag clean: regex-only builds must compile and run without ONNX.
- Never commit real client data or real prompts. Fixtures are synthetic only. Stats are counters only.
