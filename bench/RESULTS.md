# Benchmark results

Python reference harness (single thread). Shipping target is gline-rs/ONNX in Rust — expect lower
RSS there than the Python+torch numbers below. Recall is the priority (CLAUDE.md); `cover R` =
fraction of gold PII tokens masked by any predicted span (the masking-aligned metric).

| model | runtime | thr | prompts | ORG ovR | ORG covR | PER covR | LOC covR | ADDR covR | all-tok cover | p50 ms | p95 ms | thr/s | RSS MB | disk MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| urchade/gliner_multi_pii-v1 | torch fp32 | 0.3 | 200 | 0.200 | 0.872 | 1.000 | 0.787 | 0.883 | **0.870** | 177.2 | 1380.5 | 2.7 | 3273 | 1156 |
| urchade/gliner_multi_pii-v1 | torch fp32 | 0.5 | 200 | 0.200 | 0.744 | 0.968 | 0.750 | 0.844 | 0.824 | 177.5 | 1086.1 | 3.1 | 3296 | 1156 |
| knowledgator/gliner-pii-edge (model.onnx) | onnx fp32 | 0.3 | 100 | — | — | — | — | — | _n/a*_ | 13.5 | 24.5 | 69.4 | 1179 | 181 |
| knowledgator/gliner-pii-edge (model_quint8.onnx) | onnx UINT8 | 0.3 | 100 | — | — | — | — | — | _n/a*_ | **8.3** | 15.0 | 110.6 | 1006 | **46** |

`*` edge **accuracy is not valid yet** — see "Edge model status". The edge rows are a **speed/memory**
measurement only.

## Run config

- Eval slice: held-out **English** prompts from `ai4privacy/pii-masking-200k` (skip 20000); 200
  prompts (369 gold tokens) for the ceiling model, 100 for the edge speed runs. **Only ~10–24
  organization spans** — ORG accuracy numbers are noisy/small-N.
- Metrics: `exact` (boundary-strict), `overlap` (label-aware token overlap), `cover R`
  (fraction of gold PII tokens masked by ANY predicted span — the masking-aligned metric).
- Hardware: local CPU, single thread. Labels `[organization, person, location, address]`.

## Reading the numbers

### Accuracy (ceiling model)
- **Coverage recall is high** (overall 0.87 @ thr 0.3): masks ~87% of gold PII tokens; PERSON ~1.0.
  This is what matters for a masking tool.
- **Exact/overlap are far below coverage** because GLiNER emits coarser, still-correct spans
  (keeps titles "Mr/Judge", merges "Mount Hope Road" + number) while ai4privacy gold splits finely.
  Over-masking is acceptable (CLAUDE.md), so coverage is the honest metric here.
- **ORG overlap 0.20 vs coverage 0.87**: org tokens usually get masked, often under another label;
  sample is tiny. ORG needs more org-bearing eval + the eXalt synthetic set before it's trustworthy.

### Speed / memory (the edge story)
- **ONNX UINT8 edge is ~20× faster than the torch ceiling**: p50 **8.3 ms** vs 177 ms, p95 15 ms vs
  1380 ms, 110 prompts/s single thread — comfortably inside the CLAUDE.md 30–50 ms p95 budget.
- **Disk 46 MB (UINT8)** vs 1156 MB ceiling — a 25× shrink; fp32 ONNX is 181 MB.
- **RSS (~1 GB) is misleading**: it's dominated by the Python+torch import that `gliner` pulls in even
  for ONNX inference. The ONNX model itself is 46 MB. In the real **gline-rs (Rust, no torch)** path,
  RSS should be a small fraction of this — that measurement is the actual deliverable, pending the
  Rust runtime.

## Edge model status (blocker)

`knowledgator/gliner-pii-edge-v1.0` and `-small-v1.0` are **token-level GLiNER with a ModernBERT
encoder**, and ship `onnx/{model,model_fp16,model_quint8}.onnx`.

- **torch load** → per-token noise (max score ~0.1), everything labelled `organization`.
- **ONNX load** → runs fast and clean, but scores are **~100× too low** (max ~0.012); relative ranking
  is right ("Acme Corp" tops) but absolute scores never clear any usable threshold → ~0 entities.

This is a decoding/version mismatch: `gliner` 0.2.26 mis-scales these ModernBERT token-level outputs
(the silent TokenMode/SpanMode failure CLAUDE.md warns about). Reproduce with
`scripts/validate_models.py` and `scripts/try_onnx_edge.py`. To unblock accuracy: pin a `gliner`
version that supports these checkpoints, or implement token-level ONNX decode directly (the eventual
gline-rs path). **Speed/memory above are valid; edge accuracy is not, yet.**

## Next

1. Fix edge decoding (gliner version or direct ONNX/token-level decode) → real edge accuracy row.
2. Stand up the gline-rs (Rust) runtime → the true RSS number without the torch tax.
3. Grow ORG eval (more 200k + eXalt synthetic) so ORG recall is statistically meaningful.
4. Freeze a hand-checked `data/eval/` consulting set (CLAUDE.md) — current slice is a smoke proxy.
