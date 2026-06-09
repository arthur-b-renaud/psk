# Benchmark results

Python reference baseline (PyTorch CPU, single thread). Shipping target is gline-rs/ONNX — expect lower latency and RSS there. Recall is the priority (CLAUDE.md); `cover R` = fraction of gold PII tokens masked by any predicted span.

| model | thr | prompts | ORG ovR | ORG covR | PER covR | LOC covR | ADDR covR | all-tok cover | p50 ms | p95 ms | thr/s | RSS MB | disk MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| urchade/gliner_multi_pii-v1 | 0.3 | 200 | 0.200 | 0.872 | 1.000 | 0.787 | 0.883 | 0.870 | 177.2 | 1380.5 | 2.7 | 3273 | 1156 |
| urchade/gliner_multi_pii-v1 | 0.5 | 200 | 0.200 | 0.744 | 0.968 | 0.750 | 0.844 | 0.824 | 177.5 | 1086.1 | 3.1 | 3296 | 1156 |

## Run config

- Eval slice: 200 held-out **English** prompts from `ai4privacy/pii-masking-200k` (skip 20000),
  369 gold PII tokens, **only ~10 organization spans (39 tokens)** — ORG numbers are noisy, small-N.
  `openpii-1m` contributed 0 here (its English rows weren't found in the scanned window); the slice
  is 200k-only for now.
- Metrics: `exact` (boundary-strict), `overlap` (label-aware token overlap), `cover R`
  (fraction of gold PII tokens masked by ANY predicted span — the masking-aligned metric).
- Hardware: local CPU, single thread, PyTorch fp32. Model `predict_entities`, labels
  `[organization, person, location, address]`.

## Reading the numbers

- **Coverage recall is high** (overall 0.87 @ thr 0.3): the model masks ~87% of gold PII tokens.
  PERSON is ~1.0. This is what matters for a masking tool.
- **Exact/overlap are much lower than coverage** because GLiNER emits coarser, still-correct spans
  (keeps titles "Mr/Judge", merges "Mount Hope Road" + number) while ai4privacy gold splits finely.
  For masking this is fine (over-masking is acceptable, CLAUDE.md); for boundary-faithful NER it isn't.
- **ORG overlap recall 0.20 vs coverage 0.87**: org tokens usually get masked, but often under a
  different label — and the sample is tiny. ORG needs (a) far more org-bearing eval, (b) the eXalt
  synthetic set, before any number here is trustworthy.
- Lower threshold (0.3) → higher coverage than 0.5, as expected (recall-leaning).

## Caveats / known issues

- This is the **accuracy-ceiling** model (`gliner_multi_pii-v1`, ~1.2 GB on disk, ~3.3 GB RSS,
  ~180 ms p50 on CPU). It is NOT the deployment target — far too heavy. It establishes the ceiling.
- **`knowledgator/gliner-pii-edge-v1.0` (the intended default) does not load correctly under
  `gliner` 0.2.26** — it emits per-token noise (max score ~0.1), a TokenMode/SpanMode export
  mismatch (the silent-failure case CLAUDE.md warns about). Resolve via its ONNX/token-mode export
  before benching the edge tier. `scripts/validate_models.py` reproduces this.
- Speed/RSS here include the Python+torch runtime; gline-rs/ONNX+UINT8 will be dramatically lighter.

## Next

1. Stand up the edge model correctly (ONNX/token-mode) and add its row — the real latency/RSS story.
2. Grow ORG eval (more 200k + eXalt synthetic) so ORG recall is statistically meaningful.
3. Freeze a hand-checked `data/eval/` consulting set (CLAUDE.md) — this slice is a smoke proxy.
