# Data pipeline

Builds a GLiNER-format NER training set for the PSK ML layer (see [`../CLAUDE.md`](../CLAUDE.md) §1).

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r scripts/requirements.txt
```

## Build a dataset

```bash
# small slice, single corpus (validate plumbing)
python scripts/build_dataset.py --max-rows 3000

# recommended ORG-bearing mix: openpii-1m (breadth) + 200k (COMPANYNAME -> organization)
python scripts/build_dataset.py \
    --datasets ai4privacy/pii-masking-openpii-1m,ai4privacy/pii-masking-200k \
    --max-rows 2500 --val-frac 0.1

# larger / language-filtered
python scripts/build_dataset.py --datasets ai4privacy/pii-masking-openpii-1m \
    --max-rows 50000 --languages en,fr
```

`--max-rows` is **per dataset**. `stats.json` reports `rows_per_dataset` and
`organization_spans_per_dataset` so you can see exactly where ORG examples come from.

Outputs to `data/processed/`:

- `train.jsonl`, `val.jsonl` — one example per line:
  `{"tokenized_text": [...], "ner": [[tok_start, tok_end, label], ...], "language", "uid"}`
  (token indices are **inclusive**, the GLiNER training convention).
- `stats.json` — per-split label counts, source-label histogram, unmapped labels, alignment drops.

## Label mapping

`data/label_map.json` collapses the source taxonomy into the narrow PSK set
`{organization, person, location, address}`. Everything structured (emails, IDs, cards, phones, …)
maps to `O` and is dropped — those stay in the regex/secrets layers. Unknown source labels fall back
to `O` and are reported in `stats.json` so the map can be extended.

## Known gap: ORGANIZATION

`ai4privacy/pii-masking-openpii-1m` contains **no `ORGANIZATION` class** (19 labels, none org-like).
Measured org coverage across the corpora (this is why the default mix includes 200k):

| Corpus                            | Org-bearing label | Notes                                  |
| --------------------------------- | ----------------- | -------------------------------------- |
| `ai4privacy/pii-masking-openpii-1m` | — (none)        | 19 labels, **zero org**                |
| `ai4privacy/pii-masking-200k`     | `COMPANYNAME` (~6%) | 56 labels — **the public ORG source** |
| `ai4privacy/pii-masking-400k`     | — (none)          | 17 labels, no org; use for lang/volume |

So ORG examples come from **200k**, and ultimately from the **eXalt synthetic augmentation**
(CLAUDE.md §1): synthetic consulting/dev prompts seeded with client-style company names and their
aliases/legal-form variants. 200k alone is thin (~6% of rows) for a recall-first ORG target.

The `data/eval/` set (frozen, hand-checked consulting prompts) is **never** built here.

## Benchmark (first baseline)

`bench_gliner.py` runs an off-the-shelf GLiNER model over a held-out slice and reports
accuracy (exact / overlap / **token coverage**) + latency percentiles + peak RSS, appending a row to
`bench/RESULTS.md` (CLAUDE.md §2). Heavy deps (torch/gliner) live in `requirements-bench.txt`:

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r scripts/requirements-bench.txt

python scripts/bench_gliner.py --model urchade/gliner_multi_pii-v1 --threshold 0.3
python scripts/validate_models.py   # sanity-check which checkpoints load correctly
```

Note: `knowledgator/gliner-pii-edge-v1.0` (the intended edge default) does **not** load correctly
under `gliner` 0.2.26 — it needs its ONNX/token-mode export. See `bench/RESULTS.md` → "Caveats".

## Test UI

`serve.py` is a single-file, **stdlib-only** local web UI (loads the model once, daemon-style).
Paste text or pull random DB examples (with gold labels); see color-coded entities, per-request
inference latency, and rolling session speed stats. Needs the bench deps (gliner/torch).

```bash
python scripts/serve.py                 # http://127.0.0.1:7860  (default model + 200k examples)
python scripts/serve.py --no-examples   # paste-only, skip dataset load
python scripts/serve.py --model urchade/gliner_multi_pii-v1 --threshold 0.3 --port 7860
```
