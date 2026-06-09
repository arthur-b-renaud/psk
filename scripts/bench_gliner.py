#!/usr/bin/env python3
"""First baseline: run an off-the-shelf GLiNER model over a held-out PII slice and
report accuracy + speed + memory (CLAUDE.md section 2).

This is the **Python reference baseline**, not the production path. The shipping target
is gline-rs (Rust) running quantized ONNX; expect that to be faster and far lighter on
RSS than the numbers here (PyTorch/Python runtime overhead is included below).

Three matching modes are reported, because exact-span match badly understates a PII
*masking* tool:
  - exact   : predicted (tok_start,tok_end,label) == gold. Strict; boundary-sensitive.
  - overlap : predicted span token-overlaps a gold span of the SAME label. Label-aware.
  - cover   : fraction of gold PII tokens falling inside ANY predicted span (any label).
              This is the mission-aligned metric — did the sensitive token get masked?
              (Over-masking is explicitly acceptable per CLAUDE.md.)

Headline = ORGANIZATION coverage/overlap recall.

Usage:
    python scripts/bench_gliner.py --model urchade/gliner_multi_pii-v1 \
        --languages en --eval-rows 400 --threshold 0.3
"""
from __future__ import annotations

import argparse
import json
import resource
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
from build_dataset import tokenize_with_offsets, char_span_to_token_span, load_label_map

LABELS = ["organization", "person", "location", "address"]
_EN = {"en", "english"}


def build_eval(datasets, skip_rows, eval_rows, english_only, label_map, fallback):
    """Held-out slice as (text, gold_token_spans, gold_token_set). Disjoint from the
    training head via skip_rows. Prints per-dataset composition so ORG coverage is visible."""
    from datasets import load_dataset
    per_ds = max(1, eval_rows // len(datasets))
    out = []
    for ds_name in datasets:
        ds = load_dataset(ds_name, split="train", streaming=True).skip(skip_rows)
        taken = scanned = org = 0
        for ex in ds:
            if taken >= per_ds:
                break
            scanned += 1
            if scanned > 200000:
                break
            if english_only and (ex.get("language") or "").lower() not in _EN:
                continue
            text = ex.get("source_text") or ex.get("text") or ""
            toks, starts, ends = tokenize_with_offsets(text)
            gold = set()
            gold_tokens = set()
            for e in (ex.get("privacy_mask") or []):
                if not isinstance(e, dict):
                    continue
                tgt = label_map.get((e.get("label") or "").upper(), fallback)
                if tgt == "O":
                    continue
                span = char_span_to_token_span(int(e["start"]), int(e["end"]), starts, ends)
                if span:
                    gold.add((span[0], span[1], tgt))
                    gold_tokens.update(range(span[0], span[1] + 1))
                    if tgt == "organization":
                        org += 1
            out.append({"text": text, "gold": gold, "gold_tokens": gold_tokens})
            taken += 1
        print(f"  {ds_name}: {taken} prompts (org gold spans: {org})")
    return out


def overlaps(a, b):  # inclusive token ranges
    return a[0] <= b[1] and b[0] <= a[1]


def model_disk_size(model_id):
    try:
        from huggingface_hub import snapshot_download
        path = Path(snapshot_download(model_id))
        return sum(f.resolve().stat().st_size for f in path.rglob("*") if f.is_file())
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", default="urchade/gliner_multi_pii-v1")
    ap.add_argument("--datasets",
                    default="ai4privacy/pii-masking-200k,ai4privacy/pii-masking-openpii-1m")
    ap.add_argument("--skip-rows", type=int, default=20000)
    ap.add_argument("--eval-rows", type=int, default=400)
    ap.add_argument("--english-only", action="store_true", default=True)
    ap.add_argument("--all-languages", dest="english_only", action="store_false")
    ap.add_argument("--threshold", type=float, default=0.3)
    ap.add_argument("--label-map", default=str(REPO / "data" / "label_map.json"))
    ap.add_argument("--examples", type=int, default=5)
    ap.add_argument("--results", default=str(REPO / "bench" / "RESULTS.md"))
    args = ap.parse_args()

    label_map, fallback, _ = load_label_map(Path(args.label_map))
    datasets = [d.strip() for d in args.datasets.split(",") if d.strip()]

    print(f"building eval slice (target {args.eval_rows} rows, skip {args.skip_rows}, "
          f"english_only={args.english_only}) ...")
    evalset = build_eval(datasets, args.skip_rows, args.eval_rows, args.english_only, label_map, fallback)
    n_gold = sum(len(e["gold"]) for e in evalset)
    n_gold_tok = sum(len(e["gold_tokens"]) for e in evalset)
    print(f"  total {len(evalset)} prompts, {n_gold} gold spans, {n_gold_tok} gold tokens")

    from gliner import GLiNER
    t0 = time.perf_counter()
    model = GLiNER.from_pretrained(args.model).eval()
    print(f"model loaded in {time.perf_counter() - t0:.1f}s")
    for e in evalset[:3]:
        model.predict_entities(e["text"], LABELS, threshold=args.threshold)

    # counters
    ex_tp = defaultdict(int); ex_fp = defaultdict(int); ex_fn = defaultdict(int)
    ov_tp = defaultdict(int); ov_fp = defaultdict(int); ov_fn = defaultdict(int)
    cov_hit = defaultdict(int); cov_tot = defaultdict(int)  # by label: covered gold tokens
    latencies = []
    examples = []

    for e in evalset:
        t = time.perf_counter()
        preds = model.predict_entities(e["text"], LABELS, threshold=args.threshold)
        latencies.append((time.perf_counter() - t) * 1000.0)

        toks, starts, ends = tokenize_with_offsets(e["text"])
        pred_spans = []
        pred_tokens = set()
        for p in preds:
            sp = char_span_to_token_span(int(p["start"]), int(p["end"]), starts, ends)
            if sp:
                pred_spans.append((sp[0], sp[1], p["label"]))
                pred_tokens.update(range(sp[0], sp[1] + 1))
        gold = e["gold"]
        pred_set = set(pred_spans)

        # exact
        for s in pred_set:
            (ex_tp if s in gold else ex_fp)[s[2]] += 1
        for s in gold:
            if s not in pred_set:
                ex_fn[s[2]] += 1
        # overlap (label-aware)
        for p in pred_spans:
            if any(p[2] == g[2] and overlaps(p, g) for g in gold):
                ov_tp[p[2]] += 1
            else:
                ov_fp[p[2]] += 1
        for g in gold:
            if not any(p[2] == g[2] and overlaps(p, g) for p in pred_spans):
                ov_fn[g[2]] += 1
        # coverage (label-agnostic token masking)
        for (a, b, lab) in gold:
            for tok in range(a, b + 1):
                cov_tot[lab] += 1
                if tok in pred_tokens:
                    cov_hit[lab] += 1

        if len(examples) < args.examples and preds:
            examples.append((e["text"], preds, gold, toks))

    def prf(tp, fp, fn, lab):
        t, f, n = tp[lab], fp[lab], fn[lab]
        p = t / (t + f) if (t + f) else 0.0
        r = t / (t + n) if (t + n) else 0.0
        return p, r, (2 * p * r / (p + r) if (p + r) else 0.0)

    lat = sorted(latencies)
    pct = lambda q: lat[min(len(lat) - 1, int(q * len(lat)))]
    peak_rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    disk = model_disk_size(args.model)
    disk_mb = disk / 1e6 if disk else None
    thr = 1000.0 / statistics.mean(latencies)

    print("\n=== example predictions ===")
    for text, preds, gold, toks in examples:
        gstr = {f"{lab}:'{' '.join(toks[s:e+1])}'" for s, e, lab in gold}
        print(f"\nTEXT: {text[:150]}")
        print("  PRED:", [(p['label'], p['text'], round(p['score'], 2)) for p in preds])
        print("  GOLD:", gstr or "{}")

    print(f"\n=== accuracy (threshold={args.threshold}) — recall is what matters ===")
    print(f"{'entity':13} | {'exact P/R/F1':>20} | {'overlap P/R/F1':>20} | {'cover R':>8}")
    for lab in LABELS:
        ep, er, ef = prf(ex_tp, ex_fp, ex_fn, lab)
        op, orr, of = prf(ov_tp, ov_fp, ov_fn, lab)
        cr = cov_hit[lab] / cov_tot[lab] if cov_tot[lab] else float('nan')
        print(f"{lab:13} | {ep:.2f}/{er:.2f}/{ef:.2f}      | {op:.2f}/{orr:.2f}/{of:.2f}      | {cr:8.3f}")
    tot_cov = sum(cov_hit.values()) / sum(cov_tot.values()) if sum(cov_tot.values()) else 0.0
    org_ov_r = prf(ov_tp, ov_fp, ov_fn, "organization")[1]
    org_cov = cov_hit["organization"] / cov_tot["organization"] if cov_tot["organization"] else float('nan')
    print(f"\nHEADLINE  organization: overlap recall={org_ov_r:.3f}  coverage recall={org_cov:.3f}"
          f"  (org gold tokens={cov_tot['organization']})")
    print(f"OVERALL   token coverage (any PII masked) = {tot_cov:.3f}")
    print(f"speed     p50={pct(.5):.1f}ms  p95={pct(.95):.1f}ms  p99={pct(.99):.1f}ms  "
          f"mean={statistics.mean(latencies):.1f}ms  throughput={thr:.1f}/s (1 thread)")
    print(f"memory    peak RSS={peak_rss_mb:.0f}MB" + (f"  model_on_disk={disk_mb:.0f}MB" if disk_mb else ""))

    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    if not out.exists():
        out.write_text(
            "# Benchmark results\n\n"
            "Python reference baseline (PyTorch CPU, single thread). Shipping target is "
            "gline-rs/ONNX — expect lower latency and RSS there. Recall is the priority "
            "(CLAUDE.md); `cover R` = fraction of gold PII tokens masked by any predicted span.\n\n"
            "| model | thr | prompts | ORG ovR | ORG covR | PER covR | LOC covR | ADDR covR | "
            "all-tok cover | p50 ms | p95 ms | thr/s | RSS MB | disk MB |\n"
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
    cov = lambda l: (f"{cov_hit[l]/cov_tot[l]:.3f}" if cov_tot[l] else "n/a")
    with out.open("a") as f:
        f.write(f"| {args.model} | {args.threshold} | {len(evalset)} | {org_ov_r:.3f} | "
                f"{cov('organization')} | {cov('person')} | {cov('location')} | {cov('address')} | "
                f"{tot_cov:.3f} | {pct(.5):.1f} | {pct(.95):.1f} | {thr:.1f} | {peak_rss_mb:.0f} | "
                f"{disk_mb:.0f} |\n" if disk_mb else "n/a |\n")
    print(f"\nappended row -> {out}")


if __name__ == "__main__":
    main()
