#!/usr/bin/env python3
"""Build a GLiNER-format NER training set from ai4privacy PII corpora.

Pipeline (CLAUDE.md section 1):
  1. Stream a slice of an ai4privacy corpus from the HF Hub.
  2. Collapse the source PII taxonomy down to the narrow PSK set via data/label_map.json
     ({organization, person, location, address}; everything else -> dropped).
  3. Convert char-offset spans to token-indexed spans (GLiNER training format).
  4. Stratified train/val split so rare entity types are not starved.
  5. Write JSONL + a stats report.

This proves the plumbing on a small slice; scale --max-rows up (or add --dataset) later.

Usage:
    python scripts/build_dataset.py --max-rows 5000
    python scripts/build_dataset.py --dataset ai4privacy/pii-masking-openpii-1m \
        --max-rows 20000 --val-frac 0.1 --out-dir data/processed
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# Word/number/punct tokenizer matching GLiNER's default-style word splitting.
# Each token carries its char offsets so we can map char spans -> token spans.
_TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)


def tokenize_with_offsets(text: str):
    toks, starts, ends = [], [], []
    for m in _TOKEN_RE.finditer(text):
        toks.append(m.group(0))
        starts.append(m.start())
        ends.append(m.end())
    return toks, starts, ends


def char_span_to_token_span(c_start, c_end, starts, ends):
    """Map a char span to inclusive [tok_start, tok_end]; None if it doesn't align."""
    tok_start = tok_end = None
    for i, (s, e) in enumerate(zip(starts, ends)):
        if e <= c_start:
            continue
        if s >= c_end:
            break
        if tok_start is None:
            tok_start = i
        tok_end = i
    if tok_start is None:
        return None
    return tok_start, tok_end


def load_label_map(path: Path):
    obj = json.loads(path.read_text())
    return obj["map"], obj.get("fallback", "O"), obj["target_labels"]


def strat_key(labels_present: set[str], target_labels: list[str]) -> str:
    """Bucket each example by its rarest present target label, so the split keeps
    rare types (e.g. organization) proportionally balanced across train/val."""
    order = list(target_labels)  # priority: earlier == rarer/more valuable
    for lab in order:
        if lab in labels_present:
            return lab
    return "_none_"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--datasets", default="ai4privacy/pii-masking-openpii-1m",
                    help="comma-separated HF datasets to combine. "
                         "Recommended ORG-bearing mix: "
                         "ai4privacy/pii-masking-openpii-1m,ai4privacy/pii-masking-200k")
    ap.add_argument("--split", default="train")
    ap.add_argument("--max-rows", type=int, default=5000,
                    help="max rows to take from EACH dataset (after language filter)")
    ap.add_argument("--val-frac", type=float, default=0.1)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--languages", default=None,
                    help="comma-separated language codes to keep (e.g. en,fr); default: all")
    ap.add_argument("--label-map", default=str(REPO / "data" / "label_map.json"))
    ap.add_argument("--out-dir", default=str(REPO / "data" / "processed"))
    args = ap.parse_args()

    from datasets import load_dataset  # imported here so --help works without deps

    label_map, fallback, target_labels = load_label_map(Path(args.label_map))
    keep_langs = set(args.languages.split(",")) if args.languages else None
    datasets = [d.strip() for d in args.datasets.split(",") if d.strip()]

    rows = []
    src_label_counts = Counter()
    unmapped = Counter()
    mapped_counts = Counter()
    dropped_unaligned = 0
    per_dataset_rows = Counter()
    per_dataset_org = Counter()

    for ds_name in datasets:
        ds = load_dataset(ds_name, split=args.split, streaming=True)
        seen = 0
        for ex in ds:
            if seen >= args.max_rows:
                break
            lang = ex.get("language")
            if keep_langs and lang not in keep_langs:
                continue
            seen += 1
            # column names differ across corpora: source_text everywhere; uid vs id.
            text = ex.get("source_text") or ex.get("text") or ""
            toks, starts, ends = tokenize_with_offsets(text)
            ner = []
            for e in (ex.get("privacy_mask") or []):
                if not isinstance(e, dict):
                    continue
                src = (e.get("label") or "").upper()
                src_label_counts[src] += 1
                if src not in label_map:
                    unmapped[src] += 1
                tgt = label_map.get(src, fallback)
                if tgt == "O":
                    continue
                span = char_span_to_token_span(int(e["start"]), int(e["end"]), starts, ends)
                if span is None:
                    dropped_unaligned += 1
                    continue
                ner.append([span[0], span[1], tgt])
                mapped_counts[tgt] += 1
                if tgt == "organization":
                    per_dataset_org[ds_name] += 1
            rows.append({
                "tokenized_text": toks,
                "ner": ner,
                "language": lang,
                "uid": ex.get("uid") or ex.get("id"),
                "source_dataset": ds_name,
            })
            per_dataset_rows[ds_name] += 1
        print(f"  {ds_name}: {per_dataset_rows[ds_name]} rows, "
              f"{per_dataset_org[ds_name]} organization spans")

    # Deterministic stratified split by rarest present target label.
    import random
    rng = random.Random(args.seed)
    buckets: dict[str, list[int]] = defaultdict(list)
    for idx, r in enumerate(rows):
        present = {lab for _, _, lab in r["ner"]}
        buckets[strat_key(present, target_labels)].append(idx)

    val_idx = set()
    for _key, idxs in buckets.items():
        rng.shuffle(idxs)
        n_val = round(len(idxs) * args.val_frac)
        val_idx.update(idxs[:n_val])

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    train_path, val_path = out_dir / "train.jsonl", out_dir / "val.jsonl"

    split_label_counts = {"train": Counter(), "val": Counter()}
    with train_path.open("w") as ft, val_path.open("w") as fv:
        for idx, r in enumerate(rows):
            target = "val" if idx in val_idx else "train"
            (fv if target == "val" else ft).write(json.dumps(r, ensure_ascii=False) + "\n")
            for _, _, lab in r["ner"]:
                split_label_counts[target][lab] += 1

    n_train = len(rows) - len(val_idx)
    n_val = len(val_idx)
    stats = {
        "datasets": datasets,
        "rows_per_dataset": dict(per_dataset_rows),
        "organization_spans_per_dataset": dict(per_dataset_org),
        "rows_kept": len(rows),
        "rows_train": n_train,
        "rows_val": n_val,
        "val_frac": args.val_frac,
        "seed": args.seed,
        "languages_filter": sorted(keep_langs) if keep_langs else "all",
        "target_label_counts": dict(mapped_counts),
        "target_label_counts_train": dict(split_label_counts["train"]),
        "target_label_counts_val": dict(split_label_counts["val"]),
        "source_label_counts": dict(src_label_counts.most_common()),
        "unmapped_source_labels": dict(unmapped.most_common()),
        "spans_dropped_unaligned": dropped_unaligned,
    }
    (out_dir / "stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False))

    print(f"rows kept: {len(rows)}  (train {n_train} / val {n_val})")
    print(f"target spans: {dict(mapped_counts)}")
    print(f"dropped (unaligned char->token): {dropped_unaligned}")
    if unmapped:
        print(f"UNMAPPED source labels (-> '{fallback}'): {dict(unmapped.most_common())}")
    if not mapped_counts.get("organization"):
        print("WARNING: 0 'organization' spans in this corpus — augment with 200k/400k or eXalt synthetic for ORG recall.")
    print(f"wrote: {train_path}\n       {val_path}\n       {out_dir/'stats.json'}")


if __name__ == "__main__":
    main()
