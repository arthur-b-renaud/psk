"""Validate harness against a known-good GLiNER model, and probe why the edge model is empty."""
import warnings; warnings.filterwarnings("ignore")
from gliner import GLiNER

S = ["Engagement with Societe Generale led by Jean Dupont in La Defense.",
     "Acme Corp hired John Smith, who lives at 42 Baker Street, London."]
LABELS = ["organization", "person", "location", "address"]

def run(mid, thr):
    print(f"\n#### {mid}  (threshold={thr}) ####")
    try:
        m = GLiNER.from_pretrained(mid).eval()
    except Exception as e:
        print("  LOAD FAILED:", type(e).__name__, str(e)[:200]); return
    for s in S:
        print(" ", s)
        print("    ->", [(p["label"], p["text"], round(p["score"], 2))
                         for p in m.predict_entities(s, LABELS, threshold=thr)])

# 1) does the edge model output ANYTHING at threshold 0?
run("knowledgator/gliner-pii-edge-v1.0", 0.0)
# 2) known-good reference model (CLAUDE.md ceiling)
run("urchade/gliner_multi_pii-v1", 0.3)
