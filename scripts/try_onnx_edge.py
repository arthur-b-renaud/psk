"""Try loading the edge model via its ONNX export (bypasses the broken torch/ModernBERT load)."""
import warnings, time; warnings.filterwarnings("ignore")
from gliner import GLiNER

S = ["Engagement with Societe Generale led by Jean Dupont in La Defense.",
     "Acme Corp hired John Smith, who lives at 42 Baker Street, London."]
LABELS = ["organization", "person", "location", "address"]
MID = "knowledgator/gliner-pii-edge-v1.0"

for onnx_file in ["onnx/model.onnx", "onnx/model_quint8.onnx"]:
    print(f"\n#### {MID}  via ONNX {onnx_file} ####")
    try:
        t0 = time.perf_counter()
        m = GLiNER.from_pretrained(MID, load_onnx_model=True, onnx_model_file=onnx_file).eval()
        print(f"  loaded in {time.perf_counter()-t0:.1f}s")
        for s in S:
            print("  ", s)
            print("    ->", [(p["label"], p["text"], round(p["score"], 2))
                             for p in m.predict_entities(s, LABELS, threshold=0.3)])
    except Exception as e:
        import traceback; traceback.print_exc()
        print("  FAILED:", type(e).__name__, str(e)[:300])
