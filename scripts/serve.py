#!/usr/bin/env python3
"""Minimal local test UI for the PII NER model — zero extra deps (Python stdlib only).

Loads a GLiNER model once (daemon-style) and serves a single HTML page where you can:
  - paste text and detect entities, with per-request inference latency + rolling speed stats
  - pull random examples from the dataset (with gold labels) and run them

This is a developer test harness, not the product. Bind is localhost-only.

    python scripts/serve.py                       # default model + 200k examples
    python scripts/serve.py --model urchade/gliner_multi_pii-v1 --port 7860
    python scripts/serve.py --no-examples         # paste-only, skip dataset load
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

LABELS = ["organization", "person", "location", "address"]

STATE = {"model": None, "threshold": 0.3, "examples": [], "model_id": "", "lock": threading.Lock()}


def load_model(model_id):
    from gliner import GLiNER
    t0 = time.perf_counter()
    print(f"loading model {model_id} ...", flush=True)
    m = GLiNER.from_pretrained(model_id).eval()
    print(f"  ready in {time.perf_counter()-t0:.1f}s", flush=True)
    return m


def load_examples(datasets, n, skip, english_only):
    """Stream a small set of (text, gold[char-span,label]) for the 'random example' button."""
    try:
        from datasets import load_dataset
        from build_dataset import load_label_map
    except Exception as e:
        print(f"  (examples disabled: {e})", flush=True)
        return []
    label_map, fallback, _ = load_label_map(REPO / "data" / "label_map.json")
    en = {"en", "english"}
    per = max(1, n // len(datasets))
    out = []
    for ds_name in datasets:
        try:
            ds = load_dataset(ds_name, split="train", streaming=True).skip(skip)
        except Exception as e:
            print(f"  (skip {ds_name}: {e})", flush=True)
            continue
        taken = scanned = 0
        for ex in ds:
            if taken >= per or scanned > 100000:
                break
            scanned += 1
            if english_only and (ex.get("language") or "").lower() not in en:
                continue
            text = ex.get("source_text") or ex.get("text") or ""
            gold = []
            for e in (ex.get("privacy_mask") or []):
                if not isinstance(e, dict):
                    continue
                tgt = label_map.get((e.get("label") or "").upper(), fallback)
                if tgt != "O":
                    gold.append({"start": int(e["start"]), "end": int(e["end"]), "label": tgt})
            out.append({"text": text, "gold": gold, "dataset": ds_name})
            taken += 1
        print(f"  examples: {taken} from {ds_name}", flush=True)
    return out


def predict(text, threshold):
    with STATE["lock"]:
        t0 = time.perf_counter()
        ents = STATE["model"].predict_entities(text, LABELS, threshold=threshold)
        dt = (time.perf_counter() - t0) * 1000.0
    return [{"start": int(e["start"]), "end": int(e["end"]), "label": e["label"],
             "text": e["text"], "score": round(float(e["score"]), 3)} for e in ents], dt


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return self._send(200, HTML, "text/html; charset=utf-8")
        if self.path == "/api/info":
            return self._send(200, json.dumps({
                "model": STATE["model_id"], "labels": LABELS,
                "threshold": STATE["threshold"], "n_examples": len(STATE["examples"])}))
        if self.path == "/api/example":
            if not STATE["examples"]:
                return self._send(200, json.dumps({"text": "", "gold": []}))
            # rotating index, no RNG needed
            i = STATE.setdefault("_i", 0)
            ex = STATE["examples"][i % len(STATE["examples"])]
            STATE["_i"] = i + 1
            return self._send(200, json.dumps(ex))
        return self._send(404, "{}")

    def do_POST(self):
        if self.path != "/api/predict":
            return self._send(404, "{}")
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        text = req.get("text", "")
        thr = float(req.get("threshold", STATE["threshold"]))
        if not text.strip():
            return self._send(200, json.dumps({"entities": [], "latency_ms": 0, "chars": 0}))
        ents, dt = predict(text, thr)
        return self._send(200, json.dumps({
            "entities": ents, "latency_ms": round(dt, 1), "chars": len(text)}))


HTML = r"""<!doctype html><html><head><meta charset="utf-8">
<title>psk · PII NER test</title>
<style>
:root{--org:#d9534f;--person:#0275d8;--location:#5cb85c;--address:#f0ad4e}
*{box-sizing:border-box}
body{font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;margin:0;background:#0e1116;color:#d7dce2}
header{padding:10px 16px;background:#161b22;border-bottom:1px solid #30363d;display:flex;gap:16px;align-items:center;flex-wrap:wrap}
header b{color:#fff}.muted{color:#8b949e}
main{max-width:1000px;margin:0 auto;padding:16px;display:grid;gap:14px}
textarea{width:100%;min-height:130px;background:#0b0f14;color:#d7dce2;border:1px solid #30363d;border-radius:6px;padding:10px;font:inherit;resize:vertical}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
button{background:#238636;color:#fff;border:0;border-radius:6px;padding:8px 14px;cursor:pointer;font:inherit}
button.alt{background:#30363d}
button:disabled{opacity:.5;cursor:default}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px}
.out{white-space:pre-wrap;word-break:break-word;line-height:1.9}
mark{padding:1px 3px;border-radius:4px;color:#0b0f14;font-weight:600}
mark.organization{background:var(--org)}mark.person{background:var(--person);color:#fff}
mark.location{background:var(--location)}mark.address{background:var(--address)}
.chip{display:inline-block;padding:1px 7px;border-radius:10px;margin:2px;font-size:12px;color:#0b0f14}
.chip.organization{background:var(--org);color:#fff}.chip.person{background:var(--person);color:#fff}
.chip.location{background:var(--location)}.chip.address{background:var(--address)}
.legend span{margin-right:10px}.dot{display:inline-block;width:10px;height:10px;border-radius:2px;vertical-align:middle;margin-right:4px}
table{width:100%;border-collapse:collapse;font-size:12px}td,th{padding:3px 6px;text-align:right;border-bottom:1px solid #21262d}th{color:#8b949e}td:first-child,th:first-child{text-align:left}
.big{font-size:22px;color:#fff}.kpi{display:flex;gap:22px;flex-wrap:wrap}
input[type=range]{vertical-align:middle}
</style></head><body>
<header>
  <b>psk</b><span class="muted">PII NER test harness</span>
  <span class="muted">model: <span id="model">…</span></span>
  <span class="legend muted" style="margin-left:auto">
    <span><i class="dot" style="background:var(--organization,#d9534f)"></i>organization</span>
    <span><i class="dot" style="background:#0275d8"></i>person</span>
    <span><i class="dot" style="background:#5cb85c"></i>location</span>
    <span><i class="dot" style="background:#f0ad4e"></i>address</span>
  </span>
</header>
<main>
  <div class="card">
    <div class="row" style="margin-bottom:8px">
      <button id="example" class="alt">↻ Load DB example (<span id="nex">0</span>)</button>
      <button id="run">▶ Detect</button>
      <label class="muted">threshold <input id="thr" type="range" min="0" max="1" step="0.05" value="0.3"><span id="thrv">0.30</span></label>
      <label class="muted"><input id="auto" type="checkbox"> auto-detect on type</label>
    </div>
    <textarea id="text" placeholder="Paste text here, or load a DB example…">Engagement with Societe Generale led by Jean Dupont in La Defense. Acme Corp hired John Smith at 42 Baker Street, London.</textarea>
  </div>

  <div class="card">
    <div class="kpi">
      <div><div class="muted">inference</div><div class="big"><span id="lat">–</span> ms</div></div>
      <div><div class="muted">throughput</div><div class="big"><span id="cps">–</span> ch/s</div></div>
      <div><div class="muted">entities</div><div class="big"><span id="nent">–</span></div></div>
      <div><div class="muted">chars</div><div class="big"><span id="chars">–</span></div></div>
    </div>
  </div>

  <div class="card">
    <div class="muted" style="margin-bottom:6px">Detected</div>
    <div id="out" class="out muted">—</div>
    <div id="pred" style="margin-top:8px"></div>
  </div>

  <div id="goldcard" class="card" style="display:none">
    <div class="muted" style="margin-bottom:6px">Gold (from dataset) — <span id="dsname"></span></div>
    <div id="gold"></div>
  </div>

  <div class="card">
    <div class="row"><div class="muted">Session speed</div><button id="clear" class="alt" style="margin-left:auto;padding:4px 10px">clear</button></div>
    <div class="kpi" style="margin:6px 0">
      <div><div class="muted">runs</div><div class="big" id="n">0</div></div>
      <div><div class="muted">mean</div><div class="big"><span id="mean">–</span> ms</div></div>
      <div><div class="muted">p50</div><div class="big"><span id="p50">–</span> ms</div></div>
      <div><div class="muted">p95</div><div class="big"><span id="p95">–</span> ms</div></div>
    </div>
    <table><thead><tr><th>#</th><th>chars</th><th>ms</th><th>ch/s</th><th>ents</th></tr></thead><tbody id="log"></tbody></table>
  </div>
</main>
<script>
const $=s=>document.querySelector(s);
let gold=[], lats=[], runs=0;
function esc(s){return s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function highlight(text, spans){
  spans=[...spans].sort((a,b)=>a.start-b.start);
  let h='',cur=0;
  for(const s of spans){ if(s.start<cur)continue;
    h+=esc(text.slice(cur,s.start));
    h+=`<mark class="${s.label}" title="${s.label}${s.score?' '+s.score:''}">${esc(text.slice(s.start,s.end))}</mark>`;
    cur=s.end; }
  h+=esc(text.slice(cur)); return h;
}
function chips(el,spans,text){
  el.innerHTML=spans.map(s=>`<span class="chip ${s.label}">${s.label}: ${esc(s.text||text.slice(s.start,s.end))}${s.score?' · '+s.score:''}</span>`).join('')||'<span class="muted">none</span>';
}
function pct(a,q){if(!a.length)return '–';const s=[...a].sort((x,y)=>x-y);return s[Math.min(s.length-1,Math.floor(q*s.length))].toFixed(0)}
async function run(){
  const text=$('#text').value, thr=parseFloat($('#thr').value);
  $('#run').disabled=true;
  try{
    const r=await fetch('/api/predict',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text,threshold:thr})});
    const d=await r.json();
    $('#out').innerHTML=highlight(text,d.entities); $('#out').classList.remove('muted');
    chips($('#pred'),d.entities,text);
    const cps=d.latency_ms>0?Math.round(d.chars/(d.latency_ms/1000)):0;
    $('#lat').textContent=d.latency_ms; $('#cps').textContent=cps.toLocaleString();
    $('#nent').textContent=d.entities.length; $('#chars').textContent=d.chars;
    if(d.latency_ms>0){ runs++; lats.push(d.latency_ms);
      $('#n').textContent=runs;
      $('#mean').textContent=(lats.reduce((a,b)=>a+b,0)/lats.length).toFixed(0);
      $('#p50').textContent=pct(lats,.5); $('#p95').textContent=pct(lats,.95);
      const tr=document.createElement('tr');
      tr.innerHTML=`<td>${runs}</td><td>${d.chars}</td><td>${d.latency_ms}</td><td>${cps}</td><td>${d.entities.length}</td>`;
      $('#log').prepend(tr);
    }
  }catch(e){ $('#out').textContent='error: '+e } finally{ $('#run').disabled=false }
}
$('#run').onclick=run;
$('#thr').oninput=e=>{$('#thrv').textContent=parseFloat(e.target.value).toFixed(2)};
$('#clear').onclick=()=>{lats=[];runs=0;$('#log').innerHTML='';$('#n').textContent=0;$('#mean').textContent='–';$('#p50').textContent='–';$('#p95').textContent='–'};
let t; $('#text').oninput=()=>{ if(!$('#auto').checked)return; clearTimeout(t); t=setTimeout(run,400); $('#goldcard').style.display='none' };
$('#example').onclick=async()=>{
  const d=await (await fetch('/api/example')).json();
  if(!d.text){alert('no examples loaded (started with --no-examples?)');return}
  $('#text').value=d.text; gold=d.gold||[];
  $('#goldcard').style.display=gold.length?'block':'none';
  $('#dsname').textContent=d.dataset||'';
  chips($('#gold'),gold,d.text);
  run();
};
(async()=>{const i=await (await fetch('/api/info')).json();$('#model').textContent=i.model;$('#nex').textContent=i.n_examples;$('#thr').value=i.threshold;$('#thrv').textContent=i.threshold.toFixed(2)})();
run();
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", default="urchade/gliner_multi_pii-v1")
    ap.add_argument("--threshold", type=float, default=0.3)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7860)
    ap.add_argument("--datasets",
                    default="ai4privacy/pii-masking-200k,ai4privacy/pii-masking-openpii-1m")
    ap.add_argument("--examples-n", type=int, default=80)
    ap.add_argument("--skip-rows", type=int, default=20000)
    ap.add_argument("--no-examples", action="store_true")
    ap.add_argument("--all-languages", action="store_true")
    args = ap.parse_args()

    STATE["model_id"] = args.model
    STATE["threshold"] = args.threshold
    STATE["model"] = load_model(args.model)
    if not args.no_examples:
        STATE["examples"] = load_examples(
            [d.strip() for d in args.datasets.split(",") if d.strip()],
            args.examples_n, args.skip_rows, not args.all_languages)

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"\n  ▶ psk test UI on http://{args.host}:{args.port}  "
          f"({len(STATE['examples'])} examples)\n", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("bye")


if __name__ == "__main__":
    main()
