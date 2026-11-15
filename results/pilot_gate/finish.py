"""For every failed pilot request with a parse error: finish_reason and output tokens; plus the first
bad reply of the anomaly 'final' cases."""
import json, sys, glob, os
from collections import Counter

RUNS = sys.argv[1]
c = Counter()
shown = 0
for d in sorted(glob.glob(os.path.join(RUNS, "matched-*"))):
    if not os.path.exists(os.path.join(d, "manifest.json")):
        continue
    m = json.load(open(os.path.join(d, "manifest.json")))
    if len(sys.argv) > 2 and sys.argv[2] not in (m["prompt_versions"]["single"], m["prompt_versions"]["graph"], m["prompt_versions"]["single"] + "+" + m["prompt_versions"]["graph"]):  # e.g. m5-v4, wave-c-v2 or m5-v4+wave-c-v2
        continue
    if m.get("study_part") != "pilot" or "fake" in m["model"]["model_ids"].values():
        continue
    for t in sorted(glob.glob(os.path.join(d, "cases", "*.*.json"))):
        if t.endswith("checkpoint.json"):
            continue
        tr = json.load(open(t))
        msgs = [x for x in tr["messages"] if x["role"] == "assistant"]
        for q, a in zip(tr["requests"], msgs):
            p = str(q.get("parse", ""))
            if p.startswith("error"):
                c[(p.split("(")[0][:45], q.get("finish_reason"), q["output_tokens"] >= 1024)] += 1
                if "property name" in p and shown < 2:
                    shown += 1
                    print(os.path.basename(t), repr(a["content"][:400]))
for k, v in sorted(c.items(), key=lambda kv: -kv[1]):
    print(v, k)
