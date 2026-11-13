"""Graph arm: every repair (parse error followed by a retry) by node, and what the retry did."""
import json, sys, glob, os
from collections import Counter

RUNS = sys.argv[1]
out = Counter()
for d in sorted(glob.glob(os.path.join(RUNS, "matched-*"))):
    m = json.load(open(os.path.join(d, "manifest.json")))
    if m.get("study_part") != "pilot" or "fake" in m["model"]["model_ids"].values():
        continue
    for t in sorted(glob.glob(os.path.join(d, "cases", "*.graph.json"))):
        rq = json.load(open(t))["requests"]
        for a, b in zip(rq, rq[1:]):
            if str(a.get("parse", "")).startswith("error") and b["node"] == a["node"]:
                kind = "report" if a["node"] == "report_generation" else ("supervisor" if a["node"] == "supervisor" else "note-agent")
                res = str(b.get("parse"))
                res = "retry ok" if not res.startswith("error") else ("retry -> 'final' rejected" if "must be one of" in res else "retry other error")
                out[(kind, res)] += 1
for k, v in sorted(out.items()):
    print(v, k)
