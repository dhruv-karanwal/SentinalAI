"""Classify each non-ok pilot case (arm) by its final failing request."""
import json, sys, glob, os
from collections import Counter

RUNS = sys.argv[1]
by = Counter()
for d in sorted(glob.glob(os.path.join(RUNS, "matched-*"))):
    if not os.path.exists(os.path.join(d, "manifest.json")):
        continue
    m = json.load(open(os.path.join(d, "manifest.json")))
    if len(sys.argv) > 2 and m["prompt_versions"]["graph"] != sys.argv[2]:  # e.g. wave-c-v2
        continue
    if m.get("study_part") != "pilot" or "fake" in m["model"]["model_ids"].values():
        continue
    for cp in sorted(glob.glob(os.path.join(d, "cases", "*.checkpoint.json"))):
        c = json.load(open(cp))
        idx = os.path.basename(cp).split(".")[0]
        for arm, r in c["runs"].items():
            st = r["status"]
            if st == "ok":
                continue
            if st != "failed":
                cls = "budget: " + st
            else:
                t = json.load(open(os.path.join(d, "cases", f"{idx}.{arm}.json")))
                q = t["requests"][-1]
                p = str(q.get("parse", ""))
                if q.get("finish_reason") == "length":
                    cls = "output cut at max_tokens 1024 (finish=length)"
                elif "Extra data" in p:
                    cls = "format: several JSON objects in one reply"
                elif "delimiter" in p or "property name" in p:
                    cls = "format: malformed JSON (brackets / expression)"
                elif "must be one of" in p:
                    cls = "role: final answer from a non-report agent"
                elif "kind" in p or "quote" in p:
                    cls = "schema: invalid claim"
                else:
                    cls = "other: " + p[:60]
            node = (r.get("error") or "").split(":")[0] if arm == "graph" else "-"
            by[(arm, cls)] += 1
            print(f"{m['scenario']:15} {m['variant']:11} {idx} {arm:6} {node:18} {cls}")
print()
for (arm, cls), n in sorted(by.items()):
    print(f"{arm:6} {n:3}  {cls}")
