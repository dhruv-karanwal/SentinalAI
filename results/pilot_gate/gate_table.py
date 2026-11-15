"""Pilot gate: per scenario x variant x arm status counts from case checkpoints (read-only)."""
import json, sys, glob, os
from collections import Counter

RUNS = sys.argv[1]
rows = []
for d in sorted(glob.glob(os.path.join(RUNS, "matched-*"))):
    if not os.path.exists(os.path.join(d, "manifest.json")):
        continue
    m = json.load(open(os.path.join(d, "manifest.json")))
    if len(sys.argv) > 2 and sys.argv[2] not in (m["prompt_versions"]["single"], m["prompt_versions"]["graph"], m["prompt_versions"]["single"] + "+" + m["prompt_versions"]["graph"]):  # e.g. m5-v4, wave-c-v2 or m5-v4+wave-c-v2
        continue
    if m.get("study_part") != "pilot" or "fake" in m["model"]["model_ids"].values():
        continue
    if not os.path.exists(os.path.join(d, "scores.json")):
        print("INCOMPLETE", d); continue
    per = {"single": Counter(), "graph": Counter()}
    wall = {"single": 0.0, "graph": 0.0}
    for cp in sorted(glob.glob(os.path.join(d, "cases", "*.checkpoint.json"))):
        c = json.load(open(cp))
        for arm, r in c["runs"].items():
            st = r["status"]
            if st == "ok":
                per[arm]["ok"] += 1
            elif st == "failed" and r.get("parse_status") == "unparseable":
                per[arm]["parse"] += 1
            elif st in ("token_budget_exceeded", "tool_budget_exceeded"):
                per[arm][st] += 1
            else:
                per[arm]["other:" + str(st)] += 1
            wall[arm] += r.get("wall_seconds") or 0.0
            per[arm]["n"] += 1
            per[arm]["repairs"] += r.get("repairs") or 0
    for arm in ("single", "graph"):
        p = per[arm]
        rows.append((m["scenario"], m["variant"], arm, p["n"], p["ok"], p["parse"],
                     p["tool_budget_exceeded"], p["token_budget_exceeded"],
                     sum(v for k, v in p.items() if k.startswith("other")), p["repairs"], wall[arm],
                     os.path.basename(d)))

print("| scenario | variant | arm | cases | ok | parse-failed | tool-budget | token-budget | other | repairs | parse-fail rate | arm wall s | run |")
print("|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|")
tot = {"single": Counter(), "graph": Counter()}
for r in rows:
    rate = r[5] / r[3] if r[3] else 0
    print(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[5]} | {r[6]} | {r[7]} | {r[8]} | {r[9]} | {rate:.1%} | {r[10]:.0f} | {r[11]} |")
    t = tot[r[2]]
    for i, k in enumerate(["n", "ok", "parse", "tool", "token", "other", "repairs"], start=3):
        t[k] += r[i]
    t["wall"] += r[10]
print()
for arm, t in tot.items():
    print(f"TOTAL {arm}: cases {t['n']} ok {t['ok']} parse {t['parse']} ({t['parse']/t['n']:.1%}) "
          f"tool-budget {t['tool']} token-budget {t['token']} other {t['other']} repairs {t['repairs']} wall {t['wall']:.0f}s "
          f"= {t['wall']/t['n']:.1f}s/case")
print("max per-arm parse-fail rate:", max((r[5] / r[3]) for r in rows if r[3]))
