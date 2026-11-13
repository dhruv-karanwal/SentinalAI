"""Controls sanity check: event_label coverage on reachable phases per arm and baseline, from scores.json."""
import json, sys, glob, os

RUNS = sys.argv[1]
SHOW = ["cite-all", "cite-none", "cite-top-k-wazuh-level@k5", "cite-top-k-detector-order@k10",
        "cite-top-k-detector-order@k8-matched"]
names = set()
print("| scenario | variant | single | single+verifier | graph | graph+verifier | cite-all | cite-none | top-k det-order@k10 | cit. prec. event (graph+v) |")
print("|---|---|---|---|---|---|---|---|---|---|")
for d in sorted(glob.glob(os.path.join(RUNS, "matched-*"))):
    m = json.load(open(os.path.join(d, "manifest.json")))
    if m.get("study_part") != "pilot" or "fake" in m["model"]["model_ids"].values():
        continue
    s = json.load(open(os.path.join(d, "scores.json")))
    names |= set(s["baselines"])
    def cov(row):
        r = row["coverage"]["event_label"]["reachable"]
        return f"{r['covered']}/{r['cases']}"
    arms = s["arms"]
    b = s["baselines"]
    print(f"| {s['scenario']} | {s['variant']} | " + " | ".join(cov(arms[a]) for a in ("single", "single+verifier", "graph", "graph+verifier"))
          + f" | {cov(b['cite-all'])} | {cov(b['cite-none'])} | {cov(b['cite-top-k-detector-order@k10'])} | "
          + f"{arms['graph+verifier']['citation_precision']['event_label']} |")
print()
print("baseline rows present:", sorted(names))
