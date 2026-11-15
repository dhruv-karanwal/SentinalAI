"""Copy scores.json of the re-pilot runs (graph prompt wave-c-v2, non-fake) into a view dir."""
import json, os, shutil, sys
from pathlib import Path

runs, view = Path(sys.argv[1]), Path(sys.argv[2])
view.mkdir(parents=True, exist_ok=True)
n = 0
for d in sorted(runs.glob("matched-*")):
    m, s = d / "manifest.json", d / "scores.json"
    if not (m.exists() and s.exists()):
        continue
    man = json.loads(m.read_text(encoding="utf-8"))
    if man["prompt_versions"]["graph"] != "wave-c-v2" or "fake" in man["model"]["model_ids"].values():
        continue
    (view / d.name).mkdir(exist_ok=True)
    shutil.copyfile(s, view / d.name / "scores.json")
    n += 1
print(n, "runs")
