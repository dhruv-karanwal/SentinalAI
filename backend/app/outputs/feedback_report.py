"""Offline feedback report (Wave D): what analysts said about alerts, incidents, findings, reports.

A summary for people. **No retraining:** feedback never changes detectors,
ML baselines, thresholds, prompts or the study configuration automatically;
anything learned from it is a human decision made in a reviewed commit.
Analyst feedback is also never a ground-truth label for the study (labels
come only from the dataset's truth area).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from app.storage.repository import Repository

NOTE = ("Offline summary for humans. No retraining: feedback never changes detectors, models, "
        "thresholds or prompts automatically, and it is never used as a study label.")


def feedback_report(repo: Repository) -> dict[str, Any]:
    rows = repo.list_feedback()
    by_type: dict[str, Counter[str]] = defaultdict(Counter)
    by_target: dict[str, Counter[str]] = defaultdict(Counter)
    for r in rows:
        by_type[r["target_type"]][r["verdict"]] += 1
        by_target[f"{r['target_type']}:{r['target_id']}"][r["verdict"]] += 1
    disputed: list[dict[str, Any]] = [
        {"target": t, "verdicts": dict(sorted(c.items())), "entries": sum(c.values())}
        for t, c in by_target.items() if len(c) > 1]
    disputed.sort(key=lambda d: (-int(d["entries"]), str(d["target"])))
    return {"note": NOTE, "total": len(rows),
            "by_target_type": {t: dict(c.most_common()) for t, c in sorted(by_type.items())},
            "by_verdict": dict(Counter(r["verdict"] for r in rows).most_common()),
            "by_user": dict(Counter(r["username"] for r in rows).most_common()),
            "targets": len(by_target), "most_disputed": disputed[:20]}
