"""Prompt-revision selection for the analysis and export steps (study-stats, export-paper-assets).

Why: a re-pilot after a prompt fix writes new run directories next to the old ones, with the
same case keys. Reading every ``scores.json`` would then pool two prompt revisions into one
paired comparison. This module only *selects* runs; it never changes a score, a run or the
row loader (:func:`app.study.final_runs.case_rows`).

A run's revision is ``<single>+<graph>`` from ``manifest.json`` ``prompt_versions`` (written by
the matched runner); a run without one is ``unknown``. The default is the latest revision
present (numeric ``-vN`` order), and any mix of revisions produces a warning.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

UNKNOWN = "unknown"
ALL = "all"


def run_revision(run_dir: str | Path) -> str:
    """``<single>+<graph>`` prompt versions of one run directory, or ``unknown``."""
    path = Path(run_dir) / "manifest.json"
    if not path.exists():
        return UNKNOWN
    versions = json.loads(path.read_text(encoding="utf-8")).get("prompt_versions")
    if not isinstance(versions, dict) or not versions:
        return UNKNOWN
    return "+".join(str(versions.get(k, UNKNOWN)) for k in ("single", "graph"))


def revision_key(revision: str) -> tuple[int, ...]:
    """Sort key: the ``-vN`` numbers of each part (``unknown`` sorts first)."""
    if revision == UNKNOWN:
        return ()
    return tuple(int(m.group(1)) if (m := re.search(r"v(\d+)$", part)) else 0
                 for part in revision.split("+"))


@dataclass(frozen=True)
class RevisionChoice:
    chosen: str | None  # None = every revision (``all``)
    present: dict[str, int]  # revision -> number of runs
    warning: str | None


def _listing(present: Mapping[str, int]) -> str:
    return ", ".join(f"{r} ({n} runs)" for r, n in sorted(present.items(), key=lambda kv: revision_key(kv[0])))


def _matches(requested: str, revision: str) -> bool:
    return requested == revision or requested in revision.split("+")


def choose_revision(present: Mapping[str, int], requested: str | None) -> RevisionChoice:
    """Pick the revision to analyse. ``requested`` None = latest; ``all`` = no filter."""
    present = dict(present)
    mixed = len(present) > 1
    if requested == ALL:
        warning = (f"prompt revisions mixed under the same case keys: {_listing(present)}; "
                   "all kept (--prompt-version all)") if mixed else None
        return RevisionChoice(None, present, warning)
    if requested is None:
        chosen = max(present, key=revision_key) if present else None
        warning = (f"prompt revisions mixed in these runs: {_listing(present)}; using the latest, "
                   f"{chosen} (pass --prompt-version to choose one, or 'all')") if mixed else None
        return RevisionChoice(chosen, present, warning)
    hits = [r for r in present if _matches(requested, r)]
    if len(hits) != 1:
        raise ValueError(f"prompt version {requested!r} matches {len(hits)} revisions; present: "
                         f"{_listing(present) or 'none'}")
    return RevisionChoice(hits[0], present, None)


def select_rows(rows: Sequence[Mapping[str, Any]], runs_dir: str | Path,
                requested: str | None) -> tuple[list[dict[str, Any]], RevisionChoice]:
    """Rows (from ``case_rows``) of the chosen revision, plus the choice made."""
    revision_of = {run: run_revision(Path(runs_dir) / run) for run in {str(r["run_id"]) for r in rows}}
    choice = choose_revision(Counter(revision_of.values()), requested)
    kept = [dict(r) for r in rows if choice.chosen is None or revision_of[str(r["run_id"])] == choice.chosen]
    return kept, choice
