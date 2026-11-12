"""Protocol freeze and the logged held-out permit (final study).

Why: the held-out scenarios may be run exactly once the protocol is fixed.
``protocol-freeze`` writes ``experiments/freeze/protocol-freeze.json`` with
the SHA-256 of everything that decides a run's outcome:

- ``study_config`` (study.json bytes), ``statistics_config`` (the declared
  comparison family), ``final_plan`` (experiments/config/final_study.json),
  ``relevance_set`` (the frozen RAG set);
- ``single_system_prompt`` (+ ``PROMPT_VERSION``) and ``graph_prompts``
  (``PROMPTS_SHA256`` + ``GRAPH_PROMPT_VERSION``);
- ``tool_and_study_code``: every module that shapes what the agents see or
  how they are scored (:data:`FROZEN_CODE`, line endings normalised to LF so
  a checkout's CRLF setting does not matter). Analysis-only code (stats,
  the paper exporter, CLIs) is deliberately *not* in it: it reads run files
  and can be fixed after the freeze without touching any run;
- ``model_id`` (the endpoint model name) and ``seeds``.

``freeze_sha256`` is the hash of the ``hashes`` block. The git commit is
recorded as provenance only (committing the freeze changes HEAD, so it is
not compared).

:func:`authorize_held_out` is the only way to obtain a :class:`HeldOutPermit`:
it recomputes every hash, refuses on a missing freeze or any mismatch, and
appends every attempt (``authorized`` or ``refused``) to an access log.
Code that would otherwise call ``config.split.require_dev`` accepts a permit
instead (``prepare_run(..., permit=...)``).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.study.config import StudyConfig

APP = Path(__file__).resolve().parents[1]
REPO = APP.parents[1]
DEFAULT_FREEZE = REPO / "experiments" / "freeze" / "protocol-freeze.json"
DEFAULT_FINAL_PLAN = REPO / "experiments" / "config" / "final_study.json"
DEFAULT_STATISTICS = REPO / "experiments" / "config" / "statistics.json"

# Modules (relative to app/) whose code decides what an agent sees or how it is scored.
FROZEN_CODE: tuple[str, ...] = (
    "agent/*.py", "evaluation/*.py", "rag/*.py", "ingestion/*.py", "schemas/*.py",
    "alert_pipeline.py", "study/cases.py", "study/variants.py", "study/baselines.py",
    "study/config.py", "study/final_runs.py", "intel/attack.py", "storage/repository.py",
)


class FreezeError(Exception):
    """No protocol freeze, or the current protocol differs from the frozen one."""


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: str | Path) -> str:
    return _sha_bytes(Path(path).read_bytes())


def _code_hash() -> tuple[str, dict[str, str]]:
    files: dict[str, str] = {}
    for pattern in FROZEN_CODE:
        for path in sorted(APP.glob(pattern)):
            text = path.read_bytes().replace(b"\r\n", b"\n")
            files[path.relative_to(APP).as_posix()] = _sha_bytes(text)
    return _sha_bytes(json.dumps(files, sort_keys=True).encode()), files


def _git_commit() -> str | None:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True,
                             timeout=10, check=True)
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def compute_freeze(*, study_config: str | Path, statistics_config: str | Path = DEFAULT_STATISTICS,
                   final_plan: str | Path = DEFAULT_FINAL_PLAN, model_id: str,
                   model_digest: str | None = None) -> dict[str, Any]:
    from app.agent.graph import GRAPH_PROMPT_VERSION, PROMPTS_SHA256
    from app.agent.protocol import PROMPT_VERSION, SYSTEM_PROMPT
    from app.rag.retriever import DEFAULT_RELEVANCE_SET
    from app.study.config import load_study_config

    config = load_study_config(study_config)
    stats = json.loads(Path(statistics_config).read_text(encoding="utf-8"))
    seeds = {"variants": config.variant_seed, "cases": config.cases.seed,
             "statistics": int(stats["seed"])}
    code, files = _code_hash()
    hashes = {
        "study_config": _sha_file(study_config),
        "statistics_config": _sha_file(statistics_config),
        "final_plan": _sha_file(final_plan),
        "relevance_set": _sha_file(DEFAULT_RELEVANCE_SET),
        "single_system_prompt": _sha_bytes(f"{PROMPT_VERSION}\n{SYSTEM_PROMPT}".encode()),
        "graph_prompts": _sha_bytes(f"{GRAPH_PROMPT_VERSION}\n{PROMPTS_SHA256}".encode()),
        "tool_and_study_code": code,
        "model_id": model_id,
        "seeds": _sha_bytes(json.dumps(seeds, sort_keys=True).encode()),
    }
    return {
        "note": ("Protocol freeze of the final study. After this file is committed, prompts, tools, "
                 "configs and study code do not change; a later bug fix means re-running the "
                 "affected runs and recording it in docs/session-notes.md."),
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "freeze_sha256": _sha_bytes(json.dumps(hashes, sort_keys=True).encode()),
        "hashes": hashes,
        "seeds": seeds,
        "versions": {"single_prompt": PROMPT_VERSION, "graph_prompt": GRAPH_PROMPT_VERSION},
        "model": {"id": model_id, "digest": model_digest},
        "code_files": files,
    }


def write_freeze(manifest: dict[str, Any], path: str | Path = DEFAULT_FREEZE) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return out


def verify_freeze(path: str | Path, *, study_config: str | Path,
                  statistics_config: str | Path = DEFAULT_STATISTICS,
                  final_plan: str | Path = DEFAULT_FINAL_PLAN, model_id: str) -> list[str]:
    """Names of the frozen hashes that differ now (empty = protocol unchanged)."""
    frozen = json.loads(Path(path).read_text(encoding="utf-8"))
    now = compute_freeze(study_config=study_config, statistics_config=statistics_config,
                         final_plan=final_plan, model_id=model_id)
    bad = [k for k, v in frozen["hashes"].items() if now["hashes"].get(k) != v]
    if _sha_bytes(json.dumps(frozen["hashes"], sort_keys=True).encode()) != frozen["freeze_sha256"]:
        bad.append("freeze_sha256")
    if bad and "tool_and_study_code" in bad:
        changed = sorted(f for f in set(frozen["code_files"]) | set(now["code_files"])
                         if frozen["code_files"].get(f) != now["code_files"].get(f))
        bad[bad.index("tool_and_study_code")] = f"tool_and_study_code ({', '.join(changed)})"
    return bad


@dataclass(frozen=True)
class HeldOutPermit:
    freeze_path: str
    freeze_sha256: str
    reason: str

    def check(self, config: StudyConfig, scenario: str) -> str:
        if scenario not in config.split.held_out and scenario not in config.split.dev:
            raise ValueError(f"scenario {scenario!r} is not in the study split")
        return scenario


def _log(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), **event}) + "\n")


def authorize_held_out(freeze_path: str | Path, *, study_config: str | Path,
                       statistics_config: str | Path = DEFAULT_STATISTICS,
                       final_plan: str | Path = DEFAULT_FINAL_PLAN, model_id: str,
                       access_log: str | Path, reason: str) -> HeldOutPermit:
    """A permit for held-out scenarios, only if the protocol equals the frozen one (always logged)."""
    log = Path(access_log)
    path = Path(freeze_path)
    if not path.exists():
        _log(log, {"event": "refused", "why": "no protocol freeze", "freeze": str(path),
                   "reason": reason})
        raise FreezeError(f"no protocol freeze at {path}; run protocol-freeze first")
    bad = verify_freeze(path, study_config=study_config, statistics_config=statistics_config,
                        final_plan=final_plan, model_id=model_id)
    if bad:
        _log(log, {"event": "refused", "why": "mismatch", "mismatch": bad, "freeze": str(path),
                   "reason": reason})
        raise FreezeError(f"protocol differs from the freeze: {', '.join(bad)}")
    digest = json.loads(path.read_text(encoding="utf-8"))["freeze_sha256"]
    _log(log, {"event": "authorized", "freeze": str(path), "freeze_sha256": digest,
               "model_id": model_id, "reason": reason})
    return HeldOutPermit(str(path), digest, reason)
