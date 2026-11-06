"""Agent runs over the cases of a dev scenario: selection, run log, scoring.

A run = one model + agent config on one (dev scenario, variant, truncation)
and a deterministic selection of cases: attack and benign cases are
interleaved in case order (attack 1, benign 1, attack 2, ...) and the first
``limit`` are taken, so ``--limit 2`` is one attack and one benign case.

Run log, in ``<output_dir>/<run_id>/`` (git-ignored ``data/processed/runs``):

- ``manifest.json``: run id, config hash, model id and settings (never the
  API key, only the name of its variable), agent budgets, prompt version,
  scenario, variant, truncation, and per case: tokens in/out (and whether
  the endpoint reported them), requests, tool calls, latency, parse status,
  status, verdict, error, the real alert ids the case held and its
  transcript file;
- ``cases/<n>.json``: the full transcript, the request log, the final
  answer and the opaque-to-real id map;
- ``scores.json``: the agent's row and every baseline row (k = 5, 10 and k
  matched to the agent's mean citations) over the *same* cases, built by
  the same :func:`summarize_scores`, plus verdict counts.

``run_id`` = UTC start time + the first 8 hex digits of the config hash
(+ a counter if that directory exists). The config hash covers the study
config file, model settings, agent budgets, system prompt, scenario,
variant, truncation and the selected case ids.

Token bound (:func:`estimate_run`): the agent never starts a request that
could exceed ``max_tokens_per_case`` (prompt estimated at 3 characters per
token), so a run is bounded by cases x ``max_tokens_per_case``; the cost
bound prices every one of those tokens at the higher of the two prices.
Runs whose bound exceeds ``agent.run_token_budget`` need ``--confirm``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.agent.agent import CaseRun, conservative_tokens, investigate
from app.agent.client import ChatClient
from app.agent.config import AgentSettings
from app.agent.protocol import PROMPT_VERSION, SYSTEM_PROMPT
from app.agent.tools import CaseToolkit
from app.evaluation.case_scoring import CaseScore, alert_claim_index, alert_quote_index, score_case
from app.evaluation.metrics import triage_scores
from app.ingestion.ground_truth import AttackTimeline
from app.schemas.alert import Alert
from app.study.baselines import matched_k
from app.study.cases import (
    Case,
    CaseAlerts,
    CaseKind,
    baseline_summaries,
    build_cases,
    reachable_phases,
    summarize_scores,
    variant_case_views,
)
from app.study.config import TRUNCATION_CHOICES, StudyConfig
from app.study.variants import AlertPool, experiment_variants


@dataclass(frozen=True)
class PreparedRun:
    scenario: str
    variant: str
    truncation: str
    config: StudyConfig
    pool: AlertPool
    cases: tuple[Case, ...]
    views: tuple[CaseAlerts, ...]
    reachable: tuple[str, ...]


SELECTION_MODES = ("interleaved", "reachable")


def select_cases(cases: Sequence[Case], limit: int | None, *, mode: str = "interleaved",
                 reachable: Sequence[str] = (), case_ids: Sequence[str] | None = None) -> list[int]:
    """Indices of the cases a run investigates, deterministic.

    - ``case_ids``: exactly these cases, in the given order (unknown id = error);
    - mode ``interleaved``: attack and benign cases interleaved in case order;
    - mode ``reachable`` (M6): the same, restricted to attack cases on an
      alert-reachable phase and the benign cases matched to those phases, so a
      small pilot does not spend its budget on phases no detector can show.
    ``limit`` then takes the first N.
    """
    if case_ids is not None:
        index = {c.case_id: i for i, c in enumerate(cases)}
        missing = [cid for cid in case_ids if cid not in index]
        if missing:
            raise ValueError(f"unknown case id(s): {', '.join(missing)}")
        picked = [index[cid] for cid in case_ids]
        return picked if limit is None else picked[:limit]
    if mode not in SELECTION_MODES:
        raise ValueError(f"selection mode must be one of {', '.join(SELECTION_MODES)}")
    keep = set(reachable)
    allowed = [i for i, c in enumerate(cases) if mode == "interleaved" or c.phase in keep]
    attack = [i for i in allowed if cases[i].kind is CaseKind.ATTACK]
    benign = [i for i in allowed if cases[i].kind is CaseKind.BENIGN]
    order: list[int] = []
    for k in range(max(len(attack), len(benign))):
        order.extend(group[k] for group in (attack, benign) if k < len(group))
    return order if limit is None else order[:limit]


def prepare_run(processed_dir: str | Path, labels_path: str | Path, scenario: str, variant: str,
                config: StudyConfig, *, limit: int | None,
                truncation: str | None = None, selection: str = "interleaved",
                case_ids: Sequence[str] | None = None) -> PreparedRun:
    config.split.require_dev(scenario)  # before any file is read
    rule = truncation or config.cases.truncation
    if rule not in TRUNCATION_CHOICES:
        raise ValueError(f"truncation must be one of {', '.join(TRUNCATION_CHOICES)}")
    pool = AlertPool.from_processed(processed_dir, scenario)
    timeline = AttackTimeline.from_labels_csv(labels_path, scenario)
    case_config = dataclasses.replace(config.cases, truncation=rule)
    case_set = build_cases(pool, timeline, case_config)
    variants = experiment_variants(pool, config)
    if variant not in variants:
        raise ValueError(f"unknown experiment variant {variant!r}; choose from {', '.join(variants)}")
    views = variant_case_views(case_set, variants, pool, case_config)[variant]
    reachable, _ = reachable_phases(case_set, pool)
    chosen = select_cases(case_set.cases, limit, mode=selection, reachable=reachable,
                          case_ids=case_ids)
    return PreparedRun(scenario, variant, rule, config, pool,
                       tuple(case_set.cases[i] for i in chosen), tuple(views[i] for i in chosen),
                       reachable)


def _window_seconds(case: Case) -> float:
    return (case.window_end - case.window_start).total_seconds()


def _toolkit(prep: PreparedRun, index: int, alerts: Sequence[Alert], settings: AgentSettings,
             salt: str) -> CaseToolkit:
    case = prep.cases[index]
    return CaseToolkit(alerts, window_start=case.window_start, window_seconds=_window_seconds(case),
                       id_salt=f"{salt}:{index}", page_size=settings.agent.list_page_size,
                       max_output_chars=settings.agent.max_tool_output_chars)


def estimate_run(prep: PreparedRun, settings: AgentSettings) -> dict[str, Any]:
    """Token and cost bound of a run, without calling any model."""
    per_case = settings.agent.max_tokens_per_case
    bound = per_case * len(prep.cases)
    price = max(settings.model.price_input_per_million, settings.model.price_output_per_million)
    first_prompt = 0
    for i, view in enumerate(prep.views):
        kit = _toolkit(prep, i, [prep.pool.alert(e) for e in view.entries], settings, "estimate")
        first_prompt += conservative_tokens([{"role": "system", "content": SYSTEM_PROMPT},
                                             {"role": "user", "content": kit.brief()}])
    return {
        "cases": len(prep.cases),
        "token_bound_per_case": per_case,
        "token_bound": bound,
        "cost_bound_usd": bound * price / 1_000_000,
        "price_per_million_used": price,
        "first_prompt_tokens_estimate": first_prompt,
        "max_requests_per_case": settings.agent.max_tool_calls + settings.agent.repair_retries + 2,
        "run_token_budget": settings.agent.run_token_budget,
        "needs_confirm": bound > settings.agent.run_token_budget,
    }


def config_hash(prep: PreparedRun, settings: AgentSettings, model_id: str,
                study_config_path: str | Path) -> str:
    payload = {
        "study_config_sha256": hashlib.sha256(Path(study_config_path).read_bytes()).hexdigest(),
        "model": {**settings.model.public(), "model_id": model_id},
        "agent": asdict(settings.agent),
        "prompt_version": PROMPT_VERSION,
        "system_prompt_sha256": hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest(),
        "scenario": prep.scenario, "variant": prep.variant, "truncation": prep.truncation,
        "case_ids": [c.case_id for c in prep.cases],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def _dump(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
                    encoding="utf-8")


def _run_dir(output_dir: Path, now: datetime, digest: str) -> tuple[str, Path]:
    base = f"{now.astimezone(timezone.utc):%Y%m%dT%H%M%SZ}-{digest[:8]}"
    run_id, n = base, 1
    while (output_dir / run_id).exists():
        n += 1
        run_id = f"{base}-{n}"
    return run_id, output_dir / run_id


def _verdicts(cases: Sequence[Case], runs: Sequence[CaseRun]) -> dict[str, Any]:
    parsed = [(c, r) for c, r in zip(cases, runs) if r.verdict is not None]
    scores = triage_scores({c.case_id: r.verdict == "attack" for c, r in parsed},
                           {c.case_id: c.kind is CaseKind.ATTACK for c, _ in parsed})
    return {"cases": len(runs), "with_verdict": len(parsed), "failed": len(runs) - len(parsed),
            "correct": scores.tp + scores.tn, "tp": scores.tp, "fp": scores.fp,
            "fn": scores.fn, "tn": scores.tn,
            "rule": "case-level verdict vs case kind; failed cases have no verdict and are counted"}


def run_agent(prep: PreparedRun, settings: AgentSettings, client: ChatClient, *,
              output_dir: str | Path, study_config_path: str | Path,
              now: datetime | None = None) -> dict[str, Any]:
    started = now or datetime.now(timezone.utc)
    digest = config_hash(prep, settings, client.model_id, study_config_path)
    run_id, run_dir = _run_dir(Path(output_dir), started, digest)
    run_dir.mkdir(parents=True)
    runs: list[CaseRun] = []
    scores: list[CaseScore] = []
    records: list[dict[str, Any]] = []
    for i, (case, view) in enumerate(zip(prep.cases, prep.views)):
        alerts = [prep.pool.alert(e) for e in view.entries]
        kit = _toolkit(prep, i, alerts, settings, digest)
        run = investigate(client, kit, settings.agent, settings.model)
        runs.append(run)
        scores.append(score_case(case, view, run.cited_alert_ids, claims=run.claims,
                                 claim_index=alert_claim_index(alerts),
                                 quote_index=alert_quote_index(alerts)))
        transcript_file = f"cases/{i:03d}.json"
        _dump(run_dir / transcript_file, {
            "case_id": case.case_id, "messages": run.transcript, "requests": run.request_log,
            "final": run.final, "id_map": kit.id_map})
        records.append({
            "index": i, "case_id": case.case_id, "kind": case.kind.value, "phase": case.phase,
            "alerts": len(alerts), "alert_ids": [a.alert_id for a in alerts],
            "status": run.status, "parse_status": run.parse_status, "verdict": run.verdict,
            "error": run.error, "input_tokens": run.input_tokens, "output_tokens": run.output_tokens,
            "usage_reported": run.usage_reported, "requests": run.requests,
            "tool_calls": run.tool_calls, "repairs": run.repairs,
            "latency_seconds": run.latency_seconds, "wall_seconds": run.wall_seconds,
            "cited": len(run.cited_alert_ids), "claims": len(run.claims),
            "transcript_file": transcript_file})

    mean_cited = sum(s.cited for s in scores) / len(scores) if scores else 0.0
    k = matched_k(mean_cited)
    agent_row = summarize_scores(prep.cases, scores, prep.reachable)
    agent_row["runs"] = {
        "status": dict(sorted(Counter(r.status for r in runs).items())),
        "parse_status": dict(sorted(Counter(str(r.parse_status) for r in runs).items())),
        "input_tokens": sum(r.input_tokens for r in runs),
        "output_tokens": sum(r.output_tokens for r in runs),
        "usage_reported": all(r.usage_reported for r in runs),
        "tool_calls": sum(r.tool_calls for r in runs),
        "latency_seconds": sum(r.latency_seconds for r in runs),
    }
    agent_row["verdict"] = _verdicts(prep.cases, runs)
    score_report = {
        "note": ("DEV-SCENARIO AGENT RUN (pilot material on a dev scenario; not held-out results). "
                 "Baselines are scored on the same cases."),
        "scenario": prep.scenario, "variant": prep.variant, "truncation": prep.truncation,
        "headline": "coverage by event_label on alert-reachable phases; time_label = sensitivity",
        "matched_k": k,
        "agent": agent_row,
        "baselines": baseline_summaries(prep.cases, prep.views, prep.pool, prep.config.baselines,
                                        prep.reachable, matched=k),
    }
    manifest = {
        "run_id": run_id, "config_hash": digest, "started_utc": started.isoformat(),
        "scenario": prep.scenario, "scenario_split": "dev", "variant": prep.variant,
        "truncation": prep.truncation, "study_config": Path(study_config_path).name,
        "model": {"model_id": client.model_id, **settings.model.public()},
        "agent": asdict(settings.agent), "prompt_version": PROMPT_VERSION,
        "estimate": estimate_run(prep, settings),
        "cases": records,
    }
    _dump(run_dir / "manifest.json", manifest)
    _dump(run_dir / "scores.json", score_report)
    return {"run_id": run_id, "run_dir": str(run_dir), "config_hash": digest,
            "manifest": manifest, "scores": score_report}
