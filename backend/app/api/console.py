"""Console v2 routes: overview aggregates, filtered alert queries, facets, CSV export, incident
analysis, entities, global search, executive summary, user management, study results.

(No ``from __future__ import annotations``: FastAPI resolves the ``Annotated`` hints.)

Rules carried over from ``app.py``: every route needs a permission; GET routes read only;
every non-GET route writes ``audit_log``; nothing here touches the truth area. Aggregates come
from one in-memory :class:`AlertIndex` per scenario, rebuilt when the stored count changes, so
charts never ship raw records. Passwords for created or reset accounts come only from the API
host's environment (``SENTINEL_NEW_USER_PASSWORD``), never from the request.

Study results are read from ``scores.json`` + ``manifest.json`` of matched runs in
``SENTINEL_RUNS_DIR`` (default ``data/processed/runs``). Runs whose model ids include ``fake``
(FakeClient plumbing checks) are excluded and counted, never shown as results.
"""

import csv
import io
import json
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.api.auth import Role, hash_password
from app.intel.attack import DEFAULT_STIX, AttackKB
from app.outputs import analytics as an

NEW_PASSWORD_ENV = "SENTINEL_NEW_USER_PASSWORD"
RUNS_DIR_ENV = "SENTINEL_RUNS_DIR"
EXPORT_LIMIT = 200_000


class ConsoleUserBody(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    role: Role


def load_kb(extras: dict[str, Any]) -> AttackKB | None:
    """The ATT&CK bundle for tactic names: ``extras['attack_kb']`` or the local file, else None."""
    if "attack_kb" not in extras:
        extras["attack_kb"] = AttackKB.from_stix(DEFAULT_STIX) if DEFAULT_STIX.exists() else None
    kb: AttackKB | None = extras["attack_kb"]
    return kb


def study_results(runs_dir: Path) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    excluded_fake = 0
    incomplete = 0
    if runs_dir.is_dir():
        for d in sorted(p for p in runs_dir.iterdir() if p.is_dir()):
            manifest_path, scores_path = d / "manifest.json", d / "scores.json"
            if not manifest_path.exists():
                continue
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            model = manifest.get("model") or {}
            ids = [str(v) for v in (model.get("model_ids") or {}).values()] or [str(model.get("model_id"))]
            if any("fake" in i.lower() for i in ids):
                excluded_fake += 1
                continue
            if not scores_path.exists():
                incomplete += 1
                continue
            scores = json.loads(scores_path.read_text(encoding="utf-8"))
            if "arms" not in scores:  # single-agent run logs (M5) have another shape
                continue
            runs.append({"run_id": d.name, "scenario": manifest.get("scenario"),
                         "variant": manifest.get("variant"), "truncation": manifest.get("truncation"),
                         "split": manifest.get("scenario_split"), "started_utc": manifest.get("started_utc"),
                         "model_ids": model.get("model_ids"), "retrieval_mode": manifest.get("retrieval_mode"),
                         "cases": len(manifest.get("cases") or []), "matched_k": scores.get("matched_k"),
                         "arms": scores["arms"], "baselines": scores.get("baselines", {}),
                         "note": scores.get("note"), "study_part": scores.get("study_part")})
    return {"runs": runs, "excluded_fake_runs": excluded_fake, "incomplete_runs": incomplete,
            "label": "dev scenarios, pilot numbers, not paper results"}


def add_console_routes(app: FastAPI, repo: Any, search_index: Any, extras: dict[str, Any],
                       need: Callable[[str], Callable[..., Any]]) -> None:
    cache: dict[str, tuple[int, an.AlertIndex]] = {}
    lock = threading.Lock()

    def index_for(scenario: str) -> an.AlertIndex:
        stored = sum(repo.count_alerts(scenario).values())
        with lock:
            hit = cache.get(scenario)
            if hit and hit[0] == stored:
                return hit[1]
            iocs = extras.get("iocs")
            facts = []
            for row in repo.iter_alert_rows(scenario):
                ioc = None
                if iocs is not None:
                    from app.schemas.alert import Alert
                    ioc = bool(iocs.match_alert(Alert.model_validate(row["record"]), row["enrichment"]))
                facts.append(an.fact_from_row(row, ioc))
            idx = an.AlertIndex(scenario, facts, ioc_loaded=iocs is not None)
            cache[scenario] = (stored, idx)
            return idx

    def flt(detector: Optional[str], level: Optional[str], rule_id: Optional[str], technique: Optional[str],
            host: Optional[str], ip: Optional[str], since: Optional[str], until: Optional[str]) -> an.AlertFilter:
        try:
            return an.AlertFilter(detector=detector, level=level, rule_id=rule_id, technique=technique,
                                  host=host, ip=ip, since=an._epoch(since) if since else None,
                                  until=an._epoch(until) if until else None)
        except ValueError as exc:
            raise HTTPException(422, f"bad time: {exc}") from exc

    Read = Annotated[Any, Depends(need("read"))]
    Q = Optional[str]

    @app.get("/overview")
    def overview(p: Read, scenario: str) -> dict[str, Any]:
        idx = index_for(scenario)
        kb = load_kb(extras)
        incidents = repo.list_incidents(scenario)
        approvals = [a for a in repo.list_approvals()
                     if (repo.get_incident(a["incident_id"]) or {}).get("scenario") == scenario]
        return {"scenario": scenario, "alerts": len(idx),
                "status": an.queue_summary(incidents, approvals, time.time()),
                "timeseries": idx.timeseries(an.AlertFilter(), target=160),
                "incident_starts": an.incident_starts(incidents),
                "attack": idx.attack_matrix(kb), "entities": idx.entities(incidents),
                "detectors": idx.detector_comparison(), "ioc_loaded": idx.ioc_loaded,
                "kill_chain": an.kill_chain(idx.facts, kb)}

    @app.get("/alerts/query")
    def query_alerts(p: Read, scenario: str, detector: Q = None, level: Q = None, rule_id: Q = None,
                     technique: Q = None, host: Q = None, ip: Q = None, since: Q = None, until: Q = None,
                     limit: Annotated[int, Query(ge=1, le=500)] = 200,
                     offset: Annotated[int, Query(ge=0)] = 0) -> dict[str, Any]:
        from app.api.auth import allowed

        f = flt(detector, level, rule_id, technique, host, ip, since, until)
        rows = index_for(scenario).select(f)
        page = rows[offset:offset + limit]
        out = repo.get_alerts([r.alert_id for r in page])
        src = {r.alert_id: r for r in page}
        for row in out:
            fact = src[row["alert_id"]]
            row["src_ip"] = fact.src
            row["techniques"] = list(fact.techniques)
        if not allowed(p.role, "read.raw"):
            out = [{k: v for k, v in r.items() if k != "record"} for r in out]
        return {"alerts": out, "total": len(rows), "offset": offset, "filter": f.describe()}

    @app.get("/alerts/runs")
    def alert_runs(p: Read, scenario: str, detector: Q = None, level: Q = None, rule_id: Q = None,
                   technique: Q = None, host: Q = None, ip: Q = None, since: Q = None, until: Q = None,
                   limit: Annotated[int, Query(ge=1, le=500)] = 200,
                   offset: Annotated[int, Query(ge=0)] = 0) -> dict[str, Any]:
        """The filtered alerts in time order with consecutive identical rows collapsed (see
        ``analytics.alert_runs``); pages over runs, totals over runs and alerts."""
        rows = index_for(scenario).select(flt(detector, level, rule_id, technique, host, ip, since, until))
        runs = an.alert_runs(rows)
        return {"runs": runs[offset:offset + limit], "total_runs": len(runs), "total_alerts": len(rows),
                "offset": offset}

    @app.get("/alerts/facets")
    def alert_facets(p: Read, scenario: str, detector: Q = None, level: Q = None, rule_id: Q = None,
                     technique: Q = None, host: Q = None, ip: Q = None, since: Q = None,
                     until: Q = None) -> dict[str, Any]:
        f = flt(detector, level, rule_id, technique, host, ip, since, until)
        idx = index_for(scenario)
        kb = load_kb(extras)
        facets = idx.facets(f)
        for v in facets["technique"]["values"]:
            v["label"] = an.technique_name(v["value"], kb)
        return {"facets": facets, "total": len(idx.select(f)), "filter": f.describe(),
                "timeseries": idx.timeseries(f, target=120)}

    @app.get("/alerts/export.csv")
    def export_alerts(p: Read, scenario: str, detector: Q = None, level: Q = None, rule_id: Q = None,
                      technique: Q = None, host: Q = None, ip: Q = None, since: Q = None,
                      until: Q = None) -> Response:
        rows = index_for(scenario).select(flt(detector, level, rule_id, technique, host, ip, since, until))
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(an.EXPORT_COLUMNS), lineterminator="\n")
        w.writeheader()
        for r in rows[:EXPORT_LIMIT]:
            w.writerow(r.export_row())
        headers = {"Content-Disposition": f'attachment; filename="alerts-{scenario}.csv"',
                   "X-Rows": str(min(len(rows), EXPORT_LIMIT)), "X-Rows-Total": str(len(rows))}
        return Response(buf.getvalue(), media_type="text/csv", headers=headers)

    @app.get("/incidents/summary")
    def incident_summaries(p: Read, scenario: str) -> dict[str, Any]:
        incidents = repo.list_incidents(scenario)
        by_id = index_for(scenario).by_id
        return {"incidents": an.with_main_entities([an.incident_row(i) for i in incidents],
                                                   {i["incident_id"]: i for i in incidents}, by_id)}

    @app.get("/incidents/{incident_id}/analysis")
    def incident_analysis(incident_id: str, p: Read) -> dict[str, Any]:
        inc = repo.get_incident(incident_id)
        if inc is None:
            raise HTTPException(404, "no such incident")
        idx = index_for(str(inc["scenario"]))
        return an.incident_analysis(inc, an.facts_between(idx, inc["alert_ids"]), load_kb(extras))

    @app.get("/incidents/{incident_id}/node-alerts")
    def node_alerts(incident_id: str, p: Read, node: Annotated[str, Query(pattern=r"^(host|ip):.+$")]) -> dict[str, Any]:
        """Alert ids of one incident that involve a graph node (host:x matches host_ip, ip:x the source IP)."""
        inc = repo.get_incident(incident_id)
        if inc is None:
            raise HTTPException(404, "no such incident")
        kind, value = node.split(":", 1)
        rows = an.facts_between(index_for(str(inc["scenario"])), inc["alert_ids"])
        ids = [f.alert_id for f in rows if (f.host == value if kind == "host" else f.src == value)]
        return {"incident_id": incident_id, "node": node, "alert_ids": ids}

    @app.get("/entities/{kind}/{value}")
    def entity(kind: str, value: str, p: Read, scenario: str) -> dict[str, Any]:
        if kind not in ("host", "ip"):
            raise HTTPException(422, "kind must be host or ip")
        return an.entity_view(index_for(scenario), repo.list_incidents(scenario), kind, value)

    @app.get("/search")
    def global_search(p: Read, q: Annotated[str, Query(min_length=1, max_length=200)],
                      scenario: Q = None) -> dict[str, Any]:
        q = q.strip()
        out: dict[str, Any] = {"q": q, "alerts": [], "incidents": [], "ips": [], "rules": [], "text": []}
        row = repo.get_alert(q)
        if row is not None:
            out["alerts"].append({k: row[k] for k in ("alert_id", "scenario", "detector", "ts", "rule_name")})
        incidents = repo.list_incidents(scenario)
        out["incidents"] = [an.incident_row(i) for i in incidents if str(i["incident_id"]).startswith(q)][:10]
        if scenario:
            out.update(index_for(scenario).search_values(q))
        if len(q) >= 3:
            out["text"] = search_index.search(q, scenario=scenario, limit=10)
        return out

    @app.get("/executive")
    def executive(p: Read, scenario: str) -> dict[str, Any]:
        idx = index_for(scenario)
        incidents = repo.list_incidents(scenario)
        ids = {i["incident_id"] for i in incidents}
        approvals = [a for a in repo.list_approvals() if a["incident_id"] in ids]
        audit = [e for e in repo.audit_entries(limit=100_000) if e.get("target") in ids]
        out = an.executive_summary(incidents, approvals, audit, an.kill_chain(idx.facts, load_kb(extras)),
                                   time.time())
        out["top_risks"] = an.with_main_entities(out["top_risks"], {i["incident_id"]: i for i in incidents},
                                                 idx.by_id)
        return {"scenario": scenario, **out}

    @app.get("/study/results")
    def study(p: Read) -> dict[str, Any]:
        root = Path(os.environ.get(RUNS_DIR_ENV, Path(__file__).resolve().parents[3] / "data" / "processed" / "runs"))
        return study_results(root)

    # ---- users (admin) ----------------------------------------------------------------------

    Admin = Annotated[Any, Depends(need("user.manage"))]

    def env_password() -> str:
        pw = os.environ.get(NEW_PASSWORD_ENV, "")
        if len(pw) < 8:
            raise HTTPException(409, f"set {NEW_PASSWORD_ENV} (>= 8 characters) in the API host's environment")
        return pw

    @app.get("/users")
    def list_users(p: Admin) -> dict[str, Any]:
        return {"users": repo.list_users(), "password_source": NEW_PASSWORD_ENV,
                "password_source_set": len(os.environ.get(NEW_PASSWORD_ENV, "")) >= 8}

    @app.post("/console/users", status_code=201)
    def create_user(body: ConsoleUserBody, p: Admin) -> dict[str, Any]:
        if repo.get_user(body.username) is not None:
            raise HTTPException(409, "user exists")
        repo.put_user(body.username, hash_password(env_password()), body.role.value)
        repo.audit(p.username, p.role.value, "user.create", body.username,
                   {"role": body.role.value, "password": "environment"})
        return {"username": body.username, "role": body.role.value}

    def _target(username: str, p: Any) -> None:
        if repo.get_user(username) is None:
            raise HTTPException(404, "no such user")
        if username == p.username:
            raise HTTPException(409, "you cannot change your own account here")

    @app.post("/users/{username}/deactivate")
    def deactivate(username: str, p: Admin) -> dict[str, Any]:
        _target(username, p)
        repo.set_user_disabled(username, True)
        repo.audit(p.username, p.role.value, "user.deactivate", username, {})
        return {"username": username, "active": False}

    @app.post("/users/{username}/reactivate")
    def reactivate(username: str, p: Admin) -> dict[str, Any]:
        _target(username, p)
        repo.set_user_disabled(username, False)
        repo.audit(p.username, p.role.value, "user.reactivate", username, {})
        return {"username": username, "active": True}

    @app.post("/users/{username}/reset")
    def reset(username: str, p: Admin) -> dict[str, Any]:
        _target(username, p)
        repo.set_password(username, hash_password(env_password()))
        repo.audit(p.username, p.role.value, "user.reset", username, {"password": "environment"})
        return {"username": username, "reset": True}
