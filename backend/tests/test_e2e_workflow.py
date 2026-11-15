"""Milestone 10 (2026-11-15): the whole SentinelAI workflow on the SYNTHETIC sample, end to end.

ingest-alerts -> platform replay (store) -> Sigma (one synthetic rule) -> ML train + score -> triage
via the API -> graph investigation via the API (scripted FakeClient: a plumbing check, never a model
result) -> report with the investigation -> approval (four eyes) -> simulated execution -> audit.
Checks that ids stay consistent from stage to stage and that a failed agent never yields a
verified report section.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.agent.client import FakeClient
from app.api.app import Services, create_app
from app.api.auth import Role, hash_password
from app.main import main
from app.platform.bootstrap import ingest_scenario, open_stores
from app.storage.objects import LocalObjectStore
from app.study.config import load_study_config
from tests.test_api import PASSWORD, SECRET, token
from tests.test_cases import synthetic_config
from tests.test_wave_c_graph import note, route, tool
from tests.test_wave_d import LABEL_WORDS


def first_listed(messages: list[dict[str, str]]) -> str:
    return str(json.loads(messages[-1]["content"].split("\n", 1)[1])["alerts"][0]["alert_id"])


def graph_script() -> list[Any]:
    def noted(messages: list[dict[str, str]]) -> str:
        return note("first alert is the activity", [first_listed(messages)])

    def report(messages: list[dict[str, str]]) -> str:
        aid = json.loads(messages[-1]["content"].split("\n", 1)[1])["notes"][0]["alert_ids"][0]
        return json.dumps({"action": "final", "verdict": "attack", "findings": [
            {"summary": "scripted", "alert_ids": [aid], "claims": [
                {"alert_id": aid, "kind": "field_value", "field": "scenario", "value": "invented"}]}]})

    return [route("log_analysis"), tool("list_alerts"), noted,
            route("report_generation"), tool("recall_notes"), report]


def inline(job: Callable[[], None]) -> None:
    job()


@pytest.fixture()
def platform(tmp_path: Path, samples_dir: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    for var in ("SENTINEL_DB_URL", "SENTINEL_SEARCH_URL", "SENTINEL_KAFKA"):
        monkeypatch.delenv(var, raising=False)
    cfg = synthetic_config(tmp_path)
    s = samples_dir / "synthetic_ait_ads"
    processed, data, models = tmp_path / "processed", tmp_path / "platform", tmp_path / "models"
    # 1. ingest + normalize
    assert main(["ingest-alerts", "--data-dir", str(s), "--scenario", "synthetic",
                 "--labels", str(s / "synthetic_labels.csv"), "--event-labels", str(s / "synthetic_alerts.txt"),
                 "--dataset-name", "synthetic-ait-ads-format", "--output-dir", str(processed)]) == 0
    # 2. store (stream -> consumer -> core; truth separately)
    report = ingest_scenario(open_stores(data), processed, "synthetic", load_study_config(cfg))
    # 3. detection: Sigma over evidence lines, ML bundle + scores
    rule = tmp_path / "sigma" / "rules" / "linux" / "any.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text("title: synthetic any syslog line\nid: 11111111-1111-1111-1111-111111111111\n"
                    "level: low\nlogsource:\n  product: linux\ndetection:\n  keywords:\n    - ' '\n"
                    "  condition: keywords\n", encoding="utf-8")
    assert main(["sigma", "--scenario", "synthetic", "--rules-dir", str(tmp_path / "sigma"),
                 "--processed-dir", str(processed), "--output-dir", str(tmp_path / "sigma-out"),
                 "--study-config", str(cfg), "--data-dir", str(data)]) == 0
    assert main(["ml-train", "--scenarios", "synthetic", "--processed-dir", str(processed),
                 "--study-config", str(cfg), "--data-dir", str(data), "--model-dir", str(models)]) == 0
    assert main(["ml-score", "--scenario", "synthetic", "--study-config", str(cfg),
                 "--data-dir", str(data), "--model-dir", str(models)]) == 0
    stores = open_stores(data)
    for role in Role:
        stores.repo.put_user(role.value, hash_password(PASSWORD, rounds=4), role.value)
    services = Services(stores.repo, stores.index, LocalObjectStore(tmp_path / "obj"), SECRET)
    services.extras["investigation_executor"] = inline
    return {"services": services, "stored": report["alerts_in_store"], "sigma": tmp_path / "sigma-out"}


def test_whole_workflow_keeps_ids_consistent(platform: dict[str, Any]) -> None:
    services: Services = platform["services"]
    repo = services.repo
    services.extras["copilot_client"] = FakeClient(graph_script())
    c = TestClient(create_app(services))
    an, mg, ad = token(c, Role.ANALYST), token(c, Role.MANAGER), token(c, Role.ADMIN)
    stored = {a["alert_id"] for a in repo.list_alerts(limit=1000)}
    assert len(stored) == platform["stored"] > 0
    sigma = json.loads((platform["sigma"] / "synthetic.sigma.report.json").read_text(encoding="utf-8"))
    assert sigma["coverage"]["funnel"]["compiled"] == 1

    # 4-5. triage + correlation through the API
    built = c.post("/incidents/build", headers=an, json={"scenario": "synthetic"}).json()
    assert built["incidents"] >= 1
    incidents = repo.list_incidents("synthetic")
    inc = max(incidents, key=lambda i: (len(i["alert_ids"]), i["incident_id"]))
    assert set(inc["alert_ids"]) <= stored and inc["detail"]["correlation"]["reason"]
    ml = c.get(f"/incidents/{inc['incident_id']}/ml", headers=an).json()
    assert ml["influences_severity"] is False and ml["models"]

    # 6-8. graph investigation, RAG off (no index), verifier
    started = c.post(f"/incidents/{inc['incident_id']}/investigations", headers=an, json={"workflow": "graph"})
    assert started.status_code == 202
    inv = c.get(f"/investigations/{started.json()['investigation_id']}", headers=an).json()
    assert inv["status"] == "completed"
    res = inv["result"]
    cited = res["conclusion"]["cited_alert_ids"]
    assert cited and set(cited) <= set(inc["alert_ids"])
    assert res["verification"]["claims_dropped"] == 1  # the scripted false claim
    assert {"supervisor", "log_analysis", "report_generation"} <= {s["node"] for s in res["steps"]}
    assert res["knowledge"] == [] and res["retrieval"] is False

    # 9. report with the investigation, re-verified
    rep = c.post("/reports", headers=an, json={"incident_id": inc["incident_id"],
                                                "investigation_id": inv["investigation_id"]})
    assert rep.status_code == 201, rep.text
    body = c.get(f"/reports/{rep.json()['report_id']}", headers=an).json()["body"]
    assert body["findings"]["cited"] == cited
    assert body["findings"]["source"]["investigation_id"] == inv["investigation_id"]
    for fmt, kind in (("pdf", "application/pdf"), ("csv", "text/csv")):
        r = c.get(f"/reports/{rep.json()['report_id']}/download", headers=an, params={"format": fmt})
        assert r.status_code == 200 and r.headers["content-type"].startswith(kind)
    assert not any(w in json.dumps(body) for w in LABEL_WORDS)

    # 10. human approval (four eyes), simulated execution once
    ap = c.post("/approvals", headers=an, json={"incident_id": inc["incident_id"],
                                                "action": {"action_type": "isolate_host", "target": "10.0.0.9"}})
    aid = ap.json()["id"]
    assert c.post(f"/approvals/{aid}/decision", headers=an, json={"approved": True, "reason": "x"}).status_code == 403
    assert c.post(f"/approvals/{aid}/decision", headers=mg, json={"approved": True, "reason": "e2e"}).status_code == 200
    assert c.post(f"/approvals/{aid}/execute", headers=mg).status_code == 200
    assert c.post(f"/approvals/{aid}/execute", headers=mg).status_code == 409

    # 11. audit trail
    actions = [e["action"] for e in c.get("/audit", headers=ad).json()["entries"]]
    for a in ("incident.build", "investigation.start", "investigation.finish", "report.create",
              "approval.request", "denied", "approval.decide", "action.execute"):
        assert a in actions, a


def test_failed_investigation_cannot_feed_a_report(platform: dict[str, Any]) -> None:
    services: Services = platform["services"]
    services.extras["copilot_client"] = FakeClient(["not json", "still not json"])
    c = TestClient(create_app(services))
    an = token(c, Role.ANALYST)
    c.post("/incidents/build", headers=an, json={"scenario": "synthetic"})
    inc = services.repo.list_incidents("synthetic")[0]
    inv = c.post(f"/incidents/{inc['incident_id']}/investigations", headers=an, json={"workflow": "single"}).json()
    assert c.get(f"/investigations/{inv['investigation_id']}", headers=an).json()["status"] == "failed"
    r = c.post("/reports", headers=an, json={"incident_id": inc["incident_id"],
                                              "investigation_id": inv["investigation_id"]})
    assert r.status_code == 409 and "not completed" in r.text
    other = services.repo.list_incidents("synthetic")[-1]
    if other["incident_id"] != inc["incident_id"]:
        r = c.post("/reports", headers=an, json={"incident_id": other["incident_id"],
                                                  "investigation_id": inv["investigation_id"]})
        assert r.status_code == 422  # an investigation of another incident
