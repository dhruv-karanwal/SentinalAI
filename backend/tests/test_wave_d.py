"""Wave D (offline): reports, playbooks, approvals + gated executor, feedback report, copilot,
Grafana dashboard JSON, Jira stub. FakeClient only; no network."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.agent.client import FakeClient
from app.api.app import Services, create_app
from app.api.auth import PERMISSIONS, Role
from app.outputs import approvals as ap
from app.outputs import playbooks as pb
from app.outputs import reports as rp
from app.storage.repository import Repository
from tests.test_api import PASSWORD, client, services, token  # noqa: F401  (fixtures)
from tests.test_variants import processed  # noqa: F401  (fixture)

REPO = Path(__file__).resolve().parents[2]
LABEL_WORDS = ("event_label", "time_label", "ground_truth", "attack_phase", "false_positive\"")


def stored_incident(repo: Repository, n: int = 4) -> dict[str, Any]:
    ids = [a["alert_id"] for a in repo.list_alerts(limit=n)]
    alerts = [repo.alert_model(i) for i in ids]
    first = min(a.timestamp for a in alerts if a)
    last = max(a.timestamp for a in alerts if a)
    repo.put_incident({"incident_id": "inc-rep", "scenario": "synthetic", "first_ts": first.isoformat(),
                       "last_ts": last.isoformat(), "severity": "Medium", "alert_ids": ids,
                       "detail": {"severity_row": "M2", "gap_seconds": 300, "entities": ["host:10.0.0.5"],
                                  "detectors": {}}})
    inc = repo.get_incident("inc-rep")
    assert inc is not None
    return inc


# ---------------------------------------------------------------- playbooks

@pytest.mark.parametrize("technique,action", [
    ("T1110", "lock_account"), ("T1110.001", "lock_account"), ("T1078", "reset_credentials"),
    ("T1505.003", "isolate_host"), ("T1190", "block_source_ip"), ("T1595.002", "block_source_ip"),
    ("T1046", "block_source_ip"), ("T1048.003", "isolate_host"), ("T1068", "isolate_host"),
    ("T1059.004", "isolate_host"), ("T1003.008", "reset_credentials"),
])
def test_every_playbook_row(technique: str, action: str) -> None:
    recs = pb.recommend([technique])
    assert action in [r["action_type"] for r in recs]
    assert all(r["requires_approval"] == (r["action_type"] in pb.STATE_CHANGING) for r in recs)


def test_playbook_rows_are_all_tested_and_fallback_is_review_only() -> None:
    tested = {"T1110", "T1078", "T1505.003", "T1190", "T1595", "T1046", "T1048", "T1068", "T1059",
              "T1003"}
    assert {row.prefix for row in pb.PLAYBOOK} == tested
    recs = pb.recommend([])
    assert [r["action_type"] for r in recs] == ["manual_review"]
    assert recs[0]["requires_approval"] is False
    assert set(pb.ACTION_TYPES) >= pb.STATE_CHANGING | {"manual_review"}


# ---------------------------------------------------------------- reports

def test_report_body_is_deterministic_cited_and_label_free(services: Services) -> None:  # noqa: F811
    inc = stored_incident(services.repo)
    alerts = [services.repo.alert_model(i) for i in inc["alert_ids"]]
    body = rp.build_report(inc, [a for a in alerts if a])
    assert body == rp.build_report(inc, [a for a in alerts if a])
    assert body["incident"]["incident_id"] == "inc-rep" and body["incident"]["alerts"] == 4
    assert [c["alert_id"] for c in body["citations"]] == [t["alert_id"] for t in body["timeline"]]
    assert set(c["alert_id"] for c in body["citations"]) == set(inc["alert_ids"])
    assert body["recommendations"] and "approval" in body["notice"].lower()
    assert body["report_version"] == rp.REPORT_VERSION
    text = json.dumps(body)
    for word in LABEL_WORDS:
        assert word not in text


def test_report_findings_go_through_the_verifier(services: Services) -> None:  # noqa: F811
    from app.evaluation.metrics import Claim
    inc = stored_incident(services.repo)
    alerts = [a for a in (services.repo.alert_model(i) for i in inc["alert_ids"]) if a]
    a0 = alerts[0]
    findings = {"cited": [a0.alert_id, "not-in-incident"],
                "claims": [Claim(a0.alert_id, "detector", a0.detector.value),
                           Claim(a0.alert_id, "detector", "made-up")]}
    body = rp.build_report(inc, alerts, findings=findings)
    f = body["findings"]
    assert f["cited"] == [a0.alert_id] and f["dropped_citations"] == ["not-in-incident"]
    assert len(f["claims"]) == 1 and len(f["dropped_claims"]) == 1


def test_csv_and_pdf_renderings(services: Services) -> None:  # noqa: F811
    inc = stored_incident(services.repo)
    alerts = [a for a in (services.repo.alert_model(i) for i in inc["alert_ids"]) if a]
    body = rp.build_report(inc, alerts)
    rows = list(csv.DictReader(io.StringIO(rp.render_csv(body))))
    assert len(rows) == len(body["timeline"]) and list(rows[0]) == list(rp.CSV_COLUMNS)
    pdf = rp.render_pdf(body)
    assert pdf.startswith(b"%PDF") and len(pdf) > 1000
    assert rp.render_pdf(body)[:8] == pdf[:8]


# ---------------------------------------------------------------- approvals and the executor

def test_approval_rules(services: Services) -> None:  # noqa: F811
    svc = ap.ApprovalService(services.repo)
    with pytest.raises(ValueError):
        svc.request("inc-1", {"action_type": "rm_rf"}, "analyst")  # not a playbook action
    with pytest.raises(ValueError):
        svc.request("inc-1", {"action_type": "manual_review"}, "analyst")  # nothing to approve
    with pytest.raises(KeyError):
        svc.request("inc-missing", {"action_type": "block_source_ip", "target": "203.0.113.9"}, "analyst")
    aid = svc.request("inc-1", {"action_type": "block_source_ip", "target": "203.0.113.9"}, "analyst")
    with pytest.raises(ap.ApprovalError, match="not approved"):
        svc.execute(aid, "manager")  # nothing executes without an approved record
    with pytest.raises(ap.ApprovalError, match="own request"):
        svc.decide(aid, True, "analyst", "looks fine")
    with pytest.raises(ValueError):
        svc.decide(aid, True, "manager", "  ")
    svc.decide(aid, True, "manager", "scan source confirmed")
    with pytest.raises(ValueError):
        svc.decide(aid, False, "admin", "changed my mind")  # decided once
    res = svc.execute(aid, "manager")
    assert res["executed"] is True and res["mode"] == "simulated"
    with pytest.raises(ap.ApprovalError, match="already executed"):
        svc.execute(aid, "manager")
    rejected = svc.request("inc-1", {"action_type": "isolate_host", "target": "10.0.0.5"}, "analyst")
    svc.decide(rejected, False, "manager", "host is the production web server")
    with pytest.raises(ap.ApprovalError, match="not approved"):
        svc.execute(rejected, "admin")
    row = services.repo.get_approval(aid)
    assert row and row["status"] == "approved" and row["executed_by"] == "manager"


def test_approval_api_rbac_and_audit(client: TestClient, services: Services) -> None:  # noqa: F811
    an, mg, ex = (token(client, r) for r in (Role.ANALYST, Role.MANAGER, Role.EXECUTIVE))
    body = {"incident_id": "inc-1", "action": {"action_type": "block_source_ip", "target": "203.0.113.9"}}
    assert client.post("/approvals", headers=ex, json=body).status_code == 403
    r = client.post("/approvals", headers=an, json=body)
    assert r.status_code == 201
    aid = r.json()["id"]
    assert client.get("/approvals", headers=ex).status_code == 200  # executives: read-only
    assert client.post(f"/approvals/{aid}/execute", headers=mg).status_code == 409
    assert client.post(f"/approvals/{aid}/decision", headers=an,
                       json={"approved": True, "reason": "x"}).status_code == 403
    assert client.post(f"/approvals/{aid}/decision", headers=ex,
                       json={"approved": True, "reason": "x"}).status_code == 403
    assert client.post(f"/approvals/{aid}/decision", headers=mg,
                       json={"approved": True, "reason": "confirmed"}).status_code == 200
    assert client.post(f"/approvals/{aid}/execute", headers=an).status_code == 403
    r = client.post(f"/approvals/{aid}/execute", headers=mg)
    assert r.status_code == 200 and r.json()["mode"] == "simulated"
    actions = [e["action"] for e in services.repo.audit_entries()]
    for a in ("approval.request", "approval.decide", "action.execute", "denied"):
        assert a in actions


# ---------------------------------------------------------------- report API

def test_report_api_create_and_download(client: TestClient, services: Services) -> None:  # noqa: F811
    stored_incident(services.repo)
    an, ex = token(client, Role.ANALYST), token(client, Role.EXECUTIVE)
    assert client.post("/reports", headers=ex, json={"incident_id": "inc-rep"}).status_code == 403
    assert client.post("/reports", headers=an, json={"incident_id": "nope"}).status_code == 404
    r = client.post("/reports", headers=an, json={"incident_id": "inc-rep"})
    assert r.status_code == 201
    rid = r.json()["report_id"]
    pdf = client.get(f"/reports/{rid}/download", headers=ex, params={"format": "pdf"})
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert pdf.headers["content-type"] == "application/pdf"
    c = client.get(f"/reports/{rid}/download", headers=ex, params={"format": "csv"})
    assert c.status_code == 200 and c.text.startswith(",".join(rp.CSV_COLUMNS))
    j = client.get(f"/reports/{rid}/download", headers=ex, params={"format": "json"})
    assert j.json()["incident"]["incident_id"] == "inc-rep"
    assert client.get(f"/reports/{rid}/download", headers=ex, params={"format": "exe"}).status_code == 422
    assert "report.create" in [e["action"] for e in services.repo.audit_entries()]
    for word in LABEL_WORDS:
        assert word not in j.text


# ---------------------------------------------------------------- feedback report (offline)

def test_feedback_report_counts_and_never_retrains(services: Services) -> None:  # noqa: F811
    from app.outputs.feedback_report import feedback_report
    repo = services.repo
    for verdict in ("true_positive", "true_positive", "false_positive"):
        repo.add_feedback("incident", "inc-1", verdict, None, "analyst")
    repo.add_feedback("alert", "a-1", "unsure", "check later", "manager")
    rep = feedback_report(repo)
    assert rep["total"] == 4
    assert rep["by_target_type"]["incident"] == {"true_positive": 2, "false_positive": 1}
    assert rep["by_target_type"]["alert"] == {"unsure": 1}
    assert rep["most_disputed"][0]["target"] == "incident:inc-1"
    assert "no retraining" in rep["note"].lower()


def test_feedback_report_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from app.main import main
    from app.storage.db import SqliteDatabase
    db = SqliteDatabase(tmp_path / "core.db")
    db.migrate()
    Repository(db).add_feedback("incident", "inc-9", "false_positive", None, "analyst")
    assert main(["feedback-report", "--data-dir", str(tmp_path), "--output", str(tmp_path / "fb.json")]) == 0
    assert json.loads((tmp_path / "fb.json").read_text())["total"] == 1
    assert "no retraining" in capsys.readouterr().out.lower()


# ---------------------------------------------------------------- copilot

def _copilot_services(services: Services, replies: list[Any]) -> TestClient:  # noqa: F811
    services.extras["copilot_client"] = FakeClient(replies)
    return TestClient(create_app(services))


def test_copilot_uses_the_case_tools_and_the_verifier(services: Services) -> None:  # noqa: F811
    inc = stored_incident(services.repo)
    seen: list[list[dict[str, str]]] = []

    def final(messages: list[dict[str, str]]) -> str:
        seen.append(messages)
        listed = json.loads(messages[-1]["content"].split("\n", 1)[1])
        first = listed["alerts"][0]["alert_id"]
        return json.dumps({"action": "final", "verdict": "attack", "findings": [
            {"summary": "first alert", "alert_ids": [first, "al-not-real"],
             "claims": [{"alert_id": first, "kind": "field_value", "field": "detector",
                         "value": "no-such-detector"}]}]})

    c = _copilot_services(services, [json.dumps({"action": "call_tool", "tool": "list_alerts",
                                                 "arguments": {}}), final])
    an = token(c, Role.ANALYST)
    r = c.post("/copilot/ask", headers=an, json={"incident_id": "inc-rep",
                                                 "question": "Which host was targeted?"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "ok" and out["verdict"] == "attack"
    assert out["verification"]["citations_dropped"] == 1 and out["verification"]["claims_dropped"] == 1
    assert len(out["cited_alert_ids"]) == 1 and out["cited_alert_ids"][0] in inc["alert_ids"]
    assert out["claims"] == [] and out["dropped_citations"] == ["unknown:al-not-real"]
    assert [(d["kind"], d["field"]) for d in out["dropped_claims"]] == [("field_value", "detector")]
    assert out["dropped_claims"][0]["record_id"] in inc["alert_ids"] and out["dropped_claims"][0]["reason"]
    assert "Which host was targeted?" in seen[0][1]["content"]
    assert out["tool_calls"] == 1
    text = json.dumps(out)
    for word in LABEL_WORDS:
        assert word not in text
    assert "copilot.ask" in [e["action"] for e in services.repo.audit_entries()]


def test_copilot_rbac_and_missing_model(services: Services) -> None:  # noqa: F811
    stored_incident(services.repo)
    c = TestClient(create_app(services))
    body = {"incident_id": "inc-rep", "question": "summarise"}
    assert c.post("/copilot/ask", headers=token(c, Role.EXECUTIVE), json=body).status_code == 403
    assert c.post("/copilot/ask", headers=token(c, Role.ANALYST), json=body).status_code == 503


# ---------------------------------------------------------------- Grafana, Jira, docs

def test_grafana_dashboard_uses_exported_metrics() -> None:
    from app.ops.metrics import Metrics
    dash = json.loads((REPO / "infra" / "grafana" / "dashboards" / "sentinel.json").read_text(encoding="utf-8"))
    exported = Metrics().render()
    exprs = [t["expr"] for p in dash["panels"] for t in p.get("targets", [])]
    assert dash["title"] and len(exprs) >= 5
    import re
    for e in exprs:
        for name in re.findall(r"sentinel_[a-z_]+", e):
            base = re.sub(r"_(bucket|sum|count)$", "", name)
            assert base in exported, name


def test_jira_adapter_is_a_disabled_stub() -> None:
    from app.outputs.jira import JiraAdapter, JiraDisabled
    adapter = JiraAdapter()
    assert adapter.enabled is False
    sample = adapter.sample_payload()
    assert sample["labels"] == ["SYNTHETIC"] and "example" in sample["fields"]["project"]["key"].lower()
    with pytest.raises(JiraDisabled):
        adapter.create_issue(sample)


def test_security_notes_exist_and_say_what_is_not_covered() -> None:
    text = (REPO / "docs" / "security-notes.md").read_text(encoding="utf-8")
    for heading in ("## Covered", "## Not covered", "## Compliance"):
        assert heading in text


def test_new_permissions_are_in_the_table() -> None:
    assert PERMISSIONS["action.execute"] == frozenset({Role.MANAGER, Role.ADMIN})
    assert Role.EXECUTIVE not in PERMISSIONS["report.create"]
    assert Role.EXECUTIVE not in PERMISSIONS["approval.request"]
