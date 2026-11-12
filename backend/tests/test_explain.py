"""Explainable console (2026-11-13): explain mode of /copilot/ask, collapsed alert runs, graph
labels. FakeClient only; no network, no model."""

from __future__ import annotations

import json
import threading
from typing import Any

from fastapi.testclient import TestClient

from app.agent.client import FakeClient, ModelRequestError
from app.api import explain as ex
from app.api.app import Services, create_app
from app.api.auth import Role
from app.outputs import analytics as an
from app.outputs.graph_layout import place_labels
from tests.test_api import PASSWORD, client, services, token  # noqa: F401  (fixtures)
from tests.test_variants import processed  # noqa: F401  (fixture)

LABEL_WORDS = ("event_label", "time_label", "ground_truth", "attack_phase")
GLOSSARY = [{"term": "Incident", "definition": "A group of related alerts.", "why": "The unit an analyst reviews."}]


def _client(services: Services, replies: list[Any]) -> tuple[TestClient, FakeClient]:  # noqa: F811
    fake = FakeClient(replies)
    services.extras["copilot_client"] = fake
    return TestClient(create_app(services)), fake


# ---------------------------------------------------------------- explain mode

def test_explain_is_one_short_grounded_request(services: Services) -> None:  # noqa: F811
    c, fake = _client(services, ["An incident is a group of related alerts (glossary: Incident)."])
    body = {"mode": "explain", "question": "What is an incident?", "screen": "Overview",
            "context": "Open incidents: High 1", "glossary": GLOSSARY}
    r = c.post("/copilot/ask", headers=token(c, Role.ANALYST), json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["mode"] == "explain" and out["status"] == "ok"
    assert out["answer"] == ["An incident is a group of related alerts (glossary: Incident)."]
    assert out["model"] == fake.model_id and out["sources"] == ["glossary", "screen"]
    assert len(fake.calls) == 1
    system, user = fake.calls[0][0]["content"], fake.calls[0][1]["content"]
    assert "only" in system.lower() and "not shown" in system.lower()
    assert "A group of related alerts." in user and "Open incidents: High 1" in user and "Overview" in user
    assert "copilot.explain" in [e["action"] for e in services.repo.audit_entries()]


def test_explain_caps_output_tokens(services: Services) -> None:  # noqa: F811
    seen: dict[str, int] = {}

    class Capturing(FakeClient):
        def chat(self, messages: Any, *, max_tokens: int, temperature: float) -> Any:
            seen["max_tokens"] = max_tokens
            seen["temperature"] = int(temperature)
            return super().chat(messages, max_tokens=max_tokens, temperature=temperature)

    services.extras["copilot_client"] = Capturing(["ok"])
    c = TestClient(create_app(services))
    r = c.post("/copilot/ask", headers=token(c, Role.ANALYST),
               json={"mode": "explain", "question": "What is this chart?"})
    assert r.status_code == 200, r.text
    assert seen == {"max_tokens": ex.MAX_OUTPUT_TOKENS, "temperature": 0}
    assert ex.MAX_OUTPUT_TOKENS <= 300


def test_explain_adds_incident_facts_without_labels(services: Services) -> None:  # noqa: F811
    c, fake = _client(services, ["fine"])
    r = c.post("/copilot/ask", headers=token(c, Role.ANALYST),
               json={"mode": "explain", "question": "What happened here?", "incident_id": "inc-1"})
    assert r.status_code == 200, r.text
    user = fake.calls[0][1]["content"]
    assert "inc-1" in user and "High" in user
    for word in LABEL_WORDS:
        assert word not in user and word not in r.text
    assert r.json()["sources"] == ["incident"]
    missing = c.post("/copilot/ask", headers=token(c, Role.ANALYST),
                     json={"mode": "explain", "question": "x", "incident_id": "nope"})
    assert missing.status_code == 404


def test_explain_offline_errors_and_rbac(services: Services) -> None:  # noqa: F811
    plain = TestClient(create_app(services))
    body = {"mode": "explain", "question": "What is Wazuh?"}
    assert plain.post("/copilot/ask", headers=token(plain, Role.EXECUTIVE), json=body).status_code == 403
    r = plain.post("/copilot/ask", headers=token(plain, Role.ANALYST), json=body)
    assert r.status_code == 503 and "no model endpoint" in r.json()["detail"]
    c, _ = _client(services, [ModelRequestError("connection refused")])
    r = c.post("/copilot/ask", headers=token(c, Role.ANALYST), json=body)
    assert r.status_code == 503 and "unreachable" in r.json()["detail"]
    # investigate mode still needs an incident
    assert c.post("/copilot/ask", headers=token(c, Role.ANALYST), json={"question": "x"}).status_code == 422
    too_long = {"mode": "explain", "question": "x", "context": "y" * (ex.MAX_CONTEXT_CHARS + 1)}
    assert c.post("/copilot/ask", headers=token(c, Role.ANALYST), json=too_long).status_code == 422


def test_explain_runs_one_request_at_a_time(services: Services) -> None:  # noqa: F811
    c, _ = _client(services, ["ok"])
    h = token(c, Role.ANALYST)
    assert ex.MODEL_LOCK.acquire(blocking=False)
    try:
        r = c.post("/copilot/ask", headers=h, json={"mode": "explain", "question": "busy?"})
        assert r.status_code == 429 and "busy" in r.json()["detail"]
    finally:
        ex.MODEL_LOCK.release()
    assert isinstance(ex.MODEL_LOCK, type(threading.Lock()))
    assert c.post("/copilot/ask", headers=h, json={"mode": "explain", "question": "free?"}).status_code == 200


def test_explain_prompt_is_bounded() -> None:
    many = [{"term": f"t{i}", "definition": "d" * 400, "why": "w" * 400} for i in range(40)]
    msgs = ex.build_messages("q", "Alerts", "c" * ex.MAX_CONTEXT_CHARS, many, None)
    assert len(msgs) == 2
    assert len(msgs[1]["content"]) < ex.MAX_CONTEXT_CHARS + ex.MAX_GLOSSARY_TERMS * 900 + 1000
    assert msgs[1]["content"].count("TERM:") == ex.MAX_GLOSSARY_TERMS


# ---------------------------------------------------------------- collapsed alert runs

def _fact(i: int, ts: float, rule: str | None, host: str | None, det: str = "wazuh") -> an.Fact:
    return an.Fact(alert_id=f"a{i}", ts=ts, detector=det, kind="event", rule_id=rule, rule_name=f"name {rule}",
                   severity=5, host=host, src=None, techniques=(), duplicate=False, ioc=None)


def test_alert_runs_collapse_consecutive_identical_rows() -> None:
    facts = [_fact(0, 1, "r1", "h"), _fact(1, 2, "r1", "h"), _fact(2, 3, "r1", "h"),
             _fact(3, 4, "r2", "h"), _fact(4, 5, "r1", "h"), _fact(5, 6, "r1", "x")]
    runs = an.alert_runs(facts)
    assert [(r["rule_id"], r["host_ip"], r["count"]) for r in runs] == [
        ("r1", "h", 3), ("r2", "h", 1), ("r1", "h", 1), ("r1", "x", 1)]
    first = runs[0]
    assert first["first_alert_id"] == "a0" and first["last_alert_id"] == "a2"
    assert first["first_ts"] == an.iso(1) and first["last_ts"] == an.iso(3)
    assert sum(r["count"] for r in runs) == len(facts)
    assert an.alert_runs([]) == []


def test_alert_runs_route_pages_runs(client: TestClient) -> None:  # noqa: F811
    h = token(client, Role.ANALYST)
    r = client.get("/alerts/runs?scenario=synthetic&limit=500", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    total = client.get("/alerts/query?scenario=synthetic&limit=1", headers=h).json()["total"]
    assert body["total_alerts"] == total and sum(x["count"] for x in body["runs"]) == total
    assert body["total_runs"] == len(body["runs"]) <= total
    for word in LABEL_WORDS:
        assert word not in r.text


# ---------------------------------------------------------------- graph labels

def test_place_labels_avoids_overlap_and_prefers_big_nodes() -> None:
    nodes = [("big", 50.0, 50.0, 8.0, "10.0.0.1"), ("near", 52.0, 52.0, 3.0, "10.0.0.2"),
             ("far", 300.0, 200.0, 3.0, "10.0.0.3")]
    out = place_labels(nodes, 400, 300, char_w=6.0, line_h=12.0)
    shown = {p.id: p for p in out}
    assert "big" in shown and "far" in shown
    boxes = list(shown.values())
    for i, a in enumerate(boxes):
        assert 0 <= a.x0 and a.x1 <= 400 and 0 <= a.y0 and a.y1 <= 300
        for b in boxes[i + 1:]:
            assert a.x1 <= b.x0 or b.x1 <= a.x0 or a.y1 <= b.y0 or b.y1 <= a.y0
    assert place_labels(nodes, 400, 300, char_w=6.0, line_h=12.0) == out
    assert json.dumps([p.id for p in out])


def test_main_entities_count_alerts_not_names() -> None:
    facts = {f"a{i}": _fact(i, i, "r", h) for i, h in enumerate(["z-host", "z-host", "a-host", None])}
    assert an.main_entities(["a0", "a1", "a2", "a3", "missing"], facts) == {"main_host": "z-host", "main_ip": None}
    assert an.main_entities([], facts) == {"main_host": None, "main_ip": None}
    tie = {f"b{i}": _fact(i, i, "r", h) for i, h in enumerate(["b", "a"])}
    assert an.main_entities(["b0", "b1"], tie)["main_host"] == "a"


def test_summary_and_executive_name_the_main_entity(client: TestClient) -> None:  # noqa: F811
    h = token(client, Role.ANALYST)
    rows = client.get("/incidents/summary?scenario=synthetic", headers=h).json()["incidents"]
    assert rows and all("main_host" in r["detail"] and "main_ip" in r["detail"] for r in rows)
    ex = client.get("/executive?scenario=synthetic", headers=h).json()
    assert all("main_host" in r["detail"] for r in ex["top_risks"])


# ---------------------------------------------------------------- model status (no generation)

def test_copilot_status_probes_without_generation(services: Services) -> None:  # noqa: F811
    fake = FakeClient([])
    services.extras["copilot_client"] = fake
    services.extras["model_probe"] = lambda: True
    c = TestClient(create_app(services))
    r = c.get("/copilot/status", headers=token(c, Role.ANALYST))
    assert r.status_code == 200, r.text
    assert r.json() == {"state": "online", "model": fake.model_id}
    assert fake.calls == []  # the probe never sends a chat request


def test_copilot_status_offline_busy_and_unconfigured(services: Services) -> None:  # noqa: F811
    c = TestClient(create_app(services))
    h = token(c, Role.ANALYST)
    assert c.get("/copilot/status", headers=h).json() == {"state": "offline", "model": None,
                                                          "reason": "no model endpoint configured"}
    services.extras["copilot_client"] = FakeClient([])
    services.extras["model_probe"] = lambda: False
    assert c.get("/copilot/status", headers=h).json()["state"] == "offline"
    services.extras["model_probe"] = lambda: True
    assert ex.MODEL_LOCK.acquire(blocking=False)
    try:
        assert c.get("/copilot/status", headers=h).json()["state"] == "busy"
    finally:
        ex.MODEL_LOCK.release()


def test_copilot_status_needs_copilot_permission(services: Services) -> None:  # noqa: F811
    c = TestClient(create_app(services))
    assert c.get("/copilot/status", headers=token(c, Role.EXECUTIVE)).status_code == 403
