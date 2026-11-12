"""Console v2: analytics aggregates, graph layout, console routes (overview, query, facets,
export, analysis, entities, search, executive, users, study results). No labels anywhere."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.app import Services
from app.api.auth import Role
from app.outputs import analytics as an
from app.outputs.graph_layout import PAD, fnv1a, layout
from tests.test_api import PASSWORD, client, services, token  # noqa: F401  (fixtures)
from tests.test_variants import processed  # noqa: F401  (fixture)

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "frontend" / "src" / "lib" / "graph.fixture.json"
LABEL_WORDS = ("event_label", "time_label", "ground_truth", "attack_phase")


def fact(i: int, ts: float, det: str = "wazuh", *, host: str | None = "10.0.0.1", src: str | None = None,
         tech: tuple[str, ...] = (), sev: int | None = 3, rule: str = "100", dup: bool = False) -> an.Fact:
    return an.Fact(alert_id=f"a{i}", ts=ts, detector=det, kind="event", rule_id=rule, rule_name=f"rule {rule}",
                   severity=sev, host=host, src=src, techniques=tech, duplicate=dup, ioc=None)


# ---- pure ----------------------------------------------------------------------------------------

def test_bin_seconds_steps_and_edges() -> None:
    assert an.bin_seconds(0) == 1
    assert an.bin_seconds(100) == 1
    assert an.bin_seconds(121) == 5
    assert an.bin_seconds(86400 * 4) == 3600
    assert an.bin_seconds(86400 * 1000) == 86400 * 9  # beyond the table: whole days


def test_bin_facts_counts_every_fact_once() -> None:
    rows = [fact(i, 1000.0 + i * 7, "wazuh" if i % 2 else "aminer") for i in range(50)]
    ts = an.bin_facts(rows, rows[0].ts, rows[-1].ts, 20)
    assert ts["total"] == 50 and list(ts["series"]) == ["wazuh", "aminer"]
    assert sum(ts["series"]["wazuh"]) == 25 and len(ts["series"]["wazuh"]) == ts["bins"]
    one = an.bin_facts(rows[:1], rows[0].ts, rows[0].ts)
    assert one["bins"] == 1 and one["total"] == 1
    assert an.bin_facts([], None, None)["bins"] == 0


def test_filter_and_facets_exclude_their_own_facet() -> None:
    idx = an.AlertIndex("s", [fact(1, 1, "wazuh", rule="1"), fact(2, 2, "suricata", rule="2", sev=1),
                              fact(3, 3, "wazuh", rule="1", tech=("T1078",)), fact(4, 4, "aminer", sev=None)])
    f = an.AlertFilter(detector="wazuh")
    assert [x.alert_id for x in idx.select(f)] == ["a1", "a3"]
    facets = idx.facets(f)
    # the detector facet ignores the detector filter (so the other values stay clickable)
    assert {v["value"]: v["count"] for v in facets["detector"]["values"]} == {"wazuh": 2, "suricata": 1, "aminer": 1}
    assert {v["value"]: v["count"] for v in facets["technique"]["values"]} == {"T1078": 1, "unmapped": 1}
    assert facets["rule_id"]["values"][0]["label"] == "rule 1"
    assert {v["value"] for v in idx.facets(an.AlertFilter())["level"]["values"]} == {"3", "1", "none"}
    assert [x.alert_id for x in idx.select(an.AlertFilter(technique="T1078"))] == ["a3"]
    assert [x.alert_id for x in idx.select(an.AlertFilter(since=2, until=4))] == ["a2", "a3"]


def test_kill_chain_shows_gaps_and_detector_comparison() -> None:
    rows = [fact(1, 1, tech=("T9999",)), fact(2, 2, "suricata", dup=False), fact(3, 3, dup=True)]
    chain = an.kill_chain(rows, None)
    assert [c["tactic"] for c in chain] == list(an.TACTIC_ORDER)
    assert all(c["alerts"] == 0 for c in chain)  # no KB: no tactic is claimed
    idx = an.AlertIndex("s", rows)
    comp = {r["detector"]: r for r in idx.detector_comparison()}
    assert comp["wazuh"]["mapped"] == 1 and comp["wazuh"]["duplicates"] == 1
    assert comp["wazuh"]["ioc"] is None and comp["wazuh"]["ioc_share"] is None
    matrix = idx.attack_matrix(None)
    assert matrix["mapped_alerts"] == 1 and matrix["tactics"][-1]["tactic"] == an.UNKNOWN_TACTIC


def test_entity_graph_edges_and_cap() -> None:
    rows = [fact(1, 1, host="h1", src="s1"), fact(2, 2, "suricata", host="h1", src="s1"), fact(3, 3, host="h2")]
    g = an.entity_graph(rows)
    assert [n["id"] for n in g["nodes"]] == ["host:h1", "ip:s1", "host:h2"]
    assert g["edges"] == [{"source": "ip:s1", "target": "host:h1", "alerts": 2,
                           "by_detector": {"wazuh": 1, "suricata": 1}}]
    many = [fact(i, i, host=f"h{i}") for i in range(an.MAX_GRAPH_NODES + 5)]
    big = an.entity_graph(many)
    assert len(big["nodes"]) == an.MAX_GRAPH_NODES and big["nodes_omitted"] == 5


def test_queue_summary_and_time_to_review() -> None:
    now = 1_000_000.0
    incs = [{"incident_id": "i1", "severity": "High", "status": "open", "created_utc": an.iso(now - 7200),
             "first_ts": "2022-01-01T00:00:00Z", "last_ts": "2022-01-01T00:01:00Z", "alert_ids": ["a"], "scenario": "s"},
            {"incident_id": "i2", "severity": "Low", "status": "closed", "created_utc": an.iso(now - 10),
             "first_ts": "2022-01-02T00:00:00Z", "last_ts": "2022-01-02T00:01:00Z", "alert_ids": [], "scenario": "s"}]
    q = an.queue_summary(incs, [{"status": "pending"}, {"status": "approved"}], now)
    assert q["oldest_unreviewed_high"]["incident_id"] == "i1"
    assert q["age_in_queue"]["High"]["1-24 h"] == 1 and q["open_by_severity"]["Low"] == 0
    assert q["pending_approvals"] == 1
    audit = [{"action": "incident.update", "target": "i1", "ts": an.iso(now - 3600)}]
    ex = an.executive_summary(incs, [], audit, an.kill_chain([], None), now)
    assert ex["time_to_review"]["reviewed"] == 1 and ex["time_to_review"]["median_seconds"] == 3600
    assert [d["day"] for d in ex["severity_trend"]] == ["2022-01-01", "2022-01-02"]
    assert [r["incident_id"] for r in ex["top_risks"]] == ["i1"]


def test_severity_rule_words_come_from_the_triage_table() -> None:
    rule = an.severity_rule("H2")
    assert rule == {"row": "H2", "severity": "High", "rule": ">= 3 detectors agree"}
    assert an.severity_rule("nope") is None


def test_fnv1a_matches_reference_values() -> None:
    # reference: FNV-1a 32-bit of "a" is 0xe40c292c
    assert fnv1a("a") == 0xE40C292C
    assert fnv1a("") == 0x811C9DC5


def test_layout_is_deterministic_and_bounded() -> None:
    ids = [f"n{i}" for i in range(30)]
    edges = [(ids[i], ids[(i * 7) % 30]) for i in range(30)]
    a = layout(ids, edges, 600, 400)
    b = layout(ids, edges, 600, 400)
    assert a == b
    assert all(PAD <= p.x <= 600 - PAD and PAD <= p.y <= 400 - PAD for p in a)
    assert layout([], [], 100, 100) == [] and layout(["x"], [], 100, 80)[0].x == 50


def test_layout_matches_the_frontend_fixture() -> None:
    spec = json.loads(FIXTURE.read_text(encoding="utf-8"))
    got = layout(spec["nodes"], [tuple(e) for e in spec["edges"]], spec["width"], spec["height"])
    assert [[p.x, p.y] for p in got] == spec["expected"]


# ---- routes ----------------------------------------------------------------------------------

def test_overview_shape_and_no_labels(client: TestClient) -> None:  # noqa: F811
    h = token(client, Role.EXECUTIVE)
    r = client.get("/overview?scenario=synthetic", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["alerts"] == sum(sum(v) for v in body["timeseries"]["series"].values())
    assert {d["detector"] for d in body["detectors"]} <= {"wazuh", "suricata", "aminer", "sigma"}
    assert len(body["kill_chain"]) == len(an.TACTIC_ORDER)
    assert body["status"]["open_by_severity"]["High"] == 1
    for word in LABEL_WORDS:
        assert word not in r.text


def test_query_facets_export_agree(client: TestClient) -> None:  # noqa: F811
    h = token(client, Role.ANALYST)
    total = client.get("/alerts/facets?scenario=synthetic", headers=h).json()["total"]
    q = client.get("/alerts/query?scenario=synthetic&limit=5", headers=h).json()
    assert q["total"] == total and len(q["alerts"]) == min(5, total)
    assert "record" in q["alerts"][0] and "techniques" in q["alerts"][0]
    det = q["alerts"][0]["detector"]
    sub = client.get(f"/alerts/query?scenario=synthetic&detector={det}&limit=500", headers=h).json()
    assert all(a["detector"] == det for a in sub["alerts"])
    csv_text = client.get(f"/alerts/export.csv?scenario=synthetic&detector={det}", headers=h).text
    assert csv_text.splitlines()[0] == ",".join(an.EXPORT_COLUMNS)
    assert len(csv_text.splitlines()) == sub["total"] + 1
    ex = client.get("/alerts/query?scenario=synthetic&limit=2", headers=token(client, Role.EXECUTIVE)).json()
    assert all("record" not in a for a in ex["alerts"])
    assert client.get("/alerts/query?scenario=synthetic&since=notatime", headers=h).status_code == 422


def test_incident_analysis_entity_and_search(client: TestClient, services: Services) -> None:  # noqa: F811
    rows = services.repo.list_alerts(scenario="synthetic", limit=6)
    services.repo.put_incident({"incident_id": "inc-an", "scenario": "synthetic", "first_ts": rows[0]["ts"],
                                "last_ts": rows[-1]["ts"], "severity": "Medium",
                                "alert_ids": [r["alert_id"] for r in rows],
                                "detail": {"severity_row": "M3", "detectors": {"wazuh": 6},
                                           "entities": [f"host:{rows[0]['host_ip']}"]}})
    h = token(client, Role.ANALYST)
    a = client.get("/incidents/inc-an/analysis", headers=h).json()
    assert a["summary"]["alerts_found"] == 6 and a["summary"]["rule"]["row"] == "M3"
    assert sum(sum(v) for v in a["timeseries"]["series"].values()) == 6
    assert client.get("/incidents/nope/analysis", headers=h).status_code == 404
    node = a["graph"]["nodes"][0]["id"] if a["graph"]["nodes"] else None
    if node:
        ids = client.get(f"/incidents/inc-an/node-alerts?node={node}", headers=h).json()["alert_ids"]
        assert ids and set(ids) <= {r["alert_id"] for r in rows}
        assert len(ids) == a["graph"]["nodes"][0]["alerts"]
    assert client.get("/incidents/inc-an/node-alerts?node=bogus", headers=h).status_code == 422
    host = rows[0]["host_ip"]
    if host:
        e = client.get(f"/entities/host/{host}?scenario=synthetic", headers=h).json()
        assert e["alerts"] >= 1 and any(i["incident_id"] == "inc-an" for i in e["incidents"])
    s = client.get(f"/search?q={rows[0]['alert_id']}&scenario=synthetic", headers=h).json()
    assert s["alerts"][0]["alert_id"] == rows[0]["alert_id"]
    assert client.get("/search?q=inc-a&scenario=synthetic", headers=h).json()["incidents"][0]["incident_id"] == "inc-an"
    summ = client.get("/incidents/summary?scenario=synthetic", headers=h).json()["incidents"]
    assert all("timeline" not in i["detail"] for i in summ)
    exe = client.get("/executive?scenario=synthetic", headers=token(client, Role.EXECUTIVE)).json()
    assert {"severity_trend", "top_risks", "coverage", "time_to_review", "open_approvals"} <= set(exe)


def test_users_admin_env_password_and_deactivation(client: TestClient, monkeypatch: pytest.MonkeyPatch,  # noqa: F811
                                                  services: Services) -> None:  # noqa: F811
    admin = token(client, Role.ADMIN)
    assert client.get("/users", headers=token(client, Role.MANAGER)).status_code == 403
    users = client.get("/users", headers=admin).json()["users"]
    assert users and all("password_hash" not in u for u in users)
    monkeypatch.delenv("SENTINEL_NEW_USER_PASSWORD", raising=False)
    assert client.post("/console/users", headers=admin, json={"username": "neo", "role": "analyst"}).status_code == 409
    monkeypatch.setenv("SENTINEL_NEW_USER_PASSWORD", "from-the-environment")
    assert client.post("/console/users", headers=admin, json={"username": "neo", "role": "analyst"}).status_code == 201
    ok = client.post("/auth/login", json={"username": "neo", "password": "from-the-environment"})
    assert ok.status_code == 200
    neo = {"Authorization": f"Bearer {ok.json()['access_token']}"}
    assert client.post("/users/neo/deactivate", headers=admin).status_code == 200
    assert client.get("/alerts", headers=neo).status_code == 401  # existing token refused
    assert client.post("/auth/login", json={"username": "neo", "password": "from-the-environment"}).status_code == 401
    assert client.post("/users/neo/reactivate", headers=admin).status_code == 200
    monkeypatch.setenv("SENTINEL_NEW_USER_PASSWORD", "second-env-password")
    assert client.post("/users/neo/reset", headers=admin).status_code == 200
    assert client.post("/auth/login", json={"username": "neo", "password": "second-env-password"}).status_code == 200
    assert client.post("/users/admin/deactivate", headers=admin).status_code == 409  # not yourself
    actions = [e["action"] for e in services.repo.audit_entries()]
    for action in ("user.create", "user.deactivate", "user.reactivate", "user.reset", "login.refused"):
        assert action in actions


def test_study_results_skip_fake_runs(client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    runs = tmp_path / "runs"
    fake = runs / "matched-fake"
    fake.mkdir(parents=True)
    (fake / "manifest.json").write_text(json.dumps({"model": {"model_ids": {"single": "fake", "graph": "fake"}}}))
    (fake / "scores.json").write_text(json.dumps({"arms": {}}))
    real = runs / "matched-real"
    real.mkdir()
    (real / "manifest.json").write_text(json.dumps({"scenario": "russellmitchell", "variant": "fused",
                                                    "model": {"model_ids": {"single": "qwen", "graph": "qwen"}},
                                                    "cases": [{}, {}]}))
    (real / "scores.json").write_text(json.dumps({"arms": {"single": {"coverage": {}}}, "baselines": {}, "matched_k": 3}))
    monkeypatch.setenv("SENTINEL_RUNS_DIR", str(runs))
    body = client.get("/study/results", headers=token(client, Role.ANALYST)).json()
    assert body["excluded_fake_runs"] == 1 and [r["run_id"] for r in body["runs"]] == ["matched-real"]
    assert body["runs"][0]["cases"] == 2 and "not paper results" in body["label"]
    monkeypatch.setenv("SENTINEL_RUNS_DIR", str(tmp_path / "none"))
    assert client.get("/study/results", headers=token(client, Role.ANALYST)).json()["runs"] == []


def test_report_carries_charts_and_pdf_draws_them(client: TestClient, services: Services) -> None:  # noqa: F811
    from app.outputs.reports import render_pdf

    rows = services.repo.list_alerts(scenario="synthetic", limit=8)
    services.repo.put_incident({"incident_id": "inc-ch", "scenario": "synthetic", "first_ts": rows[0]["ts"],
                                "last_ts": rows[-1]["ts"], "severity": "Low",
                                "alert_ids": [r["alert_id"] for r in rows], "detail": {}})
    h = token(client, Role.ANALYST)
    rid = client.post("/reports", headers=h, json={"incident_id": "inc-ch"}).json()["report_id"]
    body = client.get(f"/reports/{rid}", headers=h).json()["body"]
    charts = body["charts"]
    assert charts["timeseries"]["total"] == 8
    g = charts["graph"]
    assert g["nodes_shown"] == len(g["nodes"]) <= an.GRAPH_SHOWN
    expect = layout([n["id"] for n in g["nodes"]], [(e["source"], e["target"]) for e in g["edges"]],
                    g["width"], g["height"])
    assert [(n["x"], n["y"]) for n in g["nodes"]] == [(p.x, p.y) for p in expect]
    with_charts = render_pdf(body)
    without = render_pdf({k: v for k, v in body.items() if k != "charts"})
    assert with_charts.startswith(b"%PDF") and len(with_charts) > len(without)
    for word in LABEL_WORDS:
        assert word not in json.dumps(body)
