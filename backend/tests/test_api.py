"""Wave A API: auth, RBAC per role, audit on every write, no labels in responses."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.app import Services, create_app
from app.api.auth import AuthError, Role, decode_token, hash_password, issue_token, jwt_secret
from app.platform.collectors import DatasetReplayCollector
from app.platform.consumer import consume
from app.platform.stream import InMemoryStream
from app.storage.db import SqliteDatabase
from app.storage.objects import LocalObjectStore
from app.storage.repository import Repository
from app.storage.search import SqliteFtsIndex
from app.study.config import load_study_config
from tests.test_cases import synthetic_config
from tests.test_variants import processed  # noqa: F401  (fixture)

SECRET = "test-secret-" + "x" * 32
PASSWORD = "correct horse battery"


@pytest.fixture()
def services(tmp_path: Path, processed: Path) -> Services:  # noqa: F811
    db = SqliteDatabase(":memory:")
    db.migrate()
    repo = Repository(db)
    index = SqliteFtsIndex()
    stream = InMemoryStream()
    DatasetReplayCollector(processed, "synthetic", load_study_config(synthetic_config(tmp_path))).publish(stream)
    consume(stream, repo, index)
    for role in Role:
        repo.put_user(role.value, hash_password(PASSWORD, rounds=4), role.value)
    repo.put_incident({"incident_id": "inc-1", "scenario": "synthetic",
                       "first_ts": "2022-01-01T00:00:00+00:00", "last_ts": "2022-01-01T00:01:00+00:00",
                       "severity": "High", "alert_ids": [], "detail": {}})
    return Services(repo, index, LocalObjectStore(tmp_path / "obj"), SECRET)


@pytest.fixture()
def client(services: Services) -> TestClient:
    return TestClient(create_app(services))


def token(client: TestClient, role: Role) -> dict[str, str]:
    r = client.post("/auth/login", json={"username": role.value, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_secret_only_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_JWT_SECRET", raising=False)
    with pytest.raises(AuthError):
        jwt_secret()
    monkeypatch.setenv("SENTINEL_JWT_SECRET", "short")
    with pytest.raises(AuthError):
        jwt_secret()


def test_tokens_expire_and_are_signed() -> None:
    from datetime import datetime, timezone
    old = issue_token("a", Role.ANALYST, SECRET, minutes=1, now=datetime(2020, 1, 1, tzinfo=timezone.utc))
    with pytest.raises(AuthError, match="Expired"):
        decode_token(old, SECRET)
    with pytest.raises(AuthError):
        decode_token(issue_token("a", Role.ADMIN, "other-secret-" + "y" * 32), SECRET)


def test_login_and_unauthenticated(client: TestClient, services: Services) -> None:
    assert client.get("/alerts").status_code == 401
    assert client.post("/auth/login", json={"username": "analyst", "password": "wrong-password"}).status_code == 401
    assert services.repo.audit_entries()[0]["action"] == "login.failed"
    assert client.get("/auth/me", headers=token(client, Role.ANALYST)).json()["role"] == "analyst"


@pytest.mark.parametrize("role,feedback,decide_audit,raw", [
    (Role.ANALYST, 201, 403, 200), (Role.MANAGER, 201, 200, 200),
    (Role.ADMIN, 201, 200, 200), (Role.EXECUTIVE, 403, 403, 403)])
def test_rbac_matrix(client: TestClient, role: Role, feedback: int, decide_audit: int, raw: int) -> None:
    h = token(client, role)
    assert client.get("/alerts", headers=h).status_code == 200
    assert client.post("/feedback", headers=h, json={"target_type": "incident", "target_id": "inc-1",
                                                     "verdict": "true_positive"}).status_code == feedback
    assert client.get("/audit", headers=h).status_code == decide_audit
    first = client.get("/alerts", headers=token(client, Role.ANALYST)).json()["alerts"][0]["alert_id"]
    assert client.get(f"/alerts/{first}", headers=h).status_code == raw


def test_executive_sees_no_raw_records(client: TestClient) -> None:
    rows = client.get("/alerts", headers=token(client, Role.EXECUTIVE)).json()["alerts"]
    assert rows and all("record" not in r for r in rows)


def test_every_write_is_audited(client: TestClient, services: Services) -> None:
    h = token(client, Role.ANALYST)
    client.post("/feedback", headers=h, json={"target_type": "alert", "target_id": "x", "verdict": "unsure"})
    client.patch("/incidents/inc-1", headers=h, json={"status": "investigating"})
    admin = token(client, Role.ADMIN)
    client.post("/users", headers=admin, json={"username": "eve", "password": "longpassword", "role": "analyst"})
    actions = [e["action"] for e in services.repo.audit_entries()]
    for action in ("feedback.create", "incident.update", "user.create"):
        assert action in actions
    client.post("/users", headers=h, json={"username": "x", "password": "longpassword", "role": "admin"})
    assert services.repo.audit_entries()[0]["action"] == "denied"


def test_search_stats_health(client: TestClient) -> None:
    h = token(client, Role.ANALYST)
    assert client.get("/health").json()["status"] == "ok"
    stats = client.get("/alerts/stats", headers=h).json()["by_detector"]
    assert sum(stats.values()) > 0
    first = client.get("/alerts", headers=h).json()["alerts"][0]
    word = next(w for w in "\n".join(first["record"]["evidence"]["log_lines"]).split() if len(w) > 4)
    hits = client.get("/alerts/search", headers=h, params={"q": word}).json()["hits"]
    assert hits


def test_no_ground_truth_in_any_response(client: TestClient) -> None:
    h = token(client, Role.ADMIN)
    bodies = [client.get(p, headers=h).text for p in
              ("/alerts?limit=500", "/incidents", "/runs", "/cases", "/reports", "/feedback")]
    for body in bodies:
        for key in ("time_label", "event_label", "ground_truth"):
            assert key not in body
    json.loads(bodies[0])
