"""Wave A: migrations, repositories, truth separation, search, objects, stream, replay, enrichment.

All on the in-process fallbacks (SQLite, FTS5, local folder, in-memory
stream) with the committed synthetic AIT-ADS sample. PostgreSQL / Kafka /
OpenSearch / MinIO integration tests live in test_infra_integration.py and
skip without Docker.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from app.alert_pipeline import iter_alert_file
from app.platform.collectors import DatasetReplayCollector
from app.platform.consumer import consume
from app.platform.enrichment import enrich, ip_info
from app.platform.stream import ALERTS_TOPIC, InMemoryStream
from app.storage import repository as repository_module
from app.storage.db import MigrationError, SqliteDatabase, migration_files, render
from app.storage.objects import LocalObjectStore, check_key
from app.storage.repository import AlertReader, Repository, TruthStore
from app.storage.search import SqliteFtsIndex, fts_query
from app.study.config import HeldOutScenarioError, load_study_config
from tests.test_cases import synthetic_config
from tests.test_variants import processed  # noqa: F401  (fixture)


TOOL_PATH_MODULES = ("tools.py", "agent.py", "protocol.py", "client.py", "graph.py",
                     "multi_tools.py", "rag_tool.py", "verifier.py", "copilot.py", "investigation.py")


@pytest.fixture()
def repo() -> Repository:
    db = SqliteDatabase(":memory:")
    db.migrate()
    return Repository(db)


def synthetic_alerts(processed: Path) -> list:  # type: ignore[type-arg]  # noqa: F811
    return list(iter_alert_file(processed / "synthetic.alerts.jsonl"))


def test_migrations_apply_once_and_detect_changes(tmp_path: Path) -> None:
    db = SqliteDatabase(tmp_path / "core.db")
    assert db.migrate() == [name for name, _ in migration_files("core")]
    assert db.migrate() == []
    db.execute("UPDATE schema_migrations SET sha256 = 'x'")
    with pytest.raises(MigrationError, match="changed"):
        db.migrate()


def test_render_dialects_and_unknown_placeholder() -> None:
    assert "JSONB" in render("x {{JSON}}", "postgres", "core")
    assert render("{{S}}t", "postgres", "truth") == "truth.t"
    assert render("{{S}}t", "sqlite", "truth") == "t"
    with pytest.raises(MigrationError):
        render("{{NOPE}}", "sqlite", "core")


def test_truth_lives_in_a_separate_area(tmp_path: Path, processed: Path) -> None:  # noqa: F811
    core = SqliteDatabase(tmp_path / "core.db")
    core.migrate()
    truth = SqliteDatabase(tmp_path / "truth.db", area="truth")
    truth.migrate()
    with pytest.raises(ValueError):
        Repository(truth)
    with pytest.raises(ValueError):
        TruthStore(core)
    tables = {r["name"] for r in core.query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "ground_truth" not in tables
    assert not any("label" in r["sql"].lower()
                   for r in core.query("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"))


def test_alert_reader_exposes_no_truth_or_writes() -> None:
    public = {n for n in dir(AlertReader) if not n.startswith("_")}
    assert public == {"get_alert", "list_alerts"}
    src = inspect.getsource(AlertReader)
    assert "TruthStore" not in src and "ground_truth" not in src
    # agent tool-path modules never import labels (the runner scores, so it may)
    import app.agent as agent_pkg
    root = Path(agent_pkg.__file__).parent
    for name in TOOL_PATH_MODULES:
        path = root / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        assert "TruthStore" not in text and "ground_truth" not in text, path
    assert "TruthStore" in dir(repository_module)


def test_replay_consume_store_index_roundtrip(repo: Repository, processed: Path,  # noqa: F811
                                              tmp_path: Path) -> None:
    config = load_study_config(synthetic_config(tmp_path))
    stream = InMemoryStream()
    collector = DatasetReplayCollector(processed, "synthetic", config)
    published = collector.publish(stream)
    assert published == len(synthetic_alerts(processed)) == stream.size(ALERTS_TOPIC)
    index = SqliteFtsIndex()
    report = consume(stream, repo, index)
    assert report.stored == published and report.rejected == 0
    assert sum(repo.count_alerts("synthetic").values()) == published
    # replay is idempotent
    collector.publish(stream)
    again = consume(stream, repo, index)
    assert again.stored == 0 and again.duplicates == published
    first = synthetic_alerts(processed)[0]
    row = repo.get_alert(first.alert_id)
    assert row is not None and row["record"]["alert_id"] == first.alert_id
    assert "label" not in row["record"]
    word = next(w for line in first.evidence.log_lines for w in line.split() if len(w) > 4)
    hits = index.search(word, scenario="synthetic")
    assert any(h["alert_id"] == first.alert_id for h in hits)


def test_replay_refuses_held_out(processed: Path) -> None:  # noqa: F811
    with pytest.raises(HeldOutScenarioError):
        DatasetReplayCollector(processed, "wilson", load_study_config())


def test_bad_messages_are_counted_not_dropped(repo: Repository) -> None:
    stream = InMemoryStream()
    stream.publish(ALERTS_TOPIC, {"source": "x", "alert": {"alert_id": "a"}})
    stream.publish(ALERTS_TOPIC, {"nothing": 1})
    report = consume(stream, repo)
    assert report.consumed == 2 and report.rejected == 2 and len(report.rejections) == 2


def test_enrichment_never_invents(processed: Path) -> None:  # noqa: F811
    for alert in synthetic_alerts(processed):
        e = enrich(alert)
        assert set(e) == {"event_type", "source", "time", "network", "geo"}
        assert e["time"]["timestamp"] == alert.timestamp.isoformat()
        if alert.host_ip is None:
            assert e["network"]["host"] is None
        if "GeoLocation" not in alert.raw_alert:
            assert e["geo"] is None
        if alert.detector.value == "aminer":
            assert e["network"]["src"] is None and e["network"]["dst_port"] is None
    assert ip_info("10.0.0.1") == {"value": "10.0.0.1", "valid": True, "version": 4, "scope": "private"}
    assert ip_info("8.8.8.8")["scope"] == "global"  # type: ignore[index]
    assert ip_info("nope") == {"value": "nope", "valid": False}
    assert ip_info(None) is None


def test_repository_incidents_reports_approvals_feedback_audit(repo: Repository) -> None:
    repo.put_incident({"incident_id": "inc-1", "scenario": "s", "first_ts": "2022-01-01T00:00:00+00:00",
                       "last_ts": "2022-01-01T00:10:00+00:00", "severity": "High",
                       "alert_ids": ["a", "b"], "detail": {"hosts": ["10.0.0.1"]}})
    assert repo.get_incident("inc-1")["alert_ids"] == ["a", "b"]  # type: ignore[index]
    rid = repo.put_report("inc-1", {"summary": "x"})
    assert repo.get_report(rid)["body"] == {"summary": "x"}  # type: ignore[index]
    aid = repo.request_approval("inc-1", {"step": "isolate host"}, "alice")
    with pytest.raises(ValueError, match="reason"):
        repo.decide_approval(aid, True, "bob", " ")
    repo.decide_approval(aid, True, "bob", "confirmed by logs")
    assert repo.get_approval(aid)["status"] == "approved"  # type: ignore[index]
    with pytest.raises(ValueError, match="already"):
        repo.decide_approval(aid, False, "bob", "changed mind")
    repo.add_feedback("incident", "inc-1", "true_positive", "real", "alice")
    assert repo.list_feedback()[0]["verdict"] == "true_positive"
    repo.audit("alice", "analyst", "feedback.create", "inc-1", {"verdict": "true_positive"})
    assert repo.audit_entries()[0]["action"] == "feedback.create"
    repo.remember("sess", "k", {"v": 1})
    assert repo.recall("sess") == [{"key": "k", "value": {"v": 1}}]


def test_object_store_rejects_escaping_keys(tmp_path: Path) -> None:
    store = LocalObjectStore(tmp_path / "obj")
    store.put("reports/inc-1/report.pdf", b"%PDF")
    assert store.get("reports/inc-1/report.pdf") == b"%PDF"
    for bad in ("../x", "/abs", "a/../../b", "a\\b", "", "a//b"):
        with pytest.raises(ValueError):
            check_key(bad)


def test_fts_query_quotes_every_token() -> None:
    assert fts_query('evil" OR 1=1 --') == '"evil" "OR" "1" "1" "--"'
    assert fts_query("   ") == ""
