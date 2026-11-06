"""Integration tests against the docker-compose services. Skip cleanly when absent.

Start with ``docker compose --profile lite up -d`` (PostgreSQL) or ``full``,
and export SENTINEL_TEST_DB_URL (and SENTINEL_TEST_AGENT_DB_URL for the
sentinel_agent role), SENTINEL_TEST_SEARCH_URL, SENTINEL_TEST_KAFKA.
"""

from __future__ import annotations

import os
import socket
import uuid
from pathlib import Path

import pytest

from app.alert_pipeline import iter_alert_file
from app.storage.db import PostgresDatabase
from app.storage.repository import Repository
from tests.test_variants import processed  # noqa: F401  (fixture)

pytestmark = pytest.mark.infra


def _reachable(env: str) -> str:
    url = os.environ.get(env)
    if not url:
        pytest.skip(f"{env} not set (docker-compose services not configured)")
    host, port = "127.0.0.1", {"SENTINEL_TEST_DB_URL": 5432, "SENTINEL_TEST_AGENT_DB_URL": 5432,
                               "SENTINEL_TEST_SEARCH_URL": 9200, "SENTINEL_TEST_KAFKA": 9092}[env]
    try:
        socket.create_connection((host, port), timeout=1).close()
    except OSError:
        pytest.skip(f"{env}: nothing listening on {host}:{port}")
    return url


def test_postgres_migrations_and_alert_roundtrip(processed: Path) -> None:  # noqa: F811
    db = PostgresDatabase(_reachable("SENTINEL_TEST_DB_URL"))
    db.migrate()
    truth = PostgresDatabase(os.environ["SENTINEL_TEST_DB_URL"], area="truth")
    truth.migrate()
    repo = Repository(db)
    alert = next(iter(iter_alert_file(processed / "synthetic.alerts.jsonl")))
    alert = alert.model_copy(update={"alert_id": f"it-{uuid.uuid4().hex}"})
    assert repo.upsert_alert(alert, {"k": 1}, "test")
    assert repo.get_alert(alert.alert_id)["enrichment"] == {"k": 1}  # type: ignore[index]


def test_agent_role_cannot_read_truth() -> None:
    url = _reachable("SENTINEL_TEST_AGENT_DB_URL")
    agent = PostgresDatabase(url)
    agent.query("SELECT COUNT(*) AS n FROM alerts")
    with pytest.raises(Exception, match="permission denied"):
        agent.query("SELECT * FROM truth.ground_truth LIMIT 1")


def test_opensearch_index_and_search(processed: Path) -> None:  # noqa: F811
    from app.storage.search import OpenSearchIndex

    index = OpenSearchIndex(_reachable("SENTINEL_TEST_SEARCH_URL"), f"it-{uuid.uuid4().hex[:8]}")
    alert = next(iter(iter_alert_file(processed / "synthetic.alerts.jsonl")))
    index.index(alert)
    index._client.indices.refresh(index=index._index)
    assert index.search(alert.evidence.log_lines[0].split()[-1]) is not None


def test_kafka_publish_consume() -> None:
    from app.platform.stream import KafkaStream

    stream = KafkaStream(_reachable("SENTINEL_TEST_KAFKA"))
    topic = f"it-{uuid.uuid4().hex[:8]}"
    stream.publish(topic, {"n": 1})
    assert list(stream.consume(topic, "it", max_messages=1)) == [{"n": 1}]
