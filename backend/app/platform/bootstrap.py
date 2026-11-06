"""Wire the platform stores from the environment and run a dev replay into them.

``open_stores(data_dir)``: PostgreSQL when ``SENTINEL_DB_URL`` is set (core
area in ``public``, truth area in schema ``truth``), else two SQLite files
(``core.db``, ``truth.db``). Search: OpenSearch if ``SENTINEL_SEARCH_URL``,
else SQLite FTS5. Stream: Kafka if ``SENTINEL_KAFKA``, else in-memory.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.alert_pipeline import iter_alert_file
from app.platform.collectors import DatasetReplayCollector
from app.platform.consumer import consume
from app.platform.stream import InMemoryStream, KafkaStream, Stream
from app.schemas.alert import GroundTruth
from app.storage.db import Database, PostgresDatabase, SqliteDatabase
from app.storage.repository import Repository, TruthStore
from app.storage.search import OpenSearchIndex, SearchIndex, SqliteFtsIndex
from app.study.config import StudyConfig


@dataclass
class Stores:
    repo: Repository
    truth: TruthStore
    index: SearchIndex
    stream: Stream


def open_stores(data_dir: str | Path) -> Stores:
    data_dir = Path(data_dir)
    dsn = os.environ.get("SENTINEL_DB_URL")
    core: Database
    truth: Database
    if dsn:
        core, truth = PostgresDatabase(dsn), PostgresDatabase(dsn, area="truth")
    else:
        core = SqliteDatabase(data_dir / "core.db")
        truth = SqliteDatabase(data_dir / "truth.db", area="truth")
    core.migrate()
    truth.migrate()
    url = os.environ.get("SENTINEL_SEARCH_URL")
    index: SearchIndex = OpenSearchIndex(url) if url else SqliteFtsIndex(data_dir / "search.db")
    kafka = os.environ.get("SENTINEL_KAFKA")
    stream: Stream = KafkaStream(kafka) if kafka else InMemoryStream()
    return Stores(Repository(core), TruthStore(truth), index, stream)


def ingest_scenario(stores: Stores, processed_dir: str | Path, scenario: str, config: StudyConfig,
                    *, limit: int | None = None) -> dict[str, Any]:
    """Replay a dev scenario: collector -> stream -> consumer -> core store; truth separately."""
    collector = DatasetReplayCollector(processed_dir, scenario, config, limit=limit)
    published = collector.publish(stores.stream)
    report = consume(stores.stream, stores.repo, stores.index)
    truth_path = Path(processed_dir) / f"{scenario}.ground_truth.jsonl"
    stored_ids = {str(r["alert_id"]) for r in stores.repo.db.query(
        "SELECT alert_id FROM alerts WHERE scenario = ?", (scenario,))}
    truths = 0
    if truth_path.exists():
        with truth_path.open(encoding="utf-8") as handle:
            batch = (GroundTruth.model_validate_json(line) for line in handle if line.strip())
            truths = stores.truth.put_many(t for t in batch if t.alert_id in stored_ids)
    return {"scenario": scenario, "published": published, **report.as_dict(),
            "ground_truth_rows": truths, "alerts_in_store": len(stored_ids),
            "note": "dev scenario replay; ground truth stored in the separate truth area"}
