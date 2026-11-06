"""Stream consumer (stage 2): message -> validated Alert -> enrich -> store + index.

A message that does not validate is counted as rejected with its error and
kept in the report, never dropped silently. Storing is idempotent by
``alert_id``, so a replay can be re-run.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from app.platform.enrichment import enrich
from app.platform.stream import ALERTS_TOPIC, Stream
from app.schemas.alert import Alert
from app.storage.repository import Repository
from app.storage.search import SearchIndex


@dataclass
class ConsumeReport:
    consumed: int = 0
    stored: int = 0
    duplicates: int = 0
    rejected: int = 0
    rejections: list[dict[str, Any]] = field(default_factory=list)
    by_detector: Counter[str] = field(default_factory=Counter)

    def as_dict(self) -> dict[str, Any]:
        return {"consumed": self.consumed, "stored": self.stored, "duplicates": self.duplicates,
                "rejected": self.rejected, "rejections": self.rejections[:20],
                "by_detector": dict(sorted(self.by_detector.items()))}


def consume(stream: Stream, repo: Repository, index: SearchIndex | None = None, *,
            topic: str = ALERTS_TOPIC, group: str = "sentinel-store",
            max_messages: int | None = None, batch_size: int = 1000) -> ConsumeReport:
    """Consume in transactions of ``batch_size`` messages (one fsync per batch)."""
    report = ConsumeReport()
    messages = stream.consume(topic, group, max_messages)
    while True:
        batch = [m for _, m in zip(range(batch_size), messages)]
        if not batch:
            break
        with repo.db.transaction():
            _store_batch(batch, repo, index, report)
    if index is not None:
        index.flush()
    return report


def _store_batch(batch: list[dict[str, Any]], repo: Repository, index: SearchIndex | None,
                 report: ConsumeReport) -> None:
    for message in batch:
        report.consumed += 1
        try:
            alert = Alert.model_validate(message["alert"])
        except (KeyError, TypeError, ValidationError) as exc:
            report.rejected += 1
            report.rejections.append({"offset": report.consumed - 1, "error": str(exc)[:300]})
            continue
        if repo.upsert_alert(alert, enrich(alert), str(message.get("source", "unknown"))):
            report.stored += 1
            report.by_detector[alert.detector.value] += 1
            if index is not None:
                index.index(alert)
        else:
            report.duplicates += 1
