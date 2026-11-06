"""Collector adapters (stage 1).

Only :class:`DatasetReplayCollector` is implemented: it replays normalized
AIT-ADS alerts from ``data/processed/<scenario>.alerts.jsonl`` onto the
stream in file order. Production collectors (Elastic Beats, Logstash,
Fluentd) would publish the same message shape to the same topic; they are
documented in ``docs/architecture.md`` and not built.

Replay is **dev scenarios only** until the held-out runs (Wave E): the study
config's ``require_dev`` is called before any file is opened. Ground truth
is never put on the stream.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any, Protocol

from app.alert_pipeline import iter_alert_file
from app.platform.stream import ALERTS_TOPIC, Stream
from app.schemas.alert import AlertSelection
from app.study.config import StudyConfig

PRODUCTION_ADAPTERS = {
    "beats": "Elastic Beats (Filebeat/Winlogbeat) -> Kafka output, topic sentinel.alerts.raw",
    "logstash": "Logstash kafka output plugin, codec json, same topic",
    "fluentd": "fluent-plugin-kafka, format json, same topic",
}


class Collector(Protocol):
    name: str

    def messages(self) -> Iterator[dict[str, Any]]: ...


class DatasetReplayCollector:
    name = "dataset-replay"

    def __init__(self, processed_dir: str | Path, scenario: str, config: StudyConfig, *,
                 limit: int | None = None, selection: AlertSelection | None = None) -> None:
        config.split.require_dev(scenario)  # before any file is read
        self.path = Path(processed_dir) / f"{scenario}.alerts.jsonl"
        self.scenario = scenario
        self.limit = limit
        self.selection = selection

    def messages(self) -> Iterator[dict[str, Any]]:
        for n, alert in enumerate(iter_alert_file(self.path, self.selection)):
            if self.limit is not None and n >= self.limit:
                return
            yield {"source": self.name, "alert": alert.model_dump(mode="json")}

    def publish(self, stream: Stream, topic: str = ALERTS_TOPIC) -> int:
        n = 0
        for message in self.messages():
            stream.publish(topic, message)
            n += 1
        return n
