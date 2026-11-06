"""Message stream between collectors and consumers.

``InMemoryStream`` (fallback: tests, study, demo) and ``KafkaStream`` (``full``
profile, optional ``confluent-kafka``) share one interface. Messages are
JSON-serializable dicts; a topic is an ordered log with per-consumer offsets,
so replay is deterministic.
"""

from __future__ import annotations

import json
import threading
from collections import defaultdict
from collections.abc import Iterator
from typing import Any, Protocol

ALERTS_TOPIC = "sentinel.alerts.raw"


class Stream(Protocol):
    def publish(self, topic: str, message: dict[str, Any]) -> None: ...
    def consume(self, topic: str, group: str, max_messages: int | None = None) -> Iterator[dict[str, Any]]: ...


class InMemoryStream:
    def __init__(self) -> None:
        self._topics: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._offsets: dict[tuple[str, str], int] = defaultdict(int)
        self._lock = threading.Lock()

    def publish(self, topic: str, message: dict[str, Any]) -> None:
        json.dumps(message)  # same contract as Kafka: must serialize
        with self._lock:
            self._topics[topic].append(message)

    def consume(self, topic: str, group: str, max_messages: int | None = None) -> Iterator[dict[str, Any]]:
        n = 0
        while max_messages is None or n < max_messages:
            with self._lock:
                offset = self._offsets[(topic, group)]
                if offset >= len(self._topics[topic]):
                    return
                message = self._topics[topic][offset]
                self._offsets[(topic, group)] = offset + 1
            n += 1
            yield message

    def size(self, topic: str) -> int:
        return len(self._topics[topic])


class KafkaStream:
    """Kafka (single-node KRaft in docker-compose ``full``)."""

    def __init__(self, bootstrap: str) -> None:
        from confluent_kafka import Producer

        self._bootstrap = bootstrap
        self._producer = Producer({"bootstrap.servers": bootstrap})

    def publish(self, topic: str, message: dict[str, Any]) -> None:
        self._producer.produce(topic, json.dumps(message).encode())
        self._producer.poll(0)

    def flush(self) -> None:
        self._producer.flush(30)

    def consume(self, topic: str, group: str, max_messages: int | None = None) -> Iterator[dict[str, Any]]:
        from confluent_kafka import Consumer

        self.flush()
        consumer = Consumer({"bootstrap.servers": self._bootstrap, "group.id": group,
                             "auto.offset.reset": "earliest"})
        consumer.subscribe([topic])
        n = 0
        try:
            while max_messages is None or n < max_messages:
                msg = consumer.poll(5.0)
                if msg is None:
                    return
                if msg.error():
                    raise RuntimeError(str(msg.error()))
                n += 1
                value = msg.value()
                if value is None:
                    continue
                yield json.loads(value)
        finally:
            consumer.close()
