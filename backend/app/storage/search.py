"""Full-text search over alerts: SQLite FTS5 (fallback) or OpenSearch (``full`` profile).

The index holds only what an analyst may search: alert id, scenario,
detector, rule name and the raw log lines. Never labels.
"""

from __future__ import annotations

import re
import sqlite3
import threading
from pathlib import Path
from typing import Any, Protocol

from app.schemas.alert import Alert


def alert_document(alert: Alert) -> dict[str, Any]:
    return {"alert_id": alert.alert_id, "scenario": alert.scenario, "detector": alert.detector.value,
            "rule_name": alert.rule_name or "", "ts": alert.timestamp.isoformat(),
            "text": "\n".join(alert.evidence.log_lines)}


class SearchIndex(Protocol):
    def index(self, alert: Alert) -> None: ...
    def flush(self) -> None: ...
    def search(self, query: str, *, scenario: str | None = None, limit: int = 50) -> list[dict[str, Any]]: ...


_TOKEN = re.compile(r"[\w.\-/:]+", re.UNICODE)


def fts_query(text: str) -> str:
    """User text -> a safe FTS5 query: every token quoted, implicit AND."""
    tokens = _TOKEN.findall(text)
    return " ".join('"' + t.replace('"', "") + '"' for t in tokens)


class SqliteFtsIndex:
    def __init__(self, path: str | Path = ":memory:") -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS alert_fts USING fts5("
                           "alert_id UNINDEXED, scenario UNINDEXED, detector UNINDEXED, ts UNINDEXED, "
                           "rule_name, text, tokenize = 'unicode61')")
        self._lock = threading.RLock()
        self._pending = 0

    def index(self, alert: Alert) -> None:
        d = alert_document(alert)
        with self._lock:
            self._conn.execute("DELETE FROM alert_fts WHERE alert_id = ?", (d["alert_id"],))
            self._conn.execute("INSERT INTO alert_fts VALUES (?, ?, ?, ?, ?, ?)",
                               (d["alert_id"], d["scenario"], d["detector"], d["ts"],
                                d["rule_name"], d["text"]))
            self._pending += 1
            if self._pending >= 1000:
                self.flush()

    def flush(self) -> None:
        with self._lock:
            self._conn.commit()
            self._pending = 0

    def search(self, query: str, *, scenario: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        q = fts_query(query)
        if not q:
            return []
        sql = ("SELECT alert_id, scenario, detector, ts, rule_name, "
               "snippet(alert_fts, 5, '[', ']', '...', 12) AS snippet FROM alert_fts "
               "WHERE alert_fts MATCH ?")
        params: list[Any] = [q]
        if scenario:
            sql += " AND scenario = ?"
            params.append(scenario)
        sql += " ORDER BY rank LIMIT ?"
        params.append(int(limit))
        self.flush()
        with self._lock:
            cur = self._conn.execute(sql, params)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]


class OpenSearchIndex:
    """OpenSearch single node (``full`` profile). Optional dependency ``opensearch-py``."""

    def __init__(self, url: str, index_name: str = "sentinel-alerts") -> None:
        from opensearchpy import OpenSearch

        self._client = OpenSearch(hosts=[url], timeout=30)
        self._index = index_name
        if not self._client.indices.exists(index=index_name):
            self._client.indices.create(index=index_name, body={"mappings": {"properties": {
                "alert_id": {"type": "keyword"}, "scenario": {"type": "keyword"},
                "detector": {"type": "keyword"}, "ts": {"type": "date"},
                "rule_name": {"type": "text"}, "text": {"type": "text"}}}})

    def index(self, alert: Alert) -> None:
        d = alert_document(alert)
        self._client.index(index=self._index, id=d["alert_id"], body=d)

    def flush(self) -> None:
        self._client.indices.refresh(index=self._index)

    def search(self, query: str, *, scenario: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        must: list[dict[str, Any]] = [{"multi_match": {"query": query, "fields": ["rule_name", "text"],
                                                       "operator": "and"}}]
        if scenario:
            must.append({"term": {"scenario": scenario}})
        res = self._client.search(index=self._index, body={"query": {"bool": {"must": must}},
                                                           "size": limit})
        return [{k: h["_source"][k] for k in ("alert_id", "scenario", "detector", "ts", "rule_name")}
                for h in res["hits"]["hits"]]
