"""Relational storage behind one small interface: SQLite (fallback) or PostgreSQL.

Why two backends: tests, the study and the demo must run without Docker, so
SQLite (stdlib) is the in-process fallback; PostgreSQL (+ pgvector) is the
production store in the docker-compose ``lite``/``full`` profiles. Both run
the *same* versioned migrations in ``migrations/<area>/NNNN_name.sql``,
written once with a few dialect placeholders:

- ``{{ID}}``    -> ``BIGSERIAL PRIMARY KEY`` | ``INTEGER PRIMARY KEY AUTOINCREMENT``
- ``{{JSON}}``  -> ``JSONB`` | ``TEXT`` (JSON text)
- ``{{TS}}``    -> ``TIMESTAMPTZ`` | ``TEXT`` (ISO 8601 UTC)
- ``{{S}}``     -> the schema prefix of the area (``truth.`` in PostgreSQL;
                   empty in SQLite, where the truth area is its own file)

Ground truth is a separate *area*: in SQLite a separate database file, in
PostgreSQL the ``truth`` schema, which the ``sentinel_agent`` role cannot
read. Agent tool paths only ever receive a core-area :class:`Database`.

Queries are written with ``?`` placeholders; the PostgreSQL backend rewrites
them to ``%s``. Applied migrations are recorded in ``schema_migrations``
(per area) with their sha256, and a changed migration file is an error.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any, Protocol

AREAS = ("core", "truth")

_DIALECT = {
    "sqlite": {"{{ID}}": "INTEGER PRIMARY KEY AUTOINCREMENT", "{{JSON}}": "TEXT", "{{TS}}": "TEXT"},
    "postgres": {"{{ID}}": "BIGSERIAL PRIMARY KEY", "{{JSON}}": "JSONB", "{{TS}}": "TIMESTAMPTZ"},
}


class MigrationError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def migration_files(area: str) -> list[tuple[str, str]]:
    """(name, sql text) of an area's migrations, in version order."""
    if area not in AREAS:
        raise ValueError(f"unknown storage area {area!r}")
    folder = resources.files("app.storage") / "migrations" / area
    names = sorted(p.name for p in folder.iterdir() if p.name.endswith(".sql"))
    if [n[:4] for n in names] != [f"{i:04d}" for i in range(1, len(names) + 1)]:
        raise MigrationError(f"{area} migrations must be numbered 0001.. without gaps: {names}")
    return [(n, (folder / n).read_text(encoding="utf-8")) for n in names]


def render(sql: str, dialect: str, area: str) -> str:
    out = sql
    for key, value in _DIALECT[dialect].items():
        out = out.replace(key, value)
    prefix = "truth." if (dialect == "postgres" and area == "truth") else ""
    out = out.replace("{{S}}", prefix)
    left = re.findall(r"\{\{\w+\}\}", out)
    if left:
        raise MigrationError(f"unknown placeholders {sorted(set(left))}")
    return out


def _split(sql: str) -> list[str]:
    """Statements of a migration (no semicolons inside string literals are used)."""
    lines = [ln for ln in sql.splitlines() if not ln.strip().startswith("--")]
    return [s.strip() for s in "\n".join(lines).split(";") if s.strip()]


class Database(Protocol):
    dialect: str
    area: str

    def execute(self, sql: str, params: Sequence[Any] = ()) -> None: ...
    def insert(self, sql: str, params: Sequence[Any] = ()) -> int: ...
    def query(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]: ...
    def migrate(self) -> list[str]: ...
    def transaction(self) -> Any: ...
    def close(self) -> None: ...


def encode_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def decode_json(value: Any) -> Any:
    """JSON columns come back as text from SQLite and as objects from PostgreSQL."""
    return json.loads(value) if isinstance(value, str) else value


class _Migrating:
    dialect: str
    area: str

    def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        raise NotImplementedError

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        raise NotImplementedError

    def _script(self, statements: Sequence[str]) -> None:
        for stmt in statements:
            self.execute(stmt)

    def migrate(self) -> list[str]:
        """Apply pending migrations of this area; returns the names applied now."""
        table = render("{{S}}schema_migrations", self.dialect, self.area)
        if self.dialect == "postgres" and self.area == "truth":
            self.execute("CREATE SCHEMA IF NOT EXISTS truth")
        self.execute(f"CREATE TABLE IF NOT EXISTS {table} (name TEXT PRIMARY KEY, "
                     "sha256 TEXT NOT NULL, applied_utc TEXT NOT NULL)")
        done = {r["name"]: r["sha256"] for r in self.query(f"SELECT name, sha256 FROM {table}")}
        applied: list[str] = []
        for name, text in migration_files(self.area):
            digest = hashlib.sha256(text.encode()).hexdigest()
            if name in done:
                if done[name] != digest:
                    raise MigrationError(f"migration {self.area}/{name} changed after it was applied")
                continue
            self._script(_split(render(text, self.dialect, self.area)))
            self.execute(f"INSERT INTO {table} (name, sha256, applied_utc) VALUES (?, ?, ?)",
                         (name, digest, utc_now()))
            applied.append(name)
        return applied


class SqliteDatabase(_Migrating):
    """In-process fallback. One connection, serialized by a lock (FastAPI threads)."""

    dialect = "sqlite"

    def __init__(self, path: str | Path, area: str = "core") -> None:
        if area not in AREAS:
            raise ValueError(f"unknown storage area {area!r}")
        self.area = area
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")
        self._lock = threading.RLock()

    def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        with self._lock:
            self._conn.execute(sql, tuple(params))

    def insert(self, sql: str, params: Sequence[Any] = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            return int(cur.lastrowid or 0)

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, tuple(params)).fetchall()]

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                yield
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def close(self) -> None:
        self._conn.close()


class PostgresDatabase(_Migrating):
    """PostgreSQL via psycopg 3 (optional dependency, imported lazily).

    ``role``: if set, every connection runs ``SET ROLE`` to it, which is how
    agent tool paths get the ``sentinel_agent`` role (no access to ``truth``).
    """

    dialect = "postgres"

    def __init__(self, dsn: str, area: str = "core", role: str | None = None) -> None:
        import psycopg
        from psycopg.rows import dict_row

        if area not in AREAS:
            raise ValueError(f"unknown storage area {area!r}")
        self.area = area
        self._conn = psycopg.connect(dsn, autocommit=True, row_factory=dict_row)
        if role is not None:
            if not re.fullmatch(r"[a-z_][a-z0-9_]*", role):
                raise ValueError("invalid role name")
            self._conn.execute(f"SET ROLE {role}")
        self._lock = threading.RLock()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock, self._conn.transaction():
            yield

    @staticmethod
    def _sql(sql: str) -> str:
        return sql.replace("%", "%%").replace("?", "%s")

    def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        with self._lock:
            self._conn.execute(self._sql(sql), tuple(params))

    def insert(self, sql: str, params: Sequence[Any] = ()) -> int:
        with self._lock:
            cur = self._conn.execute(self._sql(sql + " RETURNING id"), tuple(params))
            row = cur.fetchone()
            return int(row["id"]) if row else 0

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(self._sql(sql), tuple(params))
            return [dict(r) for r in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()
