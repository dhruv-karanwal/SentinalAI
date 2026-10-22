"""JSON and JSON Lines loaders.

Supported layouts:

- a JSON array of objects: ``[{...}, {...}]``
- a JSON object holding such an array under ``"records"`` or ``"events"``
- JSON Lines (one object per line; blank lines are skipped)

A JSON document is parsed in one go (the standard library has no streaming
parser), so very large inputs should be supplied as JSON Lines, which is read
line by line.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from app.ingestion.records import (
    MALFORMED_RECORD,
    IngestionError,
    RawRecord,
    check_limit,
    resolve_input_file,
    truncate,
)

RECORD_CONTAINER_KEYS = ("records", "events")


def iter_json_records(
    path: str | Path, *, limit: int | None = None, encoding: str = "utf-8"
) -> Iterator[RawRecord]:
    file_path = resolve_input_file(path)
    check_limit(limit)
    items = _extract_items(_load_document(file_path, encoding), file_path.name)
    return _iter_items(items, file_path.name, limit)


def iter_jsonl_records(
    path: str | Path, *, limit: int | None = None, encoding: str = "utf-8"
) -> Iterator[RawRecord]:
    file_path = resolve_input_file(path)
    check_limit(limit)
    return _read_lines(file_path, limit, encoding)


def _load_document(file_path: Path, encoding: str) -> Any:
    source = file_path.name
    try:
        text = file_path.read_text(encoding=encoding)
    except UnicodeDecodeError as exc:
        raise IngestionError(
            f"{source}: cannot decode as {encoding} ({exc.reason})"
        ) from exc
    except OSError as exc:
        raise IngestionError(f"{source}: cannot read file: {exc}") from exc
    if not text.strip():
        raise IngestionError(f"{source}: file contains only whitespace")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        hint = ""
        if exc.msg == "Extra data":
            hint = " (if this is JSON Lines, use --format jsonl)"
        raise IngestionError(
            f"{source}: invalid JSON at line {exc.lineno} column {exc.colno}: "
            f"{exc.msg}{hint}"
        ) from exc


def _extract_items(document: Any, source: str) -> list[Any]:
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in RECORD_CONTAINER_KEYS:
            if isinstance(document.get(key), list):
                return list(document[key])
    raise IngestionError(
        f"{source}: expected a JSON array of records or an object with a "
        f"{' or '.join(repr(k) for k in RECORD_CONTAINER_KEYS)} array, "
        f"found {type(document).__name__}"
    )


def _iter_items(
    items: list[Any], source: str, limit: int | None
) -> Iterator[RawRecord]:
    selected = items if limit is None else items[:limit]
    for index, item in enumerate(selected, start=1):
        yield _to_record(item, source, index)


def _to_record(item: Any, source: str, position: int) -> RawRecord:
    if isinstance(item, dict):
        return RawRecord(source, position, item)
    return RawRecord(
        source, position, None,
        error=f"record must be a JSON object, found {type(item).__name__}",
        error_category=MALFORMED_RECORD,
        raw_text=truncate(json.dumps(item, default=str)),
    )


def _read_lines(
    file_path: Path, limit: int | None, encoding: str
) -> Iterator[RawRecord]:
    source = file_path.name
    count = 0
    try:
        with file_path.open("r", encoding=encoding) as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                if limit is not None and count >= limit:
                    break
                count += 1
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    yield RawRecord(
                        source, line_number, None,
                        error=f"invalid JSON: {exc.msg} at column {exc.colno}",
                        error_category=MALFORMED_RECORD,
                        raw_text=truncate(line.rstrip("\r\n")),
                    )
                    continue
                yield _to_record(item, source, line_number)
    except UnicodeDecodeError as exc:
        raise IngestionError(
            f"{source}: cannot decode as {encoding} ({exc.reason})"
        ) from exc
    except OSError as exc:
        raise IngestionError(f"{source}: cannot read file: {exc}") from exc
