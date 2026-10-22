"""Streaming CSV loader.

Rows are read one at a time with the standard library ``csv`` module, so
large files are never loaded into memory as a whole.

Header handling: names are stripped of surrounding whitespace (CICIDS2017
headers carry leading spaces such as ``" Destination Port"``), blank names
become ``column_<n>``, and repeated names get a ``.1``, ``.2`` ... suffix
(CICIDS2017 repeats ``Fwd Header Length``). Cell values are kept exactly as
read; whitespace in values is handled by the normalizer.
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path

from app.ingestion.records import (
    EMPTY_RECORD,
    MALFORMED_RECORD,
    IngestionError,
    RawRecord,
    check_limit,
    resolve_input_file,
    truncate,
)


def clean_header(names: list[str]) -> list[str]:
    cleaned: list[str] = []
    seen: dict[str, int] = {}
    for index, name in enumerate(names, start=1):
        base = name.strip() or f"column_{index}"
        count = seen.get(base, 0)
        seen[base] = count + 1
        cleaned.append(base if count == 0 else f"{base}.{count}")
    return cleaned


def iter_csv_records(
    path: str | Path,
    *,
    limit: int | None = None,
    encoding: str = "utf-8",
    delimiter: str = ",",
) -> Iterator[RawRecord]:
    """Yield one :class:`RawRecord` per data row.

    ``limit`` caps the number of data rows read (valid or not). File-level
    problems raise :class:`IngestionError`; row-level problems are yielded
    as records with ``error`` set so they can be reported, not dropped.
    """
    file_path = resolve_input_file(path)
    check_limit(limit)
    return _read(file_path, limit, encoding, delimiter)


def _read(
    file_path: Path, limit: int | None, encoding: str, delimiter: str
) -> Iterator[RawRecord]:
    source = file_path.name
    try:
        with file_path.open("r", encoding=encoding, newline="") as handle:
            reader = csv.reader(handle, delimiter=delimiter)
            try:
                header_row = next(reader)
            except StopIteration:
                raise IngestionError(f"{source}: no header row") from None
            if not any(name.strip() for name in header_row):
                raise IngestionError(f"{source}: header row is empty")
            header = clean_header(header_row)

            count = 0
            for row in reader:
                if limit is not None and count >= limit:
                    break
                count += 1
                line = reader.line_num
                raw_text = truncate(delimiter.join(row))
                if not any(value.strip() for value in row):
                    yield RawRecord(
                        source, line, None,
                        error="empty row",
                        error_category=EMPTY_RECORD,
                        raw_text=raw_text,
                    )
                elif len(row) != len(header):
                    yield RawRecord(
                        source, line, None,
                        error=f"expected {len(header)} fields, found {len(row)}",
                        error_category=MALFORMED_RECORD,
                        raw_text=raw_text,
                    )
                else:
                    yield RawRecord(source, line, dict(zip(header, row)))
    except UnicodeDecodeError as exc:
        raise IngestionError(
            f"{source}: cannot decode as {encoding} ({exc.reason} at byte "
            f"{exc.start}); try another encoding, e.g. --encoding cp1252 "
            "for the original CICIDS2017 CSV files"
        ) from exc
    except csv.Error as exc:
        raise IngestionError(f"{source}: malformed CSV: {exc}") from exc
    except OSError as exc:
        raise IngestionError(f"{source}: cannot read file: {exc}") from exc
