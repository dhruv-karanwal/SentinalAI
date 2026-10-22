"""Shared types for loaders."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Rejection categories produced by loaders (normalizer categories live in
# app.ingestion.normalizer).
MALFORMED_RECORD = "malformed_record"
EMPTY_RECORD = "empty_record"

_RAW_TEXT_LIMIT = 500


class IngestionError(Exception):
    """The input as a whole cannot be read (missing file, bad structure...)."""


@dataclass(frozen=True)
class RawRecord:
    """One record as read from a file, before normalization.

    ``position`` is the 1-based line number (CSV, JSON Lines) or 1-based
    array index (JSON array). When the loader could not produce a usable
    record, ``data`` is ``None`` and ``error`` explains why.
    """

    source: str
    position: int
    data: dict[str, Any] | None
    error: str | None = None
    error_category: str | None = None
    raw_text: str | None = None


def truncate(text: str) -> str:
    if len(text) <= _RAW_TEXT_LIMIT:
        return text
    return text[:_RAW_TEXT_LIMIT] + "...[truncated]"


def resolve_input_file(path: str | Path) -> Path:
    """Check that ``path`` is an existing, non-empty, regular file."""
    file_path = Path(path)
    if not file_path.exists():
        raise IngestionError(f"input file not found: {file_path}")
    if not file_path.is_file():
        raise IngestionError(f"input path is not a file: {file_path}")
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise IngestionError(f"cannot access {file_path}: {exc}") from exc
    if size == 0:
        raise IngestionError(f"input file is empty: {file_path}")
    return file_path


def check_limit(limit: int | None) -> None:
    if limit is not None and limit < 1:
        raise ValueError(f"limit must be a positive integer, got {limit}")
