"""Load -> validate/normalize -> data-quality report, with optional outputs.

Outputs (when ``output_dir`` is given), named after the input file stem:

- ``<stem>.events.jsonl``   normalized ``SecurityEvent`` records
- ``<stem>.rejected.jsonl`` rejected records with reasons and raw data
- ``<stem>.quality.json``   data-quality report
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.ingestion.csv_loader import iter_csv_records
from app.ingestion.json_loader import iter_json_records, iter_jsonl_records
from app.ingestion.mappings import DatasetMapping
from app.ingestion.normalizer import Rejection, normalize_record
from app.ingestion.records import IngestionError, RawRecord
from app.schemas.event import SecurityEvent
from app.services.data_quality import DataQualityAccumulator

FORMATS = ("auto", "csv", "json", "jsonl")
_SUFFIX_FORMATS = {".csv": "csv", ".json": "json", ".jsonl": "jsonl", ".ndjson": "jsonl"}


@dataclass
class PipelineResult:
    report: dict[str, Any]
    events: list[SecurityEvent] = field(default_factory=list)
    rejections: list[Rejection] = field(default_factory=list)
    output_paths: dict[str, Path] = field(default_factory=dict)


def detect_format(path: Path, fmt: str = "auto") -> str:
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
    if fmt != "auto":
        return fmt
    try:
        return _SUFFIX_FORMATS[path.suffix.casefold()]
    except KeyError:
        raise IngestionError(
            f"cannot infer format from extension {path.suffix!r}; pass --format"
        ) from None


def load_records(
    path: Path, fmt: str, *, limit: int | None = None, encoding: str = "utf-8"
) -> Iterator[RawRecord]:
    resolved = detect_format(path, fmt)
    if resolved == "csv":
        return iter_csv_records(path, limit=limit, encoding=encoding)
    if resolved == "json":
        return iter_json_records(path, limit=limit, encoding=encoding)
    return iter_jsonl_records(path, limit=limit, encoding=encoding)


def run_pipeline(
    path: str | Path,
    mapping: DatasetMapping,
    *,
    fmt: str = "auto",
    limit: int | None = None,
    encoding: str = "utf-8",
    output_dir: str | Path | None = None,
    collect: bool = True,
) -> PipelineResult:
    """Run the Phase 1 pipeline over one file.

    ``collect=False`` keeps events/rejections out of memory (use it with
    ``output_dir`` for large inputs).
    """
    input_path = Path(path)
    resolved_format = detect_format(input_path, fmt)
    records = load_records(input_path, resolved_format, limit=limit, encoding=encoding)
    accumulator = DataQualityAccumulator()
    result = PipelineResult(report={})

    with ExitStack() as stack:
        events_out = rejected_out = None
        if output_dir is not None:
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            stem = input_path.stem
            result.output_paths = {
                "events": out / f"{stem}.events.jsonl",
                "rejected": out / f"{stem}.rejected.jsonl",
                "quality": out / f"{stem}.quality.json",
            }
            events_out = stack.enter_context(
                result.output_paths["events"].open("w", encoding="utf-8", newline="\n"))
            rejected_out = stack.enter_context(
                result.output_paths["rejected"].open("w", encoding="utf-8", newline="\n"))

        for record in records:
            outcome = normalize_record(record, mapping)
            accumulator.add(outcome)
            if isinstance(outcome, Rejection):
                if rejected_out is not None:
                    rejected_out.write(
                        json.dumps(outcome.to_dict(), default=str, ensure_ascii=False) + "\n")
                if collect:
                    result.rejections.append(outcome)
            else:
                if events_out is not None:
                    events_out.write(outcome.model_dump_json() + "\n")
                if collect:
                    result.events.append(outcome)

    result.report = {
        "source_file": input_path.name,
        "input_format": resolved_format,
        "mapping": mapping.name,
        "dataset_name": mapping.dataset_name,
        "row_limit": limit,
        **accumulator.report(),
    }
    if output_dir is not None:
        result.output_paths["quality"].write_text(
            json.dumps(result.report, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
            encoding="utf-8",
        )
    return result
