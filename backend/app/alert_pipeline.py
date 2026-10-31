"""Ingest one AIT-ADS scenario: alerts, ground truth and a quality report.

Reads ``<scenario>_wazuh.json`` and then ``<scenario>_aminer.json`` line by
line (the Wazuh files reach ~650 MB, so nothing is loaded whole), in the
same order the dataset authors used for alerts_csv, so the positional
event-label link holds. Outputs (when ``output_dir`` is given):

- ``<scenario>.alerts.jsonl``           normalized :class:`Alert` records
- ``<scenario>.alerts.rejected.jsonl``  rejected records with reasons
- ``<scenario>.ground_truth.jsonl``     one :class:`GroundTruth` per alert
- ``<scenario>.alerts.quality.json``    quality report
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from app.ingestion.alert_normalizer import normalize_ait_ads_record
from app.ingestion.ground_truth import AttackTimeline, EventLabelLinker, iter_event_label_rows
from app.ingestion.json_loader import iter_jsonl_records
from app.ingestion.mappings import (
    AIT_ADS_DATASET_NAME,
    AIT_ADS_EVENT_LABELS_DIR,
    AIT_ADS_LABELS_FILE,
    AitAdsFile,
)
from app.ingestion.normalizer import Rejection
from app.ingestion.records import RawRecord, check_limit, resolve_input_file
from app.schemas.alert import Alert, AlertSelection, GroundTruth
from app.services.alert_quality import AlertQualityAccumulator

_SCENARIO_RE = re.compile(r"[a-z0-9_]+")


@dataclass(frozen=True)
class AitAdsInputs:
    """Input files for one scenario. ``event_labels`` is optional."""

    scenario: str
    wazuh: Path
    aminer: Path
    labels: Path
    event_labels: Path | None = None

    @classmethod
    def from_layout(cls, data_dir: str | Path, scenario: str) -> AitAdsInputs:
        """Paths in the layout of the unpacked downloads (see mappings.py)."""
        if not _SCENARIO_RE.fullmatch(scenario):
            raise ValueError(f"invalid scenario name {scenario!r}; use [a-z0-9_]+")
        root = Path(data_dir)
        event_labels = root.joinpath(*AIT_ADS_EVENT_LABELS_DIR, f"{scenario}_alerts.txt")
        return cls(
            scenario=scenario,
            wazuh=root / f"{scenario}_wazuh.json",
            aminer=root / f"{scenario}_aminer.json",
            labels=root / AIT_ADS_LABELS_FILE,
            event_labels=event_labels if event_labels.is_file() else None,
        )


@dataclass
class AlertIngestResult:
    report: dict[str, Any]
    alerts: list[Alert] = field(default_factory=list)
    ground_truth: list[GroundTruth] = field(default_factory=list)
    rejections: list[Rejection] = field(default_factory=list)
    output_paths: dict[str, Path] = field(default_factory=dict)


def _records(inputs: AitAdsInputs, limit: int | None) -> Iterator[tuple[AitAdsFile, RawRecord]]:
    remaining = limit
    for kind, path in ((AitAdsFile.WAZUH, inputs.wazuh), (AitAdsFile.AMINER, inputs.aminer)):
        if remaining is not None and remaining <= 0:
            return
        for record in iter_jsonl_records(path, limit=remaining):
            yield kind, record
            if remaining is not None:
                remaining -= 1


def run_alert_ingest(
    inputs: AitAdsInputs,
    *,
    dataset_name: str | None = AIT_ADS_DATASET_NAME,
    limit: int | None = None,
    output_dir: str | Path | None = None,
    collect: bool = True,
) -> AlertIngestResult:
    """Run the alert ingest for one scenario.

    ``collect=False`` keeps records out of memory (use it with
    ``output_dir`` on the real files).
    """
    check_limit(limit)
    for path in (inputs.wazuh, inputs.aminer, inputs.labels):
        resolve_input_file(path)
    timeline = AttackTimeline.from_labels_csv(inputs.labels, inputs.scenario)
    linker = (EventLabelLinker(iter_event_label_rows(inputs.event_labels))
              if inputs.event_labels is not None else None)
    label_source = inputs.event_labels.name if inputs.event_labels is not None else None
    accumulator = AlertQualityAccumulator(timeline)
    result = AlertIngestResult(report={})

    with ExitStack() as stack:
        outputs: dict[str, IO[str]] = {}
        if output_dir is not None:
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            stem = inputs.scenario
            result.output_paths = {
                "alerts": out / f"{stem}.alerts.jsonl",
                "rejected": out / f"{stem}.alerts.rejected.jsonl",
                "ground_truth": out / f"{stem}.ground_truth.jsonl",
                "quality": out / f"{stem}.alerts.quality.json",
            }
            for name in ("alerts", "rejected", "ground_truth"):
                outputs[name] = stack.enter_context(
                    result.output_paths[name].open("w", encoding="utf-8", newline="\n"))

        for kind, record in _records(inputs, limit):
            outcome = normalize_ait_ads_record(
                record, kind, scenario=inputs.scenario, dataset_name=dataset_name)
            if isinstance(outcome, Rejection):
                if linker is not None:
                    linker.link(None)
                accumulator.add_rejection(outcome)
                if outputs:
                    outputs["rejected"].write(
                        json.dumps(outcome.to_dict(), default=str, ensure_ascii=False) + "\n")
                if collect:
                    result.rejections.append(outcome)
                continue

            row = linker.link(outcome) if linker is not None else None
            truth = GroundTruth(
                alert_id=outcome.alert_id,
                scenario=inputs.scenario,
                time_label=timeline.label_at(outcome.timestamp),
                event_label=row.event_label if row is not None else None,
                event_label_available=row is not None,
                event_label_source=f"{label_source}:{row.position}" if row is not None else None,
            )
            accumulator.add_alert(outcome, truth, row.time_label if row is not None else None)
            if outputs:
                outputs["alerts"].write(outcome.model_dump_json() + "\n")
                outputs["ground_truth"].write(truth.model_dump_json() + "\n")
            if collect:
                result.alerts.append(outcome)
                result.ground_truth.append(truth)

    if linker is not None and limit is None:
        linker.finish()
    result.report = {
        "scenario": inputs.scenario,
        "dataset_name": dataset_name,
        "inputs": {
            "wazuh": inputs.wazuh.name,
            "aminer": inputs.aminer.name,
            "labels": inputs.labels.name,
            "event_labels": label_source,
        },
        "row_limit": limit,
        **accumulator.report(linker, label_source),
    }
    if output_dir is not None:
        result.output_paths["quality"].write_text(
            json.dumps(result.report, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
            encoding="utf-8",
        )
    return result


def iter_alert_file(path: str | Path, selection: AlertSelection | None = None) -> Iterator[Alert]:
    """Stream alerts back from ``<scenario>.alerts.jsonl``.

    ``selection`` applies the documented exclusions (training mode, Suricata
    duplicates, aggregates); ``None`` yields every alert.
    """
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            alert = Alert.model_validate_json(line)
            if selection is None or selection.accepts(alert):
                yield alert
