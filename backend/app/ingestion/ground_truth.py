"""AIT-ADS ground truth: attack-phase intervals and per-alert event labels.

Ground truth is a separate layer. It is joined to alerts by ``alert_id`` and
written to its own file, never into :class:`Alert`.

Time labels (``labels.csv``)
    One row per (scenario, attack phase) with start/end in Unix seconds. The
    rows are not in time order, so they are sorted explicitly. Intervals are
    half-open, ``[start, end)``: consecutive phases share a boundary second,
    and the dataset authors' own labels assign that second to the later
    phase (checked against alerts_csv on two scenarios). Overlapping
    intervals would make the label ambiguous and abort the run.

Event labels (``alerts_csv/<scenario>_alerts.txt``)
    Written by the dataset authors with one row per input record: every
    Wazuh line, then every AMiner line, in file order. There is no alert id,
    so rows are linked by position and each link is verified on
    (whole-second time, name, ip). At the first mismatch linking stops for
    the rest of the scenario: after one misaligned row every later
    positional link would be a guess.
"""

from __future__ import annotations

import bisect
import math
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from app.ingestion.alert_normalizer import parse_alert_time
from app.ingestion.csv_loader import iter_csv_records
from app.ingestion.mappings import (
    AIT_ADS_BENIGN_TIME_LABEL,
    AIT_ADS_EVENT_LABELS_COLUMNS,
    AIT_ADS_LABELS_COLUMNS,
    AIT_ADS_NO_EVENT_LABEL,
    SURICATA_DESCRIPTION_PREFIX,
    WAZUH_CSV_NAME_PREFIX,
)
from app.ingestion.records import IngestionError, resolve_input_file
from app.schemas.alert import Alert, Detector


@dataclass(frozen=True)
class AttackInterval:
    attack: str
    start: datetime
    end: datetime


class AttackTimeline:
    """Sorted, non-overlapping attack-phase intervals of one scenario."""

    def __init__(self, scenario: str, intervals: list[AttackInterval]):
        self.scenario = scenario
        self.intervals = sorted(intervals, key=lambda i: (i.start, i.end))
        for before, after in zip(self.intervals, self.intervals[1:]):
            if after.start < before.end:
                raise IngestionError(
                    f"{scenario}: attack intervals overlap: {before.attack} "
                    f"[{before.start.isoformat()}, {before.end.isoformat()}) and "
                    f"{after.attack} starting {after.start.isoformat()}")
        self._starts = [i.start for i in self.intervals]

    @classmethod
    def from_labels_csv(cls, path: str | Path, scenario: str) -> AttackTimeline:
        intervals: list[AttackInterval] = []
        source = Path(path).name
        for record in iter_csv_records(path):
            if record.data is None:
                raise IngestionError(f"{source} line {record.position}: {record.error}")
            if tuple(record.data) != AIT_ADS_LABELS_COLUMNS:
                raise IngestionError(
                    f"{source}: expected columns {', '.join(AIT_ADS_LABELS_COLUMNS)}, "
                    f"found {', '.join(record.data)}")
            if (record.data["scenario"] or "").strip() != scenario:
                continue
            attack = (record.data["attack"] or "").strip()
            if not attack:
                raise IngestionError(f"{source} line {record.position}: empty attack name")
            start = _epoch(record.data["start"], "start", source, record.position)
            end = _epoch(record.data["end"], "end", source, record.position)
            if end < start:
                raise IngestionError(f"{source} line {record.position}: end before start")
            intervals.append(AttackInterval(attack, start, end))
        if not intervals:
            raise IngestionError(f"{source}: no attack intervals for scenario {scenario!r}")
        return cls(scenario, intervals)

    def label_at(self, when: datetime) -> str:
        index = bisect.bisect_right(self._starts, when) - 1
        if index >= 0 and when < self.intervals[index].end:
            return self.intervals[index].attack
        return AIT_ADS_BENIGN_TIME_LABEL


def _epoch(value: str | None, column: str, source: str, line: int) -> datetime:
    try:
        seconds = float((value or "").strip())
    except ValueError:
        seconds = math.nan
    if not math.isfinite(seconds):
        raise IngestionError(f"{source} line {line}: {column} {value!r} is not epoch seconds")
    return parse_alert_time(seconds, epoch=True)


@dataclass(frozen=True)
class EventLabelRow:
    position: int  # 1-based line number in the file (the header is line 1)
    time: int
    name: str
    ip: str
    time_label: str
    event_label: str | None  # None: the dataset's "-" (no labelled event)


def iter_event_label_rows(path: str | Path, encoding: str = "utf-8") -> Iterator[EventLabelRow]:
    """Stream rows of an alerts_csv file.

    The name column is written unquoted and can contain commas, so the four
    fixed fields are split off from the right and the first from the left.
    """
    file_path = resolve_input_file(path)
    source = file_path.name
    n_fixed_right = len(AIT_ADS_EVENT_LABELS_COLUMNS) - 2
    with file_path.open("r", encoding=encoding, newline="") as handle:
        header = handle.readline().rstrip("\r\n")
        if tuple(header.split(",")) != AIT_ADS_EVENT_LABELS_COLUMNS:
            raise IngestionError(
                f"{source}: unexpected header {header!r}; expected "
                f"{','.join(AIT_ADS_EVENT_LABELS_COLUMNS)}")
        for position, line in enumerate(handle, start=2):
            parts = line.rstrip("\r\n").split(",")
            if len(parts) < len(AIT_ADS_EVENT_LABELS_COLUMNS):
                raise IngestionError(f"{source} line {position}: too few fields")
            time_text, name = parts[0], ",".join(parts[1:-n_fixed_right])
            ip, _host, _short, time_label, event_label = parts[-n_fixed_right:]
            if not time_text.isdigit():
                raise IngestionError(f"{source} line {position}: time {time_text!r} is not integer seconds")
            yield EventLabelRow(
                position=position,
                time=int(time_text),
                name=name,
                ip=ip,
                time_label=time_label,
                event_label=None if event_label == AIT_ADS_NO_EVENT_LABEL else event_label,
            )


def csv_link_key(alert: Alert) -> tuple[int, str, str]:
    """(whole-second time, name, ip) as the dataset authors wrote them for this alert."""
    raw = alert.raw_alert
    if alert.detector is Detector.AMINER:
        seconds = raw["LogData"]["DetectionTimestamp"][-1]
        name = str(raw["AnalysisComponent"]["AnalysisComponentName"])
        ip = str(raw["AMiner"]["ID"])
    else:
        seconds = alert.timestamp.timestamp()
        description = str(raw["rule"]["description"])
        name = (description if description.startswith(SURICATA_DESCRIPTION_PREFIX)
                else WAZUH_CSV_NAME_PREFIX + description)
        ip = str(raw["agent"]["ip"])
    return math.floor(seconds), name, ip


class LinkStatus(StrEnum):
    NOT_PROVIDED = "not_provided"
    LINKED = "linked"              # every row so far matched
    MISMATCH = "mismatch"          # a row did not match; linking stopped there
    EXHAUSTED = "exhausted"        # more records than rows
    LEFTOVER_ROWS = "leftover_rows"  # more rows than records


class EventLabelLinker:
    """Pairs input records with alerts_csv rows by position, verifying each pair."""

    def __init__(self, rows: Iterator[EventLabelRow]):
        self._rows = rows
        self.status = LinkStatus.LINKED
        self.rows_consumed = 0
        self.left_over = 0
        self.mismatch_position: int | None = None

    def link(self, alert: Alert | None) -> EventLabelRow | None:
        """Consume the row for the next input record.

        ``alert`` is ``None`` for a rejected record: its row is consumed but
        not used. Returns the verified row, or ``None``.
        """
        if self.status is not LinkStatus.LINKED:
            return None
        row = next(self._rows, None)
        if row is None:
            self.status = LinkStatus.EXHAUSTED
            return None
        self.rows_consumed += 1
        if alert is None:
            return None
        if csv_link_key(alert) != (row.time, row.name, row.ip):
            self.status = LinkStatus.MISMATCH
            self.mismatch_position = row.position
            return None
        return row

    def finish(self) -> int:
        """Count rows never consumed (only meaningful after the full input)."""
        if self.status is LinkStatus.LINKED:
            self.left_over = sum(1 for _ in self._rows)
            if self.left_over:
                self.status = LinkStatus.LEFTOVER_ROWS
        return self.left_over
