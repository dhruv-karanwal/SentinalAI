"""Normalize raw detector records into :class:`Alert`.

Same contract as the event normalizer: each record becomes an ``Alert`` or a
:class:`Rejection` listing every problem found, and invalid values are never
coerced. Where fields live is described by an :class:`AlertMapping`; this
module only knows how to read and validate them.

Transformations applied (and only these):

- ISO 8601 timestamps with an offset, or Unix epoch seconds -> aware UTC
  (naive ISO timestamps are rejected; nothing is assumed)
- integer or integer-string severities -> ``int`` (no rescaling)
- rule id parts -> one string joined with ``":"``
- a single log line string -> a one-element list
- AMiner alerts get ``alert_id = "aminer-" + sha256(scenario, file, line,
  canonical JSON content)[:32]`` and ``alert_id_derived=True``, because the
  records carry no id of their own
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from app.ingestion.mappings import AitAdsFile, AlertMapping, route_ait_ads_record
from app.ingestion.normalizer import (
    INVALID_IP,
    INVALID_SEVERITY,
    INVALID_TIMESTAMP,
    INVALID_VALUE,
    FieldError,
    Rejection,
)
from app.ingestion.records import MALFORMED_RECORD, RawRecord
from app.schemas.alert import DETECTOR_TYPES, Alert, AlertEvidence, AlertKind

MISSING_FIELD = "missing_field"

_MISSING = object()


def get_path(data: Any, path: str) -> Any:
    """Value at a dotted path, or ``_MISSING``. ``None`` values count as missing."""
    current = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return _MISSING if current is None else current


def parse_alert_time(value: Any, *, epoch: bool) -> datetime:
    if epoch:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"expected epoch seconds, got {value!r}")
        if not math.isfinite(value):
            raise ValueError(f"timestamp {value!r} is not finite")
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError(f"epoch timestamp {value!r} out of range") from exc
    if not isinstance(value, str):
        raise ValueError(f"expected an ISO 8601 string, got {value!r}")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(f"unrecognized timestamp {value!r}; expected ISO 8601") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"timestamp {value!r} has no timezone; none is assumed")
    return parsed.astimezone(timezone.utc)


def derive_alert_id(scenario: str, record: RawRecord, data: dict[str, Any]) -> str:
    content = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(
        "\n".join((scenario, record.source, str(record.position), content)).encode("utf-8")
    ).hexdigest()
    return f"aminer-{digest[:32]}"


def normalize_ait_ads_record(
    record: RawRecord,
    kind: AitAdsFile,
    *,
    scenario: str,
    dataset_name: str | None = None,
) -> Alert | Rejection:
    if record.data is None or record.error is not None:
        error = FieldError("record", record.error_category or MALFORMED_RECORD,
                           record.error or "malformed record")
        return Rejection(record.source, record.position, (error,), record.data, record.raw_text)
    mapping, duplicate = route_ait_ads_record(kind, record.data)
    return _AlertNormalizer(record, record.data, mapping, scenario).run(
        duplicate_of_suricata=duplicate, dataset_name=dataset_name)


class _AlertNormalizer:
    def __init__(self, record: RawRecord, data: dict[str, Any], mapping: AlertMapping, scenario: str):
        self.record = record
        self.data = data
        self.mapping = mapping
        self.scenario = scenario
        self.errors: list[FieldError] = []

    def error(self, field: str, category: str, message: str) -> None:
        self.errors.append(FieldError(field, category, message))

    def text(self, field: str, path: str | None, *, required: bool = False) -> str | None:
        value = _MISSING if path is None else get_path(self.data, path)
        if value is _MISSING:
            if required:
                self.error(field, MISSING_FIELD, f"{field}: '{path}' is missing")
            return None
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            self.error(field, INVALID_VALUE, f"{field}: '{path}' must be a string, got {value!r}")
            return None
        text = str(value).strip()
        if not text:
            if required:
                self.error(field, MISSING_FIELD, f"{field}: '{path}' is empty")
            return None
        return text

    def strings(self, field: str, path: str | None) -> list[str]:
        value = _MISSING if path is None else get_path(self.data, path)
        if value is _MISSING:
            return []
        items = [value] if isinstance(value, str) else value
        if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
            self.error(field, INVALID_VALUE, f"{field}: '{path}' must be a string or list of strings")
            return []
        return list(items)

    def run(self, *, duplicate_of_suricata: bool, dataset_name: str | None) -> Alert | Rejection:
        m = self.mapping
        timestamp = self._timestamp()
        rule_id = self._rule_id()
        rule_name = self.text("rule_name", m.rule_name_path)
        severity = self._severity()
        host_ip = self._host_ip()
        training_mode = self._training_mode()
        aggregate = any(key in self.data for key in m.aggregate_keys)
        log_lines = self.strings("log_lines", m.log_lines_path)
        log_paths = self.strings("log_paths", m.log_paths_path)
        log_timestamps = self._log_timestamps()

        if m.alert_id_path is not None:
            alert_id = self.text("alert_id", m.alert_id_path, required=True)
            derived = False
        else:
            alert_id = derive_alert_id(self.scenario, self.record, self.data)
            derived = True

        if self.errors or timestamp is None or alert_id is None:
            return self._reject()
        try:
            return Alert(
                alert_id=alert_id,
                alert_id_derived=derived,
                scenario=self.scenario,
                detector=m.detector,
                detector_type=DETECTOR_TYPES[m.detector],
                kind=AlertKind.AGGREGATE if aggregate else AlertKind.EVENT,
                timestamp=timestamp,
                rule_id=rule_id,
                rule_name=rule_name,
                severity=severity,
                host_ip=host_ip,
                evidence=AlertEvidence(
                    source_alert_id=None if derived else alert_id,
                    log_lines=[] if aggregate else log_lines,
                    log_paths=log_paths,
                    log_timestamps=log_timestamps,
                ),
                training_mode=training_mode,
                duplicate_of_suricata=duplicate_of_suricata,
                raw_alert=self.data,
                dataset_name=dataset_name,
                source_file=self.record.source,
                source_line=self.record.position,
            )
        except ValidationError as exc:
            for item in exc.errors():
                self.error("record", INVALID_VALUE, str(item["msg"]))
            return self._reject()

    def _reject(self) -> Rejection:
        if not self.errors:  # pragma: no cover - guarded by the callers above
            self.error("record", INVALID_VALUE, "record could not be normalized")
        return Rejection(self.record.source, self.record.position, tuple(self.errors), self.data)

    def _timestamp(self) -> datetime | None:
        m = self.mapping
        value = get_path(self.data, m.timestamp_path)
        if m.timestamp_last and isinstance(value, list):
            value = value[-1] if value else _MISSING
        if value is _MISSING:
            self.error("timestamp", MISSING_FIELD, f"timestamp: '{m.timestamp_path}' is missing")
            return None
        try:
            return parse_alert_time(value, epoch=m.timestamp_epoch)
        except ValueError as exc:
            self.error("timestamp", INVALID_TIMESTAMP, f"timestamp: {exc}")
            return None

    def _rule_id(self) -> str | None:
        parts = [self.text("rule_id", path) for path in self.mapping.rule_id_paths]
        present = [p for p in parts if p is not None]
        if not present:
            return None
        if len(present) != len(parts):
            self.error("rule_id", INVALID_VALUE,
                       f"rule_id: only some of {', '.join(self.mapping.rule_id_paths)} are present")
            return None
        return ":".join(present)

    def _severity(self) -> int | None:
        path = self.mapping.severity_path
        value = _MISSING if path is None else get_path(self.data, path)
        if value is _MISSING:
            return None
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lstrip("+-").isdigit():
            return int(value.strip())
        self.error("severity", INVALID_SEVERITY, f"severity: '{path}' must be an integer, got {value!r}")
        return None

    def _host_ip(self) -> Any:
        path = self.mapping.host_ip_path
        value = self.text("host_ip", path)
        if value is None:
            return None
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            self.error("host_ip", INVALID_IP, f"host_ip: {value!r} is not an IP address")
            return None

    def _training_mode(self) -> bool:
        path = self.mapping.training_mode_path
        if path is None:
            return False
        value = get_path(self.data, path)
        if value is _MISSING:
            self.error("training_mode", MISSING_FIELD, f"training_mode: '{path}' is missing")
            return False
        if not isinstance(value, bool):
            self.error("training_mode", INVALID_VALUE,
                       f"training_mode: '{path}' must be true or false, got {value!r}")
            return False
        return value

    def _log_timestamps(self) -> list[datetime]:
        path = self.mapping.log_timestamps_path
        value = _MISSING if path is None else get_path(self.data, path)
        if value is _MISSING:
            return []
        if not isinstance(value, list):
            self.error("log_timestamps", INVALID_TIMESTAMP, f"log_timestamps: '{path}' must be a list")
            return []
        result = []
        for item in value:
            try:
                result.append(parse_alert_time(item, epoch=self.mapping.timestamp_epoch))
            except ValueError as exc:
                self.error("log_timestamps", INVALID_TIMESTAMP, f"log_timestamps: {exc}")
                return []
        return result
