"""Normalize loaded records into :class:`SecurityEvent`.

Each record either becomes a ``SecurityEvent`` or a :class:`Rejection` that
lists every problem found. Invalid values are never coerced into
valid-looking ones: a bad timestamp, IP, port or feature value rejects the
record, and the original data travels with the rejection.

Transformations applied (and only these):

- strings are stripped; configured missing tokens ("", "NaN", "null", "N/A")
  become ``None``
- timestamps -> timezone-aware UTC (see ``DatasetMapping``)
- IANA protocol numbers -> names for well-known protocols (6 -> "tcp");
  other numbers are kept as their decimal string; names are lower-cased
- numeric feature strings -> int/float; "Infinity"/"-Infinity" -> +/-inf
  (CICFlowMeter emits these on division by zero)
- integer labels/ids -> strings
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from app.ingestion.mappings import DatasetMapping, feature_name, normalize_column_name
from app.ingestion.records import MALFORMED_RECORD, EMPTY_RECORD, RawRecord
from app.schemas.event import FeatureValue, SecurityEvent

INVALID_TIMESTAMP = "invalid_timestamp"
INVALID_IP = "invalid_ip"
INVALID_PORT = "invalid_port"
INVALID_PROTOCOL = "invalid_protocol"
INVALID_SEVERITY = "invalid_severity"
INVALID_SOURCE_TYPE = "invalid_source_type"
INVALID_FEATURE = "invalid_feature"
INVALID_VALUE = "invalid_value"

_FIELD_CATEGORIES = {
    "timestamp": INVALID_TIMESTAMP,
    "source_ip": INVALID_IP,
    "destination_ip": INVALID_IP,
    "source_port": INVALID_PORT,
    "destination_port": INVALID_PORT,
    "protocol": INVALID_PROTOCOL,
    "severity": INVALID_SEVERITY,
    "source_type": INVALID_SOURCE_TYPE,
    "features": INVALID_FEATURE,
}

IANA_PROTOCOL_NAMES = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "ipv6-icmp",
    132: "sctp",
}

_INT_RE = re.compile(r"[+-]?\d+")
_FLOAT_RE = re.compile(r"[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?")
_INFINITY = {"infinity": math.inf, "+infinity": math.inf, "inf": math.inf,
             "+inf": math.inf, "-infinity": -math.inf, "-inf": -math.inf}


@dataclass(frozen=True)
class FieldError:
    field: str
    category: str
    message: str


@dataclass(frozen=True)
class Rejection:
    """A record that could not be normalized, with every reason found."""

    source: str
    position: int
    errors: tuple[FieldError, ...]
    raw_event: dict[str, Any] | None
    raw_text: str | None = None

    @property
    def category(self) -> str:
        """Primary rejection reason (the first error found)."""
        return self.errors[0].category

    @property
    def fields(self) -> set[str]:
        return {error.field for error in self.errors}

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_file": self.source,
            "source_position": self.position,
            "category": self.category,
            "errors": [
                {"field": e.field, "category": e.category, "message": e.message}
                for e in self.errors
            ],
            "raw_event": self.raw_event,
            "raw_text": self.raw_text,
        }


def parse_number(value: Any) -> int | float:
    """Parse a numeric value without accepting look-alikes ("1_0", "0x1")."""
    if isinstance(value, bool):
        raise ValueError(f"expected a number, got boolean {value!r}")
    if isinstance(value, (int, float)):
        return value
    if not isinstance(value, str):
        raise ValueError(f"expected a number, got {type(value).__name__}")
    text = value.strip()
    if text.casefold() in _INFINITY:
        return _INFINITY[text.casefold()]
    if _INT_RE.fullmatch(text):
        return int(text)
    if _FLOAT_RE.fullmatch(text):
        return float(text)
    raise ValueError(f"expected a number, got {value!r}")


def parse_timestamp(value: Any, mapping: DatasetMapping) -> tuple[datetime, bool]:
    """Return an aware UTC datetime and whether a timezone was assumed."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not mapping.accept_epoch_seconds:
            raise ValueError(f"numeric timestamp {value!r} is not accepted")
        if not math.isfinite(value):
            raise ValueError(f"timestamp {value!r} is not finite")
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc), False
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError(f"epoch timestamp {value!r} out of range") from exc
    if not isinstance(value, str):
        raise ValueError(f"unsupported timestamp type {type(value).__name__}")

    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        for fmt in mapping.timestamp_formats:
            try:
                parsed = datetime.strptime(value, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        expected = ["ISO 8601", *mapping.timestamp_formats]
        raise ValueError(
            f"unrecognized timestamp {value!r}; expected one of: "
            + ", ".join(expected)
        )

    if parsed.tzinfo is not None and parsed.utcoffset() is not None:
        return parsed.astimezone(timezone.utc), False
    if mapping.naive_timezone is None:
        raise ValueError(
            f"timestamp {value!r} has no timezone and the mapping does not "
            "configure one (use --assume-timezone to state an assumption)"
        )
    return parsed.replace(tzinfo=mapping.naive_timezone).astimezone(timezone.utc), True


def normalize_protocol(value: Any) -> str:
    if isinstance(value, bool):
        raise ValueError(f"invalid protocol {value!r}")
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        number = int(value)
        if not 0 <= number <= 255:
            raise ValueError(f"protocol number {number} outside 0-255")
        return IANA_PROTOCOL_NAMES.get(number, str(number))
    if isinstance(value, str):
        return value.casefold()
    raise ValueError(f"invalid protocol {value!r}")


def normalize_record(record: RawRecord, mapping: DatasetMapping) -> SecurityEvent | Rejection:
    if record.data is None or record.error is not None:
        error = FieldError(
            "record",
            record.error_category or MALFORMED_RECORD,
            record.error or "malformed record",
        )
        return Rejection(record.source, record.position, (error,), record.data, record.raw_text)
    return _Normalizer(record, record.data, mapping).run()


class _Normalizer:
    def __init__(self, record: RawRecord, data: dict[str, Any], mapping: DatasetMapping):
        self.record = record
        self.data = data
        self.mapping = mapping
        self.columns: dict[str, str] = {}
        for key in data:
            self.columns.setdefault(normalize_column_name(str(key)), key)
        self.consumed: set[str] = set()
        self.errors: list[FieldError] = []
        self.metadata: dict[str, Any] = {
            "source_file": record.source,
            "source_position": record.position,
        }

    def clean(self, value: Any) -> Any:
        if isinstance(value, str):
            text = value.strip()
            return None if text.casefold() in self.mapping.missing_tokens else text
        if isinstance(value, float) and math.isnan(value):
            return None
        return value

    def take(self, aliases: tuple[str, ...]) -> Any:
        for alias in aliases:
            key = self.columns.get(alias)
            if key is not None:
                self.consumed.add(key)
                return self.clean(self.data[key])
        return None

    def reject(self, *errors: FieldError) -> Rejection:
        return Rejection(self.record.source, self.record.position, tuple(errors), self.data)

    def run(self) -> SecurityEvent | Rejection:
        if all(self.clean(value) is None for value in self.data.values()):
            return self.reject(FieldError("record", EMPTY_RECORD, "record has no values"))

        values = {name: self.take(aliases) for name, aliases in self.mapping.field_aliases.items()}
        for key, aliases in self.mapping.metadata_aliases.items():
            value = self.take(aliases)
            if value is not None:
                self.metadata[key] = value

        timestamp = self._timestamp(values.pop("timestamp", None))
        if values.get("protocol") is not None:
            try:
                values["protocol"] = normalize_protocol(values["protocol"])
            except ValueError as exc:
                self.errors.append(FieldError("protocol", INVALID_PROTOCOL, str(exc)))
        for name in ("label", "event_id"):
            if isinstance(values.get(name), int) and not isinstance(values[name], bool):
                values[name] = str(values[name])

        features = self._features()

        event_id = values.pop("event_id", None)
        if event_id is None and self.mapping.derive_event_id:
            event_id = f"{self.record.source}:{self.record.position}"
            self.metadata["event_id_derived"] = True

        unmapped = sorted(str(k) for k in self.data if k not in self.consumed)
        if unmapped:
            self.metadata["unmapped_fields"] = unmapped

        if self.errors:
            return self.reject(*self.errors)

        source_type = values.pop("source_type", None) or self.mapping.source_type
        dataset_name = values.pop("dataset_name", None) or self.mapping.dataset_name
        if values.get("event_type") is None:
            values["event_type"] = self.mapping.event_type
        try:
            return SecurityEvent(
                event_id=event_id,
                timestamp=timestamp,
                source_type=source_type,
                features=features,
                raw_event=self.data,
                dataset_name=dataset_name,
                metadata=self.metadata,
                **values,
            )
        except ValidationError as exc:
            return self.reject(*_validation_errors(exc))

    def _timestamp(self, value: Any) -> datetime | None:
        if value is None:
            return None
        try:
            parsed, assumed = parse_timestamp(value, self.mapping)
        except ValueError as exc:
            self.errors.append(FieldError("timestamp", INVALID_TIMESTAMP, str(exc)))
            return None
        if assumed and self.mapping.naive_timezone is not None:
            self.metadata["timestamp_timezone_assumed"] = str(
                self.mapping.naive_timezone.tzname(None)
            )
        return parsed

    def _features(self) -> dict[str, FeatureValue]:
        mapping = self.mapping
        if mapping.nested_features_key is not None:
            key = self.columns.get(normalize_column_name(mapping.nested_features_key))
            if key is None:
                return {}
            self.consumed.add(key)
            nested = self.data[key]
            if nested is None:
                return {}
            if not isinstance(nested, dict):
                self.errors.append(FieldError(
                    "features", INVALID_FEATURE,
                    f"'{key}' must be an object, found {type(nested).__name__}",
                ))
                return {}
            items = [(str(name), str(name), value) for name, value in nested.items()]
        else:
            wanted = (
                None if mapping.feature_columns is None
                else {normalize_column_name(c) for c in mapping.feature_columns}
            )
            items = []
            for column, value in self.data.items():
                if column in self.consumed:
                    continue
                if wanted is not None and normalize_column_name(column) not in wanted:
                    continue
                self.consumed.add(column)
                items.append((column, feature_name(column), value))

        features: dict[str, FeatureValue] = {}
        for column, name, raw in items:
            if name in features:
                self.errors.append(FieldError(
                    "features", INVALID_FEATURE,
                    f"column {column!r} collides with feature name {name!r}",
                ))
                continue
            value = self.clean(raw)
            if value is None:
                features[name] = None
            elif mapping.numeric_features:
                try:
                    features[name] = parse_number(value)
                except ValueError as exc:
                    self.errors.append(FieldError(
                        "features", INVALID_FEATURE, f"feature {column!r}: {exc}"
                    ))
            elif isinstance(value, (bool, int, float, str)):
                features[name] = value
            else:
                self.errors.append(FieldError(
                    "features", INVALID_FEATURE,
                    f"feature {column!r} must be a scalar, found {type(value).__name__}",
                ))
        return features


def _validation_errors(exc: ValidationError) -> list[FieldError]:
    errors = []
    for error in exc.errors():
        field = str(error["loc"][0]) if error["loc"] else "record"
        got = repr(error.get("input"))
        if len(got) > 80:
            got = got[:80] + "..."
        errors.append(FieldError(
            field,
            _FIELD_CATEGORIES.get(field, INVALID_VALUE),
            f"{field}: {error['msg']} (got {got})",
        ))
    return errors
