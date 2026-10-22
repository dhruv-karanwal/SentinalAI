"""Canonical security-event schema.

Every source (network flows, endpoint telemetry, authentication logs,
application logs) is normalized into :class:`SecurityEvent`. Only
``raw_event`` is required: optional fields stay ``None`` when the source does
not provide them, so missing data is never replaced by invented values.

Timestamps
----------
``timestamp`` must be timezone-aware and is stored in UTC. Naive values are
rejected by the schema. A dataset mapping may attach a timezone to naive
source timestamps only when that assumption is configured explicitly
(``DatasetMapping.naive_timezone``); the normalizer then records the
assumption in ``metadata["timestamp_timezone_assumed"]``. The original
timestamp string is always kept in ``raw_event``.

Separation of concerns
----------------------
- ``raw_event``: the original record as loaded, for traceability.
- canonical fields: normalized identity and context fields.
- ``label``: ground truth from the dataset. It must never be used as a model
  input, so a feature named ``label`` is rejected.
- ``features``: candidate model inputs for later experiments.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
)

FeatureValue = bool | int | float | str | None


class SourceType(StrEnum):
    NETWORK = "network"
    ENDPOINT = "endpoint"
    AUTHENTICATION = "authentication"
    APPLICATION = "application"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Only unambiguous spellings are accepted; anything else is a validation error.
_SEVERITY_ALIASES = {"info": "informational", "moderate": "medium"}


class SecurityEvent(BaseModel):
    """A single normalized security event."""

    model_config = ConfigDict(extra="forbid", ser_json_inf_nan="constants")

    event_id: str | None = Field(default=None, min_length=1)
    timestamp: datetime | None = None
    source_type: SourceType = SourceType.UNKNOWN
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, min_length=1)
    event_type: str | None = Field(default=None, min_length=1)
    severity: Severity | None = None
    label: str | None = Field(default=None, min_length=1)
    features: dict[str, FeatureValue] = Field(default_factory=dict)
    raw_event: dict[str, Any]
    dataset_name: str | None = Field(default=None, min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _require_aware_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(
                "timestamp must be timezone-aware; naive timestamps need an "
                "explicit timezone assumption in the dataset mapping"
            )
        return value.astimezone(timezone.utc)

    @field_validator("source_type", mode="before")
    @classmethod
    def _normalize_source_type(cls, value: Any) -> Any:
        return value.strip().casefold() if isinstance(value, str) else value

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity(cls, value: Any) -> Any:
        if isinstance(value, str):
            key = value.strip().casefold()
            return _SEVERITY_ALIASES.get(key, key)
        return value

    @field_validator("protocol")
    @classmethod
    def _normalize_protocol(cls, value: str | None) -> str | None:
        return value.strip().casefold() if value is not None else None

    @field_validator("features")
    @classmethod
    def _check_features(
        cls, value: dict[str, FeatureValue]
    ) -> dict[str, FeatureValue]:
        for name in value:
            if not name.strip():
                raise ValueError("feature names must be non-empty")
            if name.strip().casefold() == "label":
                raise ValueError(
                    "'label' is ground truth and must not appear in features"
                )
        return value
