"""Dataset-specific mappings from source columns to the canonical schema.

To support a new dataset, add a :class:`DatasetMapping` to ``MAPPINGS``.
Column aliases are written in normalized form (see
:func:`normalize_column_name`): lower case, surrounding whitespace removed,
runs of spaces/underscores collapsed to one space.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta, timezone, tzinfo
from functools import lru_cache

from app.schemas.event import SourceType

DEFAULT_MISSING_TOKENS = frozenset({"", "nan", "null", "n/a"})


@lru_cache(maxsize=4096)
def normalize_column_name(name: str) -> str:
    return re.sub(r"[\s_]+", " ", name.strip()).casefold()


@lru_cache(maxsize=4096)
def feature_name(column: str) -> str:
    """``"Flow Bytes/s"`` -> ``"flow_bytes_s"``."""
    return re.sub(r"[^0-9a-z]+", "_", column.strip().casefold()).strip("_")


@dataclass(frozen=True)
class DatasetMapping:
    """How to turn one dataset's records into :class:`SecurityEvent`.

    field_aliases: canonical field -> source column aliases, first match wins.
    metadata_aliases: metadata key -> source column aliases.
    timestamp_formats: ``strptime`` formats tried after ISO 8601.
    naive_timezone: timezone assumed for naive timestamps. ``None`` means
        naive timestamps are rejected rather than guessed.
    accept_epoch_seconds: numeric timestamps are Unix seconds (UTC).
    event_type: constant event type when every record is the same kind of
        event (e.g. network flows); ``None`` otherwise.
    feature_columns: columns used as features. ``None`` means every column
        not consumed by a canonical/metadata field.
    nested_features_key: take features from this record key (a JSON object)
        instead of from flat columns.
    numeric_features: require feature values to be numeric; non-numeric
        values reject the record. When false, scalar values are kept as-is.
    derive_event_id: when no id column exists, use ``<file>:<position>``
        (recorded as ``metadata["event_id_derived"]``).
    """

    name: str
    dataset_name: str | None
    source_type: SourceType
    field_aliases: Mapping[str, tuple[str, ...]]
    metadata_aliases: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    timestamp_formats: tuple[str, ...] = ()
    naive_timezone: tzinfo | None = None
    accept_epoch_seconds: bool = False
    event_type: str | None = None
    feature_columns: tuple[str, ...] | None = None
    nested_features_key: str | None = None
    numeric_features: bool = True
    derive_event_id: bool = False
    missing_tokens: frozenset[str] = DEFAULT_MISSING_TOKENS


# CICIDS2017 "GeneratedLabelledFlows"/"TrafficLabelling" CSVs. The
# "MachineLearningCVE" variant lacks the IP/port/timestamp columns; those
# fields are then simply missing.
#
# Timestamps are day-first local times without a zone (e.g. "3/7/2017 8:55"
# is 3 July 2017). The capture ran 3-7 July 2017 at UNB, New Brunswick,
# Canada, so Atlantic Daylight Time (UTC-03:00) is assumed. This is an
# assumption, not a fact stated in the files; override it with
# --assume-timezone.
CICIDS2017 = DatasetMapping(
    name="cicids2017",
    dataset_name="CICIDS2017",
    source_type=SourceType.NETWORK,
    field_aliases={
        "source_ip": ("source ip", "src ip"),
        "source_port": ("source port", "src port"),
        "destination_ip": ("destination ip", "dst ip"),
        "destination_port": ("destination port", "dst port"),
        "protocol": ("protocol",),
        "timestamp": ("timestamp",),
        "label": ("label",),
    },
    metadata_aliases={"flow_id": ("flow id",)},
    timestamp_formats=(
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %I:%M %p",
        "%d/%m/%Y %I:%M:%S %p",
    ),
    naive_timezone=timezone(timedelta(hours=-3), "UTC-03:00"),
    event_type="network_flow",
    numeric_features=True,
    derive_event_id=True,
)

# Generic JSON/JSONL security events with common field spellings.
GENERIC = DatasetMapping(
    name="generic",
    dataset_name=None,
    source_type=SourceType.UNKNOWN,
    field_aliases={
        "event_id": ("event id", "id", "uuid"),
        "timestamp": ("timestamp", "@timestamp", "time", "event time", "ts"),
        "source_type": ("source type",),
        "source_ip": ("source ip", "src ip", "src", "client ip"),
        "destination_ip": ("destination ip", "dest ip", "dst ip", "dst"),
        "source_port": ("source port", "src port"),
        "destination_port": ("destination port", "dest port", "dst port"),
        "protocol": ("protocol", "proto"),
        "event_type": ("event type", "event category"),
        "severity": ("severity",),
        "label": ("label", "ground truth"),
        "dataset_name": ("dataset name", "dataset"),
    },
    metadata_aliases={"host": ("host", "hostname"), "user": ("user", "username")},
    accept_epoch_seconds=True,
    nested_features_key="features",
    numeric_features=False,
)

MAPPINGS: dict[str, DatasetMapping] = {m.name: m for m in (CICIDS2017, GENERIC)}


def get_mapping(name: str) -> DatasetMapping:
    try:
        return MAPPINGS[name]
    except KeyError:
        raise ValueError(
            f"unknown mapping {name!r}; available: {', '.join(sorted(MAPPINGS))}"
        ) from None
