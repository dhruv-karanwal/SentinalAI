"""Dataset-specific mappings from source columns to the canonical schemas.

To support a new event dataset, add a :class:`DatasetMapping` to ``MAPPINGS``.
Alert datasets (AIT-ADS) use :class:`AlertMapping`, which addresses fields in
nested JSON records by dotted path; their file layout, routing rules and
label-file conventions are defined at the end of this module.
Column aliases are written in normalized form (see
:func:`normalize_column_name`): lower case, surrounding whitespace removed,
runs of spaces/underscores collapsed to one space.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta, timezone, tzinfo
from enum import StrEnum
from functools import lru_cache
from typing import Any

from app.schemas.alert import Detector
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


# ---------------------------------------------------------------------------
# AIT Alert Data Set (AIT-ADS, Zenodo 10.5281/zenodo.8263181)
#
# Everything below was established by inspecting the downloaded files (see
# docs/session-notes.md), not assumed:
#
# - Each scenario has <scenario>_wazuh.json and <scenario>_aminer.json, one
#   JSON object per line.
# - Suricata has no file of its own: Wazuh collected its alerts. Records with
#   location /var/log/suricata/eve.json are Suricata alerts (full Suricata
#   ``data.alert``); records with location /var/log/suricata/fast.log are
#   Wazuh IDS rules (e.g. 20100) decoded from the same Suricata events, so
#   they are flagged ``duplicate_of_suricata``.
# - Wazuh ``@timestamp`` is ISO 8601 with "Z". AMiner and labels.csv use Unix
#   epoch seconds. AMiner's alert time is ``LogData.DetectionTimestamp[-1]``
#   (the value the dataset authors' analyze.py uses).
# - AMiner records with a ``CountData`` or ``FrequencyData`` object are
#   window-level aggregates. Their ``RawLogData`` holds the line that closed
#   the window, which is not evidence of the anomaly; it stays in raw_alert.
# - alerts_csv/<scenario>_alerts.txt (GitHub ait-aecid/alert-data-set) has
#   one row per Wazuh line, then one per AMiner line, in file order. The
#   name field is written unquoted and may contain commas.
# ---------------------------------------------------------------------------

AIT_ADS_DATASET_NAME = "AIT-ADS"
AIT_ADS_SCENARIOS = (
    "fox", "harrison", "russellmitchell", "santos",
    "shaw", "wardbeck", "wheeler", "wilson",
)
AIT_ADS_LABELS_FILE = "labels.csv"
AIT_ADS_LABELS_COLUMNS = ("scenario", "attack", "start", "end")
AIT_ADS_EVENT_LABELS_DIR = ("alerts_csv", "alerts_csv")  # as unpacked from alerts_csv.zip
AIT_ADS_EVENT_LABELS_COLUMNS = (
    "time", "name", "ip", "host", "short", "time_label", "event_label")
AIT_ADS_NO_EVENT_LABEL = "-"
AIT_ADS_BENIGN_TIME_LABEL = "false_positive"

SURICATA_EVE_LOCATION = "/var/log/suricata/eve.json"
SURICATA_FAST_LOG_LOCATION = "/var/log/suricata/fast.log"
# How analyze.py names Wazuh-file alerts in alerts_csv.
SURICATA_DESCRIPTION_PREFIX = "Suricata: "
WAZUH_CSV_NAME_PREFIX = "Wazuh: "
AMINER_AGGREGATE_KEYS = ("CountData", "FrequencyData")


class AitAdsFile(StrEnum):
    """Which per-scenario AIT-ADS file a record came from."""

    WAZUH = "wazuh"
    AMINER = "aminer"


@dataclass(frozen=True)
class AlertMapping:
    """Where one detector's alert fields live in its (nested) JSON record.

    Paths are dotted keys into the record (``"agent.ip"``). For list values,
    ``*_last`` options pick the last element.

    alert_id_path: native alert id; ``None`` derives a deterministic id.
    rule_id_paths: one or more values joined with ``":"`` (Suricata
        ``gid:sid:rev``).
    timestamp_epoch: the timestamp is Unix seconds rather than ISO 8601.
    training_mode_path: boolean flag, required when set.
    aggregate_keys: top-level keys that mark a window-level aggregate.
    """

    name: str
    detector: Detector
    timestamp_path: str
    rule_id_paths: tuple[str, ...]
    rule_name_path: str
    host_ip_path: str
    alert_id_path: str | None = None
    timestamp_epoch: bool = False
    timestamp_last: bool = False
    severity_path: str | None = None
    log_lines_path: str | None = None
    log_paths_path: str | None = None
    log_timestamps_path: str | None = None
    training_mode_path: str | None = None
    aggregate_keys: tuple[str, ...] = ()


AIT_ADS_WAZUH = AlertMapping(
    name="ait-ads-wazuh",
    detector=Detector.WAZUH,
    alert_id_path="id",
    timestamp_path="@timestamp",
    rule_id_paths=("rule.id",),
    rule_name_path="rule.description",
    severity_path="rule.level",
    host_ip_path="agent.ip",
    log_lines_path="full_log",
    log_paths_path="location",
)

AIT_ADS_SURICATA = AlertMapping(
    name="ait-ads-suricata",
    detector=Detector.SURICATA,
    alert_id_path="id",
    timestamp_path="@timestamp",
    rule_id_paths=("data.alert.gid", "data.alert.signature_id", "data.alert.rev"),
    rule_name_path="data.alert.signature",
    severity_path="data.alert.severity",
    host_ip_path="agent.ip",
    log_lines_path="full_log",
    log_paths_path="location",
)

AIT_ADS_AMINER = AlertMapping(
    name="ait-ads-aminer",
    detector=Detector.AMINER,
    timestamp_path="LogData.DetectionTimestamp",
    timestamp_epoch=True,
    timestamp_last=True,
    rule_id_paths=("AnalysisComponent.AnalysisComponentIdentifier",),
    rule_name_path="AnalysisComponent.AnalysisComponentName",
    host_ip_path="AMiner.ID",
    log_lines_path="LogData.RawLogData",
    log_paths_path="LogData.LogResources",
    log_timestamps_path="LogData.Timestamps",
    training_mode_path="AnalysisComponent.TrainingMode",
    aggregate_keys=AMINER_AGGREGATE_KEYS,
)


def route_ait_ads_record(kind: AitAdsFile, data: Mapping[str, Any]) -> tuple[AlertMapping, bool]:
    """Pick the detector mapping for a record; return ``(mapping, duplicate_of_suricata)``."""
    if kind is AitAdsFile.AMINER:
        return AIT_ADS_AMINER, False
    location = data.get("location")
    if location == SURICATA_EVE_LOCATION:
        return AIT_ADS_SURICATA, False
    return AIT_ADS_WAZUH, location == SURICATA_FAST_LOG_LOCATION


def suricata_twin_key(raw: Mapping[str, Any]) -> tuple[str, str, str] | None:
    """Key matching a fast.log record to its eve.json twin, or ``None``.

    Verified on the real files: (timestamp, gid:sid:rev, agent ip) matched
    every fast.log record in russellmitchell and all but 16 in shaw.
    """
    location = raw.get("location")
    timestamp = raw.get("@timestamp")
    agent_ip = (raw.get("agent") or {}).get("ip")
    data = raw.get("data") or {}
    if location == SURICATA_EVE_LOCATION:
        alert = data.get("alert") or {}
        rule = f"{alert.get('gid')}:{alert.get('signature_id')}:{alert.get('rev')}"
    elif location == SURICATA_FAST_LOG_LOCATION:
        rule = str(data.get("id"))
    else:
        return None
    return str(timestamp), rule, str(agent_ip)
