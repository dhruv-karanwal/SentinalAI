"""Command-line entry point.

    python -m app.main ingest ../data/samples/synthetic_cicids2017_format.csv \
        --mapping cicids2017 --dataset-name synthetic-cicids2017-format
    python -m app.main ingest-alerts --data-dir ../data/raw/ait_ads --scenario russellmitchell

This is a local research tool: it reads whatever path it is given. Do not
expose it behind a network API without validating paths against an
allow-listed data directory.
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import sys
from collections.abc import Sequence
from datetime import timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any

from app.alert_pipeline import AitAdsInputs, run_alert_ingest
from app.ingestion.mappings import AIT_ADS_DATASET_NAME, MAPPINGS, get_mapping
from app.ingestion.records import IngestionError
from app.pipeline import FORMATS, run_pipeline

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[2] / "data" / "processed"

_OFFSET_RE = re.compile(r"([+-])(\d{2}):?(\d{2})")


def parse_timezone(value: str) -> tzinfo | None:
    """``"UTC"``, ``"+HH:MM"``/``"-HH:MM"``, or ``"none"`` (reject naive)."""
    text = value.strip()
    if text.casefold() == "none":
        return None
    if text.casefold() in ("utc", "z"):
        return timezone.utc
    match = _OFFSET_RE.fullmatch(text)
    if not match:
        raise argparse.ArgumentTypeError(
            f"invalid timezone {value!r}; use UTC, +HH:MM, -HH:MM or none")
    sign, hours, minutes = match.groups()
    offset = timedelta(hours=int(hours), minutes=int(minutes))
    if offset >= timedelta(hours=24):
        raise argparse.ArgumentTypeError(f"offset out of range: {value!r}")
    if sign == "-":
        offset = -offset
    return timezone(offset)


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinelai", description="SentinelAI Phase 1 data pipeline")
    sub = parser.add_subparsers(dest="command", required=True)
    ingest = sub.add_parser("ingest", help="load, normalize and profile one CSV/JSON/JSONL file")
    ingest.add_argument("path", type=Path, help="input file")
    ingest.add_argument("--mapping", default="generic", choices=sorted(MAPPINGS),
                        help="dataset mapping (default: generic)")
    ingest.add_argument("--format", dest="fmt", default="auto", choices=FORMATS,
                        help="input format (default: from file extension)")
    ingest.add_argument("--limit", type=_positive_int, default=None,
                        help="read at most N input records")
    ingest.add_argument("--encoding", default="utf-8", help="file encoding (default: utf-8)")
    ingest.add_argument("--dataset-name", default=None,
                        help="dataset name for records that do not carry one")
    ingest.add_argument("--assume-timezone", type=parse_timezone, default=argparse.SUPPRESS,
                        metavar="TZ", help="timezone for naive timestamps: UTC, +HH:MM, -HH:MM "
                        "or none (default: the mapping's own assumption)")
    ingest.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help=f"where to write outputs (default: {DEFAULT_OUTPUT_DIR})")
    ingest.add_argument("--no-output", action="store_true",
                        help="only print the summary; write no files")

    alerts = sub.add_parser("ingest-alerts", help="ingest one AIT-ADS scenario (alerts + ground truth)")
    alerts.add_argument("--data-dir", type=Path, required=True,
                        help="directory holding <scenario>_wazuh.json, <scenario>_aminer.json, labels.csv")
    alerts.add_argument("--scenario", required=True, help="scenario name, e.g. russellmitchell")
    alerts.add_argument("--labels", type=Path, default=None,
                        help="attack-interval labels CSV (default: <data-dir>/labels.csv)")
    alerts.add_argument("--event-labels", type=Path, default=None,
                        help="alerts_csv file with event labels (default: "
                        "<data-dir>/alerts_csv/alerts_csv/<scenario>_alerts.txt if present)")
    alerts.add_argument("--dataset-name", default=AIT_ADS_DATASET_NAME,
                        help=f"dataset name recorded on alerts (default: {AIT_ADS_DATASET_NAME})")
    alerts.add_argument("--limit", type=_positive_int, default=None,
                        help="read at most N input records (Wazuh first, then AMiner)")
    alerts.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help=f"where to write outputs (default: {DEFAULT_OUTPUT_DIR})")
    alerts.add_argument("--no-output", action="store_true",
                        help="only print the summary; write no files")
    return parser


def _print_summary(report: dict[str, Any], output_paths: dict[str, Path]) -> None:
    counts = report["record_counts"]
    print(f"Source:     {report['source_file']} ({report['input_format']}, mapping={report['mapping']})")
    print(f"Records:    {counts['total_input']} input, {counts['normalized']} normalized, "
          f"{counts['rejected']} rejected")
    for reason, count in report["rejections"]["by_reason"].items():
        print(f"  rejected  {reason}: {count}")
    ts = report["timestamps"]
    print(f"Timestamps: {ts['parsed']} parsed, {ts['missing']} missing, "
          f"{ts['parse_failures']} parse failures")
    dup = report["duplicates"]
    print(f"Duplicates: {dup['duplicate_raw_records']} raw records, "
          f"{dup['duplicate_event_ids']} event ids, {dup['duplicate_feature_vectors']} feature vectors")
    labels = report["labels"]
    print(f"Labels:     {labels['labelled']} labelled, {labels['unlabelled']} unlabelled")
    for label, info in labels["distribution"].items():
        print(f"  {label}: {info['count']} ({info['proportion']:.2%})")
    print(f"Features:   {report['features']['feature_count']}")
    for kind, path in output_paths.items():
        print(f"Wrote {kind}: {path}")
    if counts["normalized"] == 0:
        print("WARNING: no records were normalized", file=sys.stderr)


def _print_alert_summary(report: dict[str, Any], output_paths: dict[str, Path]) -> None:
    counts = report["record_counts"]
    print(f"Scenario:   {report['scenario']} (dataset={report['dataset_name']})")
    print(f"Records:    {counts['total_input']} input, {counts['normalized']} normalized, "
          f"{counts['rejected']} rejected")
    for reason, count in report["rejections"]["by_reason"].items():
        print(f"  rejected  {reason}: {count}")
    for detector, info in report["detectors"].items():
        print(f"  {detector:9s} {info['alerts']} alerts, {info['training_mode']} training, "
              f"{info['aggregate']} aggregate, {info['duplicate_of_suricata']} fast.log duplicates, "
              f"{info['investigation_eligible']} investigation-eligible")
    dup = report["suricata_duplicates"]
    print(f"fast.log:   {dup['fast_log_matched_to_eve']}/{dup['fast_log_records']} matched to "
          f"eve.json, {dup['fast_log_unmatched']} unmatched")
    truth = report["ground_truth"]
    print(f"Intervals:  {truth['attack_intervals_within_alert_range']}/"
          f"{len(truth['attack_intervals'])} inside the alert time range")
    events = truth["event_labels"]
    print(f"Event labels: {events['link_status']}, {events['available']} available, "
          f"{events['unavailable']} unavailable")
    for kind, path in output_paths.items():
        print(f"Wrote {kind}: {path}")


def _ingest_alerts(args: argparse.Namespace) -> int:
    try:
        inputs = AitAdsInputs.from_layout(args.data_dir, args.scenario)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    overrides: dict[str, Any] = {}
    if args.labels is not None:
        overrides["labels"] = args.labels
    if args.event_labels is not None:
        overrides["event_labels"] = args.event_labels
    if overrides:
        inputs = dataclasses.replace(inputs, **overrides)
    try:
        result = run_alert_ingest(
            inputs,
            dataset_name=args.dataset_name,
            limit=args.limit,
            output_dir=None if args.no_output else args.output_dir,
            collect=False,
        )
    except IngestionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _print_alert_summary(result.report, result.output_paths)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # Labels may contain non-ASCII characters; never crash on a narrow console.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    if args.command == "ingest-alerts":
        return _ingest_alerts(args)
    mapping = get_mapping(args.mapping)
    overrides: dict[str, Any] = {}
    if args.dataset_name is not None:
        overrides["dataset_name"] = args.dataset_name
    if hasattr(args, "assume_timezone"):
        overrides["naive_timezone"] = args.assume_timezone
    if overrides:
        mapping = dataclasses.replace(mapping, **overrides)

    try:
        result = run_pipeline(
            args.path,
            mapping,
            fmt=args.fmt,
            limit=args.limit,
            encoding=args.encoding,
            output_dir=None if args.no_output else args.output_dir,
            collect=False,
        )
    except IngestionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _print_summary(result.report, result.output_paths)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
