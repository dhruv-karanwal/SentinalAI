import json
from pathlib import Path

import pytest

from app.ingestion.csv_loader import clean_header, iter_csv_records
from app.ingestion.json_loader import iter_json_records, iter_jsonl_records
from app.ingestion.records import EMPTY_RECORD, MALFORMED_RECORD, IngestionError
from app.pipeline import detect_format
from tests.conftest import write

# --- CSV -------------------------------------------------------------------


def test_clean_header_strips_and_deduplicates() -> None:
    assert clean_header([" Flow ID", "Label ", " x", "x", "", "x"]) == [
        "Flow ID", "Label", "x", "x.1", "column_5", "x.2",
    ]


def test_csv_records_keep_raw_values(tmp_path: Path) -> None:
    path = write(tmp_path / "a.csv", " Source IP, Label\n10.0.0.1 , BENIGN\n")
    records = list(iter_csv_records(path))
    assert len(records) == 1
    record = records[0]
    assert record.data == {"Source IP": "10.0.0.1 ", "Label": " BENIGN"}
    assert record.source == "a.csv"
    assert record.position == 2
    assert record.error is None


def test_csv_row_errors_are_yielded_not_dropped(tmp_path: Path) -> None:
    path = write(tmp_path / "a.csv", "a,b,c\n1,2,3\n,,\n1,2\n\n4,5,6\n")
    records = list(iter_csv_records(path))
    assert [r.position for r in records] == [2, 3, 4, 5, 6]
    assert [r.error_category for r in records] == [
        None, EMPTY_RECORD, MALFORMED_RECORD, EMPTY_RECORD, None,
    ]
    assert records[2].error == "expected 3 fields, found 2"
    assert records[2].raw_text == "1,2"


def test_csv_limit_counts_all_rows(tmp_path: Path) -> None:
    path = write(tmp_path / "a.csv", "a\n1\n\n3\n4\n")
    assert len(list(iter_csv_records(path, limit=3))) == 3


def test_csv_header_only_yields_nothing(tmp_path: Path) -> None:
    assert list(iter_csv_records(write(tmp_path / "a.csv", "a,b\n"))) == []


def test_csv_blank_header_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(IngestionError, match="header row is empty"):
        list(iter_csv_records(write(tmp_path / "a.csv", " , \n1,2\n")))


def test_csv_decode_error_suggests_encoding(tmp_path: Path) -> None:
    path = tmp_path / "cp1252.csv"
    path.write_bytes(b"Label\nWeb Attack \x96 Brute Force\n")
    with pytest.raises(IngestionError, match="--encoding cp1252"):
        list(iter_csv_records(path))
    records = list(iter_csv_records(path, encoding="cp1252"))
    assert records[0].data == {"Label": "Web Attack – Brute Force"}


@pytest.mark.parametrize(
    "loader", [iter_csv_records, iter_json_records, iter_jsonl_records]
)
def test_missing_file_raises_eagerly(tmp_path: Path, loader) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(IngestionError, match="not found"):
        loader(tmp_path / "missing.csv")


@pytest.mark.parametrize(
    "loader", [iter_csv_records, iter_json_records, iter_jsonl_records]
)
def test_empty_file_raises(tmp_path: Path, loader) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(IngestionError, match="empty"):
        loader(write(tmp_path / "empty.txt", ""))


def test_directory_is_not_a_file(tmp_path: Path) -> None:
    with pytest.raises(IngestionError, match="not a file"):
        iter_csv_records(tmp_path)


def test_invalid_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="positive"):
        iter_csv_records(write(tmp_path / "a.csv", "a\n1\n"), limit=0)


# --- JSON ------------------------------------------------------------------


def test_json_array(tmp_path: Path) -> None:
    path = write(tmp_path / "a.json", json.dumps([{"a": 1}, {"a": 2}]))
    records = list(iter_json_records(path))
    assert [r.data for r in records] == [{"a": 1}, {"a": 2}]
    assert [r.position for r in records] == [1, 2]


@pytest.mark.parametrize("key", ["records", "events"])
def test_json_object_with_records(tmp_path: Path, key: str) -> None:
    path = write(tmp_path / "a.json", json.dumps({"note": "x", key: [{"a": 1}]}))
    assert [r.data for r in iter_json_records(path)] == [{"a": 1}]


def test_json_non_object_items_are_reported(tmp_path: Path) -> None:
    path = write(tmp_path / "a.json", json.dumps([{"a": 1}, "text", 3, None]))
    records = list(iter_json_records(path))
    assert len(records) == 4
    assert [r.error_category for r in records[1:]] == [MALFORMED_RECORD] * 3
    assert records[1].error == "record must be a JSON object, found str"


def test_json_empty_array_yields_nothing(tmp_path: Path) -> None:
    assert list(iter_json_records(write(tmp_path / "a.json", "[]"))) == []


def test_json_limit(tmp_path: Path) -> None:
    path = write(tmp_path / "a.json", json.dumps([{"a": i} for i in range(5)]))
    assert len(list(iter_json_records(path, limit=2))) == 2


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('{"a": 1}', "expected a JSON array"),
        ("42", "found int"),
        ("[{]", "invalid JSON at line 1"),
        ('{"a": 1}\n{"a": 2}\n', "use --format jsonl"),
        ("   \n", "only whitespace"),
    ],
)
def test_json_structure_errors(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(IngestionError, match=message):
        iter_json_records(write(tmp_path / "a.json", text))


# --- JSON Lines ------------------------------------------------------------


def test_jsonl_reports_malformed_lines_and_skips_blank(tmp_path: Path) -> None:
    path = write(tmp_path / "a.jsonl", '{"a": 1}\n\n{"a": \n[1]\n{"a": 3}\n')
    records = list(iter_jsonl_records(path))
    assert [r.position for r in records] == [1, 3, 4, 5]
    assert records[0].data == {"a": 1}
    assert records[1].error_category == MALFORMED_RECORD
    assert records[1].error is not None and records[1].error.startswith("invalid JSON")
    assert records[1].raw_text == '{"a": '
    assert records[2].error == "record must be a JSON object, found list"
    assert records[3].data == {"a": 3}


def test_jsonl_limit(tmp_path: Path) -> None:
    path = write(tmp_path / "a.jsonl", "\n".join('{"a": %d}' % i for i in range(5)))
    assert len(list(iter_jsonl_records(path, limit=3))) == 3


# --- format detection ------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [("a.csv", "csv"), ("a.JSON", "json"), ("a.jsonl", "jsonl"), ("a.ndjson", "jsonl")],
)
def test_detect_format(name: str, expected: str) -> None:
    assert detect_format(Path(name)) == expected


def test_detect_format_unknown_extension() -> None:
    with pytest.raises(IngestionError, match="--format"):
        detect_format(Path("a.txt"))
    assert detect_format(Path("a.txt"), "csv") == "csv"
