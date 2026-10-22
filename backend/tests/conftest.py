from pathlib import Path

import pytest

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "data" / "samples"


@pytest.fixture
def samples_dir() -> Path:
    return SAMPLES_DIR


def write(path: Path, text: str, encoding: str = "utf-8") -> Path:
    path.write_text(text, encoding=encoding, newline="")
    return path
