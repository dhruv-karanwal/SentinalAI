from collections.abc import Iterator
from pathlib import Path

import pytest

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "data" / "samples"


@pytest.fixture
def samples_dir() -> Path:
    return SAMPLES_DIR


def write(path: Path, text: str, encoding: str = "utf-8") -> Path:
    path.write_text(text, encoding=encoding, newline="")
    return path


@pytest.fixture(autouse=True, scope="session")
def _repo_platform_store_untouched() -> Iterator[None]:
    """No test may create or change the repo's data/platform (the real study stores on Windows)."""
    store = Path(__file__).resolve().parents[2] / "data" / "platform"

    def snapshot() -> dict[str, float]:
        # -wal / -shm sidecars are left out: SQLite may touch them on a plain read elsewhere
        return ({str(p): p.stat().st_mtime for p in store.rglob("*")
                 if not p.name.endswith(("-wal", "-shm"))} if store.exists() else {})

    before = snapshot()
    yield
    assert snapshot() == before, f"a test wrote to {store}"
