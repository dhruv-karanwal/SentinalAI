"""Object storage for reports and artifacts: local folder (fallback) or MinIO (``full``).

Keys are relative, ``/``-separated, and validated so a key can never escape
the store root (no ``..``, no absolute paths, no backslashes).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol

_KEY = re.compile(r"^[A-Za-z0-9_\-]+(/[A-Za-z0-9_.\-]+)*$")


def check_key(key: str) -> str:
    if not _KEY.fullmatch(key) or any(part in ("", ".", "..") for part in key.split("/")):
        raise ValueError(f"invalid object key {key!r}")
    return key


class ObjectStore(Protocol):
    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str: ...
    def get(self, key: str) -> bytes: ...
    def exists(self, key: str) -> bool: ...


class LocalObjectStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        path = (self.root / check_key(key)).resolve()
        if self.root not in path.parents:
            raise ValueError(f"invalid object key {key!r}")
        return path

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return key

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()


class MinioObjectStore:
    """MinIO / S3 (optional dependency ``minio``); credentials only from the environment."""

    def __init__(self, endpoint: str, access_key: str, secret_key: str, bucket: str = "sentinel",
                 secure: bool = False) -> None:
        from minio import Minio

        self._client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)
        self._bucket = bucket
        if not self._client.bucket_exists(bucket):
            self._client.make_bucket(bucket)

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        import io

        self._client.put_object(self._bucket, check_key(key), io.BytesIO(data), len(data),
                                content_type=content_type)
        return key

    def get(self, key: str) -> bytes:
        resp = self._client.get_object(self._bucket, check_key(key))
        try:
            return bytes(resp.read())
        finally:
            resp.close()
            resp.release_conn()

    def exists(self, key: str) -> bool:
        try:
            self._client.stat_object(self._bucket, check_key(key))
            return True
        except Exception:  # noqa: BLE001 - minio raises S3Error for a missing key
            return False
