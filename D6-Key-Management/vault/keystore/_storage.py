"""Small helpers shared by the keyring and the trusted-signers store (D6).

Both stores are one JSON file that is replaced atomically: the new content is
written to a temporary file in the same directory, flushed to disk, and moved
over the old file with ``os.replace``, so a crash never leaves a half-written
file.  Files are created with permissions ``0600``.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

__all__ = ["MAX_JSON_FILE_SIZE", "now_utc", "read_json", "write_json_atomic"]

MAX_JSON_FILE_SIZE: Final[int] = 1024 * 1024
"""Largest store file that is read (1 MiB), so a modified file cannot exhaust memory."""


def now_utc() -> str:
    """Current UTC time as ``YYYY-MM-DDTHH:MM:SSZ``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    """Read and parse a store file.

    Raises:
        OSError: the file cannot be read.
        ValueError: the file is too large, is not JSON, or repeats a key.
    """
    with open(path, "rb") as handle:
        data = handle.read(MAX_JSON_FILE_SIZE + 1)
    if len(data) > MAX_JSON_FILE_SIZE:
        raise ValueError("store file too large")
    return json.loads(data, object_pairs_hook=_reject_duplicate_keys)


def write_json_atomic(path: Path, value: Any) -> None:
    """Replace ``path`` with the JSON form of ``value`` (sorted keys, compact).

    Raises:
        OSError: the file cannot be written.  The old file is left untouched.
    """
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    descriptor, temp_name = tempfile.mkstemp(prefix=".store-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
