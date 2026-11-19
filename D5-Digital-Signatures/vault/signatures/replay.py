"""Replay protection for signed containers (D5).

A signature proves who created a container, not that it is the first time the
recipient sees it.  :class:`ReplayGuard` is the recipient's memory of the
containers it has already accepted: for every signer it keeps the
``container_id`` values (see :mod:`vault.signatures.signing`) it decrypted.

Store
-----
One JSON file::

    {"format": "VRG1", "containers": {"<signer_id>": ["<container_id>", ...]}}

The file is written atomically (temporary file in the same directory, then
``os.replace``) with permissions ``0600``.  It must live on the recipient's
trusted side: an attacker who can delete or edit it can make the recipient
forget what it accepted, which is outside the threat model of D1 (the
attacker controls the storage and the network, not the recipient's device).

The store is never written for a container that failed verification: the
guard is called only after the signature is valid, so someone without the
signer's key cannot fill it.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Final

from vault.exceptions import ReplayDetectedError, ReplayStoreError

__all__ = ["ReplayGuard", "STORE_FORMAT"]

STORE_FORMAT: Final[str] = "VRG1"
"""Format identifier of the replay store file."""

_MAX_STORE_SIZE: Final[int] = 16 * 1024 * 1024
_SIGNER_ID_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
_CONTAINER_ID_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{32}")


class ReplayGuard:
    """Remember the containers a recipient accepted and refuse to accept them again.

    Args:
        path: File where the record is kept.  It is created on the first
            ``record`` call; a missing file is an empty record.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    def check(self, signer_id: str, container_id: str) -> None:
        """Raise :class:`ReplayDetectedError` if this container was already accepted.

        Raises:
            ReplayStoreError: the store exists but cannot be read or is malformed.
        """
        state = self._load()
        if container_id in state["containers"].get(signer_id, []):
            raise ReplayDetectedError()

    def record(self, signer_id: str, container_id: str) -> None:
        """Remember that this container was accepted.

        Raises:
            ReplayStoreError: the store cannot be read or written.
        """
        state = self._load()
        seen = state["containers"].setdefault(signer_id, [])
        if container_id not in seen:
            seen.append(container_id)
        self._save(state)

    # ------------------------------------------------------------------ #

    def _load(self) -> dict[str, Any]:
        try:
            with open(self._path, "rb") as handle:
                data = handle.read(_MAX_STORE_SIZE + 1)
        except FileNotFoundError:
            return {"format": STORE_FORMAT, "containers": {}}
        except OSError:
            raise ReplayStoreError("the replay store cannot be read") from None
        state = _parse(data)
        if state is None:
            raise ReplayStoreError("the replay store is corrupted")
        return state

    def _save(self, state: dict[str, Any]) -> None:
        payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
        directory = self._path.parent
        descriptor, temp_name = tempfile.mkstemp(prefix=".replay-", dir=_ensure_dir(directory))
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self._path)
        except OSError:
            _remove_quietly(temp_name)
            raise ReplayStoreError("the replay store cannot be written") from None
        except BaseException:
            _remove_quietly(temp_name)
            raise


def _ensure_dir(directory: Path) -> Path:
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise ReplayStoreError("the replay store cannot be written") from None
    return directory


def _remove_quietly(name: str) -> None:
    try:
        os.unlink(name)
    except OSError:
        pass


def _parse(data: bytes) -> Any:
    """Return the validated state, or ``None`` if the file is not a valid store."""
    if len(data) > _MAX_STORE_SIZE:
        return None
    try:
        state = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(state, dict) or set(state) != {"format", "containers"}:
        return None
    if state["format"] != STORE_FORMAT or not isinstance(state["containers"], dict):
        return None
    for signer_id, ids in state["containers"].items():
        if not _SIGNER_ID_RE.fullmatch(signer_id) or not isinstance(ids, list):
            return None
        if not all(isinstance(i, str) and _CONTAINER_ID_RE.fullmatch(i) for i in ids):
            return None
    return state
