"""Key lifecycle for one purpose: a keyring of password-protected keystores (D6).

A keyring is a directory that holds every version of one user's key of one
type (X25519 for D3 decryption, or Ed25519 for D5 signing)::

    keyring/
     ├── keyring.json         manifest: owner, key type and one entry per key
     └── keys/
          ├── <key_id>/       a keystore (see vault.keystore.keystore), one per key
          └── <key_id>/

Each key keeps its own keystore, so it is protected exactly as before: nothing
is stored in the clear and every key can have its own password.  The manifest
holds only public facts (``key_id``, dates, status), never key material.

Status of a key
---------------
``active``   the key used for new work (signing, or being chosen as a recipient).
             There is at most one.
``retired``  replaced by a newer key by :meth:`Keyring.rotate`.  It is kept so
             that files made before the rotation can still be opened.

Rotation
--------
:meth:`Keyring.rotate` stores a new key, makes it ``active`` and retires the
previous one.  Old files are not touched: they stay encrypted for the old key,
which is still in the keyring (historical access).

The manifest is a plain file on the owner's device.  Anyone who can write to it
can change a status, but cannot read or use a key without its password.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Optional

from vault.exceptions import KeystoreError
from vault.keystore._storage import now_utc, read_json, write_json_atomic
from vault.keystore.keystore import (
    Password,
    PrivateKey,
    _describe_key,
    create_keystore,
    unlock_private_key,
)

__all__ = [
    "KeyEntry",
    "Keyring",
    "KEYRING_FORMAT",
    "STATUS_ACTIVE",
    "STATUS_RETIRED",
]

KEYRING_FORMAT: Final[str] = "VKR1"
"""Format identifier of the keyring manifest."""

MANIFEST_FILE: Final[str] = "keyring.json"
KEYS_DIRECTORY: Final[str] = "keys"

STATUS_ACTIVE: Final[str] = "active"
STATUS_RETIRED: Final[str] = "retired"
_STATUSES: Final[frozenset[str]] = frozenset({STATUS_ACTIVE, STATUS_RETIRED})

_KEY_TYPES: Final[frozenset[str]] = frozenset({"X25519", "Ed25519"})
_KEY_ID_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
_MANIFEST_FIELDS: Final[frozenset[str]] = frozenset({"format", "owner", "key_type", "keys"})
_ENTRY_FIELDS: Final[frozenset[str]] = frozenset({"key_id", "status", "created", "retired_at"})


@dataclass(frozen=True)
class KeyEntry:
    """Public facts about one key of a keyring."""

    key_id: str
    status: str
    created: str
    retired_at: Optional[str]


class Keyring:
    """The versions of one key of one user, each in its own keystore.

    Every method reads the manifest from disk, so two objects for the same
    directory never disagree.  Create a keyring with :meth:`create` and open an
    existing one with :meth:`open`.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    # ------------------------------------------------------------------ #
    # Creation                                                           #
    # ------------------------------------------------------------------ #

    @classmethod
    def create(cls, path: Path, owner: str, key_type: str) -> "Keyring":
        """Create an empty keyring directory.

        Args:
            path: Directory to create.  It must not exist.
            owner: Identifier of the keys' owner (for example the D3 recipient ``id``).
            key_type: ``"X25519"`` (D3) or ``"Ed25519"`` (D5).

        Raises:
            KeystoreError: ``path`` exists, ``owner`` is empty or ``key_type`` is not supported.
        """
        target = Path(path)
        if target.exists():
            raise KeystoreError("keyring already exists; refusing to overwrite it")
        if not isinstance(owner, str) or not owner:
            raise KeystoreError("owner must be a non-empty string")
        if key_type not in _KEY_TYPES:
            raise KeystoreError("key_type must be 'X25519' or 'Ed25519'")
        target.mkdir(parents=True)
        try:
            (target / KEYS_DIRECTORY).mkdir()
            write_json_atomic(
                target / MANIFEST_FILE,
                {"format": KEYRING_FORMAT, "owner": owner, "key_type": key_type, "keys": []},
            )
        except BaseException:
            shutil.rmtree(target, ignore_errors=True)
            raise
        return cls(target)

    @classmethod
    def open(cls, path: Path) -> "Keyring":
        """Open an existing keyring; the manifest is checked.

        Raises:
            KeystoreError: the directory is not a valid keyring.
        """
        keyring = cls(path)
        keyring._load()
        return keyring

    # ------------------------------------------------------------------ #
    # Reading                                                            #
    # ------------------------------------------------------------------ #

    @property
    def path(self) -> Path:
        return self._path

    @property
    def owner(self) -> str:
        return self._load()["owner"]

    @property
    def key_type(self) -> str:
        return self._load()["key_type"]

    def entries(self) -> list[KeyEntry]:
        """Every key of the keyring, oldest first."""
        return [_entry(raw) for raw in self._load()["keys"]]

    def active_entry(self) -> Optional[KeyEntry]:
        """The key used for new work, or ``None`` if the keyring has none."""
        for entry in self.entries():
            if entry.status == STATUS_ACTIVE:
                return entry
        return None

    def entry(self, key_id: str) -> KeyEntry:
        """The entry for ``key_id``.

        Raises:
            KeystoreError: the keyring has no such key.
        """
        for entry in self.entries():
            if entry.key_id == key_id:
                return entry
        raise KeystoreError("the keyring has no key with that key_id")

    # ------------------------------------------------------------------ #
    # Using keys                                                         #
    # ------------------------------------------------------------------ #

    def rotate(self, private_key: PrivateKey, password: Optional[Password] = None) -> KeyEntry:
        """Store ``private_key`` as the new active key and retire the previous one.

        This is also how the first key is added to an empty keyring.  The new
        key gets its own keystore, protected by ``password`` (asked with
        ``getpass`` when ``None``).

        Raises:
            KeystoreError: the key type does not match the keyring, or the key is
                already in the keyring.
            InvalidKeyError: ``private_key`` is not an X25519 or Ed25519 key.
        """
        manifest = self._load()
        key_type, key_id = _describe_key(private_key)
        if key_type != manifest["key_type"]:
            raise KeystoreError(f"this keyring holds {manifest['key_type']} keys, not {key_type}")
        if any(raw["key_id"] == key_id for raw in manifest["keys"]):
            raise KeystoreError("that key is already in the keyring")

        keystore = self._keystore_path(key_id)
        create_keystore(keystore, private_key, password, owner=manifest["owner"])

        now = now_utc()
        for raw in manifest["keys"]:
            if raw["status"] == STATUS_ACTIVE:
                raw["status"] = STATUS_RETIRED
                raw["retired_at"] = now
        manifest["keys"].append(
            {"key_id": key_id, "status": STATUS_ACTIVE, "created": now, "retired_at": None}
        )
        self._save(manifest, undo_keystore=keystore)
        return self.entry(key_id)

    def unlock_active(self, password: Optional[Password] = None) -> PrivateKey:
        """Unlock the active key, for new work.

        Raises:
            KeystoreError: the keyring has no active key.
            KeystoreAccessError: wrong password, or the keystore is modified.
        """
        entry = self.active_entry()
        if entry is None:
            raise KeystoreError("the keyring has no active key; rotate to add one")
        return self._unlock(entry, password)

    def unlock(self, key_id: str, password: Optional[Password] = None) -> PrivateKey:
        """Unlock any key of the keyring by ``key_id``; used to open old files.

        Raises:
            KeystoreError: the keyring has no such key.
            KeystoreAccessError: wrong password, or the keystore is modified.
        """
        return self._unlock(self.entry(key_id), password)

    # ------------------------------------------------------------------ #
    # Internals                                                          #
    # ------------------------------------------------------------------ #

    def _keystore_path(self, key_id: str) -> Path:
        return self._path / KEYS_DIRECTORY / key_id

    def _unlock(self, entry: KeyEntry, password: Optional[Password]) -> PrivateKey:
        return unlock_private_key(
            self._keystore_path(entry.key_id), password, expected_key_type=self.key_type
        )

    def _load(self) -> dict[str, Any]:
        try:
            manifest = read_json(self._path / MANIFEST_FILE)
        except (OSError, ValueError):
            manifest = None
        if not _manifest_is_valid(manifest):
            raise KeystoreError("not a valid keyring: the manifest is missing or malformed")
        return manifest

    def _save(self, manifest: dict[str, Any], undo_keystore: Optional[Path] = None) -> None:
        try:
            write_json_atomic(self._path / MANIFEST_FILE, manifest)
        except OSError:
            failed = True
        else:
            failed = False
        if failed:
            if undo_keystore is not None:
                shutil.rmtree(undo_keystore, ignore_errors=True)
            raise KeystoreError("the keyring manifest cannot be written")


def _entry(raw: dict[str, Any]) -> KeyEntry:
    return KeyEntry(
        key_id=raw["key_id"],
        status=raw["status"],
        created=raw["created"],
        retired_at=raw["retired_at"],
    )


def _manifest_is_valid(manifest: Any) -> bool:
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_FIELDS:
        return False
    if (
        manifest["format"] != KEYRING_FORMAT
        or not isinstance(manifest["owner"], str)
        or not manifest["owner"]
        or manifest["key_type"] not in _KEY_TYPES
        or not isinstance(manifest["keys"], list)
    ):
        return False
    seen: set[str] = set()
    active = 0
    for raw in manifest["keys"]:
        if not isinstance(raw, dict) or set(raw) != _ENTRY_FIELDS:
            return False
        if (
            not isinstance(raw["key_id"], str)
            or not _KEY_ID_RE.fullmatch(raw["key_id"])
            or raw["key_id"] in seen
            or raw["status"] not in _STATUSES
            or not isinstance(raw["created"], str)
            or not (raw["retired_at"] is None or isinstance(raw["retired_at"], str))
        ):
            return False
        seen.add(raw["key_id"])
        active += raw["status"] == STATUS_ACTIVE
    return active <= 1
