"""Password-protected key store for private keys (D6).

A private key is never stored in plaintext.  Two key types are accepted: the
X25519 key of D3 (ECIES) and the Ed25519 key of D5 (signatures).  RSA keys are
not supported.  The key is serialized as PKCS#8 (DER),
encrypted with AES-256-GCM under a key derived from the user's password with
Argon2id, and stored in a directory with this layout::

    keystore/
     ├── encrypted_private_key   nonce (12 bytes) || ciphertext || tag (16 bytes)
     ├── salt                    16 random bytes (raw)
     ├── kdf_parameters          JSON: Argon2id parameters
     └── metadata                JSON: version, owner, key_type, key_id, created

``salt``, ``kdf_parameters`` and ``metadata`` are bound to the encryption as
AES-GCM associated data (same idea as the AAD of D2/D3).  Changing any of the
four files makes the authentication tag fail, so a modified keystore never
opens.

Access
------
``unlock_private_key`` asks for the password (``getpass``) when it is not
given, derives the key, decrypts, and returns the key object.  Nothing is kept
in a module-level cache and the password is never stored.

Errors
------
Every failure to open a keystore (wrong password, modified files, missing
files) raises the same :class:`~vault.exceptions.KeystoreAccessError`, without
chaining the cause.
"""

from __future__ import annotations

import getpass
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from vault.exceptions import InvalidKeyError, KeystoreAccessError, KeystoreError
from vault.hybrid.keys import get_public_key_fingerprint, validate_x25519_private_key
from vault.signatures.keys import get_signer_id

__all__ = [
    "KEYSTORE_FILES",
    "create_keystore",
    "unlock_private_key",
    "backup_keystore",
    "restore_keystore",
]

FORMAT_NAME: Final[str] = "VKS1"
"""Format identifier bound into the AAD ("vault keystore", version 1)."""

FORMAT_VERSION: Final[int] = 1

ENCRYPTED_PRIVATE_KEY: Final[str] = "encrypted_private_key"
SALT: Final[str] = "salt"
KDF_PARAMETERS: Final[str] = "kdf_parameters"
METADATA: Final[str] = "metadata"
KEYSTORE_FILES: Final[tuple[str, ...]] = (
    ENCRYPTED_PRIVATE_KEY,
    SALT,
    KDF_PARAMETERS,
    METADATA,
)

KDF_NAME: Final[str] = "argon2id"
ARGON2_ITERATIONS: Final[int] = 3
ARGON2_LANES: Final[int] = 4
ARGON2_MEMORY_KIB: Final[int] = 65536
"""RFC 9106 second recommended option: t=3, p=4, m=2^16 KiB (64 MiB)."""

SALT_SIZE: Final[int] = 16
KEY_SIZE: Final[int] = 32
NONCE_SIZE: Final[int] = 12
TAG_SIZE: Final[int] = 16

# Upper limits accepted when reading kdf_parameters from disk, so a modified
# file cannot make the program allocate unbounded memory or time.
_MAX_ITERATIONS: Final[int] = 10
_MAX_LANES: Final[int] = 16
_MAX_MEMORY_KIB: Final[int] = 1024 * 1024

_MAX_FILE_SIZE: Final[int] = 64 * 1024
_KEY_TYPES: Final[frozenset[str]] = frozenset({"X25519", "Ed25519"})
_METADATA_FIELDS: Final[frozenset[str]] = frozenset(
    {"version", "owner", "key_type", "key_id", "created"}
)
_KDF_FIELDS: Final[frozenset[str]] = frozenset(
    {"kdf", "iterations", "lanes", "memory_cost_kib", "length"}
)

PrivateKey = Union[X25519PrivateKey, Ed25519PrivateKey]
Password = Union[str, bytes]


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #


def create_keystore(
    path: Path,
    private_key: PrivateKey,
    password: Optional[Password],
    owner: str,
) -> Path:
    """Encrypt ``private_key`` under ``password`` and write the keystore directory.

    Args:
        path: Directory to create.  It must not exist (nothing is overwritten).
        private_key: An X25519 (D3) or Ed25519 (D5) private key.
        password: The user's password; asked with ``getpass`` when ``None``.
        owner: Identifier of the key's owner (for example the D3 recipient ``id``).

    Raises:
        KeystoreError: ``path`` already exists, or ``owner`` / ``password`` is empty.
        InvalidKeyError: ``private_key`` is not an X25519 or Ed25519 private key
            (an RSA key, for example, is refused).
    """
    target = Path(path)
    if target.exists():
        raise KeystoreError("keystore already exists; refusing to overwrite it")
    if not isinstance(owner, str) or not owner:
        raise KeystoreError("owner must be a non-empty string")
    password_bytes = _password_bytes(password, confirm=password is None)
    key_type, key_id = _describe_key(private_key)

    metadata = {
        "version": FORMAT_VERSION,
        "owner": owner,
        "key_type": key_type,
        "key_id": key_id,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    kdf_parameters = {
        "kdf": KDF_NAME,
        "iterations": ARGON2_ITERATIONS,
        "lanes": ARGON2_LANES,
        "memory_cost_kib": ARGON2_MEMORY_KIB,
        "length": KEY_SIZE,
    }
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    derived_key = _derive_key(password_bytes, salt, kdf_parameters)
    plaintext = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    sealed = AESGCM(derived_key).encrypt(
        nonce, plaintext, _aad(metadata, kdf_parameters, salt)
    )
    del derived_key, plaintext

    files = {
        ENCRYPTED_PRIVATE_KEY: nonce + sealed,
        SALT: salt,
        KDF_PARAMETERS: _canonical_json(kdf_parameters),
        METADATA: _canonical_json(metadata),
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".keystore-", dir=target.parent))
    try:
        for name, data in files.items():
            _write_new_file(staging / name, data)
        os.rename(staging, target)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return target


def unlock_private_key(
    path: Path,
    password: Optional[Password] = None,
    *,
    expected_key_type: Optional[str] = None,
) -> PrivateKey:
    """Ask for the password, decrypt the private key and return it.

    The key is decrypted only for this call: nothing is cached, and the caller
    should drop the returned object as soon as it has used it.

    Args:
        path: Keystore directory.
        password: The password; asked with ``getpass`` when ``None``.
        expected_key_type: ``"X25519"`` or ``"Ed25519"``; refuses a keystore that
            holds the other type, so a key is never used for the wrong purpose.

    Raises:
        KeystoreAccessError: wrong password, or the keystore is modified,
            malformed or incomplete.
        KeystoreError: the keystore is valid but holds a different key type than
            ``expected_key_type``.
    """
    password_bytes = _password_bytes(password)
    opened = _try_unlock(Path(path), password_bytes)
    if opened is None:
        raise KeystoreAccessError()
    key_type, private_key = opened
    if expected_key_type is not None and key_type != expected_key_type:
        raise KeystoreError(
            f"keystore holds a {key_type} key, expected {expected_key_type}"
        )
    return private_key


def backup_keystore(path: Path, backup_path: Path) -> Path:
    """Copy the four keystore files to a new directory.

    The backup is exactly as protected as the keystore: it holds only the
    encrypted key, never the password or the plaintext key.

    Raises:
        KeystoreError: the keystore is incomplete or ``backup_path`` exists.
    """
    source = Path(path)
    destination = Path(backup_path)
    if destination.exists():
        raise KeystoreError("backup destination already exists; refusing to overwrite it")
    _copy_keystore(source, destination)
    return destination


def restore_keystore(
    backup_path: Path,
    path: Path,
    password: Optional[Password] = None,
) -> Path:
    """Restore a keystore from a backup, checking that it opens with ``password``.

    The backup is copied to a temporary directory and opened there first; it
    is moved into place only if that works, so a corrupted backup is never
    restored.

    Raises:
        KeystoreError: ``path`` already exists or the backup is incomplete.
        KeystoreAccessError: wrong password, or the backup is modified or malformed.
    """
    target = Path(path)
    if target.exists():
        raise KeystoreError("keystore already exists; refusing to overwrite it")
    password_bytes = _password_bytes(password)
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".restore-", dir=target.parent))
    try:
        staged_keystore = staging / "keystore"
        _copy_keystore(Path(backup_path), staged_keystore)
        if _try_unlock(staged_keystore, password_bytes) is None:
            raise KeystoreAccessError()
        os.rename(staged_keystore, target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return target


# --------------------------------------------------------------------------- #
# Internals                                                                   #
# --------------------------------------------------------------------------- #


def _canonical_json(value: Any) -> bytes:
    """Deterministic JSON: sorted keys, compact separators (same rules as D3)."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _aad(metadata: dict[str, Any], kdf_parameters: dict[str, Any], salt: bytes) -> bytes:
    """AAD bound to the AES-GCM encryption: every keystore file except the ciphertext."""
    return _canonical_json(
        {
            "format": FORMAT_NAME,
            "metadata": metadata,
            "kdf_parameters": kdf_parameters,
            "salt": salt.hex(),
        }
    )


def _password_bytes(password: Optional[Password], confirm: bool = False) -> bytes:
    if password is None:
        password = getpass.getpass("Keystore password: ")
        if confirm and getpass.getpass("Repeat password: ") != password:
            raise KeystoreError("the passwords do not match")
    if isinstance(password, str):
        password = password.encode("utf-8")
    if not isinstance(password, (bytes, bytearray)) or len(password) == 0:
        raise KeystoreError("password must be a non-empty string or bytes")
    return bytes(password)


def _derive_key(password: bytes, salt: bytes, kdf_parameters: dict[str, Any]) -> bytes:
    """Derive the 256-bit encryption key from the password with Argon2id."""
    return Argon2id(
        salt=salt,
        length=kdf_parameters["length"],
        iterations=kdf_parameters["iterations"],
        lanes=kdf_parameters["lanes"],
        memory_cost=kdf_parameters["memory_cost_kib"],
    ).derive(password)


def _describe_key(private_key: object) -> tuple[str, str]:
    """Return ``(key_type, key_id)``.

    For both types the id is the SHA-256 of the raw 32-byte public key, the
    same value D3 uses as the recipient fingerprint and D5 as the ``signer_id``.
    """
    if isinstance(private_key, X25519PrivateKey):
        validated = validate_x25519_private_key(private_key)
        return "X25519", get_public_key_fingerprint(validated.public_key())
    if isinstance(private_key, Ed25519PrivateKey):
        return "Ed25519", get_signer_id(private_key.public_key())
    raise InvalidKeyError("private_key must be an X25519 or Ed25519 private key")


def _check_metadata(metadata: Any) -> dict[str, Any]:
    if not isinstance(metadata, dict) or set(metadata) != _METADATA_FIELDS:
        raise ValueError("bad metadata")
    key_id = metadata["key_id"]
    if (
        metadata["version"] != FORMAT_VERSION
        or metadata["key_type"] not in _KEY_TYPES
        or not isinstance(metadata["owner"], str)
        or not metadata["owner"]
        or not isinstance(metadata["created"], str)
        or not isinstance(key_id, str)
        or len(key_id) != 64
        or any(c not in "0123456789abcdef" for c in key_id)
    ):
        raise ValueError("bad metadata")
    return metadata


def _check_kdf_parameters(parameters: Any) -> dict[str, Any]:
    if not isinstance(parameters, dict) or set(parameters) != _KDF_FIELDS:
        raise ValueError("bad kdf_parameters")
    numbers = [parameters[k] for k in ("iterations", "lanes", "memory_cost_kib", "length")]
    if any(type(n) is not int for n in numbers):
        raise ValueError("bad kdf_parameters")
    iterations, lanes, memory, length = numbers
    if (
        parameters["kdf"] != KDF_NAME
        or length != KEY_SIZE
        or not 1 <= iterations <= _MAX_ITERATIONS
        or not 1 <= lanes <= _MAX_LANES
        or not 8 * lanes <= memory <= _MAX_MEMORY_KIB
    ):
        raise ValueError("bad kdf_parameters")
    return parameters


def _read_file(directory: Path, name: str) -> bytes:
    with open(directory / name, "rb") as handle:
        data = handle.read(_MAX_FILE_SIZE + 1)
    if len(data) > _MAX_FILE_SIZE:
        raise ValueError("keystore file too large")
    return data


def _try_unlock(directory: Path, password: bytes) -> Optional[tuple[str, PrivateKey]]:
    """Open a keystore; return ``(key_type, key)`` or ``None`` on any failure.

    Failures are returned instead of raised so the caller can raise one generic
    error outside any ``except`` block (no exception chaining).
    """
    try:
        blob = _read_file(directory, ENCRYPTED_PRIVATE_KEY)
        salt = _read_file(directory, SALT)
        kdf_parameters = _check_kdf_parameters(json.loads(_read_file(directory, KDF_PARAMETERS)))
        metadata = _check_metadata(json.loads(_read_file(directory, METADATA)))
        if len(salt) != SALT_SIZE or len(blob) < NONCE_SIZE + TAG_SIZE:
            return None

        derived_key = _derive_key(password, salt, kdf_parameters)
        plaintext = AESGCM(derived_key).decrypt(
            blob[:NONCE_SIZE], blob[NONCE_SIZE:], _aad(metadata, kdf_parameters, salt)
        )
        del derived_key

        private_key = serialization.load_der_private_key(plaintext, password=None)
        del plaintext
        if not isinstance(private_key, (X25519PrivateKey, Ed25519PrivateKey)):
            return None
        key_type, key_id = _describe_key(private_key)
        if key_type != metadata["key_type"] or key_id != metadata["key_id"]:
            return None
        return key_type, private_key
    except (InvalidTag, OSError, ValueError, TypeError, KeyError, InvalidKeyError):
        return None


def _write_new_file(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def _copy_keystore(source: Path, destination: Path) -> None:
    """Copy the four keystore files into a new directory, atomically."""
    contents = {}
    for name in KEYSTORE_FILES:
        try:
            contents[name] = _read_file(source, name)
        except (OSError, ValueError):
            raise KeystoreError(f"keystore is incomplete: cannot read '{name}'") from None
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".copy-", dir=destination.parent))
    try:
        for name, data in contents.items():
            _write_new_file(staging / name, data)
        os.rename(staging, destination)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
