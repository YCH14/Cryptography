"""X25519 key management and public-key fingerprinting for Hybrid Encryption (D3).

This module provides:
- Generation of X25519 key pairs (the recipient keys of the ECIES key wrapping).
- PEM import/export for public (``SubjectPublicKeyInfo``) and private (``PKCS8``) keys.
- Deterministic, collision-resistant SHA-256 public key fingerprinting over the
  raw 32-byte X25519 public key (the key identifier chosen by the team).
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Final, NamedTuple, Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from vault.exceptions import InvalidKeyError

__all__ = [
    "X25519KeyPair",
    "generate_x25519_keypair",
    "get_public_key_fingerprint",
    "looks_like_fingerprint",
    "validate_x25519_public_key",
    "validate_x25519_private_key",
    "export_public_key_pem",
    "export_private_key_pem",
    "load_public_key_pem",
    "load_private_key_pem",
    "import_public_key_pem",
    "import_private_key_pem",
    "save_public_key_pem",
    "save_private_key_pem",
    "load_public_key_file",
    "load_private_key_file",
    "save_public_key",
    "save_private_key",
    "load_public_key",
    "load_private_key",
    "KEY_FILE_SUFFIX",
    "MAX_KEY_FILE_SIZE",
    "check_pem_block",
    "read_key_file",
    "write_key_file",
]

_FINGERPRINT_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")

KEY_FILE_SUFFIX: Final[str] = ".pem"
"""The only extension accepted for a key file.  It is a guard against mistakes, not a security
boundary (any file can be renamed): the real checks are the ones in :func:`check_pem_block`."""

MAX_KEY_FILE_SIZE: Final[int] = 16 * 1024
"""A key file larger than this is refused without being read in full (a PEM key is under 1 KiB)."""

_PUBLIC_LABELS: Final[tuple[str, ...]] = ("PUBLIC KEY",)
_PRIVATE_LABELS: Final[tuple[str, ...]] = ("PRIVATE KEY", "ENCRYPTED PRIVATE KEY")

_PEM_BLOCK_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"-----BEGIN ([A-Z ]+)-----\r?\n((?:[A-Za-z0-9+/=]+\r?\n)+)-----END \1-----\r?\n?"
)


def looks_like_fingerprint(value: object) -> bool:
    """Return ``True`` if ``value`` has the exact shape of a key fingerprint.

    A fingerprint is always 64 lowercase hexadecimal characters (SHA-256).
    This shape is *reserved*: recipient IDs may never have it, which keeps the
    two identifier namespaces (logical ``id`` vs. key ``fingerprint``) disjoint
    and makes every recipient lookup unambiguous.
    """
    return isinstance(value, str) and _FINGERPRINT_RE.fullmatch(value) is not None


class X25519KeyPair(NamedTuple):
    """An X25519 key pair supporting both tuple unpacking ``(priv, pub)`` and named attributes."""

    private_key: X25519PrivateKey
    public_key: X25519PublicKey


def validate_x25519_public_key(pub_key: object) -> X25519PublicKey:
    """Validate that ``pub_key`` is an :class:`X25519PublicKey`.

    Raises:
        InvalidKeyError: If ``pub_key`` is not an X25519 public key.
    """
    if not isinstance(pub_key, X25519PublicKey):
        raise InvalidKeyError("public key must be an X25519PublicKey instance")
    return pub_key


def validate_x25519_private_key(priv_key: object) -> X25519PrivateKey:
    """Validate that ``priv_key`` is an :class:`X25519PrivateKey`.

    Raises:
        InvalidKeyError: If ``priv_key`` is not an X25519 private key.
    """
    if not isinstance(priv_key, X25519PrivateKey):
        raise InvalidKeyError("private key must be an X25519PrivateKey instance")
    return priv_key


def generate_x25519_keypair() -> X25519KeyPair:
    """Generate a fresh X25519 key pair ``(private_key, public_key)``."""
    private_key = X25519PrivateKey.generate()
    return X25519KeyPair(private_key=private_key, public_key=private_key.public_key())


def public_key_raw_bytes(pub_key: X25519PublicKey) -> bytes:
    """Return the raw 32-byte encoding of an X25519 public key."""
    validated = validate_x25519_public_key(pub_key)
    return validated.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def get_public_key_fingerprint(pub_key: X25519PublicKey) -> str:
    """Return the lowercase hex-encoded SHA-256 fingerprint of ``pub_key``.

    The digest is computed over the raw 32-byte X25519 public key, which is the
    key identifier chosen by the team for every key type (SHA-256 of the public
    bytes). It is deterministic, collision-resistant and independent of PEM
    headers or whitespace.

    Raises:
        InvalidKeyError: If ``pub_key`` is not an :class:`X25519PublicKey`.
    """
    return hashlib.sha256(public_key_raw_bytes(pub_key)).hexdigest()


def check_pem_block(data: bytes, allowed_labels: tuple[str, ...]) -> bytes:
    """Accept only a single, well-formed PEM block with an expected label.

    The whole input must be exactly one ``-----BEGIN <label>-----`` ... ``-----END <label>-----``
    block of base64 lines: no text before or after it, no second block, no non-ASCII bytes.
    The parser of ``cryptography`` is more tolerant (it skips surrounding text), so this check
    restricts what is accepted to the one encoding this project writes.

    Raises:
        InvalidKeyError: the data is not exactly one PEM block with an allowed label.
    """
    if len(data) > MAX_KEY_FILE_SIZE:
        raise InvalidKeyError("key data is too large")
    match = _PEM_BLOCK_RE.fullmatch(data)
    if match is None or match.group(1).decode("ascii") not in allowed_labels:
        raise InvalidKeyError("key data must be a single PEM block with the expected label")
    return data


def _check_key_path(path: Path) -> Path:
    target = Path(path)
    if target.suffix.lower() != KEY_FILE_SUFFIX:
        raise InvalidKeyError("a key file must have the .pem extension")
    return target


def read_key_file(path: Path) -> bytes:
    """Read a key file, refusing anything that is not a small regular ``.pem`` file.

    Symbolic links, directories, devices and files larger than :data:`MAX_KEY_FILE_SIZE` are
    refused; the file is never read in full before its size is known to be acceptable.
    """
    target = _check_key_path(path)
    try:
        if target.is_symlink():
            raise InvalidKeyError("a key file must not be a symbolic link")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise InvalidKeyError("the key file cannot be opened") from exc
    problem = None
    data = b""
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            problem = "a key file must be a regular file"
        else:
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                data = handle.read(MAX_KEY_FILE_SIZE + 1)
    except OSError:
        problem = "the key file cannot be read"
    finally:
        if descriptor != -1:
            os.close(descriptor)
    if problem is not None:
        raise InvalidKeyError(problem)
    if len(data) > MAX_KEY_FILE_SIZE:
        raise InvalidKeyError("the key file is too large")
    return data


def write_key_file(path: Path, data: bytes, mode: int) -> Path:
    """Create a new ``.pem`` key file; an existing file (or link) is never overwritten."""
    target = _check_key_path(path)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(target, flags, mode)
    except FileExistsError as exc:
        raise InvalidKeyError("the key file already exists and is not overwritten") from exc
    except OSError as exc:
        raise InvalidKeyError("the key file cannot be created") from exc
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)
    return target


def export_public_key_pem(pub_key: X25519PublicKey) -> bytes:
    """Serialize an :class:`X25519PublicKey` to PEM (``SubjectPublicKeyInfo``) bytes."""
    validated = validate_x25519_public_key(pub_key)
    return validated.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def export_private_key_pem(
    priv_key: X25519PrivateKey,
    password: Optional[bytes] = None,
) -> bytes:
    """Serialize an :class:`X25519PrivateKey` to PEM (``PKCS8``) bytes.

    Args:
        priv_key: X25519 private key to export.
        password: Optional passphrase bytes to encrypt the PKCS#8 container.
            If ``None``, the key is exported unencrypted.
    """
    validated = validate_x25519_private_key(priv_key)
    if password is not None:
        if not isinstance(password, (bytes, bytearray, memoryview)) or len(password) == 0:
            raise InvalidKeyError("password must be non-empty bytes when provided")
        encryption: serialization.KeySerializationEncryption = (
            serialization.BestAvailableEncryption(bytes(password))
        )
    else:
        encryption = serialization.NoEncryption()

    return validated.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def load_public_key_pem(pem_data: Union[bytes, str]) -> X25519PublicKey:
    """Load and validate an :class:`X25519PublicKey` from PEM data."""
    if isinstance(pem_data, str):
        raw = pem_data.encode("utf-8")
    elif isinstance(pem_data, (bytes, bytearray, memoryview)):
        raw = bytes(pem_data)
    else:
        raise InvalidKeyError("pem_data must be bytes or str")
    check_pem_block(raw, _PUBLIC_LABELS)

    try:
        loaded = serialization.load_pem_public_key(raw)
    except (ValueError, TypeError) as exc:
        raise InvalidKeyError("invalid PEM public key data") from exc

    return validate_x25519_public_key(loaded)


def load_private_key_pem(
    pem_data: Union[bytes, str],
    password: Optional[bytes] = None,
) -> X25519PrivateKey:
    """Load and validate an :class:`X25519PrivateKey` from PEM data."""
    if isinstance(pem_data, str):
        raw = pem_data.encode("utf-8")
    elif isinstance(pem_data, (bytes, bytearray, memoryview)):
        raw = bytes(pem_data)
    else:
        raise InvalidKeyError("pem_data must be bytes or str")

    if password is not None and not isinstance(password, (bytes, bytearray, memoryview)):
        raise InvalidKeyError("password must be bytes or None")
    check_pem_block(raw, _PRIVATE_LABELS)

    try:
        loaded = serialization.load_pem_private_key(
            raw,
            password=bytes(password) if password is not None else None,
        )
    except (ValueError, TypeError) as exc:
        raise InvalidKeyError("invalid PEM private key data or incorrect password") from exc

    return validate_x25519_private_key(loaded)


def save_public_key_pem(pub_key: X25519PublicKey, path: Path) -> Path:
    """Write ``pub_key`` in PEM format to a new ``.pem`` file (never overwrites)."""
    return write_key_file(path, export_public_key_pem(pub_key), 0o644)


def save_private_key_pem(
    priv_key: X25519PrivateKey,
    path: Path,
    password: Optional[bytes] = None,
) -> Path:
    """Write ``priv_key`` encrypted with ``password`` to a new ``.pem`` file with mode ``0600``.

    A private key is never written to disk in the clear: the password is required.  The
    protected place for a private key is the D6 keystore; this file is for exporting a key
    that is encrypted too.
    """
    if not isinstance(password, (bytes, bytearray, memoryview)) or len(password) == 0:
        raise InvalidKeyError("a private key file must be encrypted: a non-empty password is required")
    return write_key_file(path, export_private_key_pem(priv_key, password=password), 0o600)


def load_public_key_file(path: Path) -> X25519PublicKey:
    """Read and validate an :class:`X25519PublicKey` from a ``.pem`` file at ``path``."""
    return load_public_key_pem(read_key_file(path))


def load_private_key_file(
    path: Path,
    password: Optional[bytes] = None,
) -> X25519PrivateKey:
    """Read and validate an :class:`X25519PrivateKey` from a ``.pem`` file at ``path``."""
    return load_private_key_pem(read_key_file(path), password=password)


# Convenient aliases
import_public_key_pem = load_public_key_pem
import_private_key_pem = load_private_key_pem
save_public_key = save_public_key_pem
save_private_key = save_private_key_pem
load_public_key = load_public_key_file
load_private_key = load_private_key_file

