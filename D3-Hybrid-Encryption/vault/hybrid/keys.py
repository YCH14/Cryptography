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
]

_FINGERPRINT_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")


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

    try:
        loaded = serialization.load_pem_private_key(
            raw,
            password=bytes(password) if password is not None else None,
        )
    except (ValueError, TypeError) as exc:
        raise InvalidKeyError("invalid PEM private key data or incorrect password") from exc

    return validate_x25519_private_key(loaded)


def save_public_key_pem(pub_key: X25519PublicKey, path: Path) -> Path:
    """Write ``pub_key`` in PEM format to ``path``."""
    target = Path(path)
    pem = export_public_key_pem(pub_key)
    target.write_bytes(pem)
    return target


def save_private_key_pem(
    priv_key: X25519PrivateKey,
    path: Path,
    password: Optional[bytes] = None,
) -> Path:
    """Write ``priv_key`` in PEM format to ``path`` with mode ``0600``."""
    target = Path(path)
    pem = export_private_key_pem(priv_key, password=password)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(target, flags, 0o600)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    return target


def load_public_key_file(path: Path) -> X25519PublicKey:
    """Read and validate an :class:`X25519PublicKey` from a PEM file at ``path``."""
    return load_public_key_pem(Path(path).read_bytes())


def load_private_key_file(
    path: Path,
    password: Optional[bytes] = None,
) -> X25519PrivateKey:
    """Read and validate an :class:`X25519PrivateKey` from a PEM file at ``path``."""
    return load_private_key_pem(Path(path).read_bytes(), password=password)


# Convenient aliases
import_public_key_pem = load_public_key_pem
import_private_key_pem = load_private_key_pem
save_public_key = save_public_key_pem
save_private_key = save_private_key_pem
load_public_key = load_public_key_file
load_private_key = load_private_key_file

