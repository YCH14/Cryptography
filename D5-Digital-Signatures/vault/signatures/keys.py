"""Ed25519 key management and signer fingerprinting for Digital Signatures (D5).

This module provides:
- Generation of Ed25519 signing key pairs (32-byte private seed, 32-byte public key).
- PEM import/export for public (``SubjectPublicKeyInfo``) and private (``PKCS8``) keys,
  plus raw 32-byte public key serialization.
- Deterministic, collision-resistant SHA-256 signer public-key fingerprinting
  over the canonical ASN.1 DER ``SubjectPublicKeyInfo`` encoding (as well as
  raw 32-byte public-key fingerprinting).
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Final, NamedTuple, Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vault.exceptions import InvalidKeyError
from vault.hybrid.keys import looks_like_fingerprint

__all__ = [
    "ED25519_PUBLIC_KEY_SIZE",
    "ED25519_PRIVATE_KEY_SIZE",
    "ED25519_SIGNATURE_SIZE",
    "Ed25519KeyPair",
    "generate_ed25519_keypair",
    "validate_ed25519_public_key",
    "validate_ed25519_private_key",
    "get_signer_public_key_fingerprint",
    "get_ed25519_public_key_fingerprint",
    "get_signer_raw_key_fingerprint",
    "export_ed25519_public_key_pem",
    "export_ed25519_private_key_pem",
    "load_ed25519_public_key_pem",
    "load_ed25519_private_key_pem",
    "export_ed25519_public_key_raw",
    "load_ed25519_public_key_raw",
    "save_ed25519_public_key_pem",
    "save_ed25519_private_key_pem",
    "load_ed25519_public_key_file",
    "load_ed25519_private_key_file",
    "looks_like_fingerprint",
]

ED25519_PUBLIC_KEY_SIZE: Final[int] = 32
"""Length in bytes of a raw Ed25519 public key (256 bits)."""

ED25519_PRIVATE_KEY_SIZE: Final[int] = 32
"""Length in bytes of a raw Ed25519 private seed (256 bits)."""

ED25519_SIGNATURE_SIZE: Final[int] = 64
"""Length in bytes of an Ed25519 signature (512 bits)."""


class Ed25519KeyPair(NamedTuple):
    """An Ed25519 key pair supporting both tuple unpacking ``(priv, pub)`` and named attributes."""

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey


def validate_ed25519_public_key(pub_key: object) -> Ed25519PublicKey:
    """Validate that ``pub_key`` is an :class:`Ed25519PublicKey` instance.

    Raises:
        InvalidKeyError: If ``pub_key`` is not an :class:`Ed25519PublicKey`.
    """
    if not isinstance(pub_key, Ed25519PublicKey):
        raise InvalidKeyError("signer public key must be an Ed25519PublicKey instance")
    return pub_key


def validate_ed25519_private_key(priv_key: object) -> Ed25519PrivateKey:
    """Validate that ``priv_key`` is an :class:`Ed25519PrivateKey` instance.

    Raises:
        InvalidKeyError: If ``priv_key`` is not an :class:`Ed25519PrivateKey`.
    """
    if not isinstance(priv_key, Ed25519PrivateKey):
        raise InvalidKeyError("signer private key must be an Ed25519PrivateKey instance")
    return priv_key


def generate_ed25519_keypair() -> Ed25519KeyPair:
    """Generate a fresh Ed25519 signing key pair ``(private_key, public_key)``."""
    private_key = Ed25519PrivateKey.generate()
    return Ed25519KeyPair(private_key=private_key, public_key=private_key.public_key())


def get_signer_public_key_fingerprint(pub_key: Ed25519PublicKey) -> str:
    """Return the lowercase hex-encoded SHA-256 fingerprint of ``pub_key``.

    The digest is computed over the canonical ASN.1 DER ``SubjectPublicKeyInfo``
    (SPKI) representation of the Ed25519 public key, matching the convention
    used for RSA public keys in Deliverable D3.

    Args:
        pub_key: Signer's :class:`Ed25519PublicKey`.

    Returns:
        64-character lowercase hexadecimal SHA-256 digest string.

    Raises:
        InvalidKeyError: If ``pub_key`` is not a valid :class:`Ed25519PublicKey`.
    """
    validated = validate_ed25519_public_key(pub_key)
    spki_der = validated.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


get_ed25519_public_key_fingerprint = get_signer_public_key_fingerprint


def get_signer_raw_key_fingerprint(pub_key: Ed25519PublicKey) -> str:
    """Return the lowercase hex-encoded SHA-256 fingerprint over the raw 32-byte Ed25519 public key."""
    raw_bytes = export_ed25519_public_key_raw(pub_key)
    return hashlib.sha256(raw_bytes).hexdigest()


def export_ed25519_public_key_raw(pub_key: Ed25519PublicKey) -> bytes:
    """Serialize an :class:`Ed25519PublicKey` to its canonical 32-byte raw representation."""
    validated = validate_ed25519_public_key(pub_key)
    return validated.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_ed25519_public_key_raw(raw_bytes: bytes) -> Ed25519PublicKey:
    """Load an :class:`Ed25519PublicKey` from its 32-byte raw representation."""
    if not isinstance(raw_bytes, (bytes, bytearray, memoryview)):
        raise InvalidKeyError("raw_bytes must be a bytes-like object")
    raw = bytes(raw_bytes)
    if len(raw) != ED25519_PUBLIC_KEY_SIZE:
        raise InvalidKeyError(
            f"Ed25519 raw public key must be exactly {ED25519_PUBLIC_KEY_SIZE} bytes, got {len(raw)}"
        )
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise InvalidKeyError("invalid raw Ed25519 public key bytes") from exc


def export_ed25519_public_key_pem(pub_key: Ed25519PublicKey) -> bytes:
    """Serialize an :class:`Ed25519PublicKey` to PEM (``SubjectPublicKeyInfo``) bytes."""
    validated = validate_ed25519_public_key(pub_key)
    return validated.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def export_ed25519_private_key_pem(
    priv_key: Ed25519PrivateKey,
    password: Optional[bytes] = None,
) -> bytes:
    """Serialize an :class:`Ed25519PrivateKey` to PEM (``PKCS8``) bytes.

    Args:
        priv_key: Ed25519 private key to export.
        password: Optional passphrase bytes to encrypt the PKCS#8 container.
            If ``None``, the key is exported unencrypted.
    """
    validated = validate_ed25519_private_key(priv_key)
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


def load_ed25519_public_key_pem(pem_data: Union[bytes, str]) -> Ed25519PublicKey:
    """Load and validate an :class:`Ed25519PublicKey` from PEM data."""
    if isinstance(pem_data, str):
        raw = pem_data.encode("utf-8")
    elif isinstance(pem_data, (bytes, bytearray, memoryview)):
        raw = bytes(pem_data)
    else:
        raise InvalidKeyError("pem_data must be bytes or str")

    try:
        loaded = serialization.load_pem_public_key(raw)
    except (ValueError, TypeError) as exc:
        raise InvalidKeyError("invalid PEM Ed25519 public key data") from exc

    return validate_ed25519_public_key(loaded)


def load_ed25519_private_key_pem(
    pem_data: Union[bytes, str],
    password: Optional[bytes] = None,
) -> Ed25519PrivateKey:
    """Load and validate an :class:`Ed25519PrivateKey` from PEM data."""
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
        raise InvalidKeyError("invalid PEM Ed25519 private key data or incorrect password") from exc

    return validate_ed25519_private_key(loaded)


def save_ed25519_public_key_pem(pub_key: Ed25519PublicKey, path: Path) -> Path:
    """Write ``pub_key`` in PEM format to ``path``."""
    target = Path(path)
    pem = export_ed25519_public_key_pem(pub_key)
    target.write_bytes(pem)
    return target


def save_ed25519_private_key_pem(
    priv_key: Ed25519PrivateKey,
    path: Path,
    password: Optional[bytes] = None,
) -> Path:
    """Write ``priv_key`` in PEM format to ``path`` with mode ``0600``."""
    target = Path(path)
    pem = export_ed25519_private_key_pem(priv_key, password=password)
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


def load_ed25519_public_key_file(path: Path) -> Ed25519PublicKey:
    """Read and validate an :class:`Ed25519PublicKey` from a PEM file at ``path``."""
    return load_ed25519_public_key_pem(Path(path).read_bytes())


def load_ed25519_private_key_file(
    path: Path,
    password: Optional[bytes] = None,
) -> Ed25519PrivateKey:
    """Read and validate an :class:`Ed25519PrivateKey` from a PEM file at ``path``."""
    return load_ed25519_private_key_pem(Path(path).read_bytes(), password=password)

