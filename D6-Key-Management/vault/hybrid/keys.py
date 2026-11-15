"""RSA key management and public-key fingerprinting for Hybrid Encryption (D3).

This module provides:
- Generation of RSA key pairs (minimum 2048 bits; 3072/4096 bits recommended).
- PEM import/export for public (``SubjectPublicKeyInfo``) and private (``PKCS8``) keys.
- Deterministic, collision-resistant SHA-256 public key fingerprinting over the
  canonical DER ``SubjectPublicKeyInfo`` encoding.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Final, NamedTuple, Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from vault.exceptions import InvalidKeyError

__all__ = [
    "MIN_RSA_KEY_SIZE",
    "DEFAULT_RSA_KEY_SIZE",
    "RECOMMENDED_RSA_KEY_SIZE",
    "RSA_PUBLIC_EXPONENT",
    "RSAKeyPair",
    "generate_rsa_keypair",
    "get_public_key_fingerprint",
    "looks_like_fingerprint",
    "validate_rsa_public_key",
    "validate_rsa_private_key",
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

MIN_RSA_KEY_SIZE: Final[int] = 2048
"""Minimum permitted RSA modulus length in bits."""

DEFAULT_RSA_KEY_SIZE: Final[int] = 2048
"""Default RSA modulus length in bits for :func:`generate_rsa_keypair`."""

RECOMMENDED_RSA_KEY_SIZE: Final[int] = 3072
"""Recommended RSA modulus length in bits for long-term protection."""

RSA_PUBLIC_EXPONENT: Final[int] = 65537
"""Standard Fermat prime F4 public exponent (0x10001)."""

_FINGERPRINT_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")


def looks_like_fingerprint(value: object) -> bool:
    """Return ``True`` if ``value`` has the exact shape of a key fingerprint.

    A fingerprint is always 64 lowercase hexadecimal characters (SHA-256).
    This shape is *reserved*: recipient IDs may never have it, which keeps the
    two identifier namespaces (logical ``id`` vs. key ``fingerprint``) disjoint
    and makes every recipient lookup unambiguous.
    """
    return isinstance(value, str) and _FINGERPRINT_RE.fullmatch(value) is not None


class RSAKeyPair(NamedTuple):
    """An RSA key pair supporting both tuple unpacking ``(priv, pub)`` and named attributes."""

    private_key: RSAPrivateKey
    public_key: RSAPublicKey


def validate_rsa_public_key(pub_key: object) -> RSAPublicKey:
    """Validate that ``pub_key`` is an :class:`RSAPublicKey` of at least 2048 bits.

    Raises:
        InvalidKeyError: If ``pub_key`` is not an RSA public key or is smaller
            than :data:`MIN_RSA_KEY_SIZE`.
    """
    if not isinstance(pub_key, RSAPublicKey):
        raise InvalidKeyError("public key must be an RSAPublicKey instance")
    if pub_key.key_size < MIN_RSA_KEY_SIZE:
        raise InvalidKeyError(
            f"RSA key size must be at least {MIN_RSA_KEY_SIZE} bits, got {pub_key.key_size}"
        )
    return pub_key


def validate_rsa_private_key(priv_key: object) -> RSAPrivateKey:
    """Validate that ``priv_key`` is an :class:`RSAPrivateKey` of at least 2048 bits.

    Raises:
        InvalidKeyError: If ``priv_key`` is not an RSA private key or is smaller
            than :data:`MIN_RSA_KEY_SIZE`.
    """
    if not isinstance(priv_key, RSAPrivateKey):
        raise InvalidKeyError("private key must be an RSAPrivateKey instance")
    if priv_key.key_size < MIN_RSA_KEY_SIZE:
        raise InvalidKeyError(
            f"RSA key size must be at least {MIN_RSA_KEY_SIZE} bits, got {priv_key.key_size}"
        )
    return priv_key


def generate_rsa_keypair(key_size: int = DEFAULT_RSA_KEY_SIZE) -> RSAKeyPair:
    """Generate a fresh RSA key pair ``(private_key, public_key)``.

    Args:
        key_size: RSA modulus length in bits (minimum 2048; 3072 or 4096 recommended).

    Returns:
        An :class:`RSAKeyPair` ``(private_key, public_key)``.

    Raises:
        InvalidKeyError: If ``key_size`` is not an integer or is less than 2048.
    """
    if type(key_size) is not int or key_size < MIN_RSA_KEY_SIZE:
        raise InvalidKeyError(
            f"RSA key_size must be an integer >= {MIN_RSA_KEY_SIZE}, got {key_size!r}"
        )
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=key_size,
    )
    return RSAKeyPair(private_key=private_key, public_key=private_key.public_key())


def get_public_key_fingerprint(pub_key: RSAPublicKey) -> str:
    """Return the lowercase hex-encoded SHA-256 fingerprint of ``pub_key``.

    The digest is computed over the canonical ASN.1 DER ``SubjectPublicKeyInfo``
    (SPKI) representation of the RSA public key, providing deterministic,
    collision-resistant recipient key identification independent of PEM headers
    or whitespace.

    Args:
        pub_key: Recipient's :class:`RSAPublicKey`.

    Returns:
        64-character lowercase hexadecimal SHA-256 digest string.

    Raises:
        InvalidKeyError: If ``pub_key`` is not a valid :class:`RSAPublicKey`
            meeting the minimum key size requirement.
    """
    validated = validate_rsa_public_key(pub_key)
    spki_der = validated.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


def export_public_key_pem(pub_key: RSAPublicKey) -> bytes:
    """Serialize an :class:`RSAPublicKey` to PEM (``SubjectPublicKeyInfo``) bytes."""
    validated = validate_rsa_public_key(pub_key)
    return validated.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def export_private_key_pem(
    priv_key: RSAPrivateKey,
    password: Optional[bytes] = None,
) -> bytes:
    """Serialize an :class:`RSAPrivateKey` to PEM (``PKCS8``) bytes.

    Args:
        priv_key: RSA private key to export.
        password: Optional passphrase bytes to encrypt the PKCS#8 container.
            If ``None``, the key is exported unencrypted.
    """
    validated = validate_rsa_private_key(priv_key)
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


def load_public_key_pem(pem_data: Union[bytes, str]) -> RSAPublicKey:
    """Load and validate an :class:`RSAPublicKey` from PEM data."""
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

    return validate_rsa_public_key(loaded)


def load_private_key_pem(
    pem_data: Union[bytes, str],
    password: Optional[bytes] = None,
) -> RSAPrivateKey:
    """Load and validate an :class:`RSAPrivateKey` from PEM data."""
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

    return validate_rsa_private_key(loaded)


def save_public_key_pem(pub_key: RSAPublicKey, path: Path) -> Path:
    """Write ``pub_key`` in PEM format to ``path``."""
    target = Path(path)
    pem = export_public_key_pem(pub_key)
    target.write_bytes(pem)
    return target


def save_private_key_pem(
    priv_key: RSAPrivateKey,
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


def load_public_key_file(path: Path) -> RSAPublicKey:
    """Read and validate an :class:`RSAPublicKey` from a PEM file at ``path``."""
    return load_public_key_pem(Path(path).read_bytes())


def load_private_key_file(
    path: Path,
    password: Optional[bytes] = None,
) -> RSAPrivateKey:
    """Read and validate an :class:`RSAPrivateKey` from a PEM file at ``path``."""
    return load_private_key_pem(Path(path).read_bytes(), password=password)


# Convenient aliases
import_public_key_pem = load_public_key_pem
import_private_key_pem = load_private_key_pem
save_public_key = save_public_key_pem
save_private_key = save_private_key_pem
load_public_key = load_public_key_file
load_private_key = load_private_key_file

