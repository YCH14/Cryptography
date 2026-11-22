"""Ed25519 signing keys and signer identification (D5)."""

import hashlib
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vault.exceptions import InvalidKeyError
from vault.hybrid.keys import check_pem_block, read_key_file, write_key_file

_PUBLIC_LABELS = ("PUBLIC KEY",)


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 key pair (the key comes from the OS CSPRNG)."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def get_signer_id(public_key: Ed25519PublicKey) -> str:
    """Return the signer identifier: SHA-256 of the raw 32-byte public key, in hex."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def export_signer_public_key_pem(public_key: Ed25519PublicKey) -> bytes:
    """Serialize an Ed25519 public key to PEM (``SubjectPublicKeyInfo``), the one encoding accepted."""
    if not isinstance(public_key, Ed25519PublicKey):
        raise InvalidKeyError("public_key must be an Ed25519PublicKey")
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_signer_public_key_pem(pem_data: Union[bytes, str]) -> Ed25519PublicKey:
    """Load an Ed25519 public key from exactly one PEM block; any other key type is refused."""
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
    if not isinstance(loaded, Ed25519PublicKey):
        raise InvalidKeyError("the key is not an Ed25519 public key")
    return loaded


def save_signer_public_key_file(public_key: Ed25519PublicKey, path: Path) -> Path:
    """Write an Ed25519 public key to a new ``.pem`` file (never overwrites)."""
    return write_key_file(path, export_signer_public_key_pem(public_key), 0o644)


def load_signer_public_key_file(path: Path) -> Ed25519PublicKey:
    """Read an Ed25519 public key from a small regular ``.pem`` file."""
    return load_signer_public_key_pem(read_key_file(path))
