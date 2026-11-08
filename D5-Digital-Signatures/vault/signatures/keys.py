"""Ed25519 signing keys and signer identification (D5)."""

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


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
