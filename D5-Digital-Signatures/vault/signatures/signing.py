"""Sign and verify D3 hybrid containers with Ed25519 (D5).

Flow
----
Sign:    Encrypt (D3) -> add ``signer_id`` -> Hash (SHA-256) -> Sign (Ed25519) -> Store
Verify:  Read -> Hash (SHA-256) -> Verify (Ed25519) -> only then Decrypt (D3)

What is signed
--------------
The SHA-256 digest of the canonical JSON of the whole container **except the
``signature`` field**.  That covers every field of the D3 container (magic,
version, algorithm identifiers, timestamp, filename, ``metadata``,
``recipients``, ``nonce``, ``ciphertext``, ``tag``) plus ``signer_id``.

Encoding
--------
Ed25519 as specified in RFC 8032; the 64-byte signature is stored as Base64
(RFC 4648), like the other binary fields of the container.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from vault.exceptions import (
    InvalidKeyError,
    MissingSignatureError,
    SignatureVerificationError,
)
from vault.hybrid.encryption import decrypt_bytes_hybrid
from vault.signatures.keys import get_signer_id

__all__ = ["sign_container", "verify_and_decrypt"]


def _canonical_json(value: Any) -> bytes:
    """Deterministic JSON: sorted keys, compact separators (same rules as D3)."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _digest_to_sign(container: dict[str, Any]) -> bytes:
    """Hash step: SHA-256 over every container field except the signature."""
    signed_fields = {k: v for k, v in container.items() if k != "signature"}
    return hashlib.sha256(_canonical_json(signed_fields)).digest()


def sign_container(container_bytes: bytes, signer_private_key: Ed25519PrivateKey) -> bytes:
    """Add ``signer_id`` and ``signature`` to a D3 container and return it.

    Args:
        container_bytes: Output of ``encrypt_bytes_hybrid`` (the encrypted container).
        signer_private_key: The sender's Ed25519 private key.
    """
    if not isinstance(signer_private_key, Ed25519PrivateKey):
        raise InvalidKeyError("signer_private_key must be an Ed25519 private key")

    container = json.loads(container_bytes)
    container["signer_id"] = get_signer_id(signer_private_key.public_key())
    container["signature"] = base64.b64encode(
        signer_private_key.sign(_digest_to_sign(container))
    ).decode("ascii")
    return _canonical_json(container)


def _signature_is_valid(
    container: Any, signature_b64: Any, signer_public_key: Ed25519PublicKey
) -> bool:
    try:
        if container.get("signer_id") != get_signer_id(signer_public_key):
            return False
        signature = base64.b64decode(signature_b64, validate=True)
        signer_public_key.verify(signature, _digest_to_sign(container))
        return True
    except (InvalidSignature, binascii.Error, TypeError, ValueError):
        return False


def verify_and_decrypt(
    container_bytes: bytes,
    signer_public_key: Ed25519PublicKey,
    recipient_id: Optional[str],
    recipient_private_key: RSAPrivateKey,
) -> bytes:
    """Verify the signature first; only if it is valid, decrypt the container.

    Raises:
        MissingSignatureError: the container has no signature.
        SignatureVerificationError: the signature is invalid, the container was
            modified, or it was signed by a different key.  Nothing is decrypted.
        DecryptionFailedError: the signature is valid but decryption fails (D3).
    """
    if not isinstance(signer_public_key, Ed25519PublicKey):
        raise InvalidKeyError("signer_public_key must be an Ed25519 public key")

    try:
        container = json.loads(container_bytes)
    except (TypeError, ValueError):
        container = None
    if not isinstance(container, dict):
        raise SignatureVerificationError()

    signature_b64 = container.get("signature")
    if not signature_b64:
        raise MissingSignatureError()

    # Verify BEFORE decrypting: an invalid container never reaches the D3 code.
    if not _signature_is_valid(container, signature_b64, signer_public_key):
        raise SignatureVerificationError()

    encrypted_only = {
        k: v for k, v in container.items() if k not in ("signature", "signer_id")
    }
    return decrypt_bytes_hybrid(
        _canonical_json(encrypted_only), recipient_id, recipient_private_key
    )
