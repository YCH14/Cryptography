"""Sign and verify D3 hybrid containers with Ed25519 (D5).

Flow
----
Sign:    Encrypt (D3) -> add ``signer_id``, ``container_id`` (and optionally
         ``document_id`` / ``document_version``) -> Hash (SHA-256) -> Sign
         (Ed25519) -> Store
Verify:  Read -> Hash (SHA-256) -> Verify (Ed25519) -> (replay check) -> only then Decrypt (D3)

What is signed
--------------
The SHA-256 digest of the canonical JSON of the whole container **except the
``signature`` field**.  That covers every field of the D3 container (magic,
version, algorithm identifiers, timestamp, filename, ``metadata``,
``recipients``, ``nonce``, ``ciphertext``, ``tag``) plus ``signer_id``,
``container_id`` and, when present, ``document_id`` and ``document_version``.

``container_id`` is a random 128-bit identifier (32 lowercase hex characters)
chosen by the signer for each container.  Because it is signed, two different
signings of the same content give two different identifiers, and a recipient
can recognise a container it has already processed.  The recipient does that
with a :class:`~vault.signatures.replay.ReplayGuard`, passed to
:func:`verify_and_decrypt`: the guard is checked after the signature is
verified and before decryption, and the container is recorded only after it
has been decrypted successfully.

Rollback
--------
A signer may also label a container with a ``document_id`` (a name for the
logical document) and a ``document_version`` (an integer that grows with each
new version).  Both are signed.  The guard remembers the highest version it
accepted for each ``(signer_id, document_id)`` and refuses an equal or lower
one, so a storage that serves an older version of a document is detected once
the recipient has accepted a newer one.

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
import os
import re
from typing import Any, Final, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from vault.exceptions import (
    InvalidKeyError,
    InvalidMetadataError,
    MissingSignatureError,
    SignatureVerificationError,
)
from vault.hybrid.encryption import decrypt_bytes_hybrid
from vault.signatures.keys import get_signer_id
from vault.signatures.replay import ReplayGuard

__all__ = [
    "CONTAINER_ID_SIZE",
    "MAX_DOCUMENT_ID_LENGTH",
    "MAX_DOCUMENT_VERSION",
    "sign_container",
    "verify_and_decrypt",
]

CONTAINER_ID_SIZE: Final[int] = 16
"""Size in bytes of the random ``container_id`` (written as hex)."""

MAX_DOCUMENT_ID_LENGTH: Final[int] = 128
MAX_DOCUMENT_VERSION: Final[int] = 2**63 - 1

_CONTAINER_ID_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{32}")

# Fields that D5 adds on top of the D3 container; they are removed before the
# container is handed to the strict D3 parser.
_ADDED_FIELDS: Final[frozenset[str]] = frozenset(
    {"signature", "signer_id", "container_id", "document_id", "document_version"}
)


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


def _document_id_is_valid(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= MAX_DOCUMENT_ID_LENGTH
        and value.isprintable()
    )


def _document_version_is_valid(value: Any) -> bool:
    return type(value) is int and 1 <= value <= MAX_DOCUMENT_VERSION


def sign_container(
    container_bytes: bytes,
    signer_private_key: Ed25519PrivateKey,
    *,
    document_id: Optional[str] = None,
    document_version: Optional[int] = None,
) -> bytes:
    """Add ``signer_id``, ``container_id`` and ``signature`` to a D3 container and return it.

    Args:
        container_bytes: Output of ``encrypt_bytes_hybrid`` (the encrypted container).
        signer_private_key: The sender's Ed25519 private key.
        document_id: Optional name of the logical document (1 to 128 printable
            characters).  Must be given together with ``document_version``.
        document_version: Optional version number of the document (an integer
            of at least 1).  Each new version of the same ``document_id`` must
            use a higher number, so a recipient can detect a rollback.

    Raises:
        InvalidKeyError: ``signer_private_key`` is not an Ed25519 private key.
        InvalidMetadataError: only one of ``document_id`` / ``document_version``
            is given, or one of them is not valid.
    """
    if not isinstance(signer_private_key, Ed25519PrivateKey):
        raise InvalidKeyError("signer_private_key must be an Ed25519 private key")
    if (document_id is None) != (document_version is None):
        raise InvalidMetadataError("document_id and document_version must be given together")
    if document_id is not None and not (
        _document_id_is_valid(document_id) and _document_version_is_valid(document_version)
    ):
        raise InvalidMetadataError(
            "document_id must be 1 to 128 printable characters and "
            "document_version an integer of at least 1"
        )

    container = json.loads(container_bytes)
    container["signer_id"] = get_signer_id(signer_private_key.public_key())
    container["container_id"] = os.urandom(CONTAINER_ID_SIZE).hex()
    if document_id is not None:
        container["document_id"] = document_id
        container["document_version"] = document_version
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


def _container_id_is_valid(value: Any) -> bool:
    return isinstance(value, str) and _CONTAINER_ID_RE.fullmatch(value) is not None


def _read_document_fields(
    container: dict[str, Any],
) -> tuple[bool, Optional[str], Optional[int]]:
    """Return ``(well_formed, document_id, document_version)``.

    Both fields absent is well formed (the container is not versioned); only
    one of them, or an invalid value, is not.
    """
    has_id = "document_id" in container
    has_version = "document_version" in container
    if not has_id and not has_version:
        return True, None, None
    document_id = container.get("document_id")
    document_version = container.get("document_version")
    well_formed = (
        has_id
        and has_version
        and _document_id_is_valid(document_id)
        and _document_version_is_valid(document_version)
    )
    return well_formed, document_id, document_version


def verify_and_decrypt(
    container_bytes: bytes,
    signer_public_key: Ed25519PublicKey,
    recipient_id: Optional[str],
    recipient_private_key: X25519PrivateKey,
    replay_guard: Optional[ReplayGuard] = None,
) -> bytes:
    """Verify the signature first; only if it is valid, decrypt the container.

    If ``replay_guard`` is given, a container that was already accepted, or an
    older version of a document that was already accepted, is refused (after
    the signature check, before any decryption), and the container is recorded
    once it has been decrypted.  Without a guard, replay and rollback are not
    detected.

    Raises:
        MissingSignatureError: the container has no signature.
        SignatureVerificationError: the signature is invalid, the container was
            modified, it was signed by a different key, or it has no valid
            ``container_id``, or its document fields are malformed.  Nothing is
            decrypted.
        ReplayDetectedError: the container was already accepted (needs a guard).
        RollbackDetectedError: an equal or newer version of the document was
            already accepted (needs a guard).
        ReplayStoreError: the guard's store cannot be read or written.
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
    if not _container_id_is_valid(container.get("container_id")):
        raise SignatureVerificationError()

    well_formed, document_id, document_version = _read_document_fields(container)
    if not well_formed:
        raise SignatureVerificationError()

    signer_id = container["signer_id"]
    container_id = container["container_id"]
    if replay_guard is not None:
        replay_guard.check(signer_id, container_id, document_id, document_version)

    encrypted_only = {k: v for k, v in container.items() if k not in _ADDED_FIELDS}
    plaintext = decrypt_bytes_hybrid(
        _canonical_json(encrypted_only), recipient_id, recipient_private_key
    )

    if replay_guard is not None:
        replay_guard.record(signer_id, container_id, document_id, document_version)
    return plaintext
