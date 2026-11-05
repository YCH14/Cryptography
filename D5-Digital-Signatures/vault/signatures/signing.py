"""Authenticated Digital Signatures & Encrypt-then-Sign Container (D5).

Pipeline (Encrypt -> Add Metadata -> Sign -> Store)
---------------------------------------------------
1. **Encrypt (D2 + D3):** A fresh 256-bit DEK (``os.urandom(32)``) is wrapped
   independently for each recipient using **RSA-OAEP-SHA256**. The plaintext is
   encrypted once with **AES-256-GCM** under a fresh 96-bit nonce
   (``os.urandom(12)``), binding all container metadata (including ``signer_id``,
   ``signer_fingerprint``, and ``signature_algorithm``) and the full
   ``recipients`` list as AAD.
2. **Add Metadata & Canonicalize:** The unsigned container fields (``magic``,
   ``version``, ``algorithm``, ``key_wrap_algorithm``, ``signature_algorithm``,
   ``timestamp``, ``signer_id``, ``signer_fingerprint``, ``filename``,
   ``metadata``, ``recipients``, ``nonce``, ``ciphertext``, and ``tag``) are
   serialized into deterministic canonical JSON bytes.
3. **Hash -> Sign (D5):** A domain-separated **SHA-256** digest is computed over
   the canonical payload bytes and signed with the sender's **Ed25519** private
   key, producing a 64-byte deterministic signature encoded in Base64.

Verification-First Workflow (Verify -> Decrypt)
-----------------------------------------------
When opening a ``VLT3`` container:
1. Structural parsing checks that ``signature``, ``signer_id``, and
   ``signer_fingerprint`` are present and non-empty (raising
   :class:`~vault.exceptions.MissingSignatureError` immediately if absent).
2. The canonical signed payload is reconstructed from the container fields and
   its SHA-256 digest is verified against the 64-byte Ed25519 ``signature``
   using the sender's ``Ed25519PublicKey`` **before** any recipient lookup,
   RSA-OAEP private-key operation, or AES-256-GCM decryption is attempted.
3. If signature verification fails for any reason, :class:`~vault.exceptions.SignatureVerificationError`
   is raised immediately and no output file is touched on disk.
4. Only after the signature is cryptographically verified does the module unwrap
   the recipient's DEK and decrypt the payload with AES-256-GCM.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, NamedTuple, Optional, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault.exceptions import (
    DecryptionFailedError,
    InvalidKeyError,
    InvalidMetadataError,
    MissingSignatureError,
    PlaintextTooLargeError,
    RecipientNotFoundError,
    SignatureVerificationError,
)
from vault.hybrid.encryption import (
    ALGORITHM,
    DEK_SIZE,
    KEY_WRAP_ALGORITHM,
    MAX_METADATA_SIZE,
    MAX_PLAINTEXT_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
)
from vault.hybrid.keys import (
    get_public_key_fingerprint,
    looks_like_fingerprint,
    validate_rsa_private_key,
    validate_rsa_public_key,
)
from vault.signatures.keys import (
    ED25519_SIGNATURE_SIZE,
    get_signer_public_key_fingerprint,
    validate_ed25519_private_key,
    validate_ed25519_public_key,
)

__all__ = [
    "SIGNED_MAGIC",
    "SIGNED_FORMAT_VERSION",
    "ALGORITHM",
    "KEY_WRAP_ALGORITHM",
    "SIGNATURE_ALGORITHM",
    "HASH_ALGORITHM",
    "SIGNATURE_DOMAIN_SEPARATOR",
    "DEK_SIZE",
    "NONCE_SIZE",
    "TAG_SIZE",
    "SIGNATURE_SIZE",
    "MAX_PLAINTEXT_SIZE",
    "MAX_METADATA_SIZE",
    "SignedHybridDocument",
    "build_signed_aad",
    "build_canonical_signed_payload",
    "compute_payload_digest",
    "sign_canonical_payload",
    "verify_canonical_payload",
    "verify_container_signature",
    "encrypt_and_sign_bytes",
    "verify_and_decrypt_bytes",
    "verify_and_decrypt_document",
    "encrypt_and_sign_file",
    "verify_and_decrypt_file",
]

# --------------------------------------------------------------------------- #
# Format & cryptographic constants                                            #
# --------------------------------------------------------------------------- #

SIGNED_MAGIC: Final[str] = "VLT3"
"""Container magic identifier for signed multi-recipient hybrid vault format v3."""

SIGNED_FORMAT_VERSION: Final[int] = 3
"""Container schema version for signed hybrid encryption."""

SIGNATURE_ALGORITHM: Final[str] = "Ed25519"
"""Digital signature algorithm identifier."""

HASH_ALGORITHM: Final[str] = "SHA-256"
"""Cryptographic hash algorithm used to digest the canonical payload prior to signing."""

SIGNATURE_DOMAIN_SEPARATOR: Final[bytes] = b"VLT3-ED25519-SHA256-v1:"
"""Explicit domain separation prefix bound into the SHA-256 pre-hash digest."""

SIGNATURE_SIZE: Final[int] = ED25519_SIGNATURE_SIZE
"""Size in bytes of the raw Ed25519 signature (64 bytes)."""

_UNSIGNED_CONTAINER_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "magic",
        "version",
        "algorithm",
        "key_wrap_algorithm",
        "signature_algorithm",
        "timestamp",
        "signer_id",
        "signer_fingerprint",
        "filename",
        "metadata",
        "recipients",
        "nonce",
        "ciphertext",
        "tag",
    }
)

_REQUIRED_SIGNED_CONTAINER_FIELDS: Final[frozenset[str]] = _UNSIGNED_CONTAINER_FIELDS | {
    "signature"
}

_REQUIRED_RECIPIENT_FIELDS: Final[frozenset[str]] = frozenset(
    {"id", "fingerprint", "encrypted_dek"}
)


class _MissingSignatureSignal(Exception):
    """Internal signal when signature or signer_id is absent or empty."""


class _MalformedSignedContainer(Exception):
    """Internal signal for structural or signature verification failures."""


class SignedHybridDocument(NamedTuple):
    """Authenticated and signature-verified result of opening a ``VLT3`` container.

    Returned only after both the sender's Ed25519 signature and the AES-256-GCM
    authentication tag have been cryptographically verified.
    """

    plaintext: bytes
    filename: Optional[str]
    metadata: dict[str, Any]
    signer_id: str
    signer_fingerprint: str
    timestamp: int


# --------------------------------------------------------------------------- #
# Canonical Payload & Hash -> Sign -> Verify Primitives                       #
# --------------------------------------------------------------------------- #


def build_signed_aad(
    timestamp: int,
    signer_id: str,
    signer_fingerprint: str,
    recipients: Sequence[dict[str, str]],
    *,
    magic: str = SIGNED_MAGIC,
    version: int = SIGNED_FORMAT_VERSION,
    algorithm: str = ALGORITHM,
    key_wrap_algorithm: str = KEY_WRAP_ALGORITHM,
    signature_algorithm: str = SIGNATURE_ALGORITHM,
    filename: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> bytes:
    """Construct the canonical JSON Associated Authenticated Data (AAD) bytes for ``VLT3``.

    Binds all security-relevant header metadata, the sender's identity
    (``signer_id``, ``signer_fingerprint``, ``signature_algorithm``), and the
    complete ``recipients`` list into AES-256-GCM.
    """
    return _canonical_json(
        {
            "magic": magic,
            "version": version,
            "algorithm": algorithm,
            "key_wrap_algorithm": key_wrap_algorithm,
            "signature_algorithm": signature_algorithm,
            "timestamp": timestamp,
            "signer_id": signer_id,
            "signer_fingerprint": signer_fingerprint,
            "filename": filename,
            "metadata": {} if metadata is None else dict(metadata),
            "recipients": list(recipients),
        }
    )


def build_canonical_signed_payload(
    *,
    magic: str = SIGNED_MAGIC,
    version: int = SIGNED_FORMAT_VERSION,
    algorithm: str = ALGORITHM,
    key_wrap_algorithm: str = KEY_WRAP_ALGORITHM,
    signature_algorithm: str = SIGNATURE_ALGORITHM,
    timestamp: int,
    signer_id: str,
    signer_fingerprint: str,
    filename: Optional[str],
    metadata: Mapping[str, Any],
    recipients: Sequence[dict[str, str]],
    nonce: str,
    ciphertext: str,
    tag: str,
) -> bytes:
    """Construct the exact canonical JSON byte representation covered by the Ed25519 signature.

    Covers:
    - All security-relevant metadata (``magic``, ``version``, ``algorithm``,
      ``key_wrap_algorithm``, ``signature_algorithm``, ``timestamp``,
      ``signer_id``, ``signer_fingerprint``, ``filename``, ``metadata``).
    - The complete ``recipients`` list (``id``, ``fingerprint``, ``encrypted_dek``).
    - The AEAD ``nonce``, ``ciphertext``, and ``tag``.
    """
    return _canonical_json(
        {
            "magic": magic,
            "version": version,
            "algorithm": algorithm,
            "key_wrap_algorithm": key_wrap_algorithm,
            "signature_algorithm": signature_algorithm,
            "timestamp": timestamp,
            "signer_id": signer_id,
            "signer_fingerprint": signer_fingerprint,
            "filename": filename,
            "metadata": dict(metadata),
            "recipients": list(recipients),
            "nonce": nonce,
            "ciphertext": ciphertext,
            "tag": tag,
        }
    )


def compute_payload_digest(canonical_payload: bytes) -> bytes:
    """Compute the explicit 32-byte SHA-256 digest over ``canonical_payload``.

    Prepends :data:`SIGNATURE_DOMAIN_SEPARATOR` to prevent cross-protocol or
    cross-version signature replay and compresses the arbitrary-length
    canonical container representation into a fixed 256-bit digest before
    Ed25519 signing/verification.
    """
    if not isinstance(canonical_payload, (bytes, bytearray, memoryview)):
        raise TypeError("canonical_payload must be a bytes-like object")
    hasher = hashlib.sha256()
    hasher.update(SIGNATURE_DOMAIN_SEPARATOR)
    hasher.update(canonical_payload)
    return hasher.digest()


def sign_canonical_payload(
    canonical_payload: bytes,
    signer_private_key: Ed25519PrivateKey,
) -> bytes:
    """Hash ``canonical_payload`` with SHA-256 and sign the digest with Ed25519.

    Args:
        canonical_payload: Canonical UTF-8 JSON bytes of the unsigned container fields.
        signer_private_key: Sender's :class:`Ed25519PrivateKey`.

    Returns:
        64-byte raw Ed25519 signature.
    """
    validate_ed25519_private_key(signer_private_key)
    digest = compute_payload_digest(canonical_payload)
    return signer_private_key.sign(digest)


def verify_canonical_payload(
    canonical_payload: bytes,
    signature: bytes,
    signer_public_key: Ed25519PublicKey,
) -> None:
    """Hash ``canonical_payload`` with SHA-256 and verify ``signature`` with Ed25519.

    Raises:
        InvalidKeyError: If ``signer_public_key`` is not an :class:`Ed25519PublicKey`.
        SignatureVerificationError: If ``signature`` is not 64 bytes or fails
            Ed25519 cryptographic verification.
    """
    validate_ed25519_public_key(signer_public_key)
    if not isinstance(signature, (bytes, bytearray, memoryview)):
        raise SignatureVerificationError()
    raw_sig = bytes(signature)
    if len(raw_sig) != SIGNATURE_SIZE:
        raise SignatureVerificationError()

    digest = compute_payload_digest(canonical_payload)
    verified = False
    try:
        signer_public_key.verify(raw_sig, digest)
        verified = True
    except InvalidSignature:
        verified = False

    if not verified:
        raise SignatureVerificationError()


# --------------------------------------------------------------------------- #
# Public Container API (Encrypt-then-Sign & Verify-then-Decrypt)              #
# --------------------------------------------------------------------------- #


def encrypt_and_sign_bytes(
    plaintext: bytes,
    recipients: Sequence[Tuple[str, RSAPublicKey]],
    *,
    signer_id: str,
    signer_private_key: Ed25519PrivateKey,
    filename: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> bytes:
    """Encrypt ``plaintext`` for multiple recipients, bind metadata, and sign the ``VLT3`` container.

    Executes the full **Encrypt -> Add Metadata -> Sign -> Store** workflow:
    1. Validates recipient RSA public keys, the sender's ``signer_id`` and
       ``Ed25519PrivateKey``, and canonical JSON metadata.
    2. Generates a fresh 256-bit DEK (``os.urandom(32)``) and wraps it per
       recipient using RSA-OAEP-SHA256.
    3. Binds all container metadata (including ``signer_id``,
       ``signer_fingerprint``, and ``signature_algorithm``) and the
       ``recipients`` list as AAD, and encrypts ``plaintext`` with AES-256-GCM.
    4. Builds the canonical signed payload over metadata + recipients + nonce +
       ciphertext + tag, hashes it with SHA-256, and signs the digest with
       ``signer_private_key`` (Ed25519).

    Args:
        plaintext: Raw document bytes to encrypt and sign.
        recipients: Non-empty sequence of ``(recipient_id, RSAPublicKey)`` pairs.
        signer_id: Logical identifier of the sender (must not have the 64-hex
            fingerprint shape).
        signer_private_key: Sender's :class:`Ed25519PrivateKey`.
        filename: Optional original filename (stored in clear, bound in AAD & signature).
        metadata: Optional JSON-serialisable mapping (stored in clear, bound in AAD & signature).

    Returns:
        Canonical UTF-8 JSON ``VLT3`` container bytes.
    """
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be a bytes-like object")
    if memoryview(plaintext).nbytes > MAX_PLAINTEXT_SIZE:
        raise PlaintextTooLargeError(
            f"input exceeds the maximum supported size of {MAX_PLAINTEXT_SIZE} bytes"
        )

    validated_signer_id = _validate_signer_id(signer_id)
    validate_ed25519_private_key(signer_private_key)
    signer_fingerprint = get_signer_public_key_fingerprint(signer_private_key.public_key())

    validated_recipients = _validate_recipients(recipients)
    filename, metadata_obj = _validate_metadata(filename, metadata)

    # 1. Fresh 256-bit DEK from OS CSPRNG
    dek = _random_bytes(DEK_SIZE)

    # 2. Wrap DEK independently for each recipient with RSA-OAEP-SHA256
    oaep = _rsa_oaep_padding()
    recipient_entries: list[dict[str, str]] = []
    for recipient_id, pub_key in validated_recipients:
        fingerprint = get_public_key_fingerprint(pub_key)
        wrapped_dek = pub_key.encrypt(dek, oaep)
        recipient_entries.append(
            {
                "id": recipient_id,
                "fingerprint": fingerprint,
                "encrypted_dek": _b64_encode(wrapped_dek),
            }
        )

    # 3. Build canonical AAD and encrypt payload once with AES-256-GCM
    timestamp = int(datetime.now(timezone.utc).timestamp())
    aad = build_signed_aad(
        timestamp=timestamp,
        signer_id=validated_signer_id,
        signer_fingerprint=signer_fingerprint,
        recipients=recipient_entries,
        filename=filename,
        metadata=metadata_obj,
    )

    nonce = _random_bytes(NONCE_SIZE)
    sealed = AESGCM(dek).encrypt(nonce, bytes(plaintext), aad)
    del dek

    nonce_b64 = _b64_encode(nonce)
    ciphertext_b64 = _b64_encode(sealed[:-TAG_SIZE])
    tag_b64 = _b64_encode(sealed[-TAG_SIZE:])

    # 4. Canonicalize unsigned container, hash with SHA-256, and sign with Ed25519
    canonical_payload = build_canonical_signed_payload(
        timestamp=timestamp,
        signer_id=validated_signer_id,
        signer_fingerprint=signer_fingerprint,
        filename=filename,
        metadata=metadata_obj,
        recipients=recipient_entries,
        nonce=nonce_b64,
        ciphertext=ciphertext_b64,
        tag=tag_b64,
    )
    signature_bytes = sign_canonical_payload(canonical_payload, signer_private_key)

    container = {
        "magic": SIGNED_MAGIC,
        "version": SIGNED_FORMAT_VERSION,
        "algorithm": ALGORITHM,
        "key_wrap_algorithm": KEY_WRAP_ALGORITHM,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "timestamp": timestamp,
        "signer_id": validated_signer_id,
        "signer_fingerprint": signer_fingerprint,
        "filename": filename,
        "metadata": metadata_obj,
        "recipients": recipient_entries,
        "nonce": nonce_b64,
        "ciphertext": ciphertext_b64,
        "tag": tag_b64,
        "signature": _b64_encode(signature_bytes),
    }
    return _canonical_json(container)


def verify_container_signature(
    container_bytes: bytes,
    signer_public_key: Ed25519PublicKey,
    *,
    expected_signer_id: Optional[str] = None,
) -> dict[str, Any]:
    """Parse ``container_bytes`` and verify its Ed25519 origin signature before any decryption.

    Can be executed by a recipient prior to decryption or by an untrusted gateway
    / auditor that holds ``signer_public_key`` but no recipient RSA private key.

    Args:
        container_bytes: Raw ``VLT3`` JSON container bytes.
        signer_public_key: Expected sender's :class:`Ed25519PublicKey`.
        expected_signer_id: Optional logical ``signer_id`` (or 64-hex signer
            fingerprint) that the container must match.

    Returns:
        The parsed and signature-verified container dictionary.

    Raises:
        InvalidKeyError: If ``signer_public_key`` is not an :class:`Ed25519PublicKey`.
        MissingSignatureError: If ``signature``, ``signer_id``, or
            ``signer_fingerprint`` is missing or empty.
        SignatureVerificationError: If the container structure is malformed,
            ``signer_fingerprint`` or ``expected_signer_id`` does not match, or
            the Ed25519 signature verification fails.
    """
    if not isinstance(container_bytes, (bytes, bytearray, memoryview)):
        raise TypeError("container_bytes must be a bytes-like object")
    validate_ed25519_public_key(signer_public_key)
    if expected_signer_id is not None and not isinstance(expected_signer_id, str):
        raise TypeError("expected_signer_id must be a str or None")

    parsed: Optional[dict[str, Any]] = None
    missing_sig = False

    try:
        container = _parse_signed_container(bytes(container_bytes))
        expected_fp = get_signer_public_key_fingerprint(signer_public_key)

        # Verify signer key fingerprint matches the public key provided by caller
        if container["signer_fingerprint"] != expected_fp:
            raise _MalformedSignedContainer

        # If caller also pinned an expected_signer_id, enforce it deterministically
        if expected_signer_id is not None and expected_signer_id != "":
            if looks_like_fingerprint(expected_signer_id):
                if container["signer_fingerprint"] != expected_signer_id:
                    raise _MalformedSignedContainer
            else:
                if container["signer_id"] != expected_signer_id:
                    raise _MalformedSignedContainer

        # Validate Base64 encoding and sizes of binary fields covered by signature
        nonce_raw = _b64_decode(container["nonce"])
        _b64_decode(container["ciphertext"])
        tag_raw = _b64_decode(container["tag"])
        signature_raw = _b64_decode(container["signature"])

        if (
            len(nonce_raw) != NONCE_SIZE
            or len(tag_raw) != TAG_SIZE
            or len(signature_raw) != SIGNATURE_SIZE
        ):
            raise _MalformedSignedContainer

        for entry in container["recipients"]:
            wrapped = _b64_decode(entry["encrypted_dek"])
            if len(wrapped) == 0:
                raise _MalformedSignedContainer

        # Reconstruct canonical signed payload and verify SHA-256 + Ed25519 signature
        canonical_payload = build_canonical_signed_payload(
            magic=container["magic"],
            version=container["version"],
            algorithm=container["algorithm"],
            key_wrap_algorithm=container["key_wrap_algorithm"],
            signature_algorithm=container["signature_algorithm"],
            timestamp=container["timestamp"],
            signer_id=container["signer_id"],
            signer_fingerprint=container["signer_fingerprint"],
            filename=container["filename"],
            metadata=container["metadata"],
            recipients=container["recipients"],
            nonce=container["nonce"],
            ciphertext=container["ciphertext"],
            tag=container["tag"],
        )
        digest = compute_payload_digest(canonical_payload)
        signer_public_key.verify(signature_raw, digest)
        parsed = container
    except _MissingSignatureSignal:
        missing_sig = True
    except (
        InvalidSignature,
        _MalformedSignedContainer,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
        binascii.Error,
    ):
        parsed = None

    if missing_sig:
        raise MissingSignatureError()
    if parsed is None:
        raise SignatureVerificationError()
    return parsed


def verify_and_decrypt_document(
    container_bytes: bytes,
    recipient_id: Optional[str],
    recipient_private_key: RSAPrivateKey,
    signer_public_key: Ed25519PublicKey,
    *,
    expected_signer_id: Optional[str] = None,
) -> SignedHybridDocument:
    """Verify the sender's Ed25519 signature FIRST, then unwrap the DEK and decrypt.

    Strict Verification-First Workflow:
    1. Validate arguments and call :func:`verify_container_signature`.
    2. If ``signature`` / ``signer_id`` is missing or signature verification
       fails, raise :class:`MissingSignatureError` or
       :class:`SignatureVerificationError` immediately **before** touching
       ``recipient_private_key`` or invoking AES-256-GCM.
    3. Locate the recipient entry deterministically (by ``id`` or 64-hex
       ``fingerprint`` with disjoint namespaces and no fallback).
    4. Unwrap ``encrypted_dek`` with ``recipient_private_key`` (RSA-OAEP-SHA256)
       and authenticate/decrypt the payload with AES-256-GCM.
    """
    if not isinstance(container_bytes, (bytes, bytearray, memoryview)):
        raise TypeError("container_bytes must be a bytes-like object")
    validate_rsa_private_key(recipient_private_key)
    validate_ed25519_public_key(signer_public_key)
    if recipient_id is not None and not isinstance(recipient_id, str):
        raise TypeError("recipient_id must be a str or None")

    # STEP 1-4: Verify signature FIRST (raises MissingSignatureError / SignatureVerificationError)
    container = verify_container_signature(
        container_bytes,
        signer_public_key,
        expected_signer_id=expected_signer_id,
    )

    # STEP 5: Only after valid signature verification, unwrap DEK and decrypt
    document: Optional[SignedHybridDocument] = None
    not_found = False

    try:
        recipients: list[dict[str, str]] = container["recipients"]
        caller_fingerprint = get_public_key_fingerprint(recipient_private_key.public_key())

        entry = _find_recipient_entry(recipients, recipient_id, caller_fingerprint)
        if entry is None:
            not_found = True
        elif entry["fingerprint"] != caller_fingerprint:
            raise _MalformedSignedContainer
        else:
            nonce = _b64_decode(container["nonce"])
            ciphertext = _b64_decode(container["ciphertext"])
            tag = _b64_decode(container["tag"])
            encrypted_dek = _b64_decode(entry["encrypted_dek"])

            dek = recipient_private_key.decrypt(encrypted_dek, _rsa_oaep_padding())
            if len(dek) != DEK_SIZE:
                raise _MalformedSignedContainer

            aad = build_signed_aad(
                timestamp=container["timestamp"],
                signer_id=container["signer_id"],
                signer_fingerprint=container["signer_fingerprint"],
                recipients=recipients,
                magic=container["magic"],
                version=container["version"],
                algorithm=container["algorithm"],
                key_wrap_algorithm=container["key_wrap_algorithm"],
                signature_algorithm=container["signature_algorithm"],
                filename=container["filename"],
                metadata=container["metadata"],
            )
            decrypted = AESGCM(dek).decrypt(nonce, ciphertext + tag, aad)
            del dek

            document = SignedHybridDocument(
                plaintext=decrypted,
                filename=container["filename"],
                metadata=container["metadata"],
                signer_id=container["signer_id"],
                signer_fingerprint=container["signer_fingerprint"],
                timestamp=container["timestamp"],
            )
    except (
        InvalidTag,
        _MalformedSignedContainer,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
        binascii.Error,
    ):
        document = None

    if not_found:
        raise RecipientNotFoundError()
    if document is None:
        raise DecryptionFailedError()
    return document


def verify_and_decrypt_bytes(
    container_bytes: bytes,
    recipient_id: Optional[str],
    recipient_private_key: RSAPrivateKey,
    signer_public_key: Ed25519PublicKey,
    *,
    expected_signer_id: Optional[str] = None,
) -> bytes:
    """Verify the ``VLT3`` container signature first, then decrypt and return the plaintext bytes."""
    return verify_and_decrypt_document(
        container_bytes,
        recipient_id,
        recipient_private_key,
        signer_public_key,
        expected_signer_id=expected_signer_id,
    ).plaintext


def encrypt_and_sign_file(
    file_path: Path,
    recipients: Sequence[Tuple[str, RSAPublicKey]],
    output_path: Path,
    *,
    signer_id: str,
    signer_private_key: Ed25519PrivateKey,
    metadata: Optional[Mapping[str, Any]] = None,
    include_filename: bool = True,
) -> Path:
    """Encrypt ``file_path`` for multiple recipients, sign with Ed25519, and write ``output_path``."""
    source = Path(file_path)
    destination = Path(output_path)
    _validate_signer_id(signer_id)
    validate_ed25519_private_key(signer_private_key)
    _validate_recipients(recipients)
    stored_name = source.name if include_filename else None
    _validate_metadata(stored_name, metadata)

    plaintext = _read_limited(source, MAX_PLAINTEXT_SIZE)
    if plaintext is None:
        raise PlaintextTooLargeError(
            f"input exceeds the maximum supported size of {MAX_PLAINTEXT_SIZE} bytes"
        )

    container_bytes = encrypt_and_sign_bytes(
        plaintext,
        recipients,
        signer_id=signer_id,
        signer_private_key=signer_private_key,
        filename=stored_name,
        metadata=metadata,
    )
    _write_file_safely(destination, container_bytes)
    return destination


def verify_and_decrypt_file(
    vault_path: Path,
    recipient_id: Optional[str],
    recipient_private_key: RSAPrivateKey,
    signer_public_key: Ed25519PublicKey,
    output_path: Path,
    *,
    expected_signer_id: Optional[str] = None,
) -> Path:
    """Verify the ``VLT3`` container signature first and decrypt into ``output_path``.

    All cryptographic verification (Ed25519 signature check, RSA-OAEP DEK
    unwrapping, and AES-256-GCM tag verification) completes in memory before
    ``output_path`` is created or modified. On any failure, no partial or
    temporary file is left on disk.
    """
    source = Path(vault_path)
    destination = Path(output_path)
    validate_rsa_private_key(recipient_private_key)
    validate_ed25519_public_key(signer_public_key)

    try:
        container_bytes = source.read_bytes()
    except FileNotFoundError:
        raise
    except OSError:
        raise DecryptionFailedError() from None

    plaintext = verify_and_decrypt_bytes(
        container_bytes,
        recipient_id,
        recipient_private_key,
        signer_public_key,
        expected_signer_id=expected_signer_id,
    )
    _write_file_safely(destination, plaintext)
    return destination


# --------------------------------------------------------------------------- #
# Internal helpers                                                            #
# --------------------------------------------------------------------------- #


def _random_bytes(size: int) -> bytes:
    return os.urandom(size)


def _rsa_oaep_padding() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64_decode(encoded: str) -> bytes:
    if not isinstance(encoded, str):
        raise _MalformedSignedContainer
    raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise _MalformedSignedContainer
    return raw


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _validate_signer_id(signer_id: object) -> str:
    if not isinstance(signer_id, str) or not signer_id.strip():
        raise InvalidKeyError("signer_id must be a non-empty string")
    if looks_like_fingerprint(signer_id):
        raise InvalidKeyError(
            "signer_id must not have the shape of a key fingerprint "
            "(64 lowercase hex characters); that form is reserved"
        )
    return signer_id


def _validate_metadata(
    filename: Optional[str],
    metadata: Optional[Mapping[str, Any]],
) -> Tuple[Optional[str], dict[str, Any]]:
    if filename is not None and not isinstance(filename, str):
        raise InvalidMetadataError("filename must be a string")
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, Mapping):
        raise InvalidMetadataError("metadata must be a mapping (dict)")

    candidate = dict(metadata)
    try:
        encoded = _canonical_json({"filename": filename, "metadata": candidate})
        round_trip = json.loads(encoded)
    except (TypeError, ValueError, RecursionError) as exc:
        raise InvalidMetadataError(
            "metadata must be JSON-serialisable (str keys, finite numbers, "
            "no circular references)"
        ) from exc
    if round_trip != {"filename": filename, "metadata": candidate}:
        raise InvalidMetadataError(
            "metadata does not survive a canonical JSON round-trip "
            "(use str keys and lists instead of tuples)"
        )
    if len(encoded) > MAX_METADATA_SIZE:
        raise InvalidMetadataError(
            f"filename + metadata exceed the maximum of {MAX_METADATA_SIZE} bytes"
        )
    return filename, round_trip["metadata"]


def _validate_recipients(
    recipients: Sequence[Tuple[str, RSAPublicKey]],
) -> list[Tuple[str, RSAPublicKey]]:
    if not isinstance(recipients, Sequence) or isinstance(recipients, (str, bytes, bytearray)):
        raise InvalidKeyError("recipients must be a non-empty sequence of (id, RSAPublicKey) tuples")
    if len(recipients) == 0:
        raise InvalidKeyError("at least one recipient is required")

    validated: list[Tuple[str, RSAPublicKey]] = []
    seen_ids: set[str] = set()
    seen_fingerprints: set[str] = set()

    for item in recipients:
        if not isinstance(item, tuple) or len(item) != 2:
            raise InvalidKeyError("each recipient must be a (recipient_id, RSAPublicKey) tuple")
        recipient_id, pub_key = item
        if not isinstance(recipient_id, str) or not recipient_id.strip():
            raise InvalidKeyError("recipient_id must be a non-empty string")
        if looks_like_fingerprint(recipient_id):
            raise InvalidKeyError(
                "recipient_id must not have the shape of a key fingerprint "
                "(64 lowercase hex characters); that form is reserved"
            )
        validate_rsa_public_key(pub_key)

        if recipient_id in seen_ids:
            raise InvalidKeyError(f"duplicate recipient_id: {recipient_id!r}")
        fingerprint = get_public_key_fingerprint(pub_key)
        if fingerprint in seen_fingerprints:
            raise InvalidKeyError(f"duplicate recipient public key for {recipient_id!r}")

        seen_ids.add(recipient_id)
        seen_fingerprints.add(fingerprint)
        validated.append((recipient_id, pub_key))

    return validated


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _MalformedSignedContainer
        result[key] = value
    return result


def _reject_constant(_: str) -> Any:
    raise _MalformedSignedContainer


def _parse_signed_container(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _MalformedSignedContainer from exc

    parsed = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )
    if not isinstance(parsed, dict):
        raise _MalformedSignedContainer

    # Check presence of signature, signer_id, and signer_fingerprint FIRST
    for sig_field in ("signature", "signer_id", "signer_fingerprint"):
        if sig_field not in parsed or parsed[sig_field] is None:
            raise _MissingSignatureSignal
        if not isinstance(parsed[sig_field], str) or not parsed[sig_field].strip():
            raise _MissingSignatureSignal

    if parsed.keys() != _REQUIRED_SIGNED_CONTAINER_FIELDS:
        raise _MalformedSignedContainer

    if parsed["magic"] != SIGNED_MAGIC:
        raise _MalformedSignedContainer
    if type(parsed["version"]) is not int or parsed["version"] != SIGNED_FORMAT_VERSION:
        raise _MalformedSignedContainer
    if parsed["algorithm"] != ALGORITHM:
        raise _MalformedSignedContainer
    if parsed["key_wrap_algorithm"] != KEY_WRAP_ALGORITHM:
        raise _MalformedSignedContainer
    if parsed["signature_algorithm"] != SIGNATURE_ALGORITHM:
        raise _MalformedSignedContainer
    if type(parsed["timestamp"]) is not int or parsed["timestamp"] < 0:
        raise _MalformedSignedContainer

    signer_id = parsed["signer_id"]
    signer_fp = parsed["signer_fingerprint"]
    if looks_like_fingerprint(signer_id):
        raise _MalformedSignedContainer
    if not looks_like_fingerprint(signer_fp):
        raise _MalformedSignedContainer

    if parsed["filename"] is not None and not isinstance(parsed["filename"], str):
        raise _MalformedSignedContainer
    if not isinstance(parsed["metadata"], dict):
        raise _MalformedSignedContainer
    # Ensure metadata survives canonical JSON round-trip unchanged
    if json.loads(_canonical_json(parsed["metadata"])) != parsed["metadata"]:
        raise _MalformedSignedContainer

    recipients = parsed["recipients"]
    if not isinstance(recipients, list) or len(recipients) == 0:
        raise _MalformedSignedContainer

    seen_ids: set[str] = set()
    seen_fingerprints: set[str] = set()
    for entry in recipients:
        if not isinstance(entry, dict):
            raise _MalformedSignedContainer
        if entry.keys() != _REQUIRED_RECIPIENT_FIELDS:
            raise _MalformedSignedContainer
        r_id = entry["id"]
        r_fp = entry["fingerprint"]
        r_dek = entry["encrypted_dek"]
        if not (isinstance(r_id, str) and isinstance(r_fp, str) and isinstance(r_dek, str)):
            raise _MalformedSignedContainer
        if not r_id or r_id in seen_ids:
            raise _MalformedSignedContainer
        if looks_like_fingerprint(r_id):
            raise _MalformedSignedContainer
        if not looks_like_fingerprint(r_fp) or r_fp in seen_fingerprints:
            raise _MalformedSignedContainer
        seen_ids.add(r_id)
        seen_fingerprints.add(r_fp)

    for b64_field in ("nonce", "ciphertext", "tag", "signature"):
        if not isinstance(parsed[b64_field], str):
            raise _MalformedSignedContainer

    return parsed


def _find_recipient_entry(
    recipients: list[dict[str, str]],
    recipient_id: Optional[str],
    caller_fingerprint: str,
) -> Optional[dict[str, str]]:
    if recipient_id is None or recipient_id == "":
        field, wanted = "fingerprint", caller_fingerprint
    elif looks_like_fingerprint(recipient_id):
        field, wanted = "fingerprint", recipient_id
    else:
        field, wanted = "id", recipient_id
    for entry in recipients:
        if entry[field] == wanted:
            return entry
    return None


def _read_limited(path: Path, limit: int) -> Optional[bytes]:
    with path.open("rb") as handle:
        if os.fstat(handle.fileno()).st_size > limit:
            return None
        data = handle.read(limit + 1)
    return None if len(data) > limit else data


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _write_file_safely(path: Path, data: bytes) -> None:
    existed_before = os.path.lexists(path)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(path, flags, 0o600)
    try:
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        if not existed_before:
            try:
                os.unlink(path)
            except OSError:
                pass
        raise

