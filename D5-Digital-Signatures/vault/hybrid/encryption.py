"""Multi-recipient Hybrid Encryption for the Secure Digital Document Vault (D3).

Scheme
------
1. A fresh 256-bit Data Encryption Key (DEK) is generated from ``os.urandom(32)``.
2. For each authorized recipient ``(recipient_id, public_key)`` the DEK is
   independently wrapped with an **ECIES** construction built only from
   ``cryptography`` primitives: a fresh ephemeral **X25519** key pair, ECDH with
   the recipient's public key, **HKDF-SHA256** to derive a key-encryption key
   (KEK), and **AES-256-GCM** to wrap the DEK. The entry stores the recipient's
   ID, the SHA-256 fingerprint of the raw public key, the ephemeral public key
   and the wrapped DEK.
3. The container metadata and the complete ``recipients`` list (including every
   ephemeral public key) are serialized into canonical JSON and bound as
   Associated Authenticated Data (AAD) to the **AES-256-GCM** encryption of the
   payload under a fresh 96-bit nonce (``os.urandom(12)``).
4. The resulting ``VLT3`` JSON container stores ``magic``, ``version``,
   ``algorithm``, ``key_wrap_algorithm``, ``timestamp``, ``recipients``,
   ``nonce``, ``ciphertext``, and ``tag``.

Security guarantees
-------------------
- **Single-pass bulk encryption:** The document is encrypted once with
  AES-256-GCM regardless of the number of recipients.
- **AAD recipient binding:** Adding, removing, reordering, or modifying any
  recipient entry (``id``, ``fingerprint``, ``ephemeral_public_key`` or
  ``encrypted_dek``) alters the
  canonical AAD and immediately invalidates the 128-bit GCM authentication tag.
- **Oracle-free error handling & disk safety:** All cryptographic verification
  completes in memory before touching the destination path. Any failure raises
  :class:`~vault.exceptions.DecryptionFailedError` (or its subclass
  :class:`~vault.exceptions.RecipientNotFoundError`) without chaining internal
  exceptions or writing partial files to disk.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, NamedTuple, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vault.exceptions import (
    DecryptionFailedError,
    InvalidKeyError,
    InvalidMetadataError,
    PlaintextTooLargeError,
    RecipientNotFoundError,
)
from vault.hybrid.keys import (
    get_public_key_fingerprint,
    looks_like_fingerprint,
    public_key_raw_bytes,
    validate_x25519_private_key,
    validate_x25519_public_key,
)

__all__ = [
    "MAGIC",
    "FORMAT_VERSION",
    "ALGORITHM",
    "KEY_WRAP_ALGORITHM",
    "KEY_WRAP_INFO",
    "EPHEMERAL_KEY_SIZE",
    "DEK_SIZE",
    "NONCE_SIZE",
    "TAG_SIZE",
    "MAX_PLAINTEXT_SIZE",
    "MAX_METADATA_SIZE",
    "HybridDocument",
    "build_aad",
    "encrypt_bytes_hybrid",
    "decrypt_bytes_hybrid",
    "decrypt_document_hybrid",
    "encrypt_file_hybrid",
    "decrypt_file_hybrid",
]

# --------------------------------------------------------------------------- #
# Format & cryptographic constants                                            #
# --------------------------------------------------------------------------- #

MAGIC: Final[str] = "VLT3"
"""Container magic identifier for multi-recipient hybrid vault format v3 (ECIES)."""

FORMAT_VERSION: Final[int] = 3
"""Container schema version for hybrid encryption."""

ALGORITHM: Final[str] = "AES-256-GCM"
"""Symmetric AEAD cipher used for payload encryption."""

KEY_WRAP_ALGORITHM: Final[str] = "ECIES-X25519-HKDF-SHA256-AES-256-GCM"
"""Asymmetric key-wrapping scheme: ephemeral X25519 ECDH + HKDF-SHA256 + AES-256-GCM."""

KEY_WRAP_INFO: Final[bytes] = b"VLT3 ECIES X25519 HKDF-SHA256 AES-256-GCM DEK wrap"
"""Domain-separation label fed to HKDF (``info``) and to the wrap AAD."""

EPHEMERAL_KEY_SIZE: Final[int] = 32
"""Size in bytes of a raw X25519 public key (the ephemeral key of each entry)."""

DEK_SIZE: Final[int] = 32
"""Size in bytes of the symmetric Data Encryption Key (256 bits)."""

NONCE_SIZE: Final[int] = 12
"""Size in bytes of the AES-GCM nonce (96 bits)."""

TAG_SIZE: Final[int] = 16
"""Size in bytes of the AES-GCM authentication tag (128 bits)."""

MAX_PLAINTEXT_SIZE: int = 2**31 - 1 - TAG_SIZE
"""Maximum plaintext size supported by one-shot AEAD encryption."""

MAX_METADATA_SIZE: Final[int] = 64 * 1024
"""Maximum canonical-JSON size in bytes of ``filename`` + ``metadata`` combined."""

_REQUIRED_CONTAINER_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "magic",
        "version",
        "algorithm",
        "key_wrap_algorithm",
        "timestamp",
        "filename",
        "metadata",
        "recipients",
        "nonce",
        "ciphertext",
        "tag",
    }
)

_REQUIRED_RECIPIENT_FIELDS: Final[frozenset[str]] = frozenset(
    {"id", "fingerprint", "ephemeral_public_key", "encrypted_dek"}
)


class _MalformedHybridContainer(Exception):
    """Internal signal for structural/parsing failures; never escapes this module."""


class HybridDocument(NamedTuple):
    """Authenticated result of opening a ``VLT3`` container.

    ``filename`` and ``metadata`` are stored in clear in the container but are
    bound into the AAD, so they are only returned after the GCM tag verifies.
    Treat ``filename`` as untrusted input: never use it as a filesystem path.
    """

    plaintext: bytes
    filename: Optional[str]
    metadata: dict[str, Any]


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #


def build_aad(
    timestamp: int,
    recipients: Sequence[dict[str, str]],
    *,
    magic: str = MAGIC,
    version: int = FORMAT_VERSION,
    algorithm: str = ALGORITHM,
    key_wrap_algorithm: str = KEY_WRAP_ALGORITHM,
    filename: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> bytes:
    """Construct the canonical JSON Associated Authenticated Data (AAD) bytes.

    Exact structure bound into AES-256-GCM::

        canonical_json({
            "magic": "VLT3",
            "version": 3,
            "algorithm": "AES-256-GCM",
            "key_wrap_algorithm": "ECIES-X25519-HKDF-SHA256-AES-256-GCM",
            "timestamp": timestamp,
            "filename": filename,          # str or null, always present
            "metadata": metadata,          # object, always present ({} if none)
            "recipients": recipients,
        })

    ``filename`` and ``metadata`` are always part of the AAD (as ``null`` and
    ``{}`` when absent), so stripping or injecting them breaks the tag.
    """
    return _canonical_json(
        {
            "magic": magic,
            "version": version,
            "algorithm": algorithm,
            "key_wrap_algorithm": key_wrap_algorithm,
            "timestamp": timestamp,
            "filename": filename,
            "metadata": {} if metadata is None else dict(metadata),
            "recipients": list(recipients),
        }
    )


def encrypt_bytes_hybrid(
    plaintext: bytes,
    recipients: Sequence[Tuple[str, X25519PublicKey]],
    *,
    filename: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> bytes:
    """Encrypt ``plaintext`` for multiple recipients and return the JSON container bytes.

    Args:
        plaintext: Raw bytes to encrypt.
        recipients: Non-empty sequence of ``(recipient_id, X25519PublicKey)`` pairs.
        filename: Optional original file name, stored in clear and authenticated.
        metadata: Optional JSON-serialisable mapping (str keys), stored in clear
            and authenticated.

    Returns:
        Canonical UTF-8 JSON container bytes.

    Raises:
        TypeError: If ``plaintext`` is not bytes-like.
        InvalidKeyError: If ``recipients`` is empty, has duplicate/invalid IDs,
            or contains an invalid (non-X25519) public key.
        InvalidMetadataError: If ``filename``/``metadata`` are not representable
            as canonical JSON or exceed :data:`MAX_METADATA_SIZE`.
        PlaintextTooLargeError: If ``plaintext`` exceeds :data:`MAX_PLAINTEXT_SIZE`.
    """
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be a bytes-like object")
    if memoryview(plaintext).nbytes > MAX_PLAINTEXT_SIZE:
        raise PlaintextTooLargeError(
            f"input exceeds the maximum supported size of {MAX_PLAINTEXT_SIZE} bytes"
        )

    validated_recipients = _validate_recipients(recipients)
    filename, metadata_obj = _validate_metadata(filename, metadata)

    # 1. Fresh 256-bit DEK from OS CSPRNG
    dek = _random_bytes(DEK_SIZE)

    # 2. Wrap the same DEK independently for each recipient with ECIES
    #    (fresh ephemeral X25519 key, HKDF-SHA256, AES-256-GCM)
    recipient_entries: list[dict[str, str]] = []
    for recipient_id, pub_key in validated_recipients:
        fingerprint = get_public_key_fingerprint(pub_key)
        ephemeral_public, wrapped_dek = _wrap_dek(dek, pub_key)
        recipient_entries.append(
            {
                "id": recipient_id,
                "fingerprint": fingerprint,
                "ephemeral_public_key": _b64_encode(ephemeral_public),
                "encrypted_dek": _b64_encode(wrapped_dek),
            }
        )

    # 3. Build canonical AAD binding container metadata and full recipient array
    timestamp = int(datetime.now(timezone.utc).timestamp())
    aad = build_aad(
        timestamp=timestamp,
        recipients=recipient_entries,
        filename=filename,
        metadata=metadata_obj,
    )

    # 4. Encrypt file content once with AES-256-GCM and a fresh 96-bit nonce
    nonce = _random_bytes(NONCE_SIZE)
    sealed = AESGCM(dek).encrypt(nonce, bytes(plaintext), aad)
    del dek  # best effort in CPython

    ciphertext = sealed[:-TAG_SIZE]
    tag = sealed[-TAG_SIZE:]

    container = {
        "magic": MAGIC,
        "version": FORMAT_VERSION,
        "algorithm": ALGORITHM,
        "key_wrap_algorithm": KEY_WRAP_ALGORITHM,
        "timestamp": timestamp,
        "filename": filename,
        "metadata": metadata_obj,
        "recipients": recipient_entries,
        "nonce": _b64_encode(nonce),
        "ciphertext": _b64_encode(ciphertext),
        "tag": _b64_encode(tag),
    }
    return _canonical_json(container)


def decrypt_bytes_hybrid(
    container_bytes: bytes,
    recipient_id: Optional[str],
    private_key: X25519PrivateKey,
) -> bytes:
    """Authenticate and decrypt a ``VLT3`` container, returning only the plaintext.

    Thin wrapper over :func:`decrypt_document_hybrid`; see it for the recipient
    selection rules and the exceptions raised.
    """
    return decrypt_document_hybrid(container_bytes, recipient_id, private_key).plaintext


def decrypt_document_hybrid(
    container_bytes: bytes,
    recipient_id: Optional[str],
    private_key: X25519PrivateKey,
) -> HybridDocument:
    """Authenticate and decrypt a ``VLT3`` hybrid container in memory.

    The recipient entry is selected deterministically, with no fallback:

    * ``recipient_id`` is a 64-char lowercase hex string -> matched against the
      entry ``fingerprint``;
    * any other non-empty ``recipient_id`` -> matched against the entry ``id``;
    * ``None`` / ``""`` -> matched against the fingerprint of
      ``private_key.public_key()``.

    Recipient IDs shaped like a fingerprint are forbidden, so the two
    namespaces never overlap. The selected entry must additionally carry the
    fingerprint of ``private_key``; otherwise decryption fails.

    Args:
        container_bytes: Raw JSON container bytes.
        recipient_id: Recipient's logical ID, the key fingerprint, or ``None``.
        private_key: Recipient's :class:`X25519PrivateKey`.

    Returns:
        :class:`HybridDocument` with the authenticated plaintext, ``filename``
        and ``metadata``. Nothing is returned unless the GCM tag verifies.

    Raises:
        InvalidKeyError: If ``private_key`` is not a valid :class:`X25519PrivateKey`.
        RecipientNotFoundError: If no matching recipient entry exists in the container
            (subclass of :class:`DecryptionFailedError`).
        DecryptionFailedError: If key unwrapping fails, AAD/tag verification fails,
            or the container is malformed or tampered with.
    """
    if not isinstance(container_bytes, (bytes, bytearray, memoryview)):
        raise TypeError("container_bytes must be a bytes-like object")
    validate_x25519_private_key(private_key)
    if recipient_id is not None and not isinstance(recipient_id, str):
        raise TypeError("recipient_id must be a str or None")

    document: Optional[HybridDocument] = None
    not_found = False

    try:
        container = _parse_container(bytes(container_bytes))
        recipients: list[dict[str, str]] = container["recipients"]
        caller_fingerprint = get_public_key_fingerprint(private_key.public_key())

        entry = _find_recipient_entry(recipients, recipient_id, caller_fingerprint)
        if entry is None:
            not_found = True
        elif entry["fingerprint"] != caller_fingerprint:
            # Entry exists but belongs to a different key: fail before any ECDH work.
            raise _MalformedHybridContainer
        else:
            nonce = _b64_decode(container["nonce"])
            ciphertext = _b64_decode(container["ciphertext"])
            tag = _b64_decode(container["tag"])
            encrypted_dek = _b64_decode(entry["encrypted_dek"])
            ephemeral_public = _b64_decode(entry["ephemeral_public_key"])

            if len(nonce) != NONCE_SIZE or len(tag) != TAG_SIZE:
                raise _MalformedHybridContainer
            if len(ephemeral_public) != EPHEMERAL_KEY_SIZE:
                raise _MalformedHybridContainer

            # 1. Unwrap the DEK with the recipient's X25519 private key (ECIES)
            dek = _unwrap_dek(encrypted_dek, ephemeral_public, private_key)
            if len(dek) != DEK_SIZE:
                raise _MalformedHybridContainer

            # 2. Reconstruct canonical AAD over header + recipient list and verify GCM tag
            aad = build_aad(
                timestamp=container["timestamp"],
                recipients=recipients,
                magic=container["magic"],
                version=container["version"],
                algorithm=container["algorithm"],
                key_wrap_algorithm=container["key_wrap_algorithm"],
                filename=container["filename"],
                metadata=container["metadata"],
            )
            decrypted = AESGCM(dek).decrypt(nonce, ciphertext + tag, aad)
            del dek

            document = HybridDocument(
                plaintext=decrypted,
                filename=container["filename"],
                metadata=container["metadata"],
            )
    except (
        InvalidTag,
        _MalformedHybridContainer,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
        binascii.Error,
    ):
        document = None

    # Raise outside the except block so __cause__ and __context__ remain None
    # (no error oracle leaking internal exception traces).
    if not_found:
        raise RecipientNotFoundError()
    if document is None:
        raise DecryptionFailedError()
    return document


def encrypt_file_hybrid(
    file_path: Path,
    recipients: list[Tuple[str, X25519PublicKey]],
    output_path: Path,
    metadata: Optional[Mapping[str, Any]] = None,
    *,
    include_filename: bool = True,
) -> Path:
    """Encrypt ``file_path`` for multiple recipients into ``output_path``.

    Args:
        file_path: Path to the input plaintext file.
        recipients: Non-empty list of ``(recipient_id, X25519PublicKey)`` tuples.
        output_path: Destination path for the ``VLT3`` container.
        metadata: Optional JSON-serialisable mapping, authenticated and stored in clear.
        include_filename: Store ``file_path.name`` (in clear, authenticated).
            Set to ``False`` when the file name itself is sensitive.

    Returns:
        ``Path(output_path)``.

    Raises:
        InvalidKeyError: If ``recipients`` is empty or has invalid keys/IDs.
        InvalidMetadataError: If ``metadata`` is not valid canonical JSON or too large.
        PlaintextTooLargeError: If the input file exceeds :data:`MAX_PLAINTEXT_SIZE`.
        OSError: If reading or writing fails (any newly created partial output is removed).
    """
    source = Path(file_path)
    destination = Path(output_path)
    _validate_recipients(recipients)
    stored_name = source.name if include_filename else None
    _validate_metadata(stored_name, metadata)

    plaintext = _read_limited(source, MAX_PLAINTEXT_SIZE)
    if plaintext is None:
        raise PlaintextTooLargeError(
            f"input exceeds the maximum supported size of {MAX_PLAINTEXT_SIZE} bytes"
        )

    container_bytes = encrypt_bytes_hybrid(
        plaintext, recipients, filename=stored_name, metadata=metadata
    )
    _write_file_safely(destination, container_bytes)
    return destination


def decrypt_file_hybrid(
    vault_path: Path,
    recipient_id: str,
    private_key: X25519PrivateKey,
    output_path: Path,
) -> Path:
    """Authenticate and decrypt a ``VLT3`` hybrid container file into ``output_path``.

    All cryptographic operations (ECIES key unwrapping and AES-256-GCM AAD +
    ciphertext authentication) complete in memory before ``output_path`` is
    opened. On any failure, no partial or temporary file is written to disk.

    Args:
        vault_path: Path to the encrypted ``VLT3`` container file.
        recipient_id: Unique identifier of the decrypting recipient (or their
            public-key fingerprint).
        private_key: Recipient's :class:`X25519PrivateKey`.
        output_path: Destination path for the decrypted plaintext file.

    Returns:
        ``Path(output_path)``.

    Raises:
        InvalidKeyError: If ``private_key`` is not a valid :class:`X25519PrivateKey`.
        RecipientNotFoundError: If ``recipient_id`` / key fingerprint is not in
            the container's recipient list (subclass of :class:`DecryptionFailedError`).
        DecryptionFailedError: If the private key does not match, the recipient
            list or AAD was tampered with, or the ciphertext/tag is corrupted.
    """
    source = Path(vault_path)
    destination = Path(output_path)
    validate_x25519_private_key(private_key)

    try:
        container_bytes = source.read_bytes()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise DecryptionFailedError() from None

    # Full verification and decryption in memory first; disk untouched if this raises.
    plaintext = decrypt_bytes_hybrid(container_bytes, recipient_id, private_key)
    _write_file_safely(destination, plaintext)
    return destination


# --------------------------------------------------------------------------- #
# Internal helpers                                                            #
# --------------------------------------------------------------------------- #


def _random_bytes(size: int) -> bytes:
    """Single source of randomness: the operating system CSPRNG."""
    return os.urandom(size)


def _derive_wrap_key(shared_secret: bytes, ephemeral_public: bytes, recipient_public: bytes) -> bytes:
    """HKDF-SHA256 over the ECDH secret, bound to both public keys and a context label."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=DEK_SIZE,
        salt=None,
        info=KEY_WRAP_INFO + ephemeral_public + recipient_public,
    ).derive(shared_secret)


def _wrap_aad(ephemeral_public: bytes, recipient_public: bytes) -> bytes:
    return KEY_WRAP_INFO + ephemeral_public + recipient_public


def _wrap_dek(dek: bytes, recipient_public: X25519PublicKey) -> Tuple[bytes, bytes]:
    """ECIES-wrap ``dek`` for ``recipient_public``.

    Returns ``(ephemeral_public_key, wrapped_dek)`` where ``wrapped_dek`` is
    ``nonce (12) || AES-256-GCM(KEK, nonce, dek, aad) (32 + 16)``. A fresh
    ephemeral key pair is generated for every call, so the derived KEK is never
    reused and a (key, nonce) pair cannot repeat.
    """
    recipient_raw = public_key_raw_bytes(recipient_public)
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_raw = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    shared_secret = ephemeral_private.exchange(recipient_public)
    kek = _derive_wrap_key(shared_secret, ephemeral_raw, recipient_raw)
    nonce = _random_bytes(NONCE_SIZE)
    sealed = AESGCM(kek).encrypt(nonce, dek, _wrap_aad(ephemeral_raw, recipient_raw))
    return ephemeral_raw, nonce + sealed


def _unwrap_dek(wrapped: bytes, ephemeral_raw: bytes, private_key: X25519PrivateKey) -> bytes:
    """Inverse of :func:`_wrap_dek`; raises on any authentication or format failure."""
    if len(wrapped) != NONCE_SIZE + DEK_SIZE + TAG_SIZE:
        raise _MalformedHybridContainer
    recipient_raw = public_key_raw_bytes(private_key.public_key())
    ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_raw)
    shared_secret = private_key.exchange(ephemeral_public)  # rejects low-order points
    kek = _derive_wrap_key(shared_secret, ephemeral_raw, recipient_raw)
    return AESGCM(kek).decrypt(
        wrapped[:NONCE_SIZE], wrapped[NONCE_SIZE:], _wrap_aad(ephemeral_raw, recipient_raw)
    )


def _b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64_decode(encoded: str) -> bytes:
    if not isinstance(encoded, str):
        raise _MalformedHybridContainer
    # Ensure strict base64 validation without ignoring non-alphabet characters
    raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise _MalformedHybridContainer
    return raw


def _canonical_json(value: Any) -> bytes:
    """Deterministic JSON serialization: sorted keys, compact separators, ASCII-safe."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _validate_metadata(
    filename: Optional[str],
    metadata: Optional[Mapping[str, Any]],
) -> Tuple[Optional[str], dict[str, Any]]:
    """Validate ``filename``/``metadata`` and return the normalized pair.

    Mirrors the strictness of the D2 header: the value must survive a canonical
    JSON round-trip unchanged (str keys, finite numbers, lists instead of
    tuples), so the AAD computed at encryption equals the AAD recomputed from
    the parsed container at decryption.
    """
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
    recipients: Sequence[Tuple[str, X25519PublicKey]],
) -> list[Tuple[str, X25519PublicKey]]:
    if not isinstance(recipients, Sequence) or isinstance(recipients, (str, bytes, bytearray)):
        raise InvalidKeyError("recipients must be a non-empty sequence of (id, X25519PublicKey) tuples")
    if len(recipients) == 0:
        raise InvalidKeyError("at least one recipient is required")

    validated: list[Tuple[str, X25519PublicKey]] = []
    seen_ids: set[str] = set()
    seen_fingerprints: set[str] = set()

    for item in recipients:
        if not isinstance(item, tuple) or len(item) != 2:
            raise InvalidKeyError("each recipient must be a (recipient_id, X25519PublicKey) tuple")
        recipient_id, pub_key = item
        if not isinstance(recipient_id, str) or not recipient_id.strip():
            raise InvalidKeyError("recipient_id must be a non-empty string")
        if looks_like_fingerprint(recipient_id):
            raise InvalidKeyError(
                "recipient_id must not have the shape of a key fingerprint "
                "(64 lowercase hex characters); that form is reserved"
            )
        validate_x25519_public_key(pub_key)

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
            raise _MalformedHybridContainer
        result[key] = value
    return result


def _reject_constant(_: str) -> Any:
    raise _MalformedHybridContainer


def _parse_container(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _MalformedHybridContainer from exc

    parsed = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )
    if not isinstance(parsed, dict):
        raise _MalformedHybridContainer
    if parsed.keys() != _REQUIRED_CONTAINER_FIELDS:
        raise _MalformedHybridContainer

    if parsed["magic"] != MAGIC:
        raise _MalformedHybridContainer
    if type(parsed["version"]) is not int or parsed["version"] != FORMAT_VERSION:
        raise _MalformedHybridContainer
    if parsed["algorithm"] != ALGORITHM:
        raise _MalformedHybridContainer
    if parsed["key_wrap_algorithm"] != KEY_WRAP_ALGORITHM:
        raise _MalformedHybridContainer
    if type(parsed["timestamp"]) is not int or parsed["timestamp"] < 0:
        raise _MalformedHybridContainer

    if parsed["filename"] is not None and not isinstance(parsed["filename"], str):
        raise _MalformedHybridContainer
    if not isinstance(parsed["metadata"], dict):
        raise _MalformedHybridContainer

    recipients = parsed["recipients"]
    if not isinstance(recipients, list) or len(recipients) == 0:
        raise _MalformedHybridContainer

    seen_ids: set[str] = set()
    seen_fingerprints: set[str] = set()
    for entry in recipients:
        if not isinstance(entry, dict):
            raise _MalformedHybridContainer
        if entry.keys() != _REQUIRED_RECIPIENT_FIELDS:
            raise _MalformedHybridContainer
        r_id = entry["id"]
        r_fp = entry["fingerprint"]
        r_dek = entry["encrypted_dek"]
        r_eph = entry["ephemeral_public_key"]
        if not (
            isinstance(r_id, str)
            and isinstance(r_fp, str)
            and isinstance(r_dek, str)
            and isinstance(r_eph, str)
        ):
            raise _MalformedHybridContainer
        if not r_id or r_id in seen_ids:
            raise _MalformedHybridContainer
        # Disjoint namespaces: an ID may never look like a fingerprint, and a
        # fingerprint must be well-formed and unique, so lookups are unambiguous.
        if looks_like_fingerprint(r_id):
            raise _MalformedHybridContainer
        if not looks_like_fingerprint(r_fp) or r_fp in seen_fingerprints:
            raise _MalformedHybridContainer
        seen_ids.add(r_id)
        seen_fingerprints.add(r_fp)

    for b64_field in ("nonce", "ciphertext", "tag"):
        if not isinstance(parsed[b64_field], str):
            raise _MalformedHybridContainer

    return parsed


def _find_recipient_entry(
    recipients: list[dict[str, str]],
    recipient_id: Optional[str],
    caller_fingerprint: str,
) -> Optional[dict[str, str]]:
    """Locate the single recipient entry selected by ``recipient_id``.

    Exactly one field is consulted, chosen by the *shape* of the selector, with
    no fallback to the other field:

    * fingerprint-shaped selector -> ``entry["fingerprint"]``
    * any other non-empty selector -> ``entry["id"]``
    * ``None`` / ``""`` -> the caller's own key fingerprint

    ``_parse_container`` guarantees ids and fingerprints are unique and
    disjoint, so at most one entry can match.
    """
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
    """Write ``data`` to ``path`` with mode ``0600`` and remove partial file on I/O failure."""
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

