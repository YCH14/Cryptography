"""Custom exceptions for the Secure Digital Document Vault.

Design rule
-----------
Every failure that happens while *opening* a container (wrong key, modified
ciphertext, modified tag, modified header/metadata, truncated or malformed
file, unsupported parameters inside the header...) is reported through one and
the same exception, :class:`DecryptionFailedError`, carrying one and the same
message.  Distinct exception types or messages for "bad key" versus "bad
integrity" would turn the vault into an *error oracle* that tells an attacker
which part of a forged container was rejected.

Errors raised while *creating* a container, or caused by invalid arguments
supplied by the local caller (wrong key length, non-serialisable metadata...),
are not attacker-controlled and may therefore be descriptive.
"""

from __future__ import annotations

__all__ = [
    "VaultError",
    "DecryptionFailedError",
    "InvalidKeyError",
    "InvalidMetadataError",
    "PlaintextTooLargeError",
    "RecipientNotFoundError",
    "SignatureVerificationError",
    "MissingSignatureError",
    "ReplayDetectedError",
    "RollbackDetectedError",
    "ReplayStoreError",
    "KeystoreError",
    "KeystoreAccessError",
    "UntrustedSignerError",
]

_GENERIC_DECRYPTION_MESSAGE = (
    "Decryption failed: the container is invalid, has been tampered with, "
    "or the key is incorrect."
)


class VaultError(Exception):
    """Base class for every error raised by the ``vault`` package."""


class DecryptionFailedError(VaultError):
    """Generic, oracle-free failure to authenticate/decrypt a vault container.

    Raised when AEAD tag verification fails (wrong owner/private key, modified
    ciphertext, tag, nonces, wrapped DEK or metadata) and also when the
    container cannot be parsed at all.  The message is fixed on purpose and
    the exception is raised *without* chaining the underlying cause, so no
    detail about the failing stage leaks through ``__cause__``/``__context__``.
    """

    def __init__(self) -> None:
        super().__init__(_GENERIC_DECRYPTION_MESSAGE)


class RecipientNotFoundError(DecryptionFailedError):
    """Raised when the requested recipient ID or key fingerprint is not in the container.

    Subclasses :class:`DecryptionFailedError`, so code that catches the generic
    error also handles an unauthorized/missing recipient, with the same fixed
    message and no extra detail.
    """

    def __init__(self) -> None:
        super().__init__()


class InvalidKeyError(VaultError, ValueError):
    """The symmetric or asymmetric key supplied by the caller is invalid."""


class InvalidMetadataError(VaultError, ValueError):
    """User metadata cannot be serialised into the canonical JSON header."""


class PlaintextTooLargeError(VaultError, ValueError):
    """The input file exceeds the maximum size supported by one-shot AEAD."""


class SignatureVerificationError(DecryptionFailedError):
    """The container signature is invalid, or does not match the expected signer.

    Raised before any decryption is attempted.  Subclasses
    :class:`DecryptionFailedError`, so it has the same fixed message and is
    raised without chaining the underlying cause.
    """


class MissingSignatureError(SignatureVerificationError):
    """The container carries no signature, so it is rejected before decryption."""


_GENERIC_KEYSTORE_MESSAGE = (
    "Keystore access denied: the password is incorrect, or the keystore is "
    "invalid or has been modified."
)


class ReplayDetectedError(SignatureVerificationError):
    """The same signed container was already accepted by this recipient (replay).

    Raised after the signature is verified and before decryption.  It has the
    same fixed message as the other verification errors and no chained cause.
    """


class RollbackDetectedError(SignatureVerificationError):
    """An older (or equal) version of a document was already accepted (rollback).

    Raised when the signed ``document_version`` is not greater than the newest
    version of the same ``document_id`` that this recipient already accepted
    from the same signer.  Same fixed message, no chained cause.
    """


class ReplayStoreError(VaultError):
    """The replay store cannot be read or written (corrupted file, I/O error).

    This is a local failure, not attacker-controlled input, so the message is
    descriptive.  The container is not accepted when the store is unusable.
    """


class KeystoreError(VaultError):
    """A keystore cannot be created, backed up or restored (bad arguments,
    destination already exists, missing backup files, wrong key type)."""


class KeystoreAccessError(KeystoreError):
    """Generic failure to open a keystore (D6).

    Raised for a wrong password, a modified or malformed keystore and missing
    files alike, with one fixed message and without chaining the cause, so the
    error does not tell an attacker which of these happened.
    """

    def __init__(self) -> None:
        super().__init__(_GENERIC_KEYSTORE_MESSAGE)


class UntrustedSignerError(SignatureVerificationError):
    """The container was signed by a key that is unknown or revoked in the trusted signers file.

    Raised before the signature is checked and before any decryption, with the
    same fixed message as the other verification errors and no chained cause.
    """
