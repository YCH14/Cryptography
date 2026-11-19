"""Trusted signing keys of the people whose files you receive (D6).

D5 verifies a signature with a public key that the caller supplies, and the
``signer_id`` in a container is only the SHA-256 of that key: it identifies a
key, it does not say who owns it.  :class:`TrustedSigners` is where a recipient
records which signing keys it decided to trust, and what happened to them::

    trusted_signers.json
      signer_id -> name, public key, status, dates

Status
------
``trusted``     the key may be used to accept containers.
``superseded``  the signer replaced it with a newer key (:meth:`TrustedSigners.replace`).
                Containers signed with it before the replacement still verify.
``revoked``     the signer, or the recipient, declared it unusable (a lost or
                compromised key).  Containers signed with it are refused.

Distribution
------------
A key is added only together with its fingerprint, which the recipient got from
the signer through a second, independent channel (in person, a phone call, a
signed message).  :meth:`TrustedSigners.add` refuses the key if the two do not
match.  The software cannot check that the fingerprint really comes from the
signer: that is the recipient's decision.

Revocation
----------
The signer produces a revocation notice (:meth:`vault.keystore.keyring.Keyring.revocation_notice`)
and sends it through a trusted channel; the recipient imports it with
:meth:`TrustedSigners.import_revocation`.  The notice is not signed, because a
compromised key cannot vouch for its own revocation, so a forged notice could
make a recipient stop trusting a valid key; that is why it must arrive through a
trusted channel.  A revoked key is refused for every container, including ones
that were signed before the compromise, because the ``timestamp`` is written by
the signer and cannot prove that.

The file is plain JSON on the recipient's device and holds only public keys.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import Path
from typing import Any, Final, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from vault.exceptions import (
    InvalidKeyError,
    KeystoreError,
    SignatureVerificationError,
    UntrustedSignerError,
)
from vault.keystore._storage import now_utc, read_json, write_json_atomic
from vault.keystore.keyring import NOTICE_FORMAT
from vault.signatures.keys import get_signer_id
from vault.signatures.replay import ReplayGuard
from vault.signatures.signing import verify_and_decrypt

__all__ = [
    "TrustedSigners",
    "verify_with_trusted_signers",
    "TRUST_FORMAT",
    "STATUS_TRUSTED",
    "STATUS_SUPERSEDED",
    "STATUS_REVOKED",
]

TRUST_FORMAT: Final[str] = "VTS1"
"""Format identifier of the trusted-signers file."""

STATUS_TRUSTED: Final[str] = "trusted"
STATUS_SUPERSEDED: Final[str] = "superseded"
STATUS_REVOKED: Final[str] = "revoked"
_STATUSES: Final[frozenset[str]] = frozenset({STATUS_TRUSTED, STATUS_SUPERSEDED, STATUS_REVOKED})

_SIGNER_ID_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
_FILE_FIELDS: Final[frozenset[str]] = frozenset({"format", "signers"})
_ENTRY_FIELDS: Final[frozenset[str]] = frozenset(
    {"name", "public_key", "status", "added", "superseded_by", "revoked_at", "reason"}
)
_MAX_NAME_LENGTH: Final[int] = 64
_MAX_REASON_LENGTH: Final[int] = 200


class TrustedSigners:
    """The Ed25519 public keys a recipient trusts, with their status.

    Every method reads the file from disk.  A missing file is an empty list.

    Args:
        path: The JSON file; it is created by the first change.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    # ------------------------------------------------------------------ #
    # Reading                                                            #
    # ------------------------------------------------------------------ #

    def status(self, signer_id: str) -> Optional[str]:
        """``trusted``, ``superseded``, ``revoked``, or ``None`` if the key is unknown."""
        entry = self._load()["signers"].get(signer_id)
        return None if entry is None else entry["status"]

    def signer_ids(self) -> list[str]:
        """Every signer_id in the file."""
        return sorted(self._load()["signers"])

    def public_key_for(self, container_bytes: bytes) -> Ed25519PublicKey:
        """The public key that may verify this container.

        Raises:
            SignatureVerificationError: the container has no readable ``signer_id``.
            UntrustedSignerError: the signer is unknown or revoked.
        """
        try:
            signer_id = json.loads(container_bytes)["signer_id"]
        except (TypeError, ValueError, KeyError):
            signer_id = None
        if not isinstance(signer_id, str):
            raise SignatureVerificationError()
        entry = self._load()["signers"].get(signer_id)
        if entry is None or entry["status"] == STATUS_REVOKED:
            raise UntrustedSignerError()
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(entry["public_key"]))

    # ------------------------------------------------------------------ #
    # Adding, replacing, revoking                                        #
    # ------------------------------------------------------------------ #

    def add(self, name: str, public_key: Ed25519PublicKey, *, expected_fingerprint: str) -> str:
        """Trust a signing key, after its fingerprint was confirmed out of band.

        Args:
            name: Whose key it is (1 to 64 printable characters).
            public_key: The signer's Ed25519 public key.
            expected_fingerprint: The ``signer_id`` the signer gave through another channel.

        Returns:
            The ``signer_id`` of the key.

        Raises:
            InvalidKeyError: not an Ed25519 public key, or it does not match ``expected_fingerprint``.
            KeystoreError: ``name`` is not valid, or the key is already in the file.
        """
        signer_id = self._checked_signer_id(public_key, expected_fingerprint)
        data = self._load()
        _check_name(name)
        if signer_id in data["signers"]:
            raise KeystoreError("that signing key is already in the trusted signers file")
        data["signers"][signer_id] = _new_entry(name, public_key, superseded_by=None)
        self._save(data)
        return signer_id

    def replace(
        self,
        old_signer_id: str,
        new_public_key: Ed25519PublicKey,
        *,
        expected_fingerprint: str,
    ) -> str:
        """Trust a new key of the same signer and mark the old one as superseded.

        Containers signed with the old key before the replacement still verify.
        Use :meth:`revoke` instead if the old key was compromised.

        Returns:
            The ``signer_id`` of the new key.

        Raises:
            InvalidKeyError: not an Ed25519 public key, or it does not match ``expected_fingerprint``.
            KeystoreError: the old key is unknown or not ``trusted``, or the new key is already known.
        """
        new_id = self._checked_signer_id(new_public_key, expected_fingerprint)
        data = self._load()
        old = data["signers"].get(old_signer_id)
        if old is None or old["status"] != STATUS_TRUSTED:
            raise KeystoreError("the key to replace is unknown or is not trusted")
        if new_id in data["signers"]:
            raise KeystoreError("that signing key is already in the trusted signers file")
        old["status"] = STATUS_SUPERSEDED
        old["superseded_by"] = new_id
        data["signers"][new_id] = _new_entry(old["name"], new_public_key, superseded_by=None)
        self._save(data)
        return new_id

    def revoke(self, signer_id: str, reason: str) -> None:
        """Stop trusting a key: every container signed with it is refused from now on.

        Raises:
            KeystoreError: the key is unknown, already revoked, or ``reason`` is not valid.
        """
        _check_reason(reason)
        data = self._load()
        entry = data["signers"].get(signer_id)
        if entry is None:
            raise KeystoreError("unknown signing key")
        if entry["status"] == STATUS_REVOKED:
            raise KeystoreError("that signing key is already revoked")
        entry["status"] = STATUS_REVOKED
        entry["revoked_at"] = now_utc()
        entry["reason"] = reason
        self._save(data)

    def import_revocation(self, notice_bytes: bytes) -> str:
        """Revoke the key named by a revocation notice from its owner.

        The notice comes from :meth:`vault.keystore.keyring.Keyring.revocation_notice`
        and must reach the recipient through a trusted channel.

        Returns:
            The ``signer_id`` that was revoked.

        Raises:
            KeystoreError: the notice is malformed, is not about an Ed25519 key, or names an
                unknown or already revoked key.
        """
        try:
            notice = json.loads(notice_bytes)
        except (TypeError, ValueError):
            notice = None
        if not (
            isinstance(notice, dict)
            and notice.get("format") == NOTICE_FORMAT
            and notice.get("key_type") == "Ed25519"
            and isinstance(notice.get("key_id"), str)
            and _SIGNER_ID_RE.fullmatch(notice["key_id"])
            and isinstance(notice.get("reason"), str)
        ):
            raise KeystoreError("not a valid revocation notice for a signing key")
        self.revoke(notice["key_id"], notice["reason"])
        return notice["key_id"]

    # ------------------------------------------------------------------ #
    # Internals                                                          #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _checked_signer_id(public_key: object, expected_fingerprint: str) -> str:
        if not isinstance(public_key, Ed25519PublicKey):
            raise InvalidKeyError("public_key must be an Ed25519 public key")
        signer_id = get_signer_id(public_key)
        if signer_id != expected_fingerprint:
            raise InvalidKeyError("the key does not match the fingerprint that was confirmed")
        return signer_id

    def _load(self) -> dict[str, Any]:
        try:
            data = read_json(self._path)
        except FileNotFoundError:
            return {"format": TRUST_FORMAT, "signers": {}}
        except (OSError, ValueError):
            data = None
        if not _file_is_valid(data):
            raise KeystoreError("the trusted signers file is unreadable or malformed")
        return data

    def _save(self, data: dict[str, Any]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            write_json_atomic(self._path, data)
        except OSError:
            failed = True
        else:
            failed = False
        if failed:
            raise KeystoreError("the trusted signers file cannot be written")


def verify_with_trusted_signers(
    container_bytes: bytes,
    trusted_signers: TrustedSigners,
    recipient_id: Optional[str],
    recipient_private_key: X25519PrivateKey,
    replay_guard: Optional[ReplayGuard] = None,
) -> bytes:
    """Verify a signed container against the trusted signers, then decrypt it.

    The signer is chosen by the ``signer_id`` inside the container, but only among
    the keys the recipient trusts: an unknown or revoked signer is refused before
    anything else, and a trusted one goes through the normal D5 check (signature
    first, then the replay check, then decryption).

    If ``replay_guard`` is given, a container that was already accepted, or an
    older version of a document that was already accepted, is refused, and the
    container is recorded once it has been decrypted (see D5).  Without a guard,
    replay and rollback are not detected.

    Raises:
        UntrustedSignerError: the signer is unknown or revoked.
        SignatureVerificationError: the container has no ``signer_id``, or the signature is invalid.
        ReplayDetectedError: the container was already accepted (needs a guard).
        RollbackDetectedError: an equal or newer version of the document was already accepted (needs a guard).
        ReplayStoreError: the guard's store cannot be read or written.
        DecryptionFailedError: the signature is valid but decryption fails.
    """
    public_key = trusted_signers.public_key_for(container_bytes)
    return verify_and_decrypt(
        container_bytes, public_key, recipient_id, recipient_private_key, replay_guard
    )


def _check_name(name: object) -> None:
    if not (
        isinstance(name, str) and 1 <= len(name) <= _MAX_NAME_LENGTH and name.isprintable()
    ):
        raise KeystoreError("name must be 1 to 64 printable characters")


def _check_reason(reason: object) -> None:
    if not (
        isinstance(reason, str) and 1 <= len(reason) <= _MAX_REASON_LENGTH and reason.isprintable()
    ):
        raise KeystoreError("reason must be 1 to 200 printable characters")


def _new_entry(name: str, public_key: Ed25519PublicKey, superseded_by: Optional[str]) -> dict[str, Any]:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return {
        "name": name,
        "public_key": base64.b64encode(raw).decode("ascii"),
        "status": STATUS_TRUSTED,
        "added": now_utc(),
        "superseded_by": superseded_by,
        "revoked_at": None,
        "reason": None,
    }


def _file_is_valid(data: Any) -> bool:
    if not isinstance(data, dict) or set(data) != _FILE_FIELDS:
        return False
    if data["format"] != TRUST_FORMAT or not isinstance(data["signers"], dict):
        return False
    for signer_id, entry in data["signers"].items():
        if not _SIGNER_ID_RE.fullmatch(signer_id) or not isinstance(entry, dict):
            return False
        if set(entry) != _ENTRY_FIELDS or entry["status"] not in _STATUSES:
            return False
        if not (isinstance(entry["name"], str) and entry["name"]):
            return False
        try:
            raw = base64.b64decode(entry["public_key"], validate=True)
            if get_signer_id(Ed25519PublicKey.from_public_bytes(raw)) != signer_id:
                return False
        except (binascii.Error, TypeError, ValueError):
            return False
        revoked = entry["status"] == STATUS_REVOKED
        if revoked != (isinstance(entry["revoked_at"], str) and isinstance(entry["reason"], str)):
            return False
        if not revoked and (entry["revoked_at"] is not None or entry["reason"] is not None):
            return False
        if not (entry["superseded_by"] is None or isinstance(entry["superseded_by"], str)):
            return False
    return True
