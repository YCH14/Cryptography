"""D5: rollback protection with a signed document_id and document_version."""

import base64
import json

import pytest

from vault.exceptions import (
    DecryptionFailedError,
    InvalidMetadataError,
    ReplayDetectedError,
    RollbackDetectedError,
    SignatureVerificationError,
)
from vault.hybrid import generate_x25519_keypair
from vault.hybrid.encryption import encrypt_bytes_hybrid
from vault.signatures import (
    ReplayGuard,
    generate_ed25519_keypair,
    sign_container,
    verify_and_decrypt,
)
from vault.signatures.signing import _digest_to_sign

PLAINTEXT = b"Secure Digital Document Vault - D5 rollback"


@pytest.fixture(scope="module")
def bob():
    return generate_x25519_keypair()


@pytest.fixture(scope="module")
def alice_signing_keys():
    return generate_ed25519_keypair()


@pytest.fixture()
def guard(tmp_path):
    return ReplayGuard(tmp_path / "replay-store.json")


def _signed(bob, signing_private, document_id=None, document_version=None) -> bytes:
    container = encrypt_bytes_hybrid(PLAINTEXT, [("bob", bob.public_key)])
    if document_id is None:
        return sign_container(container, signing_private)
    return sign_container(
        container, signing_private, document_id=document_id, document_version=document_version
    )


def _open(signed, signing_public, bob, guard):
    return verify_and_decrypt(signed, signing_public, "bob", bob.private_key, replay_guard=guard)


def _resign(container: dict, private_key) -> bytes:
    container["signature"] = base64.b64encode(
        private_key.sign(_digest_to_sign(container))
    ).decode("ascii")
    return json.dumps(container).encode("utf-8")


# Accepted and rejected versions ---------------------------------------------------


def test_new_versions_in_order_are_accepted(bob, alice_signing_keys, guard):
    alice_private, alice_public = alice_signing_keys
    for version in (1, 2, 5):  # skipping numbers is fine; going back is not
        signed = _signed(bob, alice_private, "contract", version)
        assert _open(signed, alice_public, bob, guard) == PLAINTEXT


def test_older_version_after_a_newer_one_is_rejected(bob, alice_signing_keys, guard):
    alice_private, alice_public = alice_signing_keys
    old = _signed(bob, alice_private, "contract", 1)
    new = _signed(bob, alice_private, "contract", 2)
    _open(new, alice_public, bob, guard)
    # The storage serves the old version again: a valid signature, a fresh
    # container_id from the signer's point of view, but an older version.
    with pytest.raises(RollbackDetectedError):
        _open(old, alice_public, bob, guard)


def test_same_version_in_a_different_container_is_rejected(bob, alice_signing_keys, guard):
    alice_private, alice_public = alice_signing_keys
    first = _signed(bob, alice_private, "contract", 3)
    second = _signed(bob, alice_private, "contract", 3)
    _open(first, alice_public, bob, guard)
    with pytest.raises(RollbackDetectedError):
        _open(second, alice_public, bob, guard)


def test_the_same_container_twice_is_reported_as_replay(bob, alice_signing_keys, guard):
    alice_private, alice_public = alice_signing_keys
    signed = _signed(bob, alice_private, "contract", 1)
    _open(signed, alice_public, bob, guard)
    with pytest.raises(ReplayDetectedError):
        _open(signed, alice_public, bob, guard)


def test_documents_are_independent(bob, alice_signing_keys, guard):
    alice_private, alice_public = alice_signing_keys
    _open(_signed(bob, alice_private, "contract", 5), alice_public, bob, guard)
    assert _open(_signed(bob, alice_private, "invoice", 1), alice_public, bob, guard) == PLAINTEXT


def test_signers_are_independent(bob, alice_signing_keys, guard):
    alice_private, alice_public = alice_signing_keys
    carol_private, carol_public = generate_ed25519_keypair()
    _open(_signed(bob, alice_private, "contract", 4), alice_public, bob, guard)
    assert _open(_signed(bob, carol_private, "contract", 1), carol_public, bob, guard) == PLAINTEXT


def test_containers_without_a_version_are_not_affected(bob, alice_signing_keys, guard):
    alice_private, alice_public = alice_signing_keys
    _open(_signed(bob, alice_private, "contract", 9), alice_public, bob, guard)
    assert _open(_signed(bob, alice_private), alice_public, bob, guard) == PLAINTEXT


def test_failed_decryption_does_not_advance_the_version(bob, alice_signing_keys, guard):
    alice_private, alice_public = alice_signing_keys
    new = _signed(bob, alice_private, "contract", 2)
    with pytest.raises(DecryptionFailedError):
        _open(new, alice_public, generate_x25519_keypair(), guard)
    # Nothing was accepted, so an older version is still acceptable.
    assert _open(_signed(bob, alice_private, "contract", 1), alice_public, bob, guard) == PLAINTEXT


def test_rollback_error_is_generic(bob, alice_signing_keys, guard):
    alice_private, alice_public = alice_signing_keys
    _open(_signed(bob, alice_private, "contract", 2), alice_public, bob, guard)
    with pytest.raises(RollbackDetectedError) as caught:
        _open(_signed(bob, alice_private, "contract", 1), alice_public, bob, guard)
    assert isinstance(caught.value, SignatureVerificationError)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


# Signing arguments -------------------------------------------------------------------


@pytest.mark.parametrize(
    "document_id, document_version",
    [("contract", None), (None, 1)],
    ids=["id-only", "version-only"],
)
def test_document_fields_must_be_given_together(bob, alice_signing_keys, document_id, document_version):
    alice_private, _ = alice_signing_keys
    container = encrypt_bytes_hybrid(PLAINTEXT, [("bob", bob.public_key)])
    with pytest.raises(InvalidMetadataError):
        sign_container(
            container, alice_private, document_id=document_id, document_version=document_version
        )


@pytest.mark.parametrize(
    "document_id, document_version",
    [
        ("contract", 0),
        ("contract", -1),
        ("contract", True),
        ("contract", 1.5),
        ("contract", "1"),
        ("contract", 2**63),
        ("", 1),
        ("x" * 129, 1),
        ("bad\nid", 1),
        (5, 1),
    ],
)
def test_invalid_document_fields_are_refused(bob, alice_signing_keys, document_id, document_version):
    alice_private, _ = alice_signing_keys
    container = encrypt_bytes_hybrid(PLAINTEXT, [("bob", bob.public_key)])
    with pytest.raises(InvalidMetadataError):
        sign_container(
            container, alice_private, document_id=document_id, document_version=document_version
        )


# Tampering ------------------------------------------------------------------------------


def test_document_fields_are_covered_by_the_signature(bob, alice_signing_keys):
    alice_private, alice_public = alice_signing_keys
    signed = json.loads(_signed(bob, alice_private, "contract", 1))

    raised = dict(signed, document_version=7)
    renamed = dict(signed, document_id="other")
    stripped = {k: v for k, v in signed.items() if k not in ("document_id", "document_version")}
    for forged in (raised, renamed, stripped):
        with pytest.raises(SignatureVerificationError):
            verify_and_decrypt(
                json.dumps(forged).encode(), alice_public, "bob", bob.private_key
            )


@pytest.mark.parametrize(
    "fields",
    [
        {"document_id": "contract"},
        {"document_version": 2},
        {"document_id": "contract", "document_version": "2"},
        {"document_id": "contract", "document_version": 0},
        {"document_id": "", "document_version": 1},
    ],
    ids=["id-only", "version-only", "string-version", "zero-version", "empty-id"],
)
def test_malformed_document_fields_are_rejected_even_with_a_valid_signature(
    bob, alice_signing_keys, fields
):
    alice_private, alice_public = alice_signing_keys
    signed = json.loads(_signed(bob, alice_private))
    signed.update(fields)
    resigned = _resign(signed, alice_private)
    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt(resigned, alice_public, "bob", bob.private_key)
