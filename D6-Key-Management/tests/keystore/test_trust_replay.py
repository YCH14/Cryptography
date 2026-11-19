"""D6: trusted signers together with the D5 replay and rollback guard."""

import json

import pytest

from vault.exceptions import (
    DecryptionFailedError,
    ReplayDetectedError,
    RollbackDetectedError,
    UntrustedSignerError,
)
from vault.hybrid import generate_x25519_keypair
from vault.hybrid.encryption import encrypt_bytes_hybrid
from vault.keystore import TrustedSigners, verify_with_trusted_signers
from vault.signatures import ReplayGuard, generate_ed25519_keypair, get_signer_id, sign_container

PLAINTEXT = b"Secure Digital Document Vault - trusted signers and replay guard"


@pytest.fixture(scope="module")
def bob():
    return generate_x25519_keypair()


@pytest.fixture(scope="module")
def alice():
    return generate_ed25519_keypair()


@pytest.fixture()
def trusted(tmp_path, alice):
    signers = TrustedSigners(tmp_path / "trusted_signers.json")
    signers.add("alice", alice[1], expected_fingerprint=get_signer_id(alice[1]))
    return signers


@pytest.fixture()
def guard(tmp_path):
    return ReplayGuard(tmp_path / "replay.json")


def _signed(bob, alice, **document_fields) -> bytes:
    container = encrypt_bytes_hybrid(PLAINTEXT, [("bob", bob.public_key)])
    return sign_container(container, alice[0], **document_fields)


def _open(signed, trusted, bob, guard=None):
    return verify_with_trusted_signers(signed, trusted, "bob", bob.private_key, guard)


def test_without_a_guard_the_same_container_opens_twice(bob, alice, trusted):
    signed = _signed(bob, alice)
    assert _open(signed, trusted, bob) == PLAINTEXT
    assert _open(signed, trusted, bob) == PLAINTEXT


def test_first_delivery_is_accepted_with_a_guard(bob, alice, trusted, guard):
    assert _open(_signed(bob, alice), trusted, bob, guard) == PLAINTEXT


def test_a_replayed_container_is_refused(bob, alice, trusted, guard):
    signed = _signed(bob, alice)
    assert _open(signed, trusted, bob, guard) == PLAINTEXT
    with pytest.raises(ReplayDetectedError):
        _open(signed, trusted, bob, guard)


def test_a_new_container_from_the_same_signer_is_accepted(bob, alice, trusted, guard):
    assert _open(_signed(bob, alice), trusted, bob, guard) == PLAINTEXT
    assert _open(_signed(bob, alice), trusted, bob, guard) == PLAINTEXT


def test_an_older_document_version_is_refused(bob, alice, trusted, guard):
    new = _signed(bob, alice, document_id="contract", document_version=2)
    old = _signed(bob, alice, document_id="contract", document_version=1)
    assert _open(new, trusted, bob, guard) == PLAINTEXT
    with pytest.raises(RollbackDetectedError):
        _open(old, trusted, bob, guard)


def test_a_newer_document_version_is_accepted(bob, alice, trusted, guard):
    first = _signed(bob, alice, document_id="contract", document_version=1)
    second = _signed(bob, alice, document_id="contract", document_version=2)
    assert _open(first, trusted, bob, guard) == PLAINTEXT
    assert _open(second, trusted, bob, guard) == PLAINTEXT


def test_the_record_survives_a_new_guard_object(bob, alice, trusted, tmp_path):
    signed = _signed(bob, alice)
    path = tmp_path / "replay.json"
    assert _open(signed, trusted, bob, ReplayGuard(path)) == PLAINTEXT
    with pytest.raises(ReplayDetectedError):
        _open(signed, trusted, bob, ReplayGuard(path))


def test_an_unknown_signer_is_refused_and_not_recorded(bob, alice, tmp_path, guard):
    empty = TrustedSigners(tmp_path / "empty_trusted.json")
    signed = _signed(bob, alice)
    with pytest.raises(UntrustedSignerError):
        _open(signed, empty, bob, guard)
    assert not (tmp_path / "replay.json").exists()


def test_a_revoked_signer_is_refused_before_the_replay_check(bob, alice, trusted, guard):
    signed = _signed(bob, alice)
    assert _open(signed, trusted, bob, guard) == PLAINTEXT
    trusted.revoke(get_signer_id(alice[1]), "signing key stolen")
    with pytest.raises(UntrustedSignerError) as excinfo:
        _open(signed, trusted, bob, guard)
    assert not isinstance(excinfo.value, ReplayDetectedError)


def test_a_failed_decryption_does_not_use_up_the_container(bob, alice, trusted, guard):
    eve = generate_x25519_keypair()
    signed = _signed(bob, alice)
    with pytest.raises(DecryptionFailedError):
        verify_with_trusted_signers(signed, trusted, "bob", eve.private_key, guard)
    assert _open(signed, trusted, bob, guard) == PLAINTEXT


def test_a_tampered_container_is_not_recorded(bob, alice, trusted, tmp_path, guard):
    signed = _signed(bob, alice)
    tampered = signed.replace(b'"container_id"', b'"container_ie"', 1)
    with pytest.raises(Exception) as excinfo:
        _open(tampered, trusted, bob, guard)
    assert not isinstance(excinfo.value, ReplayDetectedError)
    record = tmp_path / "replay.json"
    assert not record.exists() or not json.loads(record.read_text())["containers"]
