"""D5: replay protection with a ReplayGuard (a container is accepted only once)."""

import json

import pytest

from vault.exceptions import (
    DecryptionFailedError,
    ReplayDetectedError,
    ReplayStoreError,
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

PLAINTEXT = b"Secure Digital Document Vault - D5 replay"


@pytest.fixture(scope="module")
def bob():
    return generate_x25519_keypair()


@pytest.fixture(scope="module")
def alice_signing_keys():
    return generate_ed25519_keypair()


@pytest.fixture()
def store(tmp_path):
    return tmp_path / "replay-store.json"


def _signed(bob, signing_private) -> bytes:
    container = encrypt_bytes_hybrid(PLAINTEXT, [("bob", bob.public_key)])
    return sign_container(container, signing_private)


def _open(signed, signing_public, bob, guard):
    return verify_and_decrypt(signed, signing_public, "bob", bob.private_key, replay_guard=guard)


def test_first_delivery_is_accepted(bob, alice_signing_keys, store):
    alice_private, alice_public = alice_signing_keys
    signed = _signed(bob, alice_private)
    assert _open(signed, alice_public, bob, ReplayGuard(store)) == PLAINTEXT


def test_same_container_delivered_twice_is_rejected(bob, alice_signing_keys, store):
    alice_private, alice_public = alice_signing_keys
    guard = ReplayGuard(store)
    signed = _signed(bob, alice_private)
    _open(signed, alice_public, bob, guard)
    with pytest.raises(ReplayDetectedError):
        _open(signed, alice_public, bob, guard)


def test_replay_is_still_detected_after_a_restart(bob, alice_signing_keys, store):
    alice_private, alice_public = alice_signing_keys
    signed = _signed(bob, alice_private)
    _open(signed, alice_public, bob, ReplayGuard(store))
    # A new guard object reads the same file, like a new run of the program.
    with pytest.raises(ReplayDetectedError):
        _open(signed, alice_public, bob, ReplayGuard(store))


def test_a_new_container_with_the_same_content_is_accepted(bob, alice_signing_keys, store):
    alice_private, alice_public = alice_signing_keys
    guard = ReplayGuard(store)
    assert _open(_signed(bob, alice_private), alice_public, bob, guard) == PLAINTEXT
    assert _open(_signed(bob, alice_private), alice_public, bob, guard) == PLAINTEXT


def test_each_signer_has_its_own_record(bob, alice_signing_keys, store):
    alice_private, alice_public = alice_signing_keys
    carol_private, carol_public = generate_ed25519_keypair()
    guard = ReplayGuard(store)
    from_alice = _signed(bob, alice_private)
    from_carol = _signed(bob, carol_private)
    assert _open(from_alice, alice_public, bob, guard) == PLAINTEXT
    assert _open(from_carol, carol_public, bob, guard) == PLAINTEXT
    with pytest.raises(ReplayDetectedError):
        _open(from_carol, carol_public, bob, guard)


def test_failed_decryption_does_not_use_up_the_container(bob, alice_signing_keys, store):
    alice_private, alice_public = alice_signing_keys
    guard = ReplayGuard(store)
    signed = _signed(bob, alice_private)
    wrong_recipient = generate_x25519_keypair()
    with pytest.raises(DecryptionFailedError):
        _open(signed, alice_public, wrong_recipient, guard)
    # The right recipient can still open it, once.
    assert _open(signed, alice_public, bob, guard) == PLAINTEXT
    with pytest.raises(ReplayDetectedError):
        _open(signed, alice_public, bob, guard)


def test_invalid_signature_never_touches_the_store(bob, alice_signing_keys, store):
    alice_private, alice_public = alice_signing_keys
    guard = ReplayGuard(store)
    forged = json.loads(_signed(bob, alice_private))
    forged["filename"] = "evil.exe"
    with pytest.raises(SignatureVerificationError):
        _open(json.dumps(forged).encode(), alice_public, bob, guard)
    assert not store.exists()


def test_corrupted_store_is_not_ignored(bob, alice_signing_keys, store):
    alice_private, alice_public = alice_signing_keys
    store.write_bytes(b"not a replay store")
    with pytest.raises(ReplayStoreError):
        _open(_signed(bob, alice_private), alice_public, bob, ReplayGuard(store))


def test_replay_error_is_generic(bob, alice_signing_keys, store):
    alice_private, alice_public = alice_signing_keys
    guard = ReplayGuard(store)
    signed = _signed(bob, alice_private)
    _open(signed, alice_public, bob, guard)
    with pytest.raises(ReplayDetectedError) as replayed:
        _open(signed, alice_public, bob, guard)
    forged = json.loads(signed)
    forged["filename"] = "x"
    with pytest.raises(SignatureVerificationError) as invalid:
        _open(json.dumps(forged).encode(), alice_public, bob, guard)
    assert str(replayed.value) == str(invalid.value)
    assert replayed.value.__cause__ is None
    assert replayed.value.__context__ is None


def test_without_a_guard_replay_is_not_detected(bob, alice_signing_keys):
    alice_private, alice_public = alice_signing_keys
    signed = _signed(bob, alice_private)
    assert verify_and_decrypt(signed, alice_public, "bob", bob.private_key) == PLAINTEXT
    assert verify_and_decrypt(signed, alice_public, "bob", bob.private_key) == PLAINTEXT


def test_store_file_holds_only_identifiers(bob, alice_signing_keys, store):
    alice_private, alice_public = alice_signing_keys
    signed = _signed(bob, alice_private)
    _open(signed, alice_public, bob, ReplayGuard(store))
    content = store.read_bytes()
    assert json.loads(signed)["container_id"].encode() in content
    assert PLAINTEXT not in content
    assert json.loads(signed)["ciphertext"].encode() not in content
