"""D6: trusted signing keys: distribution, replacement and revocation."""

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization

from vault.exceptions import (
    DecryptionFailedError,
    InvalidKeyError,
    KeystoreError,
    SignatureVerificationError,
    UntrustedSignerError,
)
from vault.hybrid import generate_x25519_keypair
from vault.hybrid.encryption import encrypt_bytes_hybrid
from vault.keystore import Keyring, TrustedSigners, verify_with_trusted_signers
from vault.signatures import generate_ed25519_keypair, get_signer_id, sign_container

PLAINTEXT = b"Secure Digital Document Vault - D6 trusted signers"
PASSWORD = "passphrase for the signing keystore"


@pytest.fixture(scope="module")
def bob():
    return generate_x25519_keypair()


@pytest.fixture(scope="module")
def alice_signing():
    return generate_ed25519_keypair()


@pytest.fixture()
def trusted(tmp_path):
    return TrustedSigners(tmp_path / "trusted_signers.json")


def _signed(bob, signing_private) -> bytes:
    container = encrypt_bytes_hybrid(PLAINTEXT, [("bob", bob.public_key)])
    return sign_container(container, signing_private)


def _open(signed, trusted, bob):
    return verify_with_trusted_signers(signed, trusted, "bob", bob.private_key)


# Distribution ------------------------------------------------------------------------------


def test_trusted_signer_is_accepted(bob, alice_signing, trusted):
    private_key, public_key = alice_signing
    signer_id = trusted.add("alice", public_key, expected_fingerprint=get_signer_id(public_key))
    assert trusted.status(signer_id) == "trusted"
    assert _open(_signed(bob, private_key), trusted, bob) == PLAINTEXT


def test_key_is_refused_if_the_fingerprint_does_not_match(alice_signing, trusted):
    _, public_key = alice_signing
    _, other_public = generate_ed25519_keypair()
    with pytest.raises(InvalidKeyError):
        trusted.add("alice", public_key, expected_fingerprint=get_signer_id(other_public))
    assert trusted.signer_ids() == []


@pytest.mark.parametrize("fingerprint", ["", "abc", "0" * 64, None])
def test_a_wrong_or_missing_fingerprint_is_refused(alice_signing, trusted, fingerprint):
    _, public_key = alice_signing
    with pytest.raises(InvalidKeyError):
        trusted.add("alice", public_key, expected_fingerprint=fingerprint)


def test_only_ed25519_public_keys_are_accepted(trusted, bob):
    with pytest.raises(InvalidKeyError):
        trusted.add("bob", bob.public_key, expected_fingerprint="0" * 64)


@pytest.mark.parametrize("name", ["", "x" * 65, "bad\nname", None, 5])
def test_name_must_be_valid(alice_signing, trusted, name):
    _, public_key = alice_signing
    with pytest.raises(KeystoreError):
        trusted.add(name, public_key, expected_fingerprint=get_signer_id(public_key))


def test_the_same_key_cannot_be_added_twice(alice_signing, trusted):
    _, public_key = alice_signing
    fingerprint = get_signer_id(public_key)
    trusted.add("alice", public_key, expected_fingerprint=fingerprint)
    with pytest.raises(KeystoreError):
        trusted.add("alice again", public_key, expected_fingerprint=fingerprint)


def test_unknown_signer_is_refused(bob, alice_signing, trusted):
    private_key, _ = alice_signing
    with pytest.raises(UntrustedSignerError):
        _open(_signed(bob, private_key), trusted, bob)


def test_a_signature_from_another_key_is_still_refused(bob, alice_signing, trusted):
    _, alice_public = alice_signing
    eve_private, _ = generate_ed25519_keypair()
    trusted.add("alice", alice_public, expected_fingerprint=get_signer_id(alice_public))
    # Eve's container names Eve's signer_id, which is not trusted.
    with pytest.raises(UntrustedSignerError):
        _open(_signed(bob, eve_private), trusted, bob)


def test_a_container_with_a_forged_signer_id_fails_the_signature(bob, alice_signing, trusted):
    _, alice_public = alice_signing
    eve_private, _ = generate_ed25519_keypair()
    trusted.add("alice", alice_public, expected_fingerprint=get_signer_id(alice_public))
    forged = json.loads(_signed(bob, eve_private))
    forged["signer_id"] = get_signer_id(alice_public)
    with pytest.raises(SignatureVerificationError):
        _open(json.dumps(forged).encode(), trusted, bob)


@pytest.mark.parametrize("data", [b"not json", b"[]", b"{}", b'{"signer_id": 5}'])
def test_containers_without_a_readable_signer_are_refused(bob, trusted, data):
    with pytest.raises(SignatureVerificationError):
        _open(data, trusted, bob)


def test_only_the_trusted_signer_decides_decryption(bob, alice_signing, trusted):
    private_key, public_key = alice_signing
    trusted.add("alice", public_key, expected_fingerprint=get_signer_id(public_key))
    with pytest.raises(DecryptionFailedError):
        verify_with_trusted_signers(
            _signed(bob, private_key), trusted, "bob", generate_x25519_keypair().private_key
        )


# Replacement ------------------------------------------------------------------------------


def test_replacing_a_key_keeps_old_containers_valid(bob, alice_signing, trusted):
    old_private, old_public = alice_signing
    new_private, new_public = generate_ed25519_keypair()
    old_id = trusted.add("alice", old_public, expected_fingerprint=get_signer_id(old_public))
    old_container = _signed(bob, old_private)

    new_id = trusted.replace(old_id, new_public, expected_fingerprint=get_signer_id(new_public))

    assert trusted.status(old_id) == "superseded"
    assert trusted.status(new_id) == "trusted"
    assert _open(old_container, trusted, bob) == PLAINTEXT
    assert _open(_signed(bob, new_private), trusted, bob) == PLAINTEXT


def test_replacing_needs_the_new_fingerprint_too(alice_signing, trusted):
    _, old_public = alice_signing
    _, new_public = generate_ed25519_keypair()
    old_id = trusted.add("alice", old_public, expected_fingerprint=get_signer_id(old_public))
    with pytest.raises(InvalidKeyError):
        trusted.replace(old_id, new_public, expected_fingerprint=old_id)
    assert trusted.status(old_id) == "trusted"


def test_only_a_trusted_key_can_be_replaced(alice_signing, trusted):
    _, old_public = alice_signing
    _, new_public = generate_ed25519_keypair()
    _, third_public = generate_ed25519_keypair()
    old_id = trusted.add("alice", old_public, expected_fingerprint=get_signer_id(old_public))
    trusted.replace(old_id, new_public, expected_fingerprint=get_signer_id(new_public))
    with pytest.raises(KeystoreError):
        trusted.replace(old_id, third_public, expected_fingerprint=get_signer_id(third_public))
    with pytest.raises(KeystoreError):
        trusted.replace("0" * 64, third_public, expected_fingerprint=get_signer_id(third_public))


# Revocation ------------------------------------------------------------------------------


def test_revoked_key_is_refused(bob, alice_signing, trusted):
    private_key, public_key = alice_signing
    signer_id = trusted.add("alice", public_key, expected_fingerprint=get_signer_id(public_key))
    before = _signed(bob, private_key)
    assert _open(before, trusted, bob) == PLAINTEXT

    trusted.revoke(signer_id, "laptop stolen")

    assert trusted.status(signer_id) == "revoked"
    # Including a container that was signed before: the timestamp cannot prove when.
    with pytest.raises(UntrustedSignerError):
        _open(before, trusted, bob)
    with pytest.raises(UntrustedSignerError):
        _open(_signed(bob, private_key), trusted, bob)


def test_revocation_of_the_old_key_does_not_affect_the_new_one(bob, alice_signing, trusted):
    old_private, old_public = alice_signing
    new_private, new_public = generate_ed25519_keypair()
    old_id = trusted.add("alice", old_public, expected_fingerprint=get_signer_id(old_public))
    trusted.replace(old_id, new_public, expected_fingerprint=get_signer_id(new_public))
    trusted.revoke(old_id, "old key was exposed")
    assert _open(_signed(bob, new_private), trusted, bob) == PLAINTEXT
    with pytest.raises(UntrustedSignerError):
        _open(_signed(bob, old_private), trusted, bob)


def test_a_key_cannot_be_revoked_twice_or_unknown(alice_signing, trusted):
    _, public_key = alice_signing
    signer_id = trusted.add("alice", public_key, expected_fingerprint=get_signer_id(public_key))
    trusted.revoke(signer_id, "first")
    with pytest.raises(KeystoreError):
        trusted.revoke(signer_id, "second")
    with pytest.raises(KeystoreError):
        trusted.revoke("0" * 64, "unknown")


def test_a_revoked_key_cannot_be_added_back(alice_signing, trusted):
    _, public_key = alice_signing
    fingerprint = get_signer_id(public_key)
    trusted.add("alice", public_key, expected_fingerprint=fingerprint)
    trusted.revoke(fingerprint, "compromised")
    with pytest.raises(KeystoreError):
        trusted.add("alice", public_key, expected_fingerprint=fingerprint)
    assert trusted.status(fingerprint) == "revoked"


def test_untrusted_signer_error_is_generic(bob, alice_signing, trusted):
    private_key, _ = alice_signing
    with pytest.raises(UntrustedSignerError) as untrusted:
        _open(_signed(bob, private_key), trusted, bob)
    with pytest.raises(SignatureVerificationError) as invalid:
        _open(b"not json", trusted, bob)
    assert isinstance(untrusted.value, SignatureVerificationError)
    assert str(untrusted.value) == str(invalid.value)
    assert untrusted.value.__cause__ is None
    assert untrusted.value.__context__ is None


# The owner's notice reaches the recipient ----------------------------------------------


def test_revocation_notice_from_the_owner_revokes_the_key(bob, tmp_path, trusted):
    # Alice keeps her signing key in a keyring and publishes her fingerprint.
    signing_keyring = Keyring.create(tmp_path / "alice-signing", "alice", "Ed25519")
    alice_private, alice_public = generate_ed25519_keypair()
    entry = signing_keyring.rotate(alice_private, PASSWORD)
    # Bob confirms the fingerprint out of band and trusts the key.
    trusted.add("alice", alice_public, expected_fingerprint=entry.key_id)
    container = _signed(bob, signing_keyring.unlock_active(PASSWORD))
    assert _open(container, trusted, bob) == PLAINTEXT

    # Alice's key is compromised: she revokes it, rotates, and sends Bob the notice.
    signing_keyring.revoke(entry.key_id, "laptop stolen", compromised=True)
    new_private, new_public = generate_ed25519_keypair()
    new_entry = signing_keyring.rotate(new_private, PASSWORD)
    notice = signing_keyring.revocation_notice(entry.key_id)

    assert trusted.import_revocation(notice) == entry.key_id
    with pytest.raises(UntrustedSignerError):
        _open(container, trusted, bob)

    # Bob confirms her new fingerprint and trusts the new key.
    trusted.add("alice", new_public, expected_fingerprint=new_entry.key_id)
    assert _open(_signed(bob, signing_keyring.unlock_active(PASSWORD)), trusted, bob) == PLAINTEXT


def test_notice_for_an_unknown_key_is_refused(tmp_path, trusted):
    keyring = Keyring.create(tmp_path / "other-signing", "carol", "Ed25519")
    key, _ = generate_ed25519_keypair()
    entry = keyring.rotate(key, PASSWORD)
    keyring.revoke(entry.key_id, "lost")
    with pytest.raises(KeystoreError):
        trusted.import_revocation(keyring.revocation_notice(entry.key_id))


def test_notice_for_a_decryption_key_is_refused(tmp_path, trusted, alice_signing):
    _, alice_public = alice_signing
    trusted.add("alice", alice_public, expected_fingerprint=get_signer_id(alice_public))
    keyring = Keyring.create(tmp_path / "alice-keyring", "alice", "X25519")
    entry = keyring.rotate(generate_x25519_keypair().private_key, PASSWORD)
    keyring.revoke(entry.key_id, "lost")
    with pytest.raises(KeystoreError):
        trusted.import_revocation(keyring.revocation_notice(entry.key_id))


@pytest.mark.parametrize(
    "notice",
    [
        b"not json",
        b"[]",
        b"{}",
        json.dumps({"format": "VRN1", "key_type": "Ed25519", "key_id": "zz", "reason": "x"}).encode(),
        json.dumps({"format": "OTHER", "key_type": "Ed25519", "key_id": "0" * 64, "reason": "x"}).encode(),
    ],
    ids=["garbage", "list", "empty", "bad-key-id", "wrong-format"],
)
def test_malformed_notice_is_refused(trusted, notice):
    with pytest.raises(KeystoreError):
        trusted.import_revocation(notice)


# What is stored ------------------------------------------------------------------------------


def test_status_is_kept_between_runs(alice_signing, trusted):
    _, public_key = alice_signing
    signer_id = trusted.add("alice", public_key, expected_fingerprint=get_signer_id(public_key))
    trusted.revoke(signer_id, "lost")
    assert TrustedSigners(trusted.path).status(signer_id) == "revoked"
    assert TrustedSigners(trusted.path).status("0" * 64) is None


def test_file_holds_only_public_keys(alice_signing, trusted):
    private_key, public_key = alice_signing
    trusted.add("alice", public_key, expected_fingerprint=get_signer_id(public_key))
    content = trusted.path.read_bytes()
    private_raw = private_key.private_bytes_raw()
    assert private_raw not in content
    assert b"PRIVATE KEY" not in content


@pytest.mark.parametrize(
    "content",
    [b"not json", b"[]", b'{"format":"VTS1"}', b'{"format":"OTHER","signers":{}}',
     b'{"format":"VTS1","signers":{"abc":{}}}'],
    ids=["garbage", "list", "missing", "wrong-format", "bad-entry"],
)
def test_a_malformed_file_is_not_ignored(trusted, content):
    trusted.path.write_bytes(content)
    with pytest.raises(KeystoreError):
        trusted.signer_ids()


def test_a_public_key_that_does_not_match_its_signer_id_is_refused(alice_signing, trusted):
    _, public_key = alice_signing
    signer_id = trusted.add("alice", public_key, expected_fingerprint=get_signer_id(public_key))
    data = json.loads(trusted.path.read_bytes())
    _, other_public = generate_ed25519_keypair()
    raw = other_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    data["signers"][signer_id]["public_key"] = base64.b64encode(raw).decode()
    trusted.path.write_bytes(json.dumps(data).encode())
    with pytest.raises(KeystoreError):
        trusted.status(signer_id)
