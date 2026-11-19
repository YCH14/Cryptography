"""D6: rotation and historical access with a keyring of keystores."""

import json

import pytest
from cryptography.hazmat.primitives import serialization

from vault.exceptions import DecryptionFailedError, KeystoreAccessError, KeystoreError
from vault.hybrid import generate_x25519_keypair
from vault.hybrid.encryption import decrypt_bytes_hybrid, encrypt_bytes_hybrid
from vault.keystore import STATUS_ACTIVE, STATUS_RETIRED, Keyring
from vault.signatures import generate_ed25519_keypair

PASSWORD_1 = "first passphrase for the first key"
PASSWORD_2 = "second passphrase for the next key"
PLAINTEXT = b"Secure Digital Document Vault - D6 keyring"


def _der(private_key) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@pytest.fixture(scope="module")
def keys():
    return [generate_x25519_keypair() for _ in range(3)]


@pytest.fixture()
def keyring(tmp_path):
    return Keyring.create(tmp_path / "alice-keyring", "alice", "X25519")


# Creating and opening ----------------------------------------------------------------


def test_create_makes_an_empty_keyring(keyring):
    assert keyring.owner == "alice"
    assert keyring.key_type == "X25519"
    assert keyring.entries() == []
    assert keyring.active_entry() is None
    assert (keyring.path / "keyring.json").is_file()


def test_existing_keyring_is_never_overwritten(keyring):
    with pytest.raises(KeystoreError):
        Keyring.create(keyring.path, "alice", "X25519")


@pytest.mark.parametrize("owner, key_type", [("", "X25519"), ("alice", "RSA"), ("alice", "")])
def test_create_refuses_bad_arguments(tmp_path, owner, key_type):
    with pytest.raises(KeystoreError):
        Keyring.create(tmp_path / "bad", owner, key_type)
    assert not (tmp_path / "bad").exists()


def test_open_refuses_something_that_is_not_a_keyring(tmp_path):
    with pytest.raises(KeystoreError):
        Keyring.open(tmp_path / "missing")
    (tmp_path / "empty").mkdir()
    with pytest.raises(KeystoreError):
        Keyring.open(tmp_path / "empty")


@pytest.mark.parametrize(
    "content",
    [b"not json", b"[]", b'{"format":"VKR1"}', b'{"format":"OTHER","owner":"a","key_type":"X25519","keys":[]}'],
    ids=["garbage", "list", "missing-fields", "wrong-format"],
)
def test_malformed_manifest_is_refused(keyring, content):
    (keyring.path / "keyring.json").write_bytes(content)
    with pytest.raises(KeystoreError):
        Keyring.open(keyring.path)


# First key and rotation ------------------------------------------------------------------


def test_first_key_becomes_active(keyring, keys):
    entry = keyring.rotate(keys[0].private_key, PASSWORD_1)
    assert entry.status == STATUS_ACTIVE
    assert keyring.active_entry() == entry
    assert _der(keyring.unlock_active(PASSWORD_1)) == _der(keys[0].private_key)


def test_rotation_makes_the_new_key_active_and_retires_the_old_one(keyring, keys):
    first = keyring.rotate(keys[0].private_key, PASSWORD_1)
    second = keyring.rotate(keys[1].private_key, PASSWORD_2)

    assert keyring.active_entry().key_id == second.key_id
    old = keyring.entry(first.key_id)
    assert old.status == STATUS_RETIRED
    assert old.retired_at is not None
    assert [e.key_id for e in keyring.entries()] == [first.key_id, second.key_id]


def test_only_one_key_is_active_after_several_rotations(keyring, keys):
    for index, key in enumerate(keys):
        keyring.rotate(key.private_key, f"passphrase number {index} for the keystore")
    statuses = [e.status for e in keyring.entries()]
    assert statuses.count(STATUS_ACTIVE) == 1
    assert statuses.count(STATUS_RETIRED) == 2


def test_each_key_has_its_own_password(keyring, keys):
    first = keyring.rotate(keys[0].private_key, PASSWORD_1)
    keyring.rotate(keys[1].private_key, PASSWORD_2)
    assert _der(keyring.unlock(first.key_id, PASSWORD_1)) == _der(keys[0].private_key)
    with pytest.raises(KeystoreAccessError):
        keyring.unlock(first.key_id, PASSWORD_2)
    with pytest.raises(KeystoreAccessError):
        keyring.unlock_active(PASSWORD_1)


def test_the_same_key_cannot_be_added_twice(keyring, keys):
    keyring.rotate(keys[0].private_key, PASSWORD_1)
    with pytest.raises(KeystoreError):
        keyring.rotate(keys[0].private_key, PASSWORD_2)
    assert len(keyring.entries()) == 1


def test_a_key_of_another_type_is_refused(keyring):
    signing_key, _ = generate_ed25519_keypair()
    with pytest.raises(KeystoreError):
        keyring.rotate(signing_key, PASSWORD_1)
    assert keyring.entries() == []


def test_unlock_active_needs_an_active_key(keyring):
    with pytest.raises(KeystoreError):
        keyring.unlock_active(PASSWORD_1)


def test_unknown_key_id_is_refused(keyring, keys):
    keyring.rotate(keys[0].private_key, PASSWORD_1)
    with pytest.raises(KeystoreError):
        keyring.unlock("0" * 64, PASSWORD_1)
    with pytest.raises(KeystoreError):
        keyring.entry("0" * 64)


def test_a_signing_keyring_rotates_too(tmp_path):
    keyring = Keyring.create(tmp_path / "alice-signing", "alice", "Ed25519")
    first, _ = generate_ed25519_keypair()
    second, _ = generate_ed25519_keypair()
    keyring.rotate(first, PASSWORD_1)
    keyring.rotate(second, PASSWORD_2)
    assert _der(keyring.unlock_active(PASSWORD_2)) == _der(second)


# What the keyring keeps on disk ------------------------------------------------------


def test_every_key_stays_in_its_own_encrypted_keystore(keyring, keys):
    entry = keyring.rotate(keys[0].private_key, PASSWORD_1)
    keystore = keyring.path / "keys" / entry.key_id
    assert sorted(p.name for p in keystore.iterdir()) == [
        "encrypted_private_key",
        "kdf_parameters",
        "metadata",
        "salt",
    ]
    assert json.loads((keystore / "metadata").read_bytes())["key_id"] == entry.key_id


def test_manifest_holds_no_key_material(keyring, keys):
    keyring.rotate(keys[0].private_key, PASSWORD_1)
    keyring.rotate(keys[1].private_key, PASSWORD_2)
    manifest = (keyring.path / "keyring.json").read_bytes()
    for key in keys[:2]:
        assert _der(key.private_key) not in manifest
        assert _der(key.private_key)[-32:] not in manifest
    assert b"PRIVATE KEY" not in manifest


# Historical access -----------------------------------------------------------------------


def test_files_made_before_a_rotation_can_still_be_opened(keyring, keys):
    old_key, new_key = keys[0], keys[1]
    old_entry = keyring.rotate(old_key.private_key, PASSWORD_1)
    old_container = encrypt_bytes_hybrid(PLAINTEXT, [("alice", old_key.public_key)])

    keyring.rotate(new_key.private_key, PASSWORD_2)
    new_container = encrypt_bytes_hybrid(PLAINTEXT, [("alice", new_key.public_key)])

    # The active key opens new files; the retired one is still there for old files.
    assert decrypt_bytes_hybrid(new_container, "alice", keyring.unlock_active(PASSWORD_2)) == PLAINTEXT
    historical_key = keyring.unlock(old_entry.key_id, PASSWORD_1)
    assert decrypt_bytes_hybrid(old_container, "alice", historical_key) == PLAINTEXT
    # ...and the new key does not open the old file.
    with pytest.raises(DecryptionFailedError):
        decrypt_bytes_hybrid(old_container, "alice", keyring.unlock_active(PASSWORD_2))
