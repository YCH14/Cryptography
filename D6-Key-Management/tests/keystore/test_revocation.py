"""D6: revocation, a compromised key, and recovering old files."""

import json

import pytest
from cryptography.hazmat.primitives import serialization

from vault.exceptions import DecryptionFailedError, KeystoreAccessError, KeystoreError
from vault.hybrid import generate_x25519_keypair
from vault.hybrid.encryption import decrypt_bytes_hybrid, encrypt_bytes_hybrid
from vault.keystore import STATUS_ACTIVE, STATUS_REVOKED, Keyring
from vault.signatures import generate_ed25519_keypair

PASSWORD_1 = "first passphrase for the first key"
PASSWORD_2 = "second passphrase for the next key"
PLAINTEXT = b"Secure Digital Document Vault - D6 revocation"


def _der(private_key) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@pytest.fixture(scope="module")
def keys():
    return [generate_x25519_keypair() for _ in range(2)]


@pytest.fixture()
def keyring(tmp_path):
    return Keyring.create(tmp_path / "alice-keyring", "alice", "X25519")


@pytest.fixture()
def rotated(keyring, keys):
    """A keyring with a retired key (0) and an active key (1)."""
    old = keyring.rotate(keys[0].private_key, PASSWORD_1)
    new = keyring.rotate(keys[1].private_key, PASSWORD_2)
    return keyring, old, new


# Revoking --------------------------------------------------------------------------------


def test_revoking_the_active_key_leaves_no_active_key(keyring, keys):
    entry = keyring.rotate(keys[0].private_key, PASSWORD_1)
    revoked = keyring.revoke(entry.key_id, "laptop stolen", compromised=True)

    assert revoked.status == STATUS_REVOKED
    assert revoked.compromised is True
    assert revoked.reason == "laptop stolen"
    assert revoked.revoked_at is not None
    assert keyring.active_entry() is None
    with pytest.raises(KeystoreError):
        keyring.unlock_active(PASSWORD_1)


def test_a_new_key_can_be_added_after_a_revocation(keyring, keys):
    first = keyring.rotate(keys[0].private_key, PASSWORD_1)
    keyring.revoke(first.key_id, "password leaked", compromised=True)
    second = keyring.rotate(keys[1].private_key, PASSWORD_2)
    assert keyring.active_entry().key_id == second.key_id
    assert keyring.entry(first.key_id).status == STATUS_REVOKED


def test_a_retired_key_can_be_revoked(rotated):
    keyring, old, new = rotated
    keyring.revoke(old.key_id, "no longer needed")
    assert keyring.entry(old.key_id).status == STATUS_REVOKED
    assert keyring.entry(old.key_id).compromised is False
    assert keyring.active_entry().key_id == new.key_id


def test_a_revoked_key_is_not_unlocked_by_default(rotated):
    keyring, old, _ = rotated
    keyring.revoke(old.key_id, "key compromised", compromised=True)
    with pytest.raises(KeystoreError):
        keyring.unlock(old.key_id, PASSWORD_1)


def test_a_revoked_key_can_be_unlocked_explicitly_to_recover_files(rotated, keys):
    keyring, old, _ = rotated
    keyring.revoke(old.key_id, "key compromised", compromised=True)
    recovered = keyring.unlock(old.key_id, PASSWORD_1, allow_revoked=True)
    assert _der(recovered) == _der(keys[0].private_key)


def test_explicit_access_still_needs_the_password(rotated):
    keyring, old, _ = rotated
    keyring.revoke(old.key_id, "key compromised", compromised=True)
    with pytest.raises(KeystoreAccessError):
        keyring.unlock(old.key_id, "wrong password", allow_revoked=True)


def test_a_key_cannot_be_revoked_twice(rotated):
    keyring, old, _ = rotated
    keyring.revoke(old.key_id, "first")
    with pytest.raises(KeystoreError):
        keyring.revoke(old.key_id, "second")


def test_unknown_key_cannot_be_revoked(keyring):
    with pytest.raises(KeystoreError):
        keyring.revoke("0" * 64, "reason")


@pytest.mark.parametrize("reason", ["", "x" * 201, "bad\nreason", None, 5])
def test_a_reason_is_required(rotated, reason):
    keyring, old, _ = rotated
    with pytest.raises(KeystoreError):
        keyring.revoke(old.key_id, reason)
    assert keyring.entry(old.key_id).status != STATUS_REVOKED


def test_revocation_survives_reopening_the_keyring(rotated):
    keyring, old, _ = rotated
    keyring.revoke(old.key_id, "key compromised", compromised=True)
    entry = Keyring.open(keyring.path).entry(old.key_id)
    assert entry.status == STATUS_REVOKED and entry.compromised is True


def test_the_keystore_of_a_revoked_key_is_kept(rotated):
    keyring, old, _ = rotated
    keyring.revoke(old.key_id, "key compromised", compromised=True)
    assert (keyring.path / "keys" / old.key_id / "encrypted_private_key").is_file()


# The notice ----------------------------------------------------------------------------------


def test_revocation_notice_describes_the_revoked_key(rotated):
    keyring, old, _ = rotated
    keyring.revoke(old.key_id, "laptop stolen", compromised=True)
    notice = json.loads(keyring.revocation_notice(old.key_id))
    assert notice == {
        "format": "VRN1",
        "owner": "alice",
        "key_type": "X25519",
        "key_id": old.key_id,
        "revoked_at": keyring.entry(old.key_id).revoked_at,
        "reason": "laptop stolen",
        "compromised": True,
    }


def test_notice_holds_no_key_material(rotated, keys):
    keyring, old, _ = rotated
    keyring.revoke(old.key_id, "laptop stolen", compromised=True)
    notice = keyring.revocation_notice(old.key_id)
    assert _der(keys[0].private_key)[-32:] not in notice


def test_only_a_revoked_key_has_a_notice(rotated):
    keyring, old, new = rotated
    with pytest.raises(KeystoreError):
        keyring.revocation_notice(old.key_id)  # retired
    with pytest.raises(KeystoreError):
        keyring.revocation_notice(new.key_id)  # active
    with pytest.raises(KeystoreError):
        keyring.revocation_notice("0" * 64)


# Historical access to old files --------------------------------------------------------


def test_decrypt_finds_the_right_key_after_a_rotation(rotated, keys):
    keyring, old, new = rotated
    old_container = encrypt_bytes_hybrid(PLAINTEXT, [("alice", keys[0].public_key)])
    new_container = encrypt_bytes_hybrid(PLAINTEXT, [("alice", keys[1].public_key)])

    assert keyring.find_key_for_container(old_container).key_id == old.key_id
    assert keyring.find_key_for_container(new_container).key_id == new.key_id
    assert keyring.decrypt(new_container, PASSWORD_2) == PLAINTEXT
    # The retired key opens the file that was made before the rotation.
    assert keyring.decrypt(old_container, PASSWORD_1) == PLAINTEXT


def test_decrypt_refuses_a_container_that_is_not_for_this_keyring(rotated):
    keyring, _, _ = rotated
    stranger = generate_x25519_keypair()
    container = encrypt_bytes_hybrid(PLAINTEXT, [("bob", stranger.public_key)])
    assert keyring.find_key_for_container(container) is None
    with pytest.raises(DecryptionFailedError):
        keyring.decrypt(container, PASSWORD_2)


@pytest.mark.parametrize("data", [b"not json", b"[]", b'{"recipients": 5}', b"{}"])
def test_find_key_ignores_data_that_is_not_a_container(rotated, data):
    keyring, _, _ = rotated
    assert keyring.find_key_for_container(data) is None


def test_signing_keyrings_do_not_match_containers(tmp_path, keys):
    keyring = Keyring.create(tmp_path / "alice-signing", "alice", "Ed25519")
    signing_key, _ = generate_ed25519_keypair()
    keyring.rotate(signing_key, PASSWORD_1)
    container = encrypt_bytes_hybrid(PLAINTEXT, [("alice", keys[0].public_key)])
    assert keyring.find_key_for_container(container) is None


def test_compromised_key_flow_recover_and_share_again(rotated, keys):
    """The whole response to a compromise, in order."""
    keyring, old, new = rotated
    old_container = encrypt_bytes_hybrid(PLAINTEXT, [("alice", keys[0].public_key)])

    # 1. The key is declared compromised: it is no longer used, and old files do not open silently.
    keyring.revoke(old.key_id, "laptop stolen", compromised=True)
    with pytest.raises(KeystoreError):
        keyring.decrypt(old_container, PASSWORD_1)

    # 2. The owner recovers the old file explicitly...
    recovered = keyring.decrypt(old_container, PASSWORD_1, allow_revoked=True)
    assert recovered == PLAINTEXT

    # 3. ...and shares it again with the new key, which the attacker does not have.
    reshared = encrypt_bytes_hybrid(recovered, [("alice", keys[1].public_key)])
    assert keyring.decrypt(reshared, PASSWORD_2) == PLAINTEXT
    with pytest.raises(DecryptionFailedError):
        decrypt_bytes_hybrid(reshared, "alice", keys[0].private_key)

    # 4. The notice for the recipients exists.
    assert json.loads(keyring.revocation_notice(old.key_id))["compromised"] is True
    assert keyring.active_entry().key_id == new.key_id and keyring.active_entry().status == STATUS_ACTIVE
