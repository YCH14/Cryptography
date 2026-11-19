"""D6 required tests: correct password, wrong password, modified keystore,
backup and restore, and a stolen keystore alone."""

import json
import shutil

import pytest
from cryptography.hazmat.primitives import serialization

from vault.exceptions import (
    DecryptionFailedError,
    KeystoreAccessError,
    KeystoreError,
)
from vault.hybrid import generate_x25519_keypair
from vault.hybrid.encryption import decrypt_bytes_hybrid, encrypt_bytes_hybrid
from vault.keystore import (
    KEYSTORE_FILES,
    backup_keystore,
    create_keystore,
    restore_keystore,
    unlock_private_key,
)
from vault.signatures import (
    generate_ed25519_keypair,
    sign_container,
    verify_and_decrypt,
)

PASSWORD = "correct horse battery staple"
PLAINTEXT = b"Secure Digital Document Vault - D6"


@pytest.fixture(scope="module")
def alice_x25519():
    return generate_x25519_keypair()


@pytest.fixture(scope="module")
def alice_ed25519():
    return generate_ed25519_keypair()


@pytest.fixture()
def keystore(tmp_path, alice_x25519):
    return create_keystore(tmp_path / "alice-x25519", alice_x25519.private_key, PASSWORD, "alice")


def _der(private_key) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


# 1. Correct password -> access granted ---------------------------------------


def test_correct_password_access_granted(keystore, alice_x25519):
    unlocked = unlock_private_key(keystore, PASSWORD)
    assert _der(unlocked) == _der(alice_x25519.private_key)

    # The unlocked key is the one D3 needs: it opens a container shared with alice.
    container = encrypt_bytes_hybrid(PLAINTEXT, [("alice", alice_x25519.public_key)])
    assert decrypt_bytes_hybrid(container, "alice", unlocked) == PLAINTEXT


def test_ed25519_key_works_with_d5(tmp_path, alice_x25519, alice_ed25519):
    private_key, public_key = alice_ed25519
    path = create_keystore(tmp_path / "alice-ed25519", private_key, PASSWORD, "alice")
    signing_key = unlock_private_key(path, PASSWORD, expected_key_type="Ed25519")

    container = encrypt_bytes_hybrid(PLAINTEXT, [("alice", alice_x25519.public_key)])
    signed = sign_container(container, signing_key)
    assert verify_and_decrypt(signed, public_key, "alice", alice_x25519.private_key) == PLAINTEXT


def test_password_is_asked_when_not_given(keystore, monkeypatch):
    asked = []
    monkeypatch.setattr(
        "getpass.getpass", lambda prompt="": asked.append(prompt) or PASSWORD
    )
    assert unlock_private_key(keystore) is not None
    assert asked == ["Keystore password: "]


# 2. Wrong password -> access denied ------------------------------------------


@pytest.mark.parametrize("password", ["wrong password", PASSWORD + " ", PASSWORD.upper()])
def test_wrong_password_denied(keystore, password):
    with pytest.raises(KeystoreAccessError) as excinfo:
        unlock_private_key(keystore, password)
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__context__ is None


def test_key_type_mismatch_refused(keystore):
    with pytest.raises(KeystoreError):
        unlock_private_key(keystore, PASSWORD, expected_key_type="Ed25519")


# 3. Modified keystore -> failure ---------------------------------------------


def _flip_first_byte(path):
    data = bytearray(path.read_bytes())
    data[0] ^= 0x01
    path.write_bytes(bytes(data))


def _edit_json(path, field, value):
    data = json.loads(path.read_bytes())
    data[field] = value
    path.write_bytes(json.dumps(data).encode("utf-8"))


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param(lambda d: _flip_first_byte(d / "encrypted_private_key"), id="encrypted_private_key"),
        pytest.param(lambda d: _flip_first_byte(d / "salt"), id="salt"),
        pytest.param(lambda d: _edit_json(d / "kdf_parameters", "iterations", 2), id="kdf_parameters"),
        pytest.param(lambda d: _edit_json(d / "metadata", "owner", "mallory"), id="metadata-owner"),
        pytest.param(lambda d: _edit_json(d / "metadata", "key_id", "0" * 64), id="metadata-key_id"),
        pytest.param(lambda d: (d / "metadata").write_bytes(b"not json"), id="metadata-garbage"),
        pytest.param(lambda d: (d / "salt").unlink(), id="salt-removed"),
    ],
)
def test_modified_keystore_fails(keystore, tamper):
    tamper(keystore)
    with pytest.raises(KeystoreAccessError):
        unlock_private_key(keystore, PASSWORD)


def test_encrypted_key_swapped_from_another_keystore_fails(tmp_path, keystore):
    # Same password, different key: binding the metadata to the ciphertext
    # keeps the identity of the key consistent.
    other = create_keystore(tmp_path / "bob-x25519", generate_x25519_keypair().private_key, PASSWORD, "bob")
    shutil.copyfile(other / "encrypted_private_key", keystore / "encrypted_private_key")
    with pytest.raises(KeystoreAccessError):
        unlock_private_key(keystore, PASSWORD)


# 4. Backup -> restore works --------------------------------------------------


def test_backup_restore_works(tmp_path, keystore, alice_x25519):
    backup = backup_keystore(keystore, tmp_path / "backup")
    assert sorted(p.name for p in backup.iterdir()) == sorted(KEYSTORE_FILES)

    shutil.rmtree(keystore)  # the original keystore is lost
    restored = restore_keystore(backup, keystore, PASSWORD)

    assert _der(unlock_private_key(restored, PASSWORD)) == _der(alice_x25519.private_key)


def test_corrupted_backup_is_not_restored(tmp_path, keystore):
    backup = backup_keystore(keystore, tmp_path / "backup")
    _flip_first_byte(backup / "encrypted_private_key")
    target = tmp_path / "restored"
    with pytest.raises(KeystoreAccessError):
        restore_keystore(backup, target, PASSWORD)
    assert not target.exists()


# 5. Stolen keystore alone -> cannot decrypt ----------------------------------


def test_stolen_keystore_alone_cannot_decrypt(tmp_path, keystore, alice_x25519):
    container = encrypt_bytes_hybrid(PLAINTEXT, [("alice", alice_x25519.public_key)])
    stolen = tmp_path / "attacker-copy"
    shutil.copytree(keystore, stolen)  # the attacker has every keystore file

    # No file holds the key in the clear.
    key_der = _der(alice_x25519.private_key)
    for name in KEYSTORE_FILES:
        content = (stolen / name).read_bytes()
        assert key_der not in content
        assert key_der[:32] not in content
        assert b"PRIVATE KEY" not in content

    # Without the password the files do not open...
    for guess in ["password", "123456", "alice", "qwerty"]:
        with pytest.raises(KeystoreAccessError):
            unlock_private_key(stolen, guess)

    # ...and a different key cannot open what was shared with alice.
    with pytest.raises(DecryptionFailedError):
        decrypt_bytes_hybrid(container, "alice", generate_x25519_keypair().private_key)


def test_existing_keystore_is_never_overwritten(keystore, alice_x25519):
    with pytest.raises(KeystoreError):
        create_keystore(keystore, alice_x25519.private_key, "another password", "alice")
    assert unlock_private_key(keystore, PASSWORD) is not None
