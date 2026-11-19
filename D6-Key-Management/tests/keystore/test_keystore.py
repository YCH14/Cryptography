"""D6 required tests: correct password, wrong password, modified keystore,
backup and restore, and a stolen keystore alone."""

import hashlib
import json
import os
import shutil

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from vault.exceptions import (
    DecryptionFailedError,
    InvalidKeyError,
    KeystoreAccessError,
    KeystoreError,
)
from vault.hybrid import generate_x25519_keypair, get_public_key_fingerprint
from vault.hybrid.encryption import decrypt_bytes_hybrid, encrypt_bytes_hybrid
from vault.keystore import keystore as keystore_module
from vault.keystore import (
    KEYSTORE_FILES,
    backup_keystore,
    create_keystore,
    restore_keystore,
    unlock_private_key,
)
from vault.signatures import (
    generate_ed25519_keypair,
    get_signer_id,
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


# 6. Key types: X25519 and Ed25519 only; RSA is not accepted -------------------


def _raw_public(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def test_key_id_is_sha256_of_raw_public_key(tmp_path, alice_x25519, alice_ed25519):
    x25519_path = create_keystore(
        tmp_path / "x25519", alice_x25519.private_key, PASSWORD, "alice"
    )
    ed25519_path = create_keystore(tmp_path / "ed25519", alice_ed25519[0], PASSWORD, "alice")

    x25519_meta = json.loads((x25519_path / "metadata").read_bytes())
    ed25519_meta = json.loads((ed25519_path / "metadata").read_bytes())

    assert x25519_meta["key_type"] == "X25519"
    assert x25519_meta["key_id"] == hashlib.sha256(_raw_public(alice_x25519.public_key)).hexdigest()
    assert x25519_meta["key_id"] == get_public_key_fingerprint(alice_x25519.public_key)

    assert ed25519_meta["key_type"] == "Ed25519"
    assert ed25519_meta["key_id"] == hashlib.sha256(_raw_public(alice_ed25519[1])).hexdigest()
    assert ed25519_meta["key_id"] == get_signer_id(alice_ed25519[1])


def test_expected_key_type_accepts_the_right_type(keystore):
    assert unlock_private_key(keystore, PASSWORD, expected_key_type="X25519") is not None


def test_rsa_private_key_is_refused(tmp_path):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    target = tmp_path / "rsa"
    with pytest.raises(InvalidKeyError):
        create_keystore(target, rsa_key, PASSWORD, "alice")
    assert not target.exists()


def test_keystore_holding_an_rsa_key_does_not_open(tmp_path):
    # Build a keystore in the exact on-disk format, but holding an RSA key, as
    # the previous version of D6 did.  The current code must not open it, even
    # with the right password.
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    metadata = {
        "version": keystore_module.FORMAT_VERSION,
        "owner": "alice",
        "key_type": "RSA",
        "key_id": "0" * 64,
        "created": "2026-01-01T00:00:00Z",
    }
    kdf = {
        "kdf": keystore_module.KDF_NAME,
        "iterations": keystore_module.ARGON2_ITERATIONS,
        "lanes": keystore_module.ARGON2_LANES,
        "memory_cost_kib": keystore_module.ARGON2_MEMORY_KIB,
        "length": keystore_module.KEY_SIZE,
    }
    salt, nonce = os.urandom(16), os.urandom(12)
    key = keystore_module._derive_key(PASSWORD.encode(), salt, kdf)
    sealed = keystore_module.AESGCM(key).encrypt(
        nonce, _der(rsa_key), keystore_module._aad(metadata, kdf, salt)
    )
    legacy = tmp_path / "legacy-rsa"
    legacy.mkdir()
    (legacy / "encrypted_private_key").write_bytes(nonce + sealed)
    (legacy / "salt").write_bytes(salt)
    (legacy / "kdf_parameters").write_bytes(keystore_module._canonical_json(kdf))
    (legacy / "metadata").write_bytes(keystore_module._canonical_json(metadata))

    with pytest.raises(KeystoreAccessError):
        unlock_private_key(legacy, PASSWORD)


def test_ed25519_backup_restore_works(tmp_path, alice_ed25519):
    private_key, _ = alice_ed25519
    original = create_keystore(tmp_path / "ed25519", private_key, PASSWORD, "alice")
    backup = backup_keystore(original, tmp_path / "ed25519-backup")

    shutil.rmtree(original)
    restored = restore_keystore(backup, original, PASSWORD)

    unlocked = unlock_private_key(restored, PASSWORD, expected_key_type="Ed25519")
    assert _der(unlocked) == _der(private_key)
