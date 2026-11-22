"""Ed25519 signer public keys: one encoding (PEM), a small regular .pem file, never overwritten."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from vault.exceptions import InvalidKeyError
from vault.hybrid import export_public_key_pem, generate_x25519_keypair
from vault.hybrid.keys import MAX_KEY_FILE_SIZE
from vault.signatures import (
    export_signer_public_key_pem,
    generate_ed25519_keypair,
    get_signer_id,
    load_signer_public_key_file,
    load_signer_public_key_pem,
    save_signer_public_key_file,
)


@pytest.fixture(scope="module")
def signer():
    return generate_ed25519_keypair()


def test_signer_public_key_round_trips_through_a_file(signer, tmp_path):
    path = save_signer_public_key_file(signer[1], tmp_path / "alice.sign.pem")
    assert get_signer_id(load_signer_public_key_file(path)) == get_signer_id(signer[1])


def test_the_file_holds_one_public_key_block(signer, tmp_path):
    path = save_signer_public_key_file(signer[1], tmp_path / "alice.sign.pem")
    content = path.read_text()
    assert content.startswith("-----BEGIN PUBLIC KEY-----")
    assert "PRIVATE" not in content


def test_only_ed25519_public_keys_are_accepted(signer, tmp_path):
    x25519_pem = export_public_key_pem(generate_x25519_keypair().public_key)
    rsa_pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    for pem in (x25519_pem, rsa_pem):
        with pytest.raises(InvalidKeyError):
            load_signer_public_key_pem(pem)
        path = tmp_path / "other.pem"
        path.write_bytes(pem)
        with pytest.raises(InvalidKeyError):
            load_signer_public_key_file(path)
        path.unlink()


def test_a_private_key_is_not_accepted_as_a_signer_public_key(signer):
    private_pem = signer[0].private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with pytest.raises(InvalidKeyError):
        load_signer_public_key_pem(private_pem)


@pytest.mark.parametrize("suffix", ["", ".txt", ".pem.txt", ".der"])
def test_only_pem_extension_is_accepted(signer, tmp_path, suffix):
    path = tmp_path / f"alice{suffix}"
    with pytest.raises(InvalidKeyError):
        save_signer_public_key_file(signer[1], path)
    path.write_bytes(export_signer_public_key_pem(signer[1]))
    with pytest.raises(InvalidKeyError):
        load_signer_public_key_file(path)


def test_an_existing_file_is_not_overwritten(signer, tmp_path):
    path = tmp_path / "alice.sign.pem"
    path.write_bytes(b"do not touch")
    with pytest.raises(InvalidKeyError):
        save_signer_public_key_file(signer[1], path)
    assert path.read_bytes() == b"do not touch"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda pem: b"# alice\n" + pem,
        lambda pem: pem + b"extra\n",
        lambda pem: pem + pem,
        lambda pem: pem.replace(b"PUBLIC KEY", b"CERTIFICATE"),
        lambda pem: b"",
    ],
    ids=["text before", "text after", "two blocks", "wrong label", "empty"],
)
def test_anything_but_a_single_pem_block_is_refused(signer, mutate):
    with pytest.raises(InvalidKeyError):
        load_signer_public_key_pem(mutate(export_signer_public_key_pem(signer[1])))


def test_a_file_that_is_too_large_is_refused(tmp_path):
    path = tmp_path / "big.pem"
    path.write_bytes(b"A" * (MAX_KEY_FILE_SIZE + 1))
    with pytest.raises(InvalidKeyError):
        load_signer_public_key_file(path)


def test_a_directory_and_a_missing_file_are_refused(tmp_path):
    (tmp_path / "folder.pem").mkdir()
    with pytest.raises(InvalidKeyError):
        load_signer_public_key_file(tmp_path / "folder.pem")
    with pytest.raises(InvalidKeyError):
        load_signer_public_key_file(tmp_path / "missing.pem")


def test_wrong_input_types_are_refused(signer):
    with pytest.raises(InvalidKeyError):
        export_signer_public_key_pem(signer[0])
    with pytest.raises(InvalidKeyError):
        load_signer_public_key_pem(12345)
