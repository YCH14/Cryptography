"""Key files on disk: a single encoding (PEM), a small regular .pem file, and no plaintext private keys."""

import os
import stat
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from vault.exceptions import InvalidKeyError
from vault.hybrid import (
    export_private_key_pem,
    export_public_key_pem,
    generate_x25519_keypair,
    get_public_key_fingerprint,
    load_private_key_file,
    load_private_key_pem,
    load_public_key_file,
    load_public_key_pem,
    save_private_key_pem,
    save_public_key_pem,
)
from vault.hybrid.keys import MAX_KEY_FILE_SIZE

PASSWORD = b"a long passphrase for the key file"


@pytest.fixture(scope="module")
def alice():
    return generate_x25519_keypair()


def _public_pem(alice) -> bytes:
    return export_public_key_pem(alice.public_key)


def _private_pem(alice) -> bytes:
    return export_private_key_pem(alice.private_key, password=PASSWORD)


# Round trip ---------------------------------------------------------------------------------------


def test_key_files_round_trip(alice, tmp_path):
    public_file = save_public_key_pem(alice.public_key, tmp_path / "alice.pub.pem")
    private_file = save_private_key_pem(alice.private_key, tmp_path / "alice.pem", password=PASSWORD)
    fingerprint = get_public_key_fingerprint(alice.public_key)
    assert get_public_key_fingerprint(load_public_key_file(public_file)) == fingerprint
    assert get_public_key_fingerprint(load_private_key_file(private_file, PASSWORD).public_key()) == fingerprint


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_private_key_file_is_owner_only(alice, tmp_path):
    path = save_private_key_pem(alice.private_key, tmp_path / "alice.pem", password=PASSWORD)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


# A private key is never written in the clear -------------------------------------------------------


@pytest.mark.parametrize("password", [None, b"", bytearray(), "text password", 123])
def test_private_key_file_requires_a_password(alice, tmp_path, password):
    path = tmp_path / "alice.pem"
    with pytest.raises(InvalidKeyError):
        save_private_key_pem(alice.private_key, path, password=password)
    assert not path.exists()


def test_the_file_written_is_encrypted(alice, tmp_path):
    path = save_private_key_pem(alice.private_key, tmp_path / "alice.pem", password=PASSWORD)
    content = path.read_bytes()
    assert content.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert b"BEGIN PRIVATE KEY" not in content
    with pytest.raises(InvalidKeyError):
        load_private_key_file(path)  # no password
    with pytest.raises(InvalidKeyError):
        load_private_key_file(path, b"another password")


# Only .pem files, never overwritten ----------------------------------------------------------------


@pytest.mark.parametrize("name", ["key.txt", "key", "key.pem.txt", "key.der", "key.pem.bak"])
def test_only_pem_extension_is_accepted(alice, tmp_path, name):
    with pytest.raises(InvalidKeyError):
        save_public_key_pem(alice.public_key, tmp_path / name)
    assert not (tmp_path / name).exists()
    (tmp_path / name).write_bytes(_public_pem(alice))
    with pytest.raises(InvalidKeyError):
        load_public_key_file(tmp_path / name)


def test_an_existing_file_is_not_overwritten(alice, tmp_path):
    path = tmp_path / "alice.pub.pem"
    path.write_bytes(b"do not touch")
    with pytest.raises(InvalidKeyError):
        save_public_key_pem(alice.public_key, path)
    assert path.read_bytes() == b"do not touch"
    private_path = tmp_path / "alice.pem"
    private_path.write_bytes(b"do not touch")
    with pytest.raises(InvalidKeyError):
        save_private_key_pem(alice.private_key, private_path, password=PASSWORD)
    assert private_path.read_bytes() == b"do not touch"


def test_an_existing_symlink_is_not_followed_when_saving(alice, tmp_path):
    target = tmp_path / "target.pem"
    target.write_bytes(b"do not touch")
    link = tmp_path / "link.pem"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks need privileges")
    with pytest.raises(InvalidKeyError):
        save_public_key_pem(alice.public_key, link)
    assert target.read_bytes() == b"do not touch"


# Only a small regular file is read -----------------------------------------------------------------


def test_a_file_that_is_too_large_is_refused(tmp_path):
    path = tmp_path / "big.pem"
    path.write_bytes(b"A" * (MAX_KEY_FILE_SIZE + 1))
    with pytest.raises(InvalidKeyError):
        load_public_key_file(path)


def test_a_directory_is_refused(tmp_path):
    folder = tmp_path / "folder.pem"
    folder.mkdir()
    with pytest.raises(InvalidKeyError):
        load_public_key_file(folder)


def test_a_missing_file_is_refused(tmp_path):
    with pytest.raises(InvalidKeyError):
        load_public_key_file(tmp_path / "missing.pem")


def test_a_symlink_is_refused_when_loading(alice, tmp_path):
    real = tmp_path / "real.pem"
    real.write_bytes(_public_pem(alice))
    link = tmp_path / "link.pem"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks need privileges")
    with pytest.raises(InvalidKeyError):
        load_public_key_file(link)


# Only one PEM encoding is accepted -----------------------------------------------------------------


def _variants(alice):
    pem = _public_pem(alice)
    other = _public_pem(generate_x25519_keypair())
    return {
        "text before": b"# my key\n" + pem,
        "text after": pem + b"trailing text\n",
        "two blocks": pem + other,
        "no newline after begin": pem.replace(b"-----\n", b"----- ", 1),
        "wrong label": pem.replace(b"PUBLIC KEY", b"CERTIFICATE"),
        "label mismatch": pem.replace(b"END PUBLIC KEY", b"END PRIVATE KEY"),
        "not base64": b"-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n",
        "empty body": b"-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n",
        "non-ascii": pem.replace(b"PUBLIC", "PÚBLIC".encode("utf-8"), 1),
        "binary der": serialization.load_pem_public_key(pem).public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        "empty": b"",
    }


@pytest.mark.parametrize(
    "variant",
    [
        "text before", "text after", "two blocks", "no newline after begin", "wrong label",
        "label mismatch", "not base64", "empty body", "non-ascii", "binary der", "empty",
    ],
)
def test_anything_but_a_single_pem_block_is_refused(alice, tmp_path, variant):
    data = _variants(alice)[variant]
    with pytest.raises(InvalidKeyError):
        load_public_key_pem(data)
    path = tmp_path / "key.pem"
    path.write_bytes(data)
    with pytest.raises(InvalidKeyError):
        load_public_key_file(path)


def test_private_key_pem_is_strict_too(alice):
    pem = _private_pem(alice)
    assert load_private_key_pem(pem, PASSWORD).public_key().public_bytes_raw() == alice.public_key.public_bytes_raw()
    for bad in (b"# note\n" + pem, pem + pem, pem + b"x", pem.replace(b"ENCRYPTED PRIVATE KEY", b"RSA PRIVATE KEY")):
        with pytest.raises(InvalidKeyError):
            load_private_key_pem(bad, PASSWORD)


def test_windows_line_endings_are_accepted(alice):
    pem = _public_pem(alice).replace(b"\n", b"\r\n")
    assert get_public_key_fingerprint(load_public_key_pem(pem)) == get_public_key_fingerprint(alice.public_key)


# Only the expected key type -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "other_key",
    [
        ed25519.Ed25519PrivateKey.generate().public_key(),
        rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(),
    ],
    ids=["ed25519", "rsa"],
)
def test_a_public_key_of_another_type_is_refused(other_key, tmp_path):
    pem = other_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(InvalidKeyError):
        load_public_key_pem(pem)
    path = tmp_path / "other.pem"
    path.write_bytes(pem)
    with pytest.raises(InvalidKeyError):
        load_public_key_file(path)


def test_a_private_key_of_another_type_is_refused(tmp_path):
    pem = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(PASSWORD),
    )
    with pytest.raises(InvalidKeyError):
        load_private_key_pem(pem, PASSWORD)
