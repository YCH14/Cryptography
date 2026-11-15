"""D5 required tests: valid, modified ciphertext, modified metadata,
wrong public key, and removed signature."""

import base64
import json

import pytest

from vault.exceptions import MissingSignatureError, SignatureVerificationError
from vault.hybrid import generate_rsa_keypair
from vault.hybrid.encryption import encrypt_bytes_hybrid
from vault.signatures import (
    generate_ed25519_keypair,
    sign_container,
    verify_and_decrypt,
)

PLAINTEXT = b"Secure Digital Document Vault - D5"


@pytest.fixture(scope="module")
def bob():
    return generate_rsa_keypair()


@pytest.fixture(scope="module")
def alice_signing_keys():
    return generate_ed25519_keypair()


@pytest.fixture()
def signed(bob, alice_signing_keys):
    alice_private, _ = alice_signing_keys
    container = encrypt_bytes_hybrid(
        PLAINTEXT,
        [("bob", bob.public_key)],
        filename="report.txt",
        metadata={"owner": "alice"},
    )
    return json.loads(sign_container(container, alice_private))


def _dump(container: dict) -> bytes:
    return json.dumps(container).encode("utf-8")


def test_valid_signature_accepted(signed, bob, alice_signing_keys):
    _, alice_public = alice_signing_keys
    assert verify_and_decrypt(_dump(signed), alice_public, "bob", bob.private_key) == PLAINTEXT


def test_modified_ciphertext_rejected(signed, bob, alice_signing_keys):
    _, alice_public = alice_signing_keys
    raw = bytearray(base64.b64decode(signed["ciphertext"]))
    raw[0] ^= 0x01
    signed["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt(_dump(signed), alice_public, "bob", bob.private_key)


def test_modified_metadata_rejected(signed, bob, alice_signing_keys):
    _, alice_public = alice_signing_keys
    signed["metadata"]["owner"] = "mallory"
    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt(_dump(signed), alice_public, "bob", bob.private_key)


def test_wrong_public_key_rejected(signed, bob):
    _, eve_public = generate_ed25519_keypair()
    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt(_dump(signed), eve_public, "bob", bob.private_key)


def test_signature_removed_rejected(signed, bob, alice_signing_keys):
    _, alice_public = alice_signing_keys
    del signed["signature"]
    with pytest.raises(MissingSignatureError):
        verify_and_decrypt(_dump(signed), alice_public, "bob", bob.private_key)
