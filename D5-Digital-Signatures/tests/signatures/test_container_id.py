"""D5: every signed container carries a unique, signed ``container_id``."""

import base64
import json
import re

import pytest

from vault.exceptions import SignatureVerificationError
from vault.hybrid import generate_x25519_keypair
from vault.hybrid.encryption import encrypt_bytes_hybrid
from vault.signatures import (
    generate_ed25519_keypair,
    sign_container,
    verify_and_decrypt,
)
from vault.signatures.signing import _digest_to_sign

PLAINTEXT = b"Secure Digital Document Vault - D5 container id"


@pytest.fixture(scope="module")
def bob():
    return generate_x25519_keypair()


@pytest.fixture(scope="module")
def alice_signing_keys():
    return generate_ed25519_keypair()


def _encrypt(bob) -> bytes:
    return encrypt_bytes_hybrid(PLAINTEXT, [("bob", bob.public_key)])


def _resign(container: dict, private_key) -> bytes:
    """Sign again after editing a field, so only the container_id rule can reject it."""
    container["signature"] = base64.b64encode(
        private_key.sign(_digest_to_sign(container))
    ).decode("ascii")
    return json.dumps(container).encode("utf-8")


def test_signed_container_has_a_container_id(bob, alice_signing_keys):
    alice_private, _ = alice_signing_keys
    signed = json.loads(sign_container(_encrypt(bob), alice_private))
    assert re.fullmatch(r"[0-9a-f]{32}", signed["container_id"])


def test_signed_container_still_decrypts(bob, alice_signing_keys):
    alice_private, alice_public = alice_signing_keys
    signed = sign_container(_encrypt(bob), alice_private)
    assert verify_and_decrypt(signed, alice_public, "bob", bob.private_key) == PLAINTEXT


def test_two_signings_of_the_same_container_have_different_ids(bob, alice_signing_keys):
    alice_private, _ = alice_signing_keys
    container = _encrypt(bob)
    first = json.loads(sign_container(container, alice_private))
    second = json.loads(sign_container(container, alice_private))
    assert first["container_id"] != second["container_id"]


def test_modified_container_id_rejected(bob, alice_signing_keys):
    alice_private, alice_public = alice_signing_keys
    signed = json.loads(sign_container(_encrypt(bob), alice_private))
    signed["container_id"] = "0" * 32
    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt(json.dumps(signed).encode(), alice_public, "bob", bob.private_key)


def test_removed_container_id_rejected(bob, alice_signing_keys):
    alice_private, alice_public = alice_signing_keys
    signed = json.loads(sign_container(_encrypt(bob), alice_private))
    del signed["container_id"]
    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt(json.dumps(signed).encode(), alice_public, "bob", bob.private_key)


def test_container_without_id_is_rejected_even_with_a_valid_signature(bob, alice_signing_keys):
    alice_private, alice_public = alice_signing_keys
    signed = json.loads(sign_container(_encrypt(bob), alice_private))
    del signed["container_id"]
    resigned = _resign(signed, alice_private)
    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt(resigned, alice_public, "bob", bob.private_key)


@pytest.mark.parametrize(
    "bad_id",
    ["", "abc", "A" * 32, "g" * 32, "0" * 31, "0" * 33, 123, None, ["0" * 32]],
    ids=["empty", "short", "uppercase", "not-hex", "31-chars", "33-chars", "int", "null", "list"],
)
def test_malformed_container_id_is_rejected_even_with_a_valid_signature(
    bob, alice_signing_keys, bad_id
):
    alice_private, alice_public = alice_signing_keys
    signed = json.loads(sign_container(_encrypt(bob), alice_private))
    signed["container_id"] = bad_id
    resigned = _resign(signed, alice_private)
    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt(resigned, alice_public, "bob", bob.private_key)
