"""ECIES key wrapping (D3): ephemeral keys, binding, interoperability and rejection cases."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vault.exceptions import DecryptionFailedError
from vault.hybrid import encryption
from vault.hybrid.encryption import (
    DEK_SIZE,
    EPHEMERAL_KEY_SIZE,
    KEY_WRAP_INFO,
    NONCE_SIZE,
    decrypt_bytes_hybrid,
    encrypt_bytes_hybrid,
)
from vault.hybrid.keys import X25519KeyPair, generate_x25519_keypair

PLAINTEXT = b"ECIES payload"


@pytest.fixture(scope="module")
def alice() -> X25519KeyPair:
    return generate_x25519_keypair()


@pytest.fixture(scope="module")
def bob() -> X25519KeyPair:
    return generate_x25519_keypair()


def _container(alice: X25519KeyPair, bob: X25519KeyPair) -> dict[str, Any]:
    raw = encrypt_bytes_hybrid(
        PLAINTEXT, [("alice", alice.public_key), ("bob", bob.public_key)]
    )
    return json.loads(raw)


def _dump(container: dict[str, Any]) -> bytes:
    return json.dumps(container, sort_keys=True, separators=(",", ":")).encode()


def _raw(public_key: X25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


class TestEphemeralKeys:
    def test_each_recipient_and_each_encryption_gets_a_fresh_ephemeral_key(
        self, alice: X25519KeyPair, bob: X25519KeyPair
    ) -> None:
        first = _container(alice, bob)
        second = _container(alice, bob)
        ephemerals = [
            entry["ephemeral_public_key"]
            for container in (first, second)
            for entry in container["recipients"]
        ]
        assert len(set(ephemerals)) == 4
        wrapped = [e["encrypted_dek"] for c in (first, second) for e in c["recipients"]]
        assert len(set(wrapped)) == 4

    def test_ephemeral_key_is_not_the_recipient_key(
        self, alice: X25519KeyPair, bob: X25519KeyPair
    ) -> None:
        container = _container(alice, bob)
        recipient_keys = {_raw(alice.public_key), _raw(bob.public_key)}
        for entry in container["recipients"]:
            assert base64.b64decode(entry["ephemeral_public_key"]) not in recipient_keys


class TestConstructionMatchesDocumentation:
    def test_wrapped_dek_can_be_opened_with_an_independent_implementation(
        self, alice: X25519KeyPair, bob: X25519KeyPair
    ) -> None:
        """Re-derive the KEK exactly as documented: X25519 -> HKDF-SHA256 -> AES-256-GCM."""
        container = _container(alice, bob)
        entry = container["recipients"][0]
        ephemeral = base64.b64decode(entry["ephemeral_public_key"])
        wrapped = base64.b64decode(entry["encrypted_dek"])
        recipient_raw = _raw(alice.public_key)

        shared = alice.private_key.exchange(X25519PublicKey.from_public_bytes(ephemeral))
        kek = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=KEY_WRAP_INFO + ephemeral + recipient_raw,
        ).derive(shared)
        dek = AESGCM(kek).decrypt(
            wrapped[:NONCE_SIZE], wrapped[NONCE_SIZE:], KEY_WRAP_INFO + ephemeral + recipient_raw
        )
        assert len(dek) == DEK_SIZE

        # The recovered DEK decrypts the payload with the container AAD.
        aad = encryption.build_aad(
            timestamp=container["timestamp"],
            recipients=container["recipients"],
            filename=container["filename"],
            metadata=container["metadata"],
        )
        sealed = base64.b64decode(container["ciphertext"]) + base64.b64decode(container["tag"])
        nonce = base64.b64decode(container["nonce"])
        assert AESGCM(dek).decrypt(nonce, sealed, aad) == PLAINTEXT

    def test_container_does_not_mention_rsa(self, alice: X25519KeyPair, bob: X25519KeyPair) -> None:
        container = _container(alice, bob)
        # Only the descriptive parts are checked: field names and algorithm names.  The base64
        # values are random, so a short word such as "rsa" can appear in them by chance.
        descriptive = [*container, container["magic"], container["algorithm"], container["key_wrap_algorithm"]]
        descriptive += [name for recipient in container["recipients"] for name in recipient]
        text = " ".join(descriptive).lower()
        assert "rsa" not in text
        assert "oaep" not in text


class TestEphemeralKeyTampering:
    def test_modified_ephemeral_key_is_rejected_for_every_recipient(
        self, alice: X25519KeyPair, bob: X25519KeyPair
    ) -> None:
        container = _container(alice, bob)
        original = base64.b64decode(container["recipients"][0]["ephemeral_public_key"])
        forged = bytearray(original)
        forged[0] ^= 0x01
        container["recipients"][0]["ephemeral_public_key"] = base64.b64encode(bytes(forged)).decode()
        tampered = _dump(container)
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes_hybrid(tampered, "alice", alice.private_key)
        # The ephemeral key is bound into the payload AAD, so Bob fails too.
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes_hybrid(tampered, "bob", bob.private_key)

    def test_swapping_ephemeral_keys_between_recipients_is_rejected(
        self, alice: X25519KeyPair, bob: X25519KeyPair
    ) -> None:
        container = _container(alice, bob)
        a, b = container["recipients"]
        a["ephemeral_public_key"], b["ephemeral_public_key"] = (
            b["ephemeral_public_key"],
            a["ephemeral_public_key"],
        )
        swapped = _dump(container)
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes_hybrid(swapped, "alice", alice.private_key)
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes_hybrid(swapped, "bob", bob.private_key)

    @pytest.mark.parametrize("size", [0, 16, 31, 33, 64])
    def test_ephemeral_key_with_wrong_length_is_rejected(
        self, alice: X25519KeyPair, bob: X25519KeyPair, size: int
    ) -> None:
        container = _container(alice, bob)
        container["recipients"][0]["ephemeral_public_key"] = base64.b64encode(b"\x09" * size).decode()
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes_hybrid(_dump(container), "alice", alice.private_key)

    def test_low_order_ephemeral_key_is_rejected(
        self, alice: X25519KeyPair, bob: X25519KeyPair
    ) -> None:
        """An all-zero point would give an all-zero shared secret; it must never be accepted."""
        container = _container(alice, bob)
        container["recipients"][0]["ephemeral_public_key"] = base64.b64encode(
            b"\x00" * EPHEMERAL_KEY_SIZE
        ).decode()
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes_hybrid(_dump(container), "alice", alice.private_key)

    @pytest.mark.parametrize("size", [0, 47, 49, 60])
    def test_wrapped_dek_with_wrong_length_is_rejected(
        self, alice: X25519KeyPair, bob: X25519KeyPair, size: int
    ) -> None:
        container = _container(alice, bob)
        container["recipients"][0]["encrypted_dek"] = base64.b64encode(b"\x07" * size).decode()
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes_hybrid(_dump(container), "alice", alice.private_key)

    def test_missing_ephemeral_key_field_is_rejected(
        self, alice: X25519KeyPair, bob: X25519KeyPair
    ) -> None:
        container = _container(alice, bob)
        del container["recipients"][0]["ephemeral_public_key"]
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes_hybrid(_dump(container), "alice", alice.private_key)


class TestKeyWrapBinding:
    def test_wrapped_dek_cannot_be_opened_with_another_recipients_key(
        self, alice: X25519KeyPair, bob: X25519KeyPair
    ) -> None:
        container = _container(alice, bob)
        entry = container["recipients"][0]
        with pytest.raises(Exception):
            encryption._unwrap_dek(
                base64.b64decode(entry["encrypted_dek"]),
                base64.b64decode(entry["ephemeral_public_key"]),
                bob.private_key,
            )

    def test_legacy_rsa_container_magic_is_rejected(
        self, alice: X25519KeyPair, bob: X25519KeyPair
    ) -> None:
        container = _container(alice, bob)
        container["magic"] = "VLT2"
        container["version"] = 2
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes_hybrid(_dump(container), "alice", alice.private_key)

    def test_wrap_key_depends_on_the_recipient_public_key(self) -> None:
        shared = b"\x11" * 32
        eph = b"\x22" * 32
        key_a = encryption._derive_wrap_key(shared, eph, b"\x33" * 32)
        key_b = encryption._derive_wrap_key(shared, eph, b"\x44" * 32)
        assert key_a != key_b and len(key_a) == 32

    def test_private_key_type_is_checked_on_decrypt(self, alice: X25519KeyPair, bob: X25519KeyPair) -> None:
        from vault.exceptions import InvalidKeyError

        raw = encrypt_bytes_hybrid(PLAINTEXT, [("alice", alice.public_key)])
        with pytest.raises(InvalidKeyError):
            decrypt_bytes_hybrid(raw, "alice", object())  # type: ignore[arg-type]
        assert isinstance(alice.private_key, X25519PrivateKey)
