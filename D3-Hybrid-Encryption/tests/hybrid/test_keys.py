"""X25519 key management for D3: key type, PEM round trip and fingerprints."""

from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from vault.exceptions import InvalidKeyError
from vault.hybrid.keys import (
    X25519KeyPair,
    export_private_key_pem,
    export_public_key_pem,
    generate_x25519_keypair,
    get_public_key_fingerprint,
    load_private_key_pem,
    load_public_key_pem,
    looks_like_fingerprint,
)


@pytest.fixture(scope="module")
def alice() -> X25519KeyPair:
    return generate_x25519_keypair()


class TestFingerprintShape:
    @pytest.mark.parametrize("value", ["a" * 64, "0123456789abcdef" * 4])
    def test_accepts_exact_fingerprint_shape(self, value: str) -> None:
        assert looks_like_fingerprint(value)

    @pytest.mark.parametrize(
        "value",
        ["", "alice", "a" * 63, "a" * 65, "A" * 64, "g" * 64, " " + "a" * 63, None, 42, b"a" * 64],
    )
    def test_rejects_everything_else(self, value: object) -> None:
        assert not looks_like_fingerprint(value)

    def test_real_fingerprint_has_reserved_shape(self, alice: X25519KeyPair) -> None:
        assert looks_like_fingerprint(get_public_key_fingerprint(alice.public_key))


class TestKeyManagement:
    def test_public_key_fingerprint_is_sha256_of_raw_public_bytes(self, alice: X25519KeyPair) -> None:
        raw = alice.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        assert len(raw) == 32
        assert get_public_key_fingerprint(alice.public_key) == hashlib.sha256(raw).hexdigest()

    @pytest.mark.parametrize(
        "bad_key",
        [
            ed25519.Ed25519PrivateKey.generate().public_key(),
            ec.generate_private_key(ec.SECP256R1()).public_key(),
            "not a key",
            None,
        ],
    )
    def test_non_x25519_public_key_is_rejected(self, bad_key: object) -> None:
        with pytest.raises(InvalidKeyError):
            get_public_key_fingerprint(bad_key)  # type: ignore[arg-type]

    def test_non_x25519_pem_is_rejected(self) -> None:
        ed_pem = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(InvalidKeyError):
            load_public_key_pem(ed_pem)

    def test_public_pem_round_trip_keeps_fingerprint(self, alice: X25519KeyPair) -> None:
        loaded = load_public_key_pem(export_public_key_pem(alice.public_key))
        assert get_public_key_fingerprint(loaded) == get_public_key_fingerprint(alice.public_key)

    def test_encrypted_private_pem_round_trip(self, alice: X25519KeyPair) -> None:
        pem = export_private_key_pem(alice.private_key, password=b"long passphrase")
        assert b"ENCRYPTED" in pem
        loaded = load_private_key_pem(pem, password=b"long passphrase")
        assert get_public_key_fingerprint(loaded.public_key()) == get_public_key_fingerprint(
            alice.public_key
        )

    def test_wrong_pem_password_is_rejected(self, alice: X25519KeyPair) -> None:
        pem = export_private_key_pem(alice.private_key, password=b"right")
        with pytest.raises(InvalidKeyError):
            load_private_key_pem(pem, password=b"wrong")

    def test_garbage_pem_is_rejected(self) -> None:
        with pytest.raises(InvalidKeyError):
            load_public_key_pem(b"not a pem")
