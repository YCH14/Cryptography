"""RSA key management for D3: key size, PEM round trip and fingerprints."""

from __future__ import annotations

import pytest

from vault.exceptions import InvalidKeyError
from vault.hybrid.keys import (
    RSAKeyPair,
    export_private_key_pem,
    export_public_key_pem,
    generate_rsa_keypair,
    get_public_key_fingerprint,
    load_private_key_pem,
    load_public_key_pem,
    looks_like_fingerprint,
)


@pytest.fixture(scope="module")
def alice() -> RSAKeyPair:
    return generate_rsa_keypair(2048)


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

    def test_real_fingerprint_has_reserved_shape(self, alice: RSAKeyPair) -> None:
        assert looks_like_fingerprint(get_public_key_fingerprint(alice.public_key))


class TestKeyManagement:
    @pytest.mark.parametrize("size", [1024, 512, 0, -1, "2048", None])
    def test_weak_or_invalid_key_size_is_rejected(self, size: object) -> None:
        with pytest.raises(InvalidKeyError):
            generate_rsa_keypair(size)  # type: ignore[arg-type]

    def test_public_pem_round_trip_keeps_fingerprint(self, alice: RSAKeyPair) -> None:
        loaded = load_public_key_pem(export_public_key_pem(alice.public_key))
        assert get_public_key_fingerprint(loaded) == get_public_key_fingerprint(alice.public_key)

    def test_encrypted_private_pem_round_trip(self, alice: RSAKeyPair) -> None:
        pem = export_private_key_pem(alice.private_key, password=b"long passphrase")
        assert b"ENCRYPTED" in pem
        loaded = load_private_key_pem(pem, password=b"long passphrase")
        assert get_public_key_fingerprint(loaded.public_key()) == get_public_key_fingerprint(
            alice.public_key
        )

    def test_wrong_pem_password_is_rejected(self, alice: RSAKeyPair) -> None:
        pem = export_private_key_pem(alice.private_key, password=b"right")
        with pytest.raises(InvalidKeyError):
            load_private_key_pem(pem, password=b"wrong")

    def test_garbage_pem_is_rejected(self) -> None:
        with pytest.raises(InvalidKeyError):
            load_public_key_pem(b"not a pem")
