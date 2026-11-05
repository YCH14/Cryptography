"""Unit tests for Ed25519 key management and Hash -> Sign -> Verify primitives (D5)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from vault.exceptions import InvalidKeyError, SignatureVerificationError
from vault.hybrid.keys import generate_rsa_keypair
from vault.signatures.keys import (
    ED25519_PUBLIC_KEY_SIZE,
    ED25519_SIGNATURE_SIZE,
    export_ed25519_private_key_pem,
    export_ed25519_public_key_pem,
    export_ed25519_public_key_raw,
    generate_ed25519_keypair,
    get_ed25519_public_key_fingerprint,
    get_signer_public_key_fingerprint,
    get_signer_raw_key_fingerprint,
    load_ed25519_private_key_file,
    load_ed25519_private_key_pem,
    load_ed25519_public_key_file,
    load_ed25519_public_key_pem,
    load_ed25519_public_key_raw,
    looks_like_fingerprint,
    save_ed25519_private_key_pem,
    save_ed25519_public_key_pem,
    validate_ed25519_private_key,
    validate_ed25519_public_key,
)
from vault.signatures.signing import (
    SIGNATURE_DOMAIN_SEPARATOR,
    compute_payload_digest,
    sign_canonical_payload,
    verify_canonical_payload,
)


class TestEd25519KeyGenerationAndValidation:
    """Tests for Ed25519 key pair generation, validation, and fingerprints."""

    def test_generate_ed25519_keypair_ProducesDistinctKeys(self) -> None:
        kp1 = generate_ed25519_keypair()
        kp2 = generate_ed25519_keypair()
        priv1, pub1 = kp1

        assert priv1 is kp1.private_key
        assert pub1 is kp1.public_key
        assert validate_ed25519_private_key(priv1) is priv1
        assert validate_ed25519_public_key(pub1) is pub1
        assert get_signer_public_key_fingerprint(pub1) != get_signer_public_key_fingerprint(
            kp2.public_key
        )

    def test_validate_rejects_non_ed25519_keys(self) -> None:
        rsa_priv, rsa_pub = generate_rsa_keypair(2048)
        with pytest.raises(InvalidKeyError):
            validate_ed25519_public_key(rsa_pub)
        with pytest.raises(InvalidKeyError):
            validate_ed25519_private_key(rsa_priv)
        with pytest.raises(InvalidKeyError):
            validate_ed25519_public_key("not-a-key")
        with pytest.raises(InvalidKeyError):
            validate_ed25519_private_key(None)

    def test_fingerprints_are_deterministic_64_hex(self) -> None:
        priv, pub = generate_ed25519_keypair()
        spki_fp = get_signer_public_key_fingerprint(pub)
        raw_fp = get_signer_raw_key_fingerprint(pub)

        assert looks_like_fingerprint(spki_fp)
        assert looks_like_fingerprint(raw_fp)
        assert spki_fp == get_ed25519_public_key_fingerprint(priv.public_key())
        assert spki_fp != raw_fp  # SPKI DER header differs from raw 32-byte key


class TestEd25519SerializationAndFiles:
    """Tests for PEM and raw key import/export and secure file permissions."""

    def test_public_key_pem_and_raw_roundtrip(self, tmp_path: Path) -> None:
        _, pub = generate_ed25519_keypair()
        pem_bytes = export_ed25519_public_key_pem(pub)
        loaded_from_bytes = load_ed25519_public_key_pem(pem_bytes)
        loaded_from_str = load_ed25519_public_key_pem(pem_bytes.decode("ascii"))

        raw_bytes = export_ed25519_public_key_raw(pub)
        assert len(raw_bytes) == ED25519_PUBLIC_KEY_SIZE
        loaded_from_raw = load_ed25519_public_key_raw(raw_bytes)

        pub_path = save_ed25519_public_key_pem(pub, tmp_path / "signer_pub.pem")
        loaded_from_file = load_ed25519_public_key_file(pub_path)

        expected_fp = get_signer_public_key_fingerprint(pub)
        assert get_signer_public_key_fingerprint(loaded_from_bytes) == expected_fp
        assert get_signer_public_key_fingerprint(loaded_from_str) == expected_fp
        assert get_signer_public_key_fingerprint(loaded_from_raw) == expected_fp
        assert get_signer_public_key_fingerprint(loaded_from_file) == expected_fp

    def test_private_key_pem_unencrypted_and_encrypted_roundtrip(self, tmp_path: Path) -> None:
        priv, pub = generate_ed25519_keypair()
        password = b"strong-passphrase-for-ed25519"

        pem_plain = export_ed25519_private_key_pem(priv)
        loaded_plain = load_ed25519_private_key_pem(pem_plain)
        assert get_signer_public_key_fingerprint(
            loaded_plain.public_key()
        ) == get_signer_public_key_fingerprint(pub)

        priv_path = save_ed25519_private_key_pem(
            priv, tmp_path / "signer_priv.pem", password=password
        )
        if os.name == "posix":
            mode = stat.S_IMODE(priv_path.stat().st_mode)
            assert mode == 0o600

        loaded_enc = load_ed25519_private_key_file(priv_path, password=password)
        assert get_signer_public_key_fingerprint(
            loaded_enc.public_key()
        ) == get_signer_public_key_fingerprint(pub)

        # Wrong or missing password fails with InvalidKeyError
        with pytest.raises(InvalidKeyError):
            load_ed25519_private_key_file(priv_path, password=b"wrong-password")
        with pytest.raises(InvalidKeyError):
            load_ed25519_private_key_file(priv_path, password=None)

    def test_invalid_serialized_key_inputs_rejected(self) -> None:
        priv, _ = generate_ed25519_keypair()
        with pytest.raises(InvalidKeyError):
            export_ed25519_private_key_pem(priv, password=b"")
        with pytest.raises(InvalidKeyError):
            load_ed25519_public_key_raw(b"short")
        with pytest.raises(InvalidKeyError):
            load_ed25519_public_key_pem(b"not-a-pem")
        with pytest.raises(InvalidKeyError):
            load_ed25519_private_key_pem(b"not-a-pem")


class TestHashSignVerifyPipeline:
    """Tests for the explicit SHA-256 pre-hash -> Ed25519 sign -> Ed25519 verify pipeline."""

    def test_hash_sign_verify_deterministic_and_tamper_evident(self) -> None:
        priv, pub = generate_ed25519_keypair()
        payload = b'{"algorithm":"AES-256-GCM","magic":"VLT3","version":3}'

        digest1 = compute_payload_digest(payload)
        digest2 = compute_payload_digest(payload)
        assert len(digest1) == 32
        assert digest1 == digest2
        assert SIGNATURE_DOMAIN_SEPARATOR.startswith(b"VLT3-ED25519-SHA256")

        sig1 = sign_canonical_payload(payload, priv)
        sig2 = sign_canonical_payload(payload, priv)
        assert len(sig1) == ED25519_SIGNATURE_SIZE
        # Ed25519 signatures are completely deterministic (no per-signature CSPRNG nonce)
        assert sig1 == sig2

        # Valid verification succeeds without raising
        verify_canonical_payload(payload, sig1, pub)

        # Single-bit flip in payload or signature raises SignatureVerificationError
        tampered_payload = payload[:-1] + bytes([payload[-1] ^ 0x01])
        with pytest.raises(SignatureVerificationError):
            verify_canonical_payload(tampered_payload, sig1, pub)

        tampered_sig = sig1[:-1] + bytes([sig1[-1] ^ 0x01])
        with pytest.raises(SignatureVerificationError):
            verify_canonical_payload(payload, tampered_sig, pub)

