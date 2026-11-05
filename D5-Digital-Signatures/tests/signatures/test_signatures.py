"""Comprehensive unit test suite for Deliverable 5: Digital Signatures & Origin Authentication."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from vault.exceptions import (
    DecryptionFailedError,
    InvalidKeyError,
    InvalidMetadataError,
    MissingSignatureError,
    RecipientNotFoundError,
    SignatureVerificationError,
)
from vault.hybrid.keys import generate_rsa_keypair, get_public_key_fingerprint
from vault.signatures.keys import (
    generate_ed25519_keypair,
    get_signer_public_key_fingerprint,
)
from vault.signatures.signing import (
    SIGNATURE_ALGORITHM,
    SIGNATURE_SIZE,
    SIGNED_FORMAT_VERSION,
    SIGNED_MAGIC,
    encrypt_and_sign_bytes,
    encrypt_and_sign_file,
    verify_and_decrypt_bytes,
    verify_and_decrypt_document,
    verify_and_decrypt_file,
    verify_container_signature,
)


# --------------------------------------------------------------------------- #
# Shared fixtures                                                             #
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def crypto_actors() -> dict[str, Any]:
    """Generate deterministic test actors: sender (Ed25519) and 3 RSA recipients."""
    sender_priv, sender_pub = generate_ed25519_keypair()
    other_signer_priv, other_signer_pub = generate_ed25519_keypair()
    alice_priv, alice_pub = generate_rsa_keypair(2048)
    bob_priv, bob_pub = generate_rsa_keypair(2048)
    carol_priv, carol_pub = generate_rsa_keypair(2048)
    return {
        "sender_id": "sender-origin",
        "sender_priv": sender_priv,
        "sender_pub": sender_pub,
        "other_signer_priv": other_signer_priv,
        "other_signer_pub": other_signer_pub,
        "alice_priv": alice_priv,
        "alice_pub": alice_pub,
        "bob_priv": bob_priv,
        "bob_pub": bob_pub,
        "carol_priv": carol_priv,
        "carol_pub": carol_pub,
    }


def _flip_b64_byte(encoded: str, index: int = 0, mask: int = 0x01) -> str:
    raw = bytearray(base64.b64decode(encoded))
    raw[index % len(raw)] ^= mask
    return base64.b64encode(bytes(raw)).decode("ascii")


def _reserialize(container: dict[str, Any]) -> bytes:
    return json.dumps(
        container,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


# --------------------------------------------------------------------------- #
# 5 Mandatory Top-Level Tests (Step 3 Requirements 1-5)                       #
# --------------------------------------------------------------------------- #


def test_valid_signature_accepted(tmp_path: Path, crypto_actors: dict[str, Any]) -> None:
    """Case 1: Encrypt and sign a file for 2 recipients; verify signature succeeds and both recover exact file."""
    original_content = (
        b"CONFIDENTIAL CONTRACT VLT3\x00\xff\xfe\n"
        b"Signed with Ed25519 and encrypted with AES-256-GCM + RSA-OAEP-SHA256." * 64
    )
    src_file = tmp_path / "contract.pdf"
    vault_file = tmp_path / "contract.vlt3"
    alice_out = tmp_path / "alice_contract.pdf"
    bob_out = tmp_path / "bob_contract.pdf"
    src_file.write_bytes(original_content)

    recipients = [
        ("alice", crypto_actors["alice_pub"]),
        ("bob", crypto_actors["bob_pub"]),
    ]

    encrypt_and_sign_file(
        src_file,
        recipients=recipients,
        output_path=vault_file,
        signer_id=crypto_actors["sender_id"],
        signer_private_key=crypto_actors["sender_priv"],
        metadata={"classification": "restricted", "version": 5},
    )

    # Standalone pre-decryption verification succeeds without any RSA private key
    verified_dict = verify_container_signature(
        vault_file.read_bytes(),
        crypto_actors["sender_pub"],
        expected_signer_id=crypto_actors["sender_id"],
    )
    assert verified_dict["magic"] == SIGNED_MAGIC
    assert verified_dict["version"] == SIGNED_FORMAT_VERSION
    assert verified_dict["signature_algorithm"] == SIGNATURE_ALGORITHM
    assert verified_dict["signer_id"] == crypto_actors["sender_id"]
    assert verified_dict["signer_fingerprint"] == get_signer_public_key_fingerprint(
        crypto_actors["sender_pub"]
    )

    # Both Alice and Bob verify the signature first and recover the exact file byte-for-byte
    verify_and_decrypt_file(
        vault_file,
        "alice",
        crypto_actors["alice_priv"],
        crypto_actors["sender_pub"],
        alice_out,
        expected_signer_id=crypto_actors["sender_id"],
    )
    verify_and_decrypt_file(
        vault_file,
        "bob",
        crypto_actors["bob_priv"],
        crypto_actors["sender_pub"],
        bob_out,
        expected_signer_id=crypto_actors["sender_id"],
    )

    assert alice_out.read_bytes() == original_content
    assert bob_out.read_bytes() == original_content


def test_modified_ciphertext_rejected(tmp_path: Path, crypto_actors: dict[str, Any]) -> None:
    """Case 2: Flip 1 bit/byte in ciphertext; verify signature fails BEFORE decryption is attempted."""
    container_bytes = encrypt_and_sign_bytes(
        b"Sensitive financial ledger data",
        recipients=[
            ("alice", crypto_actors["alice_pub"]),
            ("bob", crypto_actors["bob_pub"]),
        ],
        signer_id=crypto_actors["sender_id"],
        signer_private_key=crypto_actors["sender_priv"],
        filename="ledger.csv",
        metadata={"quarter": "Q4"},
    )

    parsed = json.loads(container_bytes)
    parsed["ciphertext"] = _flip_b64_byte(parsed["ciphertext"], index=0, mask=0x01)
    tampered_bytes = _reserialize(parsed)

    tampered_file = tmp_path / "tampered.vlt3"
    output_file = tmp_path / "should_not_exist.csv"
    tampered_file.write_bytes(tampered_bytes)

    # Spy on RSA private key decryption to prove signature failure aborts BEFORE key unwrapping
    with patch.object(
        type(crypto_actors["alice_priv"]),
        "decrypt",
        wraps=crypto_actors["alice_priv"].decrypt,
    ) as spy_rsa_decrypt:
        with pytest.raises(SignatureVerificationError) as exc_info:
            verify_and_decrypt_file(
                tampered_file,
                "alice",
                crypto_actors["alice_priv"],
                crypto_actors["sender_pub"],
                output_file,
            )
        assert exc_info.value.__cause__ is None
        assert spy_rsa_decrypt.call_count == 0

    assert not output_file.exists()


def test_modified_metadata_rejected(crypto_actors: dict[str, Any]) -> None:
    """Case 3: Modify timestamp, algorithm, signer_id, metadata, or recipient list; verify immediate rejection."""
    container_bytes = encrypt_and_sign_bytes(
        b"Payload protected by metadata-bound Ed25519 signature",
        recipients=[
            ("alice", crypto_actors["alice_pub"]),
            ("bob", crypto_actors["bob_pub"]),
        ],
        signer_id=crypto_actors["sender_id"],
        signer_private_key=crypto_actors["sender_priv"],
        filename="report.txt",
        metadata={"dept": "security", "clearance": 3},
    )
    base = json.loads(container_bytes)

    mutations: list[dict[str, Any]] = []

    # 1. Modified timestamp
    m_ts = json.loads(container_bytes)
    m_ts["timestamp"] = base["timestamp"] + 3600
    mutations.append(m_ts)

    # 2. Modified signer_id
    m_signer = json.loads(container_bytes)
    m_signer["signer_id"] = "spoofed-sender"
    mutations.append(m_signer)

    # 3. Modified user metadata
    m_meta = json.loads(container_bytes)
    m_meta["metadata"] = {"dept": "security", "clearance": 1}
    mutations.append(m_meta)

    # 4. Modified filename
    m_fname = json.loads(container_bytes)
    m_fname["filename"] = "evil.exe"
    mutations.append(m_fname)

    # 5. Modified recipient list (removing Bob)
    m_rem = json.loads(container_bytes)
    m_rem["recipients"] = [m_rem["recipients"][0]]
    mutations.append(m_rem)

    # 6. Modified recipient list (reordering Bob and Alice)
    m_ord = json.loads(container_bytes)
    m_ord["recipients"] = list(reversed(m_ord["recipients"]))
    mutations.append(m_ord)

    # 7. Modified recipient ID
    m_rid = json.loads(container_bytes)
    m_rid["recipients"][1]["id"] = "mallory"
    mutations.append(m_rid)

    # 8. Modified recipient encrypted_dek
    m_dek = json.loads(container_bytes)
    m_dek["recipients"][1]["encrypted_dek"] = _flip_b64_byte(
        m_dek["recipients"][1]["encrypted_dek"], 0, 0x01
    )
    mutations.append(m_dek)

    for mutated in mutations:
        raw_mutated = _reserialize(mutated)
        with patch.object(
            type(crypto_actors["alice_priv"]),
            "decrypt",
            wraps=crypto_actors["alice_priv"].decrypt,
        ) as spy_rsa_decrypt:
            with pytest.raises(SignatureVerificationError):
                verify_and_decrypt_bytes(
                    raw_mutated,
                    "alice",
                    crypto_actors["alice_priv"],
                    crypto_actors["sender_pub"],
                )
            assert spy_rsa_decrypt.call_count == 0


def test_wrong_public_key_rejected(tmp_path: Path, crypto_actors: dict[str, Any]) -> None:
    """Case 4: Attempt verification with another user's Ed25519 public key; verify rejection before decrypting."""
    vault_file = tmp_path / "signed_by_sender.vlt3"
    src_file = tmp_path / "doc.txt"
    out_file = tmp_path / "decrypted.txt"
    src_file.write_bytes(b"Authentic sender payload")

    encrypt_and_sign_file(
        src_file,
        recipients=[("alice", crypto_actors["alice_pub"])],
        output_path=vault_file,
        signer_id=crypto_actors["sender_id"],
        signer_private_key=crypto_actors["sender_priv"],
    )

    # Verification fails when given another user's Ed25519 public key
    with patch.object(
        type(crypto_actors["alice_priv"]),
        "decrypt",
        wraps=crypto_actors["alice_priv"].decrypt,
    ) as spy_rsa_decrypt:
        with pytest.raises(SignatureVerificationError):
            verify_and_decrypt_file(
                vault_file,
                "alice",
                crypto_actors["alice_priv"],
                crypto_actors["other_signer_pub"],
                out_file,
            )
        assert spy_rsa_decrypt.call_count == 0

    assert not out_file.exists()

    # Also test when signer_fingerprint in container is forged to match other_signer_pub
    # while keeping original sender's signature bytes -> Ed25519 verify rejects it
    parsed = json.loads(vault_file.read_bytes())
    parsed["signer_fingerprint"] = get_signer_public_key_fingerprint(
        crypto_actors["other_signer_pub"]
    )
    forged_bytes = _reserialize(parsed)
    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt_bytes(
            forged_bytes,
            "alice",
            crypto_actors["alice_priv"],
            crypto_actors["other_signer_pub"],
        )


def test_signature_removed_rejected(tmp_path: Path, crypto_actors: dict[str, Any]) -> None:
    """Case 5: Remove, zero out, or truncate the signature field; verify immediate rejection and no disk output."""
    container_bytes = encrypt_and_sign_bytes(
        b"Critical document requiring mandatory signature verification",
        recipients=[("alice", crypto_actors["alice_pub"])],
        signer_id=crypto_actors["sender_id"],
        signer_private_key=crypto_actors["sender_priv"],
    )

    # 5a. Signature field completely removed
    no_sig = json.loads(container_bytes)
    del no_sig["signature"]
    no_sig_file = tmp_path / "no_sig.vlt3"
    out_file = tmp_path / "out.bin"
    no_sig_file.write_bytes(_reserialize(no_sig))

    with pytest.raises(MissingSignatureError):
        verify_and_decrypt_file(
            no_sig_file,
            "alice",
            crypto_actors["alice_priv"],
            crypto_actors["sender_pub"],
            out_file,
        )
    assert not out_file.exists()

    # 5b. Signature field set to empty string or None
    for empty_val in ("", "   ", None):
        empty_sig = json.loads(container_bytes)
        empty_sig["signature"] = empty_val
        with pytest.raises(MissingSignatureError):
            verify_and_decrypt_bytes(
                _reserialize(empty_sig),
                "alice",
                crypto_actors["alice_priv"],
                crypto_actors["sender_pub"],
            )

    # 5c. Signer ID removed or empty
    no_signer = json.loads(container_bytes)
    del no_signer["signer_id"]
    with pytest.raises(MissingSignatureError):
        verify_and_decrypt_bytes(
            _reserialize(no_signer),
            "alice",
            crypto_actors["alice_priv"],
            crypto_actors["sender_pub"],
        )

    # 5d. Signature zeroed out (64 zero bytes)
    zero_sig = json.loads(container_bytes)
    zero_sig["signature"] = base64.b64encode(b"\x00" * SIGNATURE_SIZE).decode("ascii")
    zero_file = tmp_path / "zero_sig.vlt3"
    zero_file.write_bytes(_reserialize(zero_sig))
    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt_file(
            zero_file,
            "alice",
            crypto_actors["alice_priv"],
            crypto_actors["sender_pub"],
            out_file,
        )
    assert not out_file.exists()

    # 5e. Signature truncated (32 bytes and 63 bytes) or extended (65 bytes)
    raw_sig = base64.b64decode(json.loads(container_bytes)["signature"])
    for bad_bytes in (raw_sig[:32], raw_sig[:63], raw_sig + b"\x00"):
        trunc_sig = json.loads(container_bytes)
        trunc_sig["signature"] = base64.b64encode(bad_bytes).decode("ascii")
        trunc_file = tmp_path / "trunc_sig.vlt3"
        trunc_file.write_bytes(_reserialize(trunc_sig))
        with pytest.raises(SignatureVerificationError):
            verify_and_decrypt_file(
                trunc_file,
                "alice",
                crypto_actors["alice_priv"],
                crypto_actors["sender_pub"],
                out_file,
            )
        assert not out_file.exists()


# --------------------------------------------------------------------------- #
# Extended Security & Edge-Case Tests                                         #
# --------------------------------------------------------------------------- #


class TestSignedHybridExtendedSecurity:
    """Additional security tests covering recipient lookup, nonce/tag tampering, and validation."""

    @pytest.mark.parametrize("size", [0, 1, 17, 1024, 65536])
    def test_various_payload_sizes_and_recipient_selectors(
        self, size: int, crypto_actors: dict[str, Any]
    ) -> None:
        payload = bytes((i * 31) % 256 for i in range(size))
        container_bytes = encrypt_and_sign_bytes(
            payload,
            recipients=[
                ("alice", crypto_actors["alice_pub"]),
                ("bob", crypto_actors["bob_pub"]),
            ],
            signer_id=crypto_actors["sender_id"],
            signer_private_key=crypto_actors["sender_priv"],
            filename="payload.bin",
            metadata={"size": size},
        )

        alice_fp = get_public_key_fingerprint(crypto_actors["alice_pub"])
        sender_fp = get_signer_public_key_fingerprint(crypto_actors["sender_pub"])

        # Decrypt by logical ID, by recipient fingerprint, and with recipient_id=None
        doc_by_id = verify_and_decrypt_document(
            container_bytes,
            "alice",
            crypto_actors["alice_priv"],
            crypto_actors["sender_pub"],
            expected_signer_id=crypto_actors["sender_id"],
        )
        doc_by_fp = verify_and_decrypt_document(
            container_bytes,
            alice_fp,
            crypto_actors["alice_priv"],
            crypto_actors["sender_pub"],
            expected_signer_id=sender_fp,
        )
        doc_by_none = verify_and_decrypt_document(
            container_bytes,
            None,
            crypto_actors["bob_priv"],
            crypto_actors["sender_pub"],
        )

        assert doc_by_id.plaintext == payload
        assert doc_by_fp.plaintext == payload
        assert doc_by_none.plaintext == payload
        assert doc_by_id.filename == "payload.bin"
        assert doc_by_id.metadata == {"size": size}
        assert doc_by_id.signer_id == crypto_actors["sender_id"]
        assert doc_by_id.signer_fingerprint == sender_fp

    def test_unauthorized_recipient_rejected_after_valid_signature(
        self, crypto_actors: dict[str, Any]
    ) -> None:
        container_bytes = encrypt_and_sign_bytes(
            b"Only for Alice and Bob",
            recipients=[
                ("alice", crypto_actors["alice_pub"]),
                ("bob", crypto_actors["bob_pub"]),
            ],
            signer_id=crypto_actors["sender_id"],
            signer_private_key=crypto_actors["sender_priv"],
        )

        # Signature is valid, but Carol is not in recipients -> RecipientNotFoundError
        with pytest.raises(RecipientNotFoundError):
            verify_and_decrypt_bytes(
                container_bytes,
                "carol",
                crypto_actors["carol_priv"],
                crypto_actors["sender_pub"],
            )

        # Alice's ID with Bob's RSA private key -> DecryptionFailedError
        with pytest.raises(DecryptionFailedError):
            verify_and_decrypt_bytes(
                container_bytes,
                "alice",
                crypto_actors["bob_priv"],
                crypto_actors["sender_pub"],
            )

    def test_tampered_nonce_or_tag_rejected_by_signature_first(
        self, crypto_actors: dict[str, Any]
    ) -> None:
        container_bytes = encrypt_and_sign_bytes(
            b"Nonce and tag are covered by Ed25519 signature",
            recipients=[("alice", crypto_actors["alice_pub"])],
            signer_id=crypto_actors["sender_id"],
            signer_private_key=crypto_actors["sender_priv"],
        )

        for field in ("nonce", "tag", "signature"):
            tampered = json.loads(container_bytes)
            tampered[field] = _flip_b64_byte(tampered[field], 0, 0x80)
            with pytest.raises(SignatureVerificationError):
                verify_and_decrypt_bytes(
                    _reserialize(tampered),
                    "alice",
                    crypto_actors["alice_priv"],
                    crypto_actors["sender_pub"],
                )

    def test_invalid_signer_id_or_metadata_rejected_on_encrypt(
        self, crypto_actors: dict[str, Any]
    ) -> None:
        fp_shaped_id = "a" * 64
        with pytest.raises(InvalidKeyError):
            encrypt_and_sign_bytes(
                b"data",
                recipients=[("alice", crypto_actors["alice_pub"])],
                signer_id=fp_shaped_id,
                signer_private_key=crypto_actors["sender_priv"],
            )
        with pytest.raises(InvalidKeyError):
            encrypt_and_sign_bytes(
                b"data",
                recipients=[("alice", crypto_actors["alice_pub"])],
                signer_id="   ",
                signer_private_key=crypto_actors["sender_priv"],
            )
        with pytest.raises(InvalidMetadataError):
            encrypt_and_sign_bytes(
                b"data",
                recipients=[("alice", crypto_actors["alice_pub"])],
                signer_id="sender",
                signer_private_key=crypto_actors["sender_priv"],
                metadata={"bad_tuple": (1, 2)},
            )

