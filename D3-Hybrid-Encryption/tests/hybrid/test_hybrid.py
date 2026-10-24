"""Automated test suite for Multi-Recipient Hybrid Encryption (Deliverable D3).

Covers:
1. Multi-Recipient Decryption (Alice, Bob, and 3+ recipients; byte-identical output).
2. Unauthorized Recipient Rejection (Carol not in recipient list -> RecipientNotFoundError / DecryptionFailedError).
3. Wrong Private Key (decrypting Alice's entry with a different RSA private key -> DecryptionFailedError).
4. Tampered Recipient List (modified recipient ID, modified fingerprint, modified encrypted_dek, reordered/injected recipients -> AEAD tag validation failure).
5. Recipient Removal Attack (stripping Bob from the container causes Alice's decryption to fail via AAD mismatch).
6. Corrupted Ciphertext / Tag / Nonce / Header (1-bit flips -> DecryptionFailedError, zero disk residue).
7. RSA Key Management, PEM import/export, SHA-256 SPKI fingerprints, and CSPRNG hygiene.
"""

from __future__ import annotations

import ast
import base64
import copy
import errno
import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from vault.exceptions import (
    DecryptionFailedError,
    InvalidKeyError,
    PlaintextTooLargeError,
    RecipientNotFoundError,
    VaultError,
)
from vault.hybrid import encryption, keys
from vault.hybrid.encryption import (
    ALGORITHM,
    DEK_SIZE,
    FORMAT_VERSION,
    KEY_WRAP_ALGORITHM,
    MAGIC,
    NONCE_SIZE,
    TAG_SIZE,
    build_aad,
    decrypt_bytes_hybrid,
    decrypt_file_hybrid,
    encrypt_bytes_hybrid,
    encrypt_file_hybrid,
)
from vault.hybrid.keys import (
    RSAKeyPair,
    export_private_key_pem,
    export_public_key_pem,
    generate_rsa_keypair,
    get_public_key_fingerprint,
    load_private_key_file,
    load_private_key_pem,
    load_public_key_file,
    load_public_key_pem,
    save_private_key_pem,
    save_public_key_pem,
)


# --------------------------------------------------------------------------- #
# Helpers & Fixtures                                                          #
# --------------------------------------------------------------------------- #


def flip_b64_byte(b64_str: str, byte_index: int = 0, bit: int = 0) -> str:
    """Flip a single bit in a base64-encoded field and re-encode to base64."""
    raw = bytearray(base64.b64decode(b64_str))
    raw[byte_index % len(raw)] ^= 1 << bit
    return base64.b64encode(bytes(raw)).decode("ascii")


def load_container_json(vault_path: Path) -> dict:
    return json.loads(vault_path.read_text(encoding="utf-8"))


def write_container_json(vault_path: Path, data: dict) -> Path:
    vault_path.write_text(
        json.dumps(data, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return vault_path


@pytest.fixture(scope="module")
def alice_keys() -> RSAKeyPair:
    return generate_rsa_keypair(2048)


@pytest.fixture(scope="module")
def bob_keys() -> RSAKeyPair:
    return generate_rsa_keypair(2048)


@pytest.fixture(scope="module")
def carol_keys() -> RSAKeyPair:
    return generate_rsa_keypair(2048)


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    p = tmp_path / "confidential_contract.pdf"
    p.write_bytes(b"%PDF-1.7\nCONFIDENTIAL-MULTI-RECIPIENT-PAYLOAD\n" + os.urandom(4096) + b"\n%%EOF\n")
    return p


@pytest.fixture
def shared_vault(
    sample_file: Path,
    alice_keys: RSAKeyPair,
    bob_keys: RSAKeyPair,
    tmp_path: Path,
) -> Path:
    vault_path = tmp_path / "shared_contract.vlt2"
    recipients = [
        ("alice", alice_keys.public_key),
        ("bob", bob_keys.public_key),
    ]
    return encrypt_file_hybrid(sample_file, recipients, vault_path)


# --------------------------------------------------------------------------- #
# 1. Multi-Recipient Decryption                                               #
# --------------------------------------------------------------------------- #


class TestMultiRecipientDecryption:
    def test_alice_and_bob_decrypt_exact_original_file(
        self,
        sample_file: Path,
        shared_vault: Path,
        alice_keys: RSAKeyPair,
        bob_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        alice_out = tmp_path / "alice_decrypted.pdf"
        bob_out = tmp_path / "bob_decrypted.pdf"

        res_alice = decrypt_file_hybrid(shared_vault, "alice", alice_keys.private_key, alice_out)
        res_bob = decrypt_file_hybrid(shared_vault, "bob", bob_keys.private_key, bob_out)

        original_bytes = sample_file.read_bytes()
        assert res_alice == alice_out
        assert res_bob == bob_out
        assert alice_out.read_bytes() == original_bytes
        assert bob_out.read_bytes() == original_bytes
        assert hashlib.sha256(alice_out.read_bytes()).hexdigest() == hashlib.sha256(original_bytes).hexdigest()
        assert hashlib.sha256(bob_out.read_bytes()).hexdigest() == hashlib.sha256(original_bytes).hexdigest()

    @pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 4096, 256 * 1024 + 7])
    def test_multi_recipient_various_payload_sizes(
        self,
        size: int,
        alice_keys: RSAKeyPair,
        bob_keys: RSAKeyPair,
        carol_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        src = tmp_path / f"payload_{size}.bin"
        src.write_bytes(os.urandom(size))
        vault_path = tmp_path / f"payload_{size}.vlt2"

        recipients = [
            ("alice@example.com", alice_keys.public_key),
            ("bob@example.com", bob_keys.public_key),
            ("carol@example.com", carol_keys.public_key),
        ]
        encrypt_file_hybrid(src, recipients, vault_path)

        for uid, kp in [
            ("alice@example.com", alice_keys),
            ("bob@example.com", bob_keys),
            ("carol@example.com", carol_keys),
        ]:
            out = tmp_path / f"out_{uid}_{size}.bin"
            decrypt_file_hybrid(vault_path, uid, kp.private_key, out)
            assert out.read_bytes() == src.read_bytes()

    def test_container_schema_and_aad_structure_match_spec(
        self,
        sample_file: Path,
        shared_vault: Path,
        alice_keys: RSAKeyPair,
        bob_keys: RSAKeyPair,
    ) -> None:
        container = load_container_json(shared_vault)
        assert container["magic"] == MAGIC == "VLT2"
        assert container["version"] == FORMAT_VERSION == 2
        assert container["algorithm"] == ALGORITHM == "AES-256-GCM"
        assert container["key_wrap_algorithm"] == KEY_WRAP_ALGORITHM == "RSA-OAEP-SHA256"
        assert isinstance(container["timestamp"], int)

        recipients = container["recipients"]
        assert len(recipients) == 2
        assert recipients[0]["id"] == "alice"
        assert recipients[0]["fingerprint"] == get_public_key_fingerprint(alice_keys.public_key)
        assert recipients[1]["id"] == "bob"
        assert recipients[1]["fingerprint"] == get_public_key_fingerprint(bob_keys.public_key)
        # RSA-OAEP wraps the same DEK independently, so ciphertexts must differ
        assert recipients[0]["encrypted_dek"] != recipients[1]["encrypted_dek"]

        nonce = base64.b64decode(container["nonce"])
        ciphertext = base64.b64decode(container["ciphertext"])
        tag = base64.b64decode(container["tag"])
        assert len(nonce) == NONCE_SIZE == 12
        assert len(tag) == TAG_SIZE == 16
        assert len(ciphertext) == sample_file.stat().st_size

    def test_recipient_identification_by_fingerprint(
        self,
        sample_file: Path,
        shared_vault: Path,
        alice_keys: RSAKeyPair,
        bob_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        alice_fp = get_public_key_fingerprint(alice_keys.public_key)
        bob_fp = get_public_key_fingerprint(bob_keys.public_key)

        out_alice = tmp_path / "alice_by_fp.pdf"
        out_bob = tmp_path / "bob_by_fp.pdf"
        decrypt_file_hybrid(shared_vault, alice_fp, alice_keys.private_key, out_alice)
        decrypt_file_hybrid(shared_vault, bob_fp, bob_keys.private_key, out_bob)

        assert out_alice.read_bytes() == sample_file.read_bytes()
        assert out_bob.read_bytes() == sample_file.read_bytes()


# --------------------------------------------------------------------------- #
# 2. Unauthorized Recipient Rejection                                         #
# --------------------------------------------------------------------------- #


class TestUnauthorizedRecipientRejection:
    def test_unlisted_recipient_carol_is_rejected(
        self,
        shared_vault: Path,
        carol_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        carol_out = tmp_path / "carol_unauthorized.pdf"
        with pytest.raises((RecipientNotFoundError, DecryptionFailedError)) as exc_info:
            decrypt_file_hybrid(shared_vault, "carol", carol_keys.private_key, carol_out)

        # RecipientNotFoundError is a subclass of DecryptionFailedError
        assert isinstance(exc_info.value, RecipientNotFoundError)
        assert isinstance(exc_info.value, DecryptionFailedError)
        assert not carol_out.exists()

    def test_unlisted_recipient_by_fingerprint_is_rejected(
        self,
        shared_vault: Path,
        carol_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        carol_fp = get_public_key_fingerprint(carol_keys.public_key)
        carol_out = tmp_path / "carol_fp.pdf"
        with pytest.raises(RecipientNotFoundError):
            decrypt_file_hybrid(shared_vault, carol_fp, carol_keys.private_key, carol_out)
        assert not carol_out.exists()


# --------------------------------------------------------------------------- #
# 3. Wrong Private Key                                                        #
# --------------------------------------------------------------------------- #


class TestWrongPrivateKey:
    def test_decrypt_alice_entry_with_carol_private_key_fails(
        self,
        shared_vault: Path,
        carol_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        out = tmp_path / "wrong_priv.pdf"
        with pytest.raises(DecryptionFailedError) as exc_info:
            decrypt_file_hybrid(shared_vault, "alice", carol_keys.private_key, out)
        assert exc_info.value.__cause__ is None
        assert not out.exists()

    def test_decrypt_alice_entry_with_bob_private_key_fails(
        self,
        shared_vault: Path,
        bob_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        out = tmp_path / "cross_priv.pdf"
        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(shared_vault, "alice", bob_keys.private_key, out)
        assert not out.exists()


# --------------------------------------------------------------------------- #
# 4. Tampered Recipient List (Integrity Check)                                #
# --------------------------------------------------------------------------- #


class TestTamperedRecipientList:
    def test_tampered_recipient_id_breaks_aead_tag(
        self,
        shared_vault: Path,
        alice_keys: RSAKeyPair,
        bob_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        # Case A: Modify Bob's recipient ID; Alice attempts to decrypt
        container_a = load_container_json(shared_vault)
        container_a["recipients"][1]["id"] = "mallory"
        tampered_a = write_container_json(tmp_path / "tampered_bob_id.vlt2", container_a)
        out_a = tmp_path / "out_a.pdf"

        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(tampered_a, "alice", alice_keys.private_key, out_a)
        assert not out_a.exists()

        # Case B: Modify Alice's own recipient ID; Alice attempts to decrypt
        container_b = load_container_json(shared_vault)
        container_b["recipients"][0]["id"] = "mallory"
        tampered_b = write_container_json(tmp_path / "tampered_alice_id.vlt2", container_b)
        out_b = tmp_path / "out_b.pdf"

        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(tampered_b, "alice", alice_keys.private_key, out_b)
        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(tampered_b, "mallory", alice_keys.private_key, out_b)
        assert not out_b.exists()

    def test_tampered_recipient_fingerprint_breaks_aead_tag(
        self,
        shared_vault: Path,
        alice_keys: RSAKeyPair,
        carol_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        carol_fp = get_public_key_fingerprint(carol_keys.public_key)

        # Case A: Swap Bob's fingerprint with Carol's fingerprint; Alice decrypts
        container_a = load_container_json(shared_vault)
        container_a["recipients"][1]["fingerprint"] = carol_fp
        tampered_a = write_container_json(tmp_path / "tampered_bob_fp.vlt2", container_a)
        out_a = tmp_path / "out_fp_a.pdf"

        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(tampered_a, "alice", alice_keys.private_key, out_a)
        assert not out_a.exists()

        # Case B: Modify Alice's own fingerprint; Alice decrypts
        container_b = load_container_json(shared_vault)
        container_b["recipients"][0]["fingerprint"] = carol_fp
        tampered_b = write_container_json(tmp_path / "tampered_alice_fp.vlt2", container_b)
        out_b = tmp_path / "out_fp_b.pdf"

        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(tampered_b, "alice", alice_keys.private_key, out_b)
        assert not out_b.exists()

    def test_tampered_encrypted_dek_single_byte_fails(
        self,
        shared_vault: Path,
        alice_keys: RSAKeyPair,
        bob_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        # Case A: Modify 1 byte of Alice's encrypted_dek -> fails RSA-OAEP unwrap
        container_a = load_container_json(shared_vault)
        container_a["recipients"][0]["encrypted_dek"] = flip_b64_byte(
            container_a["recipients"][0]["encrypted_dek"], byte_index=10
        )
        tampered_a = write_container_json(tmp_path / "tampered_alice_dek.vlt2", container_a)
        out_a = tmp_path / "out_dek_a.pdf"

        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(tampered_a, "alice", alice_keys.private_key, out_a)
        # Bob's decryption of container_a MUST ALSO FAIL because Alice's encrypted_dek is in AAD!
        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(tampered_a, "bob", bob_keys.private_key, out_a)
        assert not out_a.exists()

    def test_reordered_or_injected_recipient_list_breaks_aead_tag(
        self,
        shared_vault: Path,
        alice_keys: RSAKeyPair,
        carol_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        # Reorder [alice, bob] -> [bob, alice]
        container_reordered = load_container_json(shared_vault)
        container_reordered["recipients"].reverse()
        reordered_path = write_container_json(tmp_path / "reordered.vlt2", container_reordered)
        out = tmp_path / "out_reordered.pdf"

        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(reordered_path, "alice", alice_keys.private_key, out)
        assert not out.exists()

        # Inject Carol into the recipient list
        container_injected = load_container_json(shared_vault)
        container_injected["recipients"].append(
            {
                "id": "carol",
                "fingerprint": get_public_key_fingerprint(carol_keys.public_key),
                "encrypted_dek": container_injected["recipients"][0]["encrypted_dek"],
            }
        )
        injected_path = write_container_json(tmp_path / "injected.vlt2", container_injected)
        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(injected_path, "alice", alice_keys.private_key, out)
        assert not out.exists()


# --------------------------------------------------------------------------- #
# 5. Recipient Removal Attack                                                 #
# --------------------------------------------------------------------------- #


class TestRecipientRemovalAttack:
    def test_stripping_bob_causes_alice_decryption_to_fail(
        self,
        shared_vault: Path,
        alice_keys: RSAKeyPair,
        bob_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        container = load_container_json(shared_vault)
        # Remove Bob (index 1), leaving only Alice
        container["recipients"] = [r for r in container["recipients"] if r["id"] != "bob"]
        assert len(container["recipients"]) == 1

        stripped_vault = write_container_json(tmp_path / "stripped_bob.vlt2", container)
        alice_out = tmp_path / "alice_after_strip.pdf"
        bob_out = tmp_path / "bob_after_strip.pdf"

        # Alice still unwraps the DEK with her RSA private key, but AES-GCM AAD verification fails!
        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(stripped_vault, "alice", alice_keys.private_key, alice_out)
        assert not alice_out.exists()

        # Bob is no longer in the recipient list at all
        with pytest.raises((RecipientNotFoundError, DecryptionFailedError)):
            decrypt_file_hybrid(stripped_vault, "bob", bob_keys.private_key, bob_out)
        assert not bob_out.exists()


# --------------------------------------------------------------------------- #
# 6. Corrupted Ciphertext & Tag                                               #
# --------------------------------------------------------------------------- #


class TestCorruptedCiphertextAndTag:
    @pytest.mark.parametrize("byte_offset", [0, 1, 50, -1])
    @pytest.mark.parametrize("bit", [0, 3, 7])
    def test_single_bit_flip_in_ciphertext_fails(
        self,
        shared_vault: Path,
        alice_keys: RSAKeyPair,
        tmp_path: Path,
        byte_offset: int,
        bit: int,
    ) -> None:
        container = load_container_json(shared_vault)
        container["ciphertext"] = flip_b64_byte(container["ciphertext"], byte_offset, bit)
        corrupted = write_container_json(
            tmp_path / f"corrupted_ct_{byte_offset}_{bit}.vlt2", container
        )
        out = tmp_path / "corrupted_ct.pdf"

        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(corrupted, "alice", alice_keys.private_key, out)
        assert not out.exists()

    @pytest.mark.parametrize("byte_offset", [0, 7, 15])
    @pytest.mark.parametrize("bit", [0, 4, 7])
    def test_single_bit_flip_in_tag_fails(
        self,
        shared_vault: Path,
        alice_keys: RSAKeyPair,
        tmp_path: Path,
        byte_offset: int,
        bit: int,
    ) -> None:
        container = load_container_json(shared_vault)
        container["tag"] = flip_b64_byte(container["tag"], byte_offset, bit)
        corrupted = write_container_json(
            tmp_path / f"corrupted_tag_{byte_offset}_{bit}.vlt2", container
        )
        out = tmp_path / "corrupted_tag.pdf"

        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(corrupted, "alice", alice_keys.private_key, out)
        assert not out.exists()

    def test_single_bit_flip_in_nonce_or_timestamp_fails(
        self,
        shared_vault: Path,
        alice_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        # Flip bit in nonce
        c_nonce = load_container_json(shared_vault)
        c_nonce["nonce"] = flip_b64_byte(c_nonce["nonce"], 0, 0)
        p_nonce = write_container_json(tmp_path / "bad_nonce.vlt2", c_nonce)
        out = tmp_path / "out_nonce.pdf"
        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(p_nonce, "alice", alice_keys.private_key, out)
        assert not out.exists()

        # Tamper with timestamp in AAD
        c_ts = load_container_json(shared_vault)
        c_ts["timestamp"] += 1
        p_ts = write_container_json(tmp_path / "bad_ts.vlt2", c_ts)
        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(p_ts, "alice", alice_keys.private_key, out)
        assert not out.exists()

    @pytest.mark.parametrize(
        "raw_payload",
        [
            b"",
            b"not json at all",
            b'{"magic":"VLT1"}',
            b'{"magic":"VLT2","version":2}',
        ],
    )
    def test_malformed_containers_raise_decryption_failed_error(
        self,
        raw_payload: bytes,
        alice_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        bad_file = tmp_path / "malformed.vlt2"
        bad_file.write_bytes(raw_payload)
        out = tmp_path / "out_malformed.pdf"
        with pytest.raises(DecryptionFailedError):
            decrypt_file_hybrid(bad_file, "alice", alice_keys.private_key, out)
        assert not out.exists()


# --------------------------------------------------------------------------- #
# 7. RSA Key Management, Fingerprints, CSPRNG & Disk Safety                   #
# --------------------------------------------------------------------------- #


class TestKeysAndSecurityHygiene:
    def test_keypair_generation_and_fingerprint_determinism(
        self,
        alice_keys: RSAKeyPair,
        bob_keys: RSAKeyPair,
    ) -> None:
        priv, pub = alice_keys
        assert priv.key_size == 2048
        assert pub.key_size == 2048

        fp1 = get_public_key_fingerprint(pub)
        fp2 = get_public_key_fingerprint(priv.public_key())
        expected_der = pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert fp1 == fp2 == hashlib.sha256(expected_der).hexdigest()
        assert len(fp1) == 64
        assert fp1 != get_public_key_fingerprint(bob_keys.public_key)

    def test_pem_export_import_and_file_persistence(
        self,
        alice_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        pub_pem = export_public_key_pem(alice_keys.public_key)
        priv_pem = export_private_key_pem(alice_keys.private_key)
        enc_priv_pem = export_private_key_pem(alice_keys.private_key, password=b"strong-passphrase")

        loaded_pub = load_public_key_pem(pub_pem)
        loaded_priv = load_private_key_pem(priv_pem)
        loaded_enc_priv = load_private_key_pem(enc_priv_pem, password=b"strong-passphrase")

        assert get_public_key_fingerprint(loaded_pub) == get_public_key_fingerprint(alice_keys.public_key)
        assert get_public_key_fingerprint(loaded_priv.public_key()) == get_public_key_fingerprint(alice_keys.public_key)
        assert get_public_key_fingerprint(loaded_enc_priv.public_key()) == get_public_key_fingerprint(alice_keys.public_key)

        with pytest.raises(InvalidKeyError):
            load_private_key_pem(enc_priv_pem, password=b"wrong-password")

        pub_file = save_public_key_pem(alice_keys.public_key, tmp_path / "alice_pub.pem")
        priv_file = save_private_key_pem(alice_keys.private_key, tmp_path / "alice_priv.pem")
        assert get_public_key_fingerprint(load_public_key_file(pub_file)) == get_public_key_fingerprint(alice_keys.public_key)
        assert get_public_key_fingerprint(load_private_key_file(priv_file).public_key()) == get_public_key_fingerprint(alice_keys.public_key)

    @pytest.mark.parametrize("bad_size", [512, 1024, 2047, 0, -1, True, "2048"])
    def test_weak_or_invalid_rsa_key_size_rejected(self, bad_size: object) -> None:
        with pytest.raises(InvalidKeyError):
            generate_rsa_keypair(bad_size)  # type: ignore[arg-type]

    def test_invalid_recipients_rejected_on_encrypt(
        self,
        sample_file: Path,
        alice_keys: RSAKeyPair,
        tmp_path: Path,
    ) -> None:
        out = tmp_path / "never_created.vlt2"
        # Empty recipients list
        with pytest.raises(InvalidKeyError):
            encrypt_file_hybrid(sample_file, [], out)
        # Duplicate recipient ID
        with pytest.raises(InvalidKeyError):
            encrypt_file_hybrid(
                sample_file,
                [("alice", alice_keys.public_key), ("alice", alice_keys.public_key)],
                out,
            )
        # Duplicate public key under different IDs
        with pytest.raises(InvalidKeyError):
            encrypt_file_hybrid(
                sample_file,
                [("alice", alice_keys.public_key), ("alice_alias", alice_keys.public_key)],
                out,
            )
        assert not out.exists()

    def test_csprng_used_exclusively_for_dek_and_nonce(
        self,
        alice_keys: RSAKeyPair,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        requested: list[int] = []
        real_urandom = os.urandom

        def spy(size: int) -> bytes:
            requested.append(size)
            return real_urandom(size)

        monkeypatch.setattr(encryption.os, "urandom", spy)
        encrypt_bytes_hybrid(b"secret", [("alice", alice_keys.public_key)])
        assert requested == [DEK_SIZE, NONCE_SIZE]

        for module in (encryption, keys):
            tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
            imported = {
                alias.name.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            } | {
                node.module.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            }
            assert "random" not in imported

    def test_disk_failure_mid_write_cleans_up_partial_file(
        self,
        shared_vault: Path,
        alice_keys: RSAKeyPair,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def write_partial_then_fail(fd: int, data: bytes) -> None:
            os.write(fd, data[:16])
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(encryption, "_write_all", write_partial_then_fail)
        out = tmp_path / "partial_cleanup.pdf"
        with pytest.raises(OSError):
            decrypt_file_hybrid(shared_vault, "alice", alice_keys.private_key, out)
        assert not out.exists()

