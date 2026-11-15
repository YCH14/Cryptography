"""Authenticated ``filename`` / ``metadata`` in the VLT2 container (Deliverable D3).

Both fields are always present in the container and in the AAD (``null`` / ``{}``
when unused), are stored in clear, and are only returned after the GCM tag
verifies. Stripping, injecting or editing them must break decryption for every
recipient.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest

from vault.exceptions import DecryptionFailedError, InvalidMetadataError
from vault.hybrid.encryption import (
    MAX_METADATA_SIZE,
    HybridDocument,
    build_aad,
    decrypt_bytes_hybrid,
    decrypt_document_hybrid,
    decrypt_file_hybrid,
    encrypt_bytes_hybrid,
    encrypt_file_hybrid,
)
from vault.hybrid.keys import RSAKeyPair, generate_rsa_keypair

PLAINTEXT = b"contract body \x00\xff binary"
META = {"owner": "alice", "invoice": "invoice-42", "tags": ["q4", "finance"], "n": 7}


@pytest.fixture(scope="module")
def alice() -> RSAKeyPair:
    return generate_rsa_keypair(2048)


@pytest.fixture(scope="module")
def bob() -> RSAKeyPair:
    return generate_rsa_keypair(2048)


@pytest.fixture(scope="module")
def recipients(alice: RSAKeyPair, bob: RSAKeyPair) -> list:
    return [("alice", alice.public_key), ("bob", bob.public_key)]


@pytest.fixture(scope="module")
def container(recipients: list) -> bytes:
    return encrypt_bytes_hybrid(
        PLAINTEXT, recipients, filename="contract.pdf", metadata=META
    )


def _edit(container: bytes, mutate) -> bytes:
    data = json.loads(container)
    mutate(data)
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class TestRoundTrip:
    def test_every_recipient_gets_plaintext_filename_and_metadata(
        self, container: bytes, alice: RSAKeyPair, bob: RSAKeyPair
    ) -> None:
        for rid, keys in [("alice", alice), ("bob", bob)]:
            doc = decrypt_document_hybrid(container, rid, keys.private_key)
            assert isinstance(doc, HybridDocument)
            assert doc.plaintext == PLAINTEXT
            assert doc.filename == "contract.pdf"
            assert doc.metadata == META

    def test_decrypt_bytes_still_returns_plain_bytes(
        self, container: bytes, alice: RSAKeyPair
    ) -> None:
        assert decrypt_bytes_hybrid(container, "alice", alice.private_key) == PLAINTEXT

    def test_defaults_are_null_filename_and_empty_metadata(
        self, recipients: list, alice: RSAKeyPair
    ) -> None:
        blob = encrypt_bytes_hybrid(PLAINTEXT, recipients)
        data = json.loads(blob)
        assert data["filename"] is None
        assert data["metadata"] == {}
        doc = decrypt_document_hybrid(blob, "alice", alice.private_key)
        assert (doc.filename, doc.metadata) == (None, {})

    def test_unicode_and_nested_metadata_roundtrip(
        self, recipients: list, bob: RSAKeyPair
    ) -> None:
        meta = {"título": "Contrato ñandú 🔐", "nested": {"a": [1, 2.5, None, True], "b": {}}}
        blob = encrypt_bytes_hybrid(PLAINTEXT, recipients, filename="café.pdf", metadata=meta)
        doc = decrypt_document_hybrid(blob, "bob", bob.private_key)
        assert doc.metadata == meta
        assert doc.filename == "café.pdf"

    def test_metadata_is_authenticated_but_stored_in_clear(self, container: bytes) -> None:
        assert b"invoice-42" in container
        assert b"contract.pdf" in container


class TestAadBinding:
    def test_aad_always_contains_filename_and_metadata(self) -> None:
        aad = json.loads(build_aad(timestamp=1, recipients=[]))
        assert aad["filename"] is None
        assert aad["metadata"] == {}

    def test_aad_changes_with_filename_and_metadata(self) -> None:
        base = build_aad(timestamp=1, recipients=[])
        assert build_aad(timestamp=1, recipients=[], filename="x") != base
        assert build_aad(timestamp=1, recipients=[], metadata={"k": "v"}) != base


class TestTamperingBreaksEveryRecipient:
    @pytest.mark.parametrize(
        "mutate",
        [
            lambda d: d["metadata"].__setitem__("owner", "mallory"),
            lambda d: d["metadata"].__setitem__("injected", True),
            lambda d: d["metadata"].pop("invoice"),
            lambda d: d.__setitem__("metadata", {}),
            lambda d: d.__setitem__("filename", "evil.exe"),
            lambda d: d.__setitem__("filename", None),
        ],
        ids=[
            "edit-metadata-value",
            "inject-metadata-key",
            "remove-metadata-key",
            "wipe-metadata",
            "swap-filename",
            "strip-filename",
        ],
    )
    def test_modified_fields_fail_for_alice_and_bob(
        self, mutate, container: bytes, alice: RSAKeyPair, bob: RSAKeyPair
    ) -> None:
        forged = _edit(container, mutate)
        for rid, keys in [("alice", alice), ("bob", bob)]:
            with pytest.raises(DecryptionFailedError) as info:
                decrypt_document_hybrid(forged, rid, keys.private_key)
            assert info.value.__cause__ is None

    @pytest.mark.parametrize("field", ["filename", "metadata"])
    def test_removing_the_field_entirely_is_rejected(
        self, field: str, container: bytes, alice: RSAKeyPair
    ) -> None:
        forged = _edit(container, lambda d: d.pop(field))
        with pytest.raises(DecryptionFailedError):
            decrypt_document_hybrid(forged, "alice", alice.private_key)

    @pytest.mark.parametrize(
        ("field", "bad"),
        [("filename", 123), ("filename", ["x"]), ("metadata", []), ("metadata", "str"), ("metadata", None)],
    )
    def test_wrong_field_types_are_rejected(
        self, field: str, bad: Any, container: bytes, alice: RSAKeyPair
    ) -> None:
        forged = _edit(container, lambda d: d.__setitem__(field, bad))
        with pytest.raises(DecryptionFailedError):
            decrypt_document_hybrid(forged, "alice", alice.private_key)


class TestInvalidMetadataRejectedOnEncrypt:
    @pytest.mark.parametrize(
        "metadata",
        [
            {"obj": object()},
            {"t": (1, 2)},  # tuple would silently become a list
            {1: "int key"},  # int key would silently become "1"
            {"nan": math.nan},
            {"inf": math.inf},
            {"bytes": b"raw"},
            ["not", "a", "mapping"],
            "string",
        ],
    )
    def test_non_canonical_metadata_is_rejected(
        self, metadata: Any, recipients: list
    ) -> None:
        with pytest.raises(InvalidMetadataError):
            encrypt_bytes_hybrid(PLAINTEXT, recipients, metadata=metadata)

    def test_non_string_filename_is_rejected(self, recipients: list) -> None:
        with pytest.raises(InvalidMetadataError):
            encrypt_bytes_hybrid(PLAINTEXT, recipients, filename=123)  # type: ignore[arg-type]

    def test_oversized_metadata_is_rejected(self, recipients: list) -> None:
        with pytest.raises(InvalidMetadataError):
            encrypt_bytes_hybrid(
                PLAINTEXT, recipients, metadata={"blob": "x" * MAX_METADATA_SIZE}
            )

    def test_circular_metadata_is_rejected(self, recipients: list) -> None:
        loop: dict[str, Any] = {}
        loop["self"] = loop
        with pytest.raises(InvalidMetadataError):
            encrypt_bytes_hybrid(PLAINTEXT, recipients, metadata=loop)


class TestFileApi:
    def test_file_name_and_metadata_are_stored_by_default(
        self, recipients: list, alice: RSAKeyPair, tmp_path: Path
    ) -> None:
        src = tmp_path / "report.docx"
        src.write_bytes(PLAINTEXT)
        vault = encrypt_file_hybrid(src, recipients, tmp_path / "r.vlt2", {"dept": "legal"})
        doc = decrypt_document_hybrid(vault.read_bytes(), "alice", alice.private_key)
        assert doc.filename == "report.docx"
        assert doc.metadata == {"dept": "legal"}

    def test_include_filename_false_stores_null(
        self, recipients: list, alice: RSAKeyPair, tmp_path: Path
    ) -> None:
        src = tmp_path / "secret-name.txt"
        src.write_bytes(PLAINTEXT)
        vault = encrypt_file_hybrid(
            src, recipients, tmp_path / "r.vlt2", include_filename=False
        )
        assert b"secret-name" not in vault.read_bytes()
        doc = decrypt_document_hybrid(vault.read_bytes(), "alice", alice.private_key)
        assert doc.filename is None

    def test_invalid_metadata_creates_no_output_file(
        self, recipients: list, tmp_path: Path
    ) -> None:
        src = tmp_path / "a.bin"
        src.write_bytes(PLAINTEXT)
        out = tmp_path / "never.vlt2"
        with pytest.raises(InvalidMetadataError):
            encrypt_file_hybrid(src, recipients, out, {"bad": object()})
        assert not out.exists()

    def test_hostile_filename_never_influences_the_output_path(
        self, recipients: list, alice: RSAKeyPair, tmp_path: Path
    ) -> None:
        blob = encrypt_bytes_hybrid(PLAINTEXT, recipients, filename="../../escape.txt")
        vault = tmp_path / "hostile.vlt2"
        vault.write_bytes(blob)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        out = out_dir / "chosen.bin"
        decrypt_file_hybrid(vault, "alice", alice.private_key, out)
        assert out.read_bytes() == PLAINTEXT
        assert not (tmp_path / "escape.txt").exists()
        assert not (tmp_path.parent / "escape.txt").exists()
        assert sorted(p.name for p in out_dir.iterdir()) == ["chosen.bin"]
