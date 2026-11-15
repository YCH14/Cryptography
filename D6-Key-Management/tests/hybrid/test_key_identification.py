"""Deterministic, confusion-free recipient key identification (Deliverable D3).

Rule under test
---------------
* A recipient ID may never have the shape of a key fingerprint
  (64 lowercase hex characters): that form is reserved, so the ``id`` and
  ``fingerprint`` namespaces are disjoint.
* The selector passed to decrypt picks exactly ONE field of the recipient
  entry by its shape, with no fallback to the other field.
* The selected entry must carry the fingerprint of the private key in use.
"""

from __future__ import annotations

import json

import pytest

from vault.exceptions import (
    DecryptionFailedError,
    InvalidKeyError,
    RecipientNotFoundError,
)
from vault.hybrid.encryption import decrypt_bytes_hybrid, encrypt_bytes_hybrid
from vault.hybrid.keys import (
    RSAKeyPair,
    generate_rsa_keypair,
    get_public_key_fingerprint,
    looks_like_fingerprint,
)

PLAINTEXT = b"top secret shared payload"


@pytest.fixture(scope="module")
def alice() -> RSAKeyPair:
    return generate_rsa_keypair(2048)


@pytest.fixture(scope="module")
def bob() -> RSAKeyPair:
    return generate_rsa_keypair(2048)


@pytest.fixture(scope="module")
def container(alice: RSAKeyPair, bob: RSAKeyPair) -> bytes:
    return encrypt_bytes_hybrid(
        PLAINTEXT, [("alice", alice.public_key), ("bob", bob.public_key)]
    )


def _edit(container: bytes, mutate) -> bytes:
    data = json.loads(container)
    mutate(data)
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class TestEncryptRejectsConfusableIds:
    def test_id_equal_to_another_recipients_fingerprint_is_rejected(
        self, alice: RSAKeyPair, bob: RSAKeyPair
    ) -> None:
        bob_fp = get_public_key_fingerprint(bob.public_key)
        with pytest.raises(InvalidKeyError):
            encrypt_bytes_hybrid(
                PLAINTEXT, [(bob_fp, alice.public_key), ("bob", bob.public_key)]
            )

    def test_any_fingerprint_shaped_id_is_rejected(self, alice: RSAKeyPair) -> None:
        with pytest.raises(InvalidKeyError):
            encrypt_bytes_hybrid(PLAINTEXT, [("f" * 64, alice.public_key)])

    def test_uppercase_hex_is_not_reserved_and_stays_a_plain_id(
        self, alice: RSAKeyPair
    ) -> None:
        # Fingerprints are lowercase; 64 uppercase hex chars is just an ordinary ID.
        rid = "F" * 64
        blob = encrypt_bytes_hybrid(PLAINTEXT, [(rid, alice.public_key)])
        assert decrypt_bytes_hybrid(blob, rid, alice.private_key) == PLAINTEXT


class TestDeterministicLookup:
    @pytest.mark.parametrize("who", ["alice", "bob"])
    @pytest.mark.parametrize("selector", ["id", "fingerprint", "none", "empty"])
    def test_every_selector_form_finds_the_right_entry(
        self,
        who: str,
        selector: str,
        container: bytes,
        alice: RSAKeyPair,
        bob: RSAKeyPair,
    ) -> None:
        keys = {"alice": alice, "bob": bob}[who]
        rid = {
            "id": who,
            "fingerprint": get_public_key_fingerprint(keys.public_key),
            "none": None,
            "empty": "",
        }[selector]
        assert decrypt_bytes_hybrid(container, rid, keys.private_key) == PLAINTEXT

    def test_unknown_id_has_no_fallback_to_the_callers_fingerprint(
        self, container: bytes, bob: RSAKeyPair
    ) -> None:
        # Bob IS a recipient, but naming a non-existent ID must not silently
        # fall back to his key fingerprint.
        with pytest.raises(RecipientNotFoundError):
            decrypt_bytes_hybrid(container, "zed", bob.private_key)

    def test_id_of_another_recipient_with_my_key_fails(
        self, container: bytes, bob: RSAKeyPair
    ) -> None:
        with pytest.raises(DecryptionFailedError) as info:
            decrypt_bytes_hybrid(container, "alice", bob.private_key)
        assert not isinstance(info.value, RecipientNotFoundError)

    def test_fingerprint_of_another_recipient_with_my_key_fails(
        self, container: bytes, alice: RSAKeyPair, bob: RSAKeyPair
    ) -> None:
        alice_fp = get_public_key_fingerprint(alice.public_key)
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes_hybrid(container, alice_fp, bob.private_key)

    def test_uppercase_fingerprint_is_treated_as_an_id_not_found(
        self, container: bytes, alice: RSAKeyPair
    ) -> None:
        upper = get_public_key_fingerprint(alice.public_key).upper()
        with pytest.raises(RecipientNotFoundError):
            decrypt_bytes_hybrid(container, upper, alice.private_key)


class TestContainerNamespaceIsEnforcedOnRead:
    """A hand-crafted container can never re-introduce the ambiguity."""

    def test_entry_with_fingerprint_shaped_id_is_rejected(
        self, container: bytes, alice: RSAKeyPair, bob: RSAKeyPair
    ) -> None:
        bob_fp = get_public_key_fingerprint(bob.public_key)
        crafted = _edit(container, lambda d: d["recipients"][0].__setitem__("id", bob_fp))
        for rid, keys in [("bob", bob), (bob_fp, bob), ("alice", alice), (None, alice)]:
            with pytest.raises(DecryptionFailedError):
                decrypt_bytes_hybrid(crafted, rid, keys.private_key)

    def test_duplicate_fingerprints_are_rejected(
        self, container: bytes, alice: RSAKeyPair
    ) -> None:
        def dup(d: dict) -> None:
            d["recipients"][1]["fingerprint"] = d["recipients"][0]["fingerprint"]

        crafted = _edit(container, dup)
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes_hybrid(crafted, "alice", alice.private_key)

    @pytest.mark.parametrize("bad_fp", ["", "xyz", "A" * 64, "a" * 63])
    def test_malformed_fingerprint_field_is_rejected(
        self, container: bytes, alice: RSAKeyPair, bad_fp: str
    ) -> None:
        crafted = _edit(
            container, lambda d: d["recipients"][1].__setitem__("fingerprint", bad_fp)
        )
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes_hybrid(crafted, "alice", alice.private_key)
