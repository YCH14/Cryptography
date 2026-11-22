"""D6: a signer key file goes through the fingerprint confirmation before it is trusted."""

import pytest

from vault.exceptions import InvalidKeyError
from vault.keystore import TrustedSigners
from vault.signatures import (
    generate_ed25519_keypair,
    get_signer_id,
    load_signer_public_key_file,
    save_signer_public_key_file,
)


def test_a_key_file_is_trusted_only_with_the_confirmed_fingerprint(tmp_path):
    alice_private, alice_public = generate_ed25519_keypair()
    key_file = save_signer_public_key_file(alice_public, tmp_path / "alice.sign.pem")
    trusted = TrustedSigners(tmp_path / "trusted_signers.json")

    imported = load_signer_public_key_file(key_file)
    with pytest.raises(InvalidKeyError):
        trusted.add("alice", imported, expected_fingerprint="0" * 64)
    assert trusted.status(get_signer_id(alice_public)) is None

    trusted.add("alice", imported, expected_fingerprint=get_signer_id(alice_public))
    assert trusted.status(get_signer_id(alice_public)) == "trusted"


def test_a_substituted_key_file_does_not_match_the_confirmed_fingerprint(tmp_path):
    _, alice_public = generate_ed25519_keypair()
    _, mallory_public = generate_ed25519_keypair()
    swapped = save_signer_public_key_file(mallory_public, tmp_path / "alice.sign.pem")
    trusted = TrustedSigners(tmp_path / "trusted_signers.json")
    with pytest.raises(InvalidKeyError):
        trusted.add("alice", load_signer_public_key_file(swapped), expected_fingerprint=get_signer_id(alice_public))
