import pytest
from vault.signatures.keys import generate_ed25519_keypair
from vault.signatures.signing import encrypt_and_sign, verify_and_decrypt
from vault.exceptions import SignatureVerificationError, MissingSignatureError

def test_valid_signature_accepted():
    alice_priv, alice_pub = generate_ed25519_keypair()
    data = b"Examen de Criptografia D5 - UNAM"
    container = encrypt_and_sign(data, "alice", alice_priv, ["bob", "carol"])
    
    res_bob = verify_and_decrypt(container, alice_pub, "bob")
    res_carol = verify_and_decrypt(container, alice_pub, "carol")
    assert res_bob == data
    assert res_carol == data

def test_modified_ciphertext_rejected():
    alice_priv, alice_pub = generate_ed25519_keypair()
    container = encrypt_and_sign(b"Top Secret", "alice", alice_priv, ["bob"])
    
    # Tamper ciphertext
    container["ciphertext"] = "AAAA" + container["ciphertext"][4:]
    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt(container, alice_pub, "bob")

def test_modified_metadata_rejected():
    alice_priv, alice_pub = generate_ed25519_keypair()
    container = encrypt_and_sign(b"Top Secret", "alice", alice_priv, ["bob"])
    
    # Tamper timestamp
    container["metadata"]["timestamp"] += 100
    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt(container, alice_pub, "bob")

def test_wrong_public_key_rejected():
    alice_priv, _ = generate_ed25519_keypair()
    _, eve_pub = generate_ed25519_keypair()
    container = encrypt_and_sign(b"Top Secret", "alice", alice_priv, ["bob"])
    
    with pytest.raises(SignatureVerificationError):
        verify_and_decrypt(container, eve_pub, "bob")

def test_signature_removed_rejected():
    alice_priv, alice_pub = generate_ed25519_keypair()
    container = encrypt_and_sign(b"Top Secret", "alice", alice_priv, ["bob"])
    
    del container["signature"]
    with pytest.raises(MissingSignatureError):
        verify_and_decrypt(container, alice_pub, "bob")
