import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def generate_ed25519_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()

def get_signer_fingerprint(public_key: ed25519.Ed25519PublicKey) -> str:
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw_bytes).hexdigest()

def export_public_key(public_key: ed25519.Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
