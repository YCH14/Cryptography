"""Digital signatures for vault containers (D5)."""

from vault.signatures.keys import generate_ed25519_keypair, get_signer_id
from vault.signatures.signing import sign_container, verify_and_decrypt

__all__ = [
    "generate_ed25519_keypair",
    "get_signer_id",
    "sign_container",
    "verify_and_decrypt",
]
