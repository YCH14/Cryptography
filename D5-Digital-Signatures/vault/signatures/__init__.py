"""Digital signatures for vault containers (D5)."""

from vault.signatures.keys import generate_ed25519_keypair, get_signer_id
from vault.signatures.replay import ReplayGuard
from vault.signatures.signing import sign_container, verify_and_decrypt

__all__ = [
    "ReplayGuard",
    "generate_ed25519_keypair",
    "get_signer_id",
    "sign_container",
    "verify_and_decrypt",
]
