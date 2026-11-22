"""Digital signatures for vault containers (D5)."""

from vault.signatures.keys import (
    export_signer_public_key_pem,
    generate_ed25519_keypair,
    get_signer_id,
    load_signer_public_key_file,
    load_signer_public_key_pem,
    save_signer_public_key_file,
)
from vault.signatures.replay import ReplayGuard
from vault.signatures.signing import sign_container, verify_and_decrypt

__all__ = [
    "ReplayGuard",
    "export_signer_public_key_pem",
    "generate_ed25519_keypair",
    "get_signer_id",
    "load_signer_public_key_file",
    "load_signer_public_key_pem",
    "save_signer_public_key_file",
    "sign_container",
    "verify_and_decrypt",
]
