"""Secure Digital Document Vault."""

from vault.exceptions import (
    DecryptionFailedError,
    InvalidKeyError,
    InvalidMetadataError,
    PlaintextTooLargeError,
    RecipientNotFoundError,
    VaultError,
)
from vault.hybrid import (
    decrypt_bytes_hybrid,
    decrypt_file_hybrid,
    encrypt_bytes_hybrid,
    encrypt_file_hybrid,
    export_private_key_pem,
    export_public_key_pem,
    generate_rsa_keypair,
    get_public_key_fingerprint,
    load_private_key_pem,
    load_public_key_pem,
)
from vault.symmetric import (
    DecryptedDocument,
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
    generate_owner_key,
)

__all__ = [
    "DecryptedDocument",
    "DecryptionFailedError",
    "InvalidKeyError",
    "InvalidMetadataError",
    "PlaintextTooLargeError",
    "RecipientNotFoundError",
    "VaultError",
    "decrypt_bytes",
    "decrypt_bytes_hybrid",
    "decrypt_file",
    "decrypt_file_hybrid",
    "encrypt_bytes",
    "encrypt_bytes_hybrid",
    "encrypt_file",
    "encrypt_file_hybrid",
    "export_private_key_pem",
    "export_public_key_pem",
    "generate_owner_key",
    "generate_rsa_keypair",
    "get_public_key_fingerprint",
    "load_private_key_pem",
    "load_public_key_pem",
]

