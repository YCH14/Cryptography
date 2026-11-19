"""Password-protected key store (D6)."""

from vault.keystore.keyring import (
    STATUS_ACTIVE,
    STATUS_RETIRED,
    STATUS_REVOKED,
    KeyEntry,
    Keyring,
)
from vault.keystore.keystore import (
    KEYSTORE_FILES,
    backup_keystore,
    create_keystore,
    restore_keystore,
    unlock_private_key,
)
from vault.keystore.trust import TrustedSigners, verify_with_trusted_signers

__all__ = [
    "KEYSTORE_FILES",
    "STATUS_ACTIVE",
    "STATUS_RETIRED",
    "STATUS_REVOKED",
    "KeyEntry",
    "Keyring",
    "TrustedSigners",
    "backup_keystore",
    "create_keystore",
    "restore_keystore",
    "unlock_private_key",
    "verify_with_trusted_signers",
]
