# D6 – Key Management

Private keys are never stored in plaintext. Each private key (the X25519 key of D3 or the Ed25519 key of D5) is encrypted with **AES-256-GCM** under a key derived from the user's password with **Argon2id**, and stored in a keystore directory. The password is asked when the key is needed, and nothing is cached. The keystore can be backed up and restored. A **keyring** keeps every version of a key, so keys can be rotated and revoked, and old files stay readable. RSA keys are not supported: they are refused when a keystore is created, and a keystore from an earlier version that holds an RSA key does not open (create a new X25519 keystore instead).

- Key management design, lifecycle, threat model alignment and security discussion: [`docs/key_management_d6.md`](docs/key_management_d6.md)
- Modules: [`vault/keystore/keystore.py`](vault/keystore/keystore.py) (one key), [`vault/keystore/keyring.py`](vault/keystore/keyring.py) (rotation, revocation, historical access), [`vault/keystore/trust.py`](vault/keystore/trust.py) (trusted signing keys)
- Tests: [`tests/keystore/`](tests/keystore/) (`test_keystore.py`, `test_keyring.py`, `test_revocation.py`, `test_trust.py`)

This folder is self-contained: it includes the D2, D3 and D5 modules it builds on.

```text
D6-Key-Management/
├── vault/
│   ├── symmetric.py        # D2 module (unchanged)
│   ├── exceptions.py       # D2/D3/D5 errors + keystore errors, UntrustedSignerError
│   ├── hybrid/             # D3 module (ECIES with X25519)
│   ├── signatures/         # D5 module (Ed25519)
│   └── keystore/
│       ├── keystore.py     # create_keystore, unlock_private_key, backup_keystore, restore_keystore
│       ├── keyring.py      # Keyring: rotate, revoke, revocation_notice, decrypt old files
│       └── trust.py        # TrustedSigners: add, replace, revoke, verify_with_trusted_signers
├── tests/
│   ├── test_symmetric.py   # D2 suite
│   ├── hybrid/             # D3 suite
│   ├── signatures/         # D5 suite
│   └── keystore/           # D6: the five required tests, keyring, revocation and trusted signers
├── docs/key_management_d6.md
├── requirements.txt
├── requirements-dev.txt
└── pytest.ini
```

## Keystore format

```text
keystore/
 ├── encrypted_private_key   nonce (12 bytes) + ciphertext + tag (16 bytes)
 ├── salt                    16 random bytes
 ├── kdf_parameters          JSON: argon2id, iterations 3, lanes 4, memory 65536 KiB
 └── metadata                JSON: version, owner, key_type, key_id, created
```

`metadata`, `kdf_parameters` and `salt` are bound to the encryption as AES-GCM associated data, so changing any file makes the keystore fail to open.

## Setup and tests

Requires Python 3.11 or newer and `cryptography` 44 or newer (Argon2id). Run these commands from this folder (`D6-Key-Management/`):

```bash
# Linux / macOS
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -v

# Windows (Git Bash)
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt
.venv/Scripts/python -m pytest -v
```

## Usage

```python
from pathlib import Path

from vault.exceptions import KeystoreAccessError
from vault.hybrid import generate_x25519_keypair
from vault.keystore import (
    backup_keystore,
    create_keystore,
    restore_keystore,
    unlock_private_key,
)

keys = generate_x25519_keypair()

# Encrypt the private key under a password and store it.
create_keystore(Path("alice-x25519"), keys.private_key, "a long passphrase", owner="alice")

# Unlock it only when needed (the password is asked with getpass if omitted).
private_key = unlock_private_key(Path("alice-x25519"), "a long passphrase", expected_key_type="X25519")

# A wrong password, or a modified keystore, is refused.
try:
    unlock_private_key(Path("alice-x25519"), "wrong password")
except KeystoreAccessError:
    print("denied")

# Back up the encrypted key and restore it (the password is checked on restore).
backup_keystore(Path("alice-x25519"), Path("alice-x25519-backup"))
restore_keystore(Path("alice-x25519-backup"), Path("alice-x25519-restored"), "a long passphrase")
```

## Rotation, revocation and old files

```python
from vault.keystore import Keyring, TrustedSigners, verify_with_trusted_signers

# A keyring holds every version of one key of one type ("X25519" or "Ed25519").
keyring = Keyring.create(Path("alice-keyring"), "alice", "X25519")
keyring.rotate(keys.private_key, "first passphrase")        # first key: active

# Rotation: the new key becomes active, the old one is retired but kept.
new_keys = generate_x25519_keypair()
keyring.rotate(new_keys.private_key, "second passphrase")

# Files made before the rotation still open: the keyring finds the key by the container's recipients.
plaintext = keyring.decrypt(old_container, "first passphrase")

# A key that may be known to someone else is revoked and never used for new work.
old_id = keyring.entries()[0].key_id
keyring.revoke(old_id, "laptop stolen", compromised=True)
notice = keyring.revocation_notice(old_id)                  # send it through a trusted channel

# Recover a file explicitly, then share it again with the new key (D3).
plaintext = keyring.decrypt(old_container, "first passphrase", allow_revoked=True)

# The recipient of Alice's signed files keeps the signing keys it trusts.
trusted = TrustedSigners(Path("trusted_signers.json"))
trusted.add("alice", alice_public, expected_fingerprint=fingerprint_from_alice)  # confirmed out of band
trusted.import_revocation(notice_for_alice_signing_key)     # refuses her revoked key from now on
plaintext = verify_with_trusted_signers(signed, trusted, "bob", bob_private_key)
```

The design, the order of the steps after a compromise and the limits are in [`docs/key_management_d6.md`](docs/key_management_d6.md).
