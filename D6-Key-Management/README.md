# D6 – Key Management

Private keys are never stored in plaintext. Each private key (the RSA key of D3 or the Ed25519 key of D5) is encrypted with **AES-256-GCM** under a key derived from the user's password with **Argon2id**, and stored in a keystore directory. The password is asked when the key is needed, and nothing is cached. The keystore can be backed up and restored.

- Key management design, lifecycle, threat model alignment and security discussion: [`docs/key_management_d6.md`](docs/key_management_d6.md)
- Module: [`vault/keystore/keystore.py`](vault/keystore/keystore.py)
- Tests: [`tests/keystore/test_keystore.py`](tests/keystore/test_keystore.py)

This folder is self-contained: it includes the D2, D3 and D5 modules it builds on.

```text
D6-Key-Management/
├── vault/
│   ├── symmetric.py        # D2 module (unchanged)
│   ├── exceptions.py       # D2/D3/D5 errors + KeystoreError, KeystoreAccessError
│   ├── hybrid/             # D3 module (unchanged)
│   ├── signatures/         # D5 module (unchanged)
│   └── keystore/
│       └── keystore.py     # create_keystore, unlock_private_key, backup_keystore, restore_keystore
├── tests/
│   ├── test_symmetric.py   # D2 suite
│   ├── hybrid/             # D3 suite
│   ├── signatures/         # D5 suite
│   └── keystore/           # D6: the five required tests and the integration checks
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
from vault.hybrid import generate_rsa_keypair
from vault.keystore import (
    backup_keystore,
    create_keystore,
    restore_keystore,
    unlock_private_key,
)

keys = generate_rsa_keypair()

# Encrypt the private key under a password and store it.
create_keystore(Path("alice-rsa"), keys.private_key, "a long passphrase", owner="alice")

# Unlock it only when needed (the password is asked with getpass if omitted).
private_key = unlock_private_key(Path("alice-rsa"), "a long passphrase", expected_key_type="RSA")

# A wrong password, or a modified keystore, is refused.
try:
    unlock_private_key(Path("alice-rsa"), "wrong password")
except KeystoreAccessError:
    print("denied")

# Back up the encrypted key and restore it (the password is checked on restore).
backup_keystore(Path("alice-rsa"), Path("alice-rsa-backup"))
restore_keystore(Path("alice-rsa-backup"), Path("alice-rsa-restored"), "a long passphrase")
```
