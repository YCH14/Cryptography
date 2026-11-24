# D6 – Key Management

Private keys are never stored in plaintext. Each private key (the X25519 key of D3 or the Ed25519 key of D5) is encrypted with **AES-256-GCM** under a key derived from the user's password with **Argon2id**, and stored in a keystore directory. The password is asked when the key is needed, and nothing is cached. The keystore can be backed up and restored. A **keyring** keeps every version of a key, so keys can be rotated and revoked, and old files stay readable. RSA keys are not supported: they are refused when a keystore is created, and a keystore from an earlier version that holds an RSA key does not open (create a new X25519 keystore instead).

- Key management design, lifecycle, threat model alignment and security discussion: [`docs/key_management_d6.md`](docs/key_management_d6.md)
- Modules: [`vault/keystore/keystore.py`](vault/keystore/keystore.py) (one key), [`vault/keystore/keyring.py`](vault/keystore/keyring.py) (rotation, revocation, historical access), [`vault/keystore/trust.py`](vault/keystore/trust.py) (trusted signing keys)
- Tests: [`tests/keystore/`](tests/keystore/) (`test_keystore.py`, `test_keyring.py`, `test_revocation.py`, `test_trust.py`, `test_trust_replay.py`, `test_signer_key_import.py`); key files: `tests/hybrid/test_key_files.py` and `tests/signatures/test_signer_key_files.py`

This folder is self-contained: it includes the D2, D3 and D5 modules it builds on.

```text
D6-Key-Management/
├── vault/
│   ├── symmetric.py        # D2 module (unchanged)
│   ├── exceptions.py       # D2/D3/D5 errors + keystore errors, UntrustedSignerError
│   ├── hybrid/             # D3 module (ECIES with X25519)
│   ├── signatures/         # D5 module (Ed25519, ReplayGuard: replay and rollback)
│   ├── cli.py              # command-line interface (python -m vault)
│   ├── __main__.py
│   └── keystore/
│       ├── keystore.py     # create_keystore, unlock_private_key, backup_keystore, restore_keystore
│       ├── keyring.py      # Keyring: rotate, revoke, revocation_notice, decrypt old files
│       └── trust.py        # TrustedSigners: add, replace, revoke, verify_with_trusted_signers
├── tests/
│   ├── test_symmetric.py   # D2 suite
│   ├── hybrid/             # D3 suite
│   ├── signatures/         # D5 suite (signatures, container_id, replay, rollback)
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

### Key files

Public keys (X25519 and Ed25519) and exported private keys are PEM files, and nothing else is accepted: a regular `.pem` file of at most 16 KiB with exactly one PEM block of the expected type. A private key is never written without a password, and an existing file is never overwritten. The details are in [`docs/key_management_d6.md`](docs/key_management_d6.md).

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

## Command-line interface

Users do not need to write Python: `python -m vault` opens an interactive menu (in Spanish) to create an identity, encrypt and decrypt files, share public keys, manage contacts and trusted signers, rotate or revoke keys and back everything up. The same actions are available as subcommands for scripts. It uses only the standard library on top of the modules above.

```bash
# Linux / macOS: creates .venv on the first run
./vault.sh
# Windows: double-click vault.bat, or run it from a terminal
vault.bat

# or, with the environment already set up
python -m vault                       # interactive menu
python -m vault --help                # every subcommand
```

Typical use between two people (`alice` and `bob`), each with their own folder (`~/.vault` by default, `--home DIR` or `VAULT_HOME` to change it):

```bash
python -m vault init --owner alice                    # keys for encrypting and for signing
python -m vault export encrypt                        # writes alice-encrypt.pub.pem and prints its fingerprint
python -m vault contacts add bob bob-encrypt.pub.pem --fingerprint "<fingerprint Bob gave you>"
python -m vault encrypt report.pdf --to bob           # report.pdf.vault, signed by default, readable by Bob and by Alice
python -m vault trust add alice alice-sign.pub.pem --fingerprint "<fingerprint Alice gave you>"   # Bob
python -m vault inspect report.pdf.vault              # public fields only: recipients, signer; no password, nothing decrypted
python -m vault decrypt report.pdf.vault              # Bob: checks the signature, then decrypts
python -m vault rotate encrypt                        # new key; old files stay readable
python -m vault revoke sign --reason "laptop stolen" --compromised   # also writes the revocation notice
python -m vault backup ../vault-backup
```

Notes:

- Passwords are always asked with `getpass`, never as arguments, and one password protects both keys at creation (each key can get another one when rotated).
- Fingerprints must be compared through a second channel. `contacts add` and `trust add` both require `--fingerprint` and refuse the key if it does not match (D6).
- `encrypt` signs by default (`--no-sign` to skip it). `decrypt` refuses a file that is not signed, or whose signature was removed, unless you pass `--allow-unsigned`: otherwise anyone could strip the signature and the file would be accepted. Your own signing key is trusted automatically, so you can open what you encrypted. Because the signature is checked with the replay record, decrypting the same file twice needs `--no-replay-check`.
- `inspect` verifies nothing: it only shows what is written in the file (recipients, signer, document version), so do not trust it as proof of who made the file; `decrypt` does the checks.
- Files the tool writes (keys, `.vault`, decrypted output) are created readable only by their owner and never through a symbolic link.
- `decrypt` never overwrites an existing file (use `--force`), opens unsigned files with a warning, and verifies signed files only against trusted signers. A signed container that was already accepted is refused as a replay (`--no-replay-check` to override).
- Decryption failures keep the generic message of D3, so the CLI does not reveal whether the key or the file was wrong.
- Tests: [`tests/cli/`](tests/cli/).

## Rotation, revocation and old files

```python
from vault.keystore import Keyring, TrustedSigners, verify_with_trusted_signers
from vault.signatures import ReplayGuard

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

# With a ReplayGuard (D5) the same container, or an older version of a document, is refused.
guard = ReplayGuard(Path("bob-replay.json"))
plaintext = verify_with_trusted_signers(signed, trusted, "bob", bob_private_key, guard)
# A second call with the same `signed` raises ReplayDetectedError.
```

The design, the order of the steps after a compromise and the limits are in [`docs/key_management_d6.md`](docs/key_management_d6.md).
