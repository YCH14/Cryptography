# D5 – Signatures & Authentication

An Ed25519 digital signature is added on top of the D3 hybrid container, so a recipient can verify **who created the file** and detect **any modification** of the ciphertext, the recipients or the metadata. The signature is verified **before** anything is decrypted; a forged or tampered container is rejected.

Flow: **Encrypt (D3) → Add metadata → Hash (SHA-256) → Sign (Ed25519) → Store**, and **Read → Hash → Verify → Decrypt**.

- Signature design and security decisions: [`docs/signature_design_d5.md`](docs/signature_design_d5.md)
- Modules: [`vault/signatures/keys.py`](vault/signatures/keys.py), [`vault/signatures/signing.py`](vault/signatures/signing.py), [`vault/signatures/replay.py`](vault/signatures/replay.py)
- Tests: [`tests/signatures/`](tests/signatures/) (`test_signatures.py`, `test_container_id.py`, `test_replay.py`, `test_rollback.py`)

This folder is self-contained: it includes the D2 and D3 modules it builds on.

```text
D5-Digital-Signatures/
├── vault/
│   ├── symmetric.py        # D2 module (unchanged)
│   ├── exceptions.py       # D2/D3 errors + signature, replay and rollback errors
│   ├── hybrid/             # D3 module (unchanged)
│   └── signatures/
│       ├── keys.py         # Ed25519 key pair and signer_id
│       ├── signing.py      # sign_container / verify_and_decrypt
│       └── replay.py       # ReplayGuard: replay and rollback detection
├── tests/
│   ├── test_symmetric.py   # D2 suite
│   ├── hybrid/             # D3 suite
│   └── signatures/         # D5: the five required tests + container id, replay and rollback
├── docs/signature_design_d5.md
├── requirements.txt
├── requirements-dev.txt
└── pytest.ini
```

## Container

The D3 container plus these fields:

```text
{ metadata, recipients, ciphertext, tag, signature, signer_id, container_id,
  [document_id, document_version], ... }
```

- `signer_id`: SHA-256 (hex) of the signer's raw Ed25519 public key.
- `container_id`: random 128-bit identifier (32 hex characters), new for every signing.
- `document_id` and `document_version` (optional, together): name and version number of the logical document, used to detect rollback.
- `signature`: Ed25519 signature (RFC 8032), Base64-encoded.
- Signed data: SHA-256 of the canonical JSON of the whole container except `signature`.

## Setup and tests

Requires Python 3.11 or newer. Run these commands from this folder (`D5-Digital-Signatures/`):

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
from vault.exceptions import SignatureVerificationError
from vault.hybrid import generate_x25519_keypair
from vault.hybrid.encryption import encrypt_bytes_hybrid
from vault.signatures import generate_ed25519_keypair, sign_container, verify_and_decrypt

bob = generate_x25519_keypair()
alice_private, alice_public = generate_ed25519_keypair()

container = encrypt_bytes_hybrid(b"secret", [("bob", bob.public_key)])
signed = sign_container(container, alice_private)

# Bob verifies the signature first, then decrypts.
plaintext = verify_and_decrypt(signed, alice_public, "bob", bob.private_key)

# Wrong signer key, modified container or missing signature -> rejected.
try:
    verify_and_decrypt(signed, generate_ed25519_keypair()[1], "bob", bob.private_key)
except SignatureVerificationError:
    print("rejected")
```

### Replay and rollback

A valid signature does not show that a container is new or the latest version. The recipient can pass a `ReplayGuard` (a small JSON file on its own side) to `verify_and_decrypt`; the signer can label each container with a `document_id` and an increasing `document_version`.

```python
from pathlib import Path

from vault.exceptions import ReplayDetectedError, RollbackDetectedError
from vault.signatures import ReplayGuard

guard = ReplayGuard(Path("bob-replay-record.json"))

# Alice labels the container with the document name and a version number.
signed_v1 = sign_container(container, alice_private, document_id="contract", document_version=1)

plaintext = verify_and_decrypt(signed_v1, alice_public, "bob", bob.private_key, replay_guard=guard)

try:  # the same container again
    verify_and_decrypt(signed_v1, alice_public, "bob", bob.private_key, replay_guard=guard)
except ReplayDetectedError:
    print("replay")

# After version 2 was accepted, an equal or older version is refused (RollbackDetectedError).
```

Without a `replay_guard`, replay and rollback are not detected. See the limits in [`docs/signature_design_d5.md`](docs/signature_design_d5.md).
