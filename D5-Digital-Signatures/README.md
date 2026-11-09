# D5 – Signatures & Authentication

An Ed25519 digital signature is added on top of the D3 hybrid container, so a recipient can verify **who created the file** and detect **any modification** of the ciphertext, the recipients or the metadata. The signature is verified **before** anything is decrypted; a forged or tampered container is rejected.

Flow: **Encrypt (D3) → Add metadata → Hash (SHA-256) → Sign (Ed25519) → Store**, and **Read → Hash → Verify → Decrypt**.

- Signature design and security decisions: [`docs/signature_design_d5.md`](docs/signature_design_d5.md)
- Modules: [`vault/signatures/keys.py`](vault/signatures/keys.py), [`vault/signatures/signing.py`](vault/signatures/signing.py)
- Tests: [`tests/signatures/test_signatures.py`](tests/signatures/test_signatures.py)

This folder is self-contained: it includes the D2 and D3 modules it builds on.

```text
D5-Digital-Signatures/
├── vault/
│   ├── symmetric.py        # D2 module (unchanged)
│   ├── exceptions.py       # D2/D3 errors + SignatureVerificationError, MissingSignatureError
│   ├── hybrid/             # D3 module (unchanged)
│   └── signatures/
│       ├── keys.py         # Ed25519 key pair and signer_id
│       └── signing.py      # sign_container / verify_and_decrypt
├── tests/
│   ├── test_symmetric.py   # D2 suite
│   ├── hybrid/             # D3 suite
│   └── signatures/         # D5: the five required tests
├── docs/signature_design_d5.md
├── requirements.txt
├── requirements-dev.txt
└── pytest.ini
```

## Container

The D3 container plus two fields:

```text
{ metadata, recipients, ciphertext, tag, signature, signer_id, ... }
```

- `signer_id`: SHA-256 (hex) of the signer's raw Ed25519 public key.
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
from vault.hybrid import generate_rsa_keypair
from vault.hybrid.encryption import encrypt_bytes_hybrid
from vault.signatures import generate_ed25519_keypair, sign_container, verify_and_decrypt

bob = generate_rsa_keypair()
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
