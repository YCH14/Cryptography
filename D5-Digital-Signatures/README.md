# D5 – Digital Signatures and Origin Authentication

In Deliverable 5 (`VLT3`), the vault implements the **Encrypt-then-Sign** (`Encrypt -> Add Metadata -> Sign -> Store`) and **Verify-then-Decrypt** (`Verify Signature -> Unwrap DEK -> Decrypt Payload`) workflows:

1. A file is encrypted **once** with **AES-256-GCM** under a fresh 256-bit DEK (`os.urandom(32)`), and the DEK is wrapped per recipient with **RSA-OAEP-SHA256**.
2. All container metadata (`magic`, `version`, `algorithm`, `key_wrap_algorithm`, `signature_algorithm`, `timestamp`, `signer_id`, `signer_fingerprint`, `filename`, `metadata`) and the complete `recipients` list are bound into the AES-256-GCM AAD.
3. The canonical JSON representation of the entire unsigned container (metadata + `recipients` + `nonce` + `ciphertext` + `tag`) is hashed with **SHA-256** (`SIGNATURE_DOMAIN_SEPARATOR = b"VLT3-ED25519-SHA256-v1:"`) and signed with the sender's **Ed25519** private key.
4. On open, the recipient (or an external gateway) verifies the 64-byte **Ed25519** signature **first** before touching any RSA private key or attempting AES-256-GCM decryption.

- Design and security rationale (Spanish): [`docs/signature_design_d5.md`](docs/signature_design_d5.md)
- Architecture overview: [`docs/architecture.md`](docs/architecture.md)
- Previous hybrid design (D3): [`docs/hybrid_design_d3.md`](docs/hybrid_design_d3.md)
- Modules: [`vault/signatures/keys.py`](vault/signatures/keys.py), [`vault/signatures/signing.py`](vault/signatures/signing.py), [`vault/hybrid/`](vault/hybrid/), [`vault/symmetric.py`](vault/symmetric.py)
- Tests: [`tests/signatures/`](tests/signatures/), [`tests/hybrid/`](tests/hybrid/), [`tests/test_symmetric.py`](tests/test_symmetric.py)

```text
D5-Digital-Signatures/
├── vault/
│   ├── symmetric.py              # D2 symmetric AEAD module
│   ├── exceptions.py             # D2/D3 errors + SignatureVerificationError, MissingSignatureError
│   ├── hybrid/                   # D3 RSA-OAEP-SHA256 + AES-256-GCM module (VLT2)
│   │   ├── keys.py
│   │   └── encryption.py
│   └── signatures/               # D5 Ed25519 + SHA-256 Encrypt-then-Sign module (VLT3)
│       ├── keys.py               # Ed25519 key pairs, PEM/raw import/export, SHA-256 SPKI fingerprints
│       └── signing.py            # encrypt_and_sign_file / verify_and_decrypt_file / verify_container_signature
├── tests/
│   ├── test_symmetric.py         # D2 test suite
│   ├── hybrid/                   # D3 test suite
│   └── signatures/               # D5 test suite (test_ed25519_keys.py, test_signatures.py)
├── docs/
│   ├── architecture-diagram.jpeg
│   ├── architecture.md
│   ├── hybrid_design_d3.md
│   └── signature_design_d5.md
├── requirements.txt
├── requirements-dev.txt
└── pytest.ini
```

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
from pathlib import Path
from vault.exceptions import (
    DecryptionFailedError,
    MissingSignatureError,
    RecipientNotFoundError,
    SignatureVerificationError,
)
from vault.hybrid.keys import generate_rsa_keypair
from vault.signatures import (
    encrypt_and_sign_file,
    generate_ed25519_keypair,
    get_signer_public_key_fingerprint,
    verify_and_decrypt_document,
    verify_and_decrypt_file,
    verify_container_signature,
)

# 1. Sender generates an Ed25519 signing key pair; recipients generate RSA key pairs.
sender_priv, sender_pub = generate_ed25519_keypair()
alice_priv, alice_pub = generate_rsa_keypair(3072)
bob_priv, bob_pub = generate_rsa_keypair(3072)

print("Sender Ed25519 fingerprint:", get_signer_public_key_fingerprint(sender_pub))

# 2. Encrypt -> Add Metadata -> Sign -> Store (single AES-256-GCM pass + Ed25519 signature).
Path("contrato.pdf").write_bytes(b"%PDF- contenido autenticado y confidencial")
encrypt_and_sign_file(
    Path("contrato.pdf"),
    recipients=[("alice", alice_pub), ("bob", bob_pub)],
    output_path=Path("contrato.vlt3"),
    signer_id="alice-sender",
    signer_private_key=sender_priv,
    metadata={"departamento": "legal"},
)

# 3. Pre-decryption origin verification (no RSA private key required).
verify_container_signature(
    Path("contrato.vlt3").read_bytes(),
    sender_pub,
    expected_signer_id="alice-sender",
)

# 4. Verify -> Decrypt: Ed25519 signature is verified FIRST before RSA-OAEP or AES-GCM runs.
verify_and_decrypt_file(
    Path("contrato.vlt3"),
    "alice",
    alice_priv,
    sender_pub,
    Path("contrato_alice.pdf"),
    expected_signer_id="alice-sender",
)

doc = verify_and_decrypt_document(
    Path("contrato.vlt3").read_bytes(),
    "bob",
    bob_priv,
    sender_pub,
)
print(doc.signer_id, doc.filename, doc.metadata)

# 5. Any tampering with ciphertext, metadata, recipients, or signer key is rejected before decrypting.
_, wrong_signer_pub = generate_ed25519_keypair()
try:
    verify_and_decrypt_file(
        Path("contrato.vlt3"),
        "alice",
        alice_priv,
        wrong_signer_pub,
        Path("x.pdf"),
    )
except MissingSignatureError:
    print("Falta la firma o el identificador del remitente")
except SignatureVerificationError:
    print("Firma inválida o contenedor alterado (rechazado antes de descifrar)")
except RecipientNotFoundError:
    print("Destinatario no autorizado")
except DecryptionFailedError:
    print("Fallo de descifrado")
```

