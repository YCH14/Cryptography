# D2 – Secure Symmetric Encryption Module

Authenticated file encryption for a single owner using **AES-256-GCM** and envelope encryption: a fresh random key per file, nonces from the operating system CSPRNG, and a header authenticated as AAD, so any modification is detected.

- Design and security rationale: [`docs/`](docs/)
- Module: [`vault/symmetric.py`](vault/symmetric.py)
- Tests: [`tests/test_symmetric.py`](tests/test_symmetric.py)

```text
D2-Symmetric-Encryption/
├── vault/
│   ├── symmetric.py     # encrypt_file / decrypt_file (+ in-memory variants)
│   └── exceptions.py    # DecryptionFailedError and validation errors
├── tests/
│   └── test_symmetric.py
├── docs/                # design, security rationale and threat model
├── requirements.txt
├── requirements-dev.txt
└── pytest.ini
```

## Setup and tests

Requires Python 3.11 or newer. Run these commands from this folder (`D2-Symmetric-Encryption/`):

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
from vault import encrypt_file, decrypt_file, generate_owner_key, DecryptionFailedError

kek = generate_owner_key()  # 32 bytes from the OS CSPRNG; store it safely

encrypt_file(Path("contract.pdf"), kek, Path("contract.pdf.vault"),
             metadata={"case": "2026-17"})          # authenticated metadata, NOT encrypted

try:
    decrypt_file(Path("contract.pdf.vault"), kek, Path("contract_restored.pdf"))
except DecryptionFailedError:
    print("Invalid or tampered container, or wrong key")  # nothing is written to disk
```

Option: `include_filename=True` stores the original file name in the header (in clear, although authenticated). It is off by default. Output paths are never overwritten (`FileExistsError`).

## Security in one line

Every byte of the container (`magic | len | header | wrap_nonce | wrapped_dek | payload_nonce | ciphertext | tag`) is covered by an AEAD tag; any alteration raises a generic `DecryptionFailedError` and writes nothing to disk. The threat model and what is out of scope (replay/rollback, metadata confidentiality, key management) are described in [`docs/`](docs/).
