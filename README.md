# Cryptography
Calzontzi Hernández Yaretzi:  YCH14 (Yaretzi Calzontzi ) 
Carrada Alarcón Bruno Gabriel: https://github.com/BrunoUNAM2002
Álvarez Lugo Víctor Manuel: https://github.com/BeruR1se
Bailon Cruz Owen Isaac: OwenIBC

## D2 – Authenticated symmetric encryption

The `vault/` module encrypts files for a single owner with **AES-256-GCM** and *envelope encryption*: a fresh key
per file, random nonces from the operating system, and a header authenticated as AAD, so any alteration is
detected.

- Design and security rationale: [docs/design_d2.md](docs/design_d2.md)
- Module: [vault/symmetric.py](vault/symmetric.py)
- Tests: [tests/test_symmetric.py](tests/test_symmetric.py)

```text
vault/
  symmetric.py     # encrypt_file / decrypt_file (+ in-memory variants)
  exceptions.py    # DecryptionFailedError and validation errors
tests/
  test_symmetric.py
docs/
  design_d2.md     # design, security rationale, threat model, Git workflow
```

### Installation and tests

Requires Python 3.11 or higher.

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

### Usage

```python
from pathlib import Path
from vault import encrypt_file, decrypt_file, generate_owner_key, DecryptionFailedError

kek = generate_owner_key()  # 32 bytes from the OS CSPRNG; store it securely

encrypt_file(Path("contract.pdf"), kek, Path("contract.pdf.vault"),
             metadata={"case": "2026-17"})          # authenticated metadata, NOT encrypted

try:
    decrypt_file(Path("contract.pdf.vault"), kek, Path("contract_restored.pdf"))
except DecryptionFailedError:
    print("Invalid or tampered container, or wrong key")  # nothing is written to disk
```

Option: `include_filename=True` stores the original file name in the header (in clear, although authenticated). It is
disabled by default. Output paths are never overwritten (`FileExistsError`).

### Security in one line

Every byte of the container (`magic | len | header | wrap_nonce | wrapped_dek | payload_nonce | ciphertext | tag`)
is covered by an AEAD tag; any alteration produces a generic `DecryptionFailedError` with no output on disk. The
threat model and what remains **out of scope** (replay/rollback, metadata confidentiality, key management) are in
[docs/design_d2.md](docs/design_d2.md#33-threat-model).
