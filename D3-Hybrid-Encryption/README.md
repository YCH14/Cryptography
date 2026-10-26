# D3 – Multi-Recipient Hybrid Encryption

A file is encrypted **once** with AES-256-GCM; the file key (DEK) is then wrapped separately for each recipient with their RSA public key (RSA-OAEP-SHA256). The recipient list, key fingerprints, algorithms, `filename` and `metadata` are bound as AAD, so adding, removing or editing a recipient breaks decryption.

- Design and security rationale (Spanish): [`docs/hybrid_design_d3.md`](docs/hybrid_design_d3.md)
- Modules: [`vault/hybrid/keys.py`](vault/hybrid/keys.py), [`vault/hybrid/encryption.py`](vault/hybrid/encryption.py)
- Tests: [`tests/hybrid/`](tests/hybrid/)

This folder is self-contained: it includes the D2 modules (`vault/symmetric.py`, `vault/exceptions.py`) it builds on, plus `RecipientNotFoundError`.

```text
D3-Hybrid-Encryption/
├── vault/
│   ├── symmetric.py       # D2 module (unchanged)
│   ├── exceptions.py      # D2 errors + RecipientNotFoundError
│   └── hybrid/
│       ├── keys.py        # RSA key pairs, PEM import/export, SHA-256 SPKI fingerprints
│       └── encryption.py  # encrypt_file_hybrid / decrypt_file_hybrid (VLT2 container)
├── tests/
│   ├── test_symmetric.py  # D2 suite
│   └── hybrid/            # test_keys.py, test_key_identification.py, test_hybrid.py, test_metadata.py
├── docs/hybrid_design_d3.md
├── requirements.txt
├── requirements-dev.txt
└── pytest.ini
```

## Setup and tests

Requires Python 3.11 or newer. Run these commands from this folder (`D3-Hybrid-Encryption/`):

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
from vault.exceptions import DecryptionFailedError, RecipientNotFoundError
from vault.hybrid.encryption import (
    decrypt_document_hybrid,
    decrypt_file_hybrid,
    encrypt_file_hybrid,
)
from vault.hybrid.keys import (
    generate_rsa_keypair,
    get_public_key_fingerprint,
    save_private_key_pem,
    save_public_key_pem,
    load_private_key_file,
    load_public_key_file,
)

# 1. Cada persona genera su par de claves; la pública se comparte, la privada nunca.
alice_priv, alice_pub = generate_rsa_keypair(3072)
bob_priv, bob_pub = generate_rsa_keypair(3072)
save_private_key_pem(alice_priv, Path("alice_priv.pem"), password=b"una-frase-larga")
save_public_key_pem(alice_pub, Path("alice_pub.pem"))

# 2. Verifica la huella de cada clave pública por otro canal antes de cifrar.
print(get_public_key_fingerprint(load_public_key_file(Path("alice_pub.pem"))))

# 3. Se cifra UNA vez; la DEK se envuelve por separado para cada destinatario.
Path("contrato.pdf").write_bytes(b"%PDF- contenido confidencial")
encrypt_file_hybrid(
    Path("contrato.pdf"),
    recipients=[("alice", alice_pub), ("bob", bob_pub)],
    output_path=Path("contrato.vlt2"),
    metadata={"departamento": "legal"},     # opcional: autenticado, en claro
    # include_filename=False,               # no guardar el nombre original
)

# 4. Cada destinatario descifra de forma independiente con su clave privada.
alice_priv = load_private_key_file(Path("alice_priv.pem"), password=b"una-frase-larga")
decrypt_file_hybrid(Path("contrato.vlt2"), "alice", alice_priv, Path("contrato_alice.pdf"))
decrypt_file_hybrid(Path("contrato.vlt2"), "bob", bob_priv, Path("contrato_bob.pdf"))

# 5. Para leer también filename y metadata (sólo se devuelven si el tag verifica):
doc = decrypt_document_hybrid(Path("contrato.vlt2").read_bytes(), "alice", alice_priv)
print(doc.filename, doc.metadata)           # contrato.pdf {'departamento': 'legal'}

# 6. Quien no es destinatario, o usa la clave equivocada, no obtiene nada.
carol_priv, _ = generate_rsa_keypair(3072)
try:
    decrypt_file_hybrid(Path("contrato.vlt2"), "carol", carol_priv, Path("x.pdf"))
except RecipientNotFoundError:
    print("Carol no figura en la lista de destinatarios")
except DecryptionFailedError:
    print("Contenedor manipulado o clave incorrecta")   # no se escribe nada en disco
```

**Cómo se elige tu entrada.** El segundo argumento puede ser tu `id` lógico (`"alice"`), la huella SHA-256 de tu clave
pública (64 hex en minúscula) o `None` para usar la huella de tu clave privada. La forma de huella está reservada, de modo
que un `id` nunca puede confundirse con una huella; no hay *fallback* entre ambos. Detalle en
[docs/hybrid_design_d3.md §4.1](docs/hybrid_design_d3.md).

**Qué no hace D3.** No autentica a quién cifró (no hay firma del remitente), no revoca accesos ya concedidos y no oculta
la lista de destinatarios ni los metadatos (van en claro, autenticados). Ver §4.5 del documento de diseño.
