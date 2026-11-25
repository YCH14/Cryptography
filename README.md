# Cryptography – Secure File Exchange Platform (Secure Digital Document Vault)

A command-line vault that encrypts and signs files so they can be stored and shared on untrusted infrastructure (cloud or shared storage) without exposing or silently altering their contents. Course project, UNAM Computer Engineering (Cryptography).

## What it does

- **Confidentiality:** each file is encrypted with its own random AES-256-GCM key; that key is wrapped separately for every recipient (ECIES: ephemeral X25519, HKDF-SHA256, AES-256-GCM).
- **Integrity and authenticity:** the whole container (ciphertext, recipient list, metadata) is authenticated and signed with Ed25519 and verified before anything is decrypted.
- **Key protection:** private keys are stored encrypted with a password-derived key (Argon2id, AES-256-GCM), with rotation, revocation, backup and restore.
- **Replay and rollback protection:** a recipient refuses a container it already accepted and an older version of a document.

## Architecture

```text
 password ──Argon2id──► key ──AES-GCM──► private keys (keystore)         D6
                                              │
 file ──AES-256-GCM(fresh DEK)──► ciphertext  │                          D2
 DEK ──ECIES per recipient──► recipient list  │                          D3
 container ──Ed25519 (signer key)──► signature ◄──────────────────────────┘   D5
```

| ID | Deliverable | Folder |
|----|-------------|--------|
| D1 | Architecture and threat model: assets, adversaries, threats, requirements | [`D1-Architecture-Threat-Model/`](D1-Architecture-Threat-Model/) |
| D2 | Symmetric encryption: AES-256-GCM, a fresh key per file, authenticated metadata | [`D2-Symmetric-Encryption/`](D2-Symmetric-Encryption/) |
| D3 | Multi-recipient hybrid encryption: ECIES key wrapping, recipient list bound as AAD | [`D3-Hybrid-Encryption/`](D3-Hybrid-Encryption/) |
| D5 | Signatures: Ed25519 over the encrypted container, replay and rollback guard | [`D5-Digital-Signatures/`](D5-Digital-Signatures/) |
| D6 | Key management and the `vault` command line / menu: keystore, rotation, revocation, backup | [`D6-Key-Management/`](D6-Key-Management/) |

Each module builds on the previous one (D6 uses D5, D5 uses D3, D3 uses D2). The complete application is in `D6-Key-Management`.

## Installation

Requires Python 3.11 or newer.

```bash
git clone https://github.com/YCH14/Cryptography.git
cd Cryptography/D6-Key-Management
python -m venv .venv
source .venv/bin/activate            # Windows (Git Bash): source .venv/Scripts/activate
python -m pip install -r requirements.txt
```

## Usage

```bash
cd D6-Key-Management
python -m vault                                   # interactive menu (Spanish)
python -m vault --home alice init --owner alice   # or use subcommands
python -m vault --home alice encrypt report.pdf --to bob
python -m vault --home bob decrypt report.pdf.vault --out report.pdf
```

Full command reference: [`D6-Key-Management/README.md`](D6-Key-Management/README.md). A scripted three-user demo and a two-terminal walkthrough are in [`examples/`](examples/): `python examples/demo.py`.

## Tests

```bash
cd D6-Key-Management
python -m pip install -r requirements-dev.txt
python -m pytest -q          # 550 tests on Linux (3 are skipped on Windows: POSIX permissions and symlinks)
```

GitHub Actions runs the tests of every module on Python 3.11 and 3.12 (8 jobs) for each push and Pull Request.

## Security documentation

| Document | Content |
|----------|---------|
| [`docs/README.md`](docs/README.md) | Index |
| [`docs/threat-model.md`](docs/threat-model.md) | Assets, adversaries, threats and how each is addressed |
| [`docs/cryptographic-design.md`](docs/cryptographic-design.md) | Algorithms, container format, parameters |
| [`docs/canonicalization.md`](docs/canonicalization.md) | Canonical JSON used for AAD and signatures |
| [`docs/key-management.md`](docs/key-management.md) | Keystore, lifecycle, rotation, revocation, backup |
| [`docs/security-requirements.md`](docs/security-requirements.md) | Each requirement mapped to implementation and tests |
| [`docs/security-audit-findings.md`](docs/security-audit-findings.md) | Issues found during development, fixes and residual risks |

## Security assumptions

- The storage and the network are untrusted; the endpoint of each user is trusted while the tool runs.
- Public-key fingerprints are compared through a second channel. A key is not accepted without its fingerprint.
- The user chooses a strong password (the tool requires at least 8 characters); there is no password recovery.
- The operating system random generator is secure and the system clock is roughly correct.

## Known limitations

- A compromised computer (malware, keylogger) defeats every protection here.
- `--force` overwrites a file non-atomically; the replay record is a local file, so it protects only that user's copy.
- Windows does not enforce POSIX file modes, so owner-only permissions are best-effort there.
- Availability is out of scope: whoever controls the storage can delete files.

The complete list is in [`docs/security-audit-findings.md`](docs/security-audit-findings.md).

## Team and workflow

Álvarez Lugo Víctor Manuel · Bailón Cruz Owen Isaac · Calzontzi Hernández Yaretzi · Carrada Alarcon Bruno Gabriel

- Nothing is pushed directly to `main`. Work happens on a branch and is merged through a Pull Request.
- Every Pull Request needs at least one review from someone other than its author, and the CI tests must pass.
- Merge with **Create a merge commit** (not *Squash and merge*) so each member's commits are preserved.
- Pull Requests state which parts, if any, were generated with an AI tool.

## Where to find what

The repository is organized by course deliverable instead of a single `src/` folder, because each module builds on the previous one and has its own tests.

| Usual folder | Here |
|--------------|------|
| `src/` (source code) | `D6-Key-Management/vault/` is the complete application; it includes the code of D2, D3 and D5 (`vault/symmetric.py`, `vault/hybrid/`, `vault/signatures/`, `vault/keystore/`). Each of D2, D3 and D5 also keeps its own copy of the module it delivered |
| `tests/` | `<module>/tests/` in each module; `D6-Key-Management/tests/` covers the whole application |
| `docs/` | [`docs/`](docs/) (security documentation) and `D1-Architecture-Threat-Model/` (design and diagram) |
| `examples/` | [`examples/`](examples/) |
| `keys/` | Not in the repository on purpose: keys are created on the user's computer (`python -m vault init`) and `*.key` and `*.vault` files are in `.gitignore` |
| Dependencies | `D6-Key-Management/requirements.txt` and `requirements-dev.txt` |

## Repository layout

```text
.
├── D1-Architecture-Threat-Model/   # design document and architecture diagram
├── D2-Symmetric-Encryption/        # AES-256-GCM module
├── D3-Hybrid-Encryption/           # multi-recipient hybrid module
├── D5-Digital-Signatures/          # Ed25519 signatures, replay guard
├── D6-Key-Management/              # keystore, CLI and menu (the application)
├── docs/                           # security documentation
├── examples/                       # scripted demo and walkthrough
├── .github/                        # CI workflow and Pull Request template
└── README.md
```
