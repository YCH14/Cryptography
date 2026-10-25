# Cryptography – Secure Digital Document Vault

Course project: a secure digital document vault that encrypts and signs files so they can be stored and shared on untrusted infrastructure (cloud or shared storage) without exposing or silently altering their contents.

## Deliverables

| ID | Deliverable | Folder |
|----|-------------|--------|
| D1 | Architecture & Threat Model: system design, security requirements, threat model and attack surface | [`D1-Architecture-Threat-Model/`](D1-Architecture-Threat-Model/) |
| D2 | Secure Symmetric Encryption Module: AES-256-GCM, a fresh key per file, authenticated metadata and tamper detection | [`D2-Symmetric-Encryption/`](D2-Symmetric-Encryption/) |
| D3 | Multi-Recipient Hybrid Encryption: AES-256-GCM for the file, RSA-OAEP-SHA256 key wrapping per recipient, recipient list bound as AAD | [`D3-Hybrid-Encryption/`](D3-Hybrid-Encryption/) |

Each deliverable lives in its own folder with its own README and documentation.

## Repository layout

```text
.
├── D1-Architecture-Threat-Model/   # D1: design document and architecture diagram
├── D2-Symmetric-Encryption/        # D2: encryption module, tests and design document
├── D3-Hybrid-Encryption/           # D3: hybrid multi-recipient module, tests and design document
├── .github/                        # CI workflow and Pull Request template (must stay at the repo root)
├── .gitignore
└── README.md
```

## Team workflow

- Nothing is pushed directly to `main`. Work happens on a branch and is merged through a Pull Request.
- Every Pull Request needs at least one review from someone other than its author, and the CI tests must pass.
- Merge with **Create a merge commit** (not *Squash and merge*) so each member's commits are preserved.