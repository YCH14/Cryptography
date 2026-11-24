# Threat model summary

Full document: [`D1-Architecture-Threat-Model/secure-digital-document-vault-design.md`](../D1-Architecture-Threat-Model/secure-digital-document-vault-design.md) (sections 3 to 7). This page summarizes it.

## What the system does

Users store and share documents on infrastructure they do not control (a cloud drive, a shared folder). A file is encrypted once, the key is wrapped for each recipient, and the sender signs the result. Storage and network only ever see the signed container.

## Assets

| ID | Asset | Needs |
|---|---|---|
| A1 | File contents | Confidentiality and integrity |
| A2 | Private keys | Confidentiality; they never leave the Key Store |
| A3 | User passwords | Confidentiality; they unlock the Key Store |
| A4 | Signature validity and metadata | Integrity: nothing can be detached, swapped or forged |

## Adversaries

| ID | Adversary | Capability |
|---|---|---|
| ADV1 | Malicious storage provider | Reads, copies, edits, deletes and replays every stored container |
| ADV2 | Network attacker | Intercepts and alters a container in transit; may try to substitute a public key |
| ADV3 | Thief with a powered-off device | Copies the Key Store and guesses the password offline |

## Threats and how the design answers them

| Threat | What the attacker does | Main control | Where |
|---|---|---|---|
| T1 Read ciphertext | Reads stored or intercepted containers | AES-256-GCM with a fresh key per file; the key is wrapped per recipient (ECIES) | D2, D3 |
| T2 Alter ciphertext or tag | Flips a bit | GCM tag; the signature is checked first | D2, D5 |
| T3 Edit recipients, filename or metadata | Adds, removes or reorders recipients | All of them are AAD and are inside the signed bytes | D3, D5 |
| T4 Forge, move or strip the signature | Attaches a copied signature, or deletes it | Ed25519 over the whole container; an unsigned container is refused unless the user explicitly allows it | D5, D6 CLI |
| T5 Replay or roll back | Delivers an old container again | Signed `container_id`, `document_id` and `document_version`, plus the recipient's `ReplayGuard` | D5 |
| T6 Substitute a public key | Swaps the key before encryption | Fingerprint confirmed out of band is required to add a contact or a trusted signer | D3, D6 |
| T7 Guess the password offline | Brute force on a stolen Key Store | Argon2id (64 MiB, 3 iterations, 4 lanes) and an authenticated format | D6 |
| T8 Hostile container | Duplicate keys, bad base64, huge fields | Strict parser, exact fields, size limits, one generic error | D2, D3 |
| T9 Hostile filename or metadata | `../../x` as a name | The stored name is never used as an output path; sizes are limited | D3 |
| T10 Bad public key file | Wrong type or malformed PEM | One accepted encoding: a single PEM block, `.pem`, at most 16 KiB, expected key type | D3, D5, D6 |

The mapping asset → threat → scenario → requirement → constraint is the traceability matrix in section 7.2 of D1. Every asset, requirement (SR1 to SR5), scenario (S1 to S11) and constraint (C1 to C11) appears in it.

## Security assumptions

- The operating system provides a secure random source, and endpoints are free of malware while keys are unlocked.
- Storage and network are hostile and give no privacy, integrity or retention guarantee.
- **Public keys are authentic (AS6).** Fingerprints are compared through another channel. The software enforces the comparison, but it cannot create trust: a signer id names a key, not a person, and there is no certificate authority.
- **Replay protection depends on the recipient (AS5).** The `ReplayGuard` is a local file. Whoever can delete it makes the recipient forget.

## Out of scope

Algorithms written from scratch, protecting a file after a legitimate recipient has decrypted it, denial of service against the storage, and an attacker who can read the memory of a running trusted endpoint.
