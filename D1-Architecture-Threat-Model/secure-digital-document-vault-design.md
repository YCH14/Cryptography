# System Level Design: Secure Digital Document Vault

## 1. System Overview

**Problem Solved:**
Users need to store and share digital documents securely across untrusted infrastructures (such as cloud environments or shared local storage). The system ensures that neither the storage provider nor network attackers can access or alter the file contents.

**Core Features:**
- Local file encryption and protection (Authenticated Encryption).
- Use of digital signatures to guarantee package authenticity and non-repudiation.
- Secure management and storage of cryptographic material within a protected local Key Store.
- Command-line interface (CLI) execution for direct file processing and vault operations.

**Explicitly Out of Scope:**
- Implementation of cryptographic algorithms from scratch (proven schemes via standard Python libraries will be used).
- Digital Rights Management (DRM) once the legitimate "User / Recipient" has recovered and decrypted the file.
- Protection against Denial of Service (DoS) attacks targeting the remote storage server.

## 2. Architecture Diagram

![Architecture Diagram: Secure Digital Document Vault](architecture-diagram.jpeg)

**Diagram Overview:** The architecture strictly isolates cryptographic operations by defining three exact zones:

- **TRUSTED: SENDER** — The local environment where explicitly "ENCRYPTION HAPPENS HERE" and "SIGNING HAPPENS HERE." It contains the CLI "Application (Vault)" and the "Key Store," handling the sequence from file selection (Step 1) to package signing (Step 4).
- **UNTRUSTED ENVIRONMENT** — The transit and rest zone that houses the "SECURE PACKAGE / ENCRYPTED FILE CONTAINER." Here resides the "STORAGE (LOCAL OR REMOTE)" that only reads and writes ciphertext, and it is the environment where an "Attacker" is assumed to be present.
- **TRUSTED: RECIPIENT** — The local environment where explicitly "PRIVATE KEY USED HERE" and "DECRYPTION + VERIFICATION HAPPENS HERE." It covers package validation (Step 5), key recovery, decryption, and delivery of the original file (Steps 6 to 8).

## 3. Security Requirements

- **SR1 – Confidentiality of file contents:** An attacker who obtains the encrypted container from the "UNTRUSTED ENVIRONMENT" must not be able to learn anything about the file contents without possessing the recipient's protected private key.
- **SR2 – Integrity of file contents:** Any alteration of the package in the untrusted environment must be mandatorily detected in Step 5 ("Verify package") before attempting decryption.
- **SR3 – Authenticity of file sender:** The system must prove to the recipient (in Step 7, "Decrypt and verify") that the package irrefutably originates from the claimed sender's public key.
- **SR4 – Confidentiality of private keys:** The "private key material" must remain immovable within the local Key Store and under no circumstances cross into the untrusted environment.
- **SR5 – Protection against tampering:** Public information and metadata linked to the file must not be detachable or reassignable by an attacker without invalidating the signature verification.

## 4. Threat Model

**Assets (What must be protected):**

- **A1 – File contents:** Requires maximum confidentiality and integrity (protection steps 1 and 2).
- **A2 – Private keys:** Requires critical confidentiality; stored exclusively in trusted environments (Key Store).
- **A3 – User passwords:** Requires critical confidentiality (used to unlock the local Key Store).
- **A4 – Signature validity / Metadata:** Requires integrity protection against tampering and forgery.

**Adversaries (Who are you defending against):**

- **ADV1 – Malicious Storage Provider:** The administrator of the "STORAGE" who has read access to all stored encrypted containers.
- **ADV2 – Network Attacker:** An adversary capable of intercepting the signed and encrypted package while in transit through the "UNTRUSTED ENVIRONMENT."
- **ADV3 – Attacker with temporary local access:** An attacker who gains physical access to a powered-off device and attempts to extract the protected Key Store.

**Threats (What could happen to the assets):**

| ID | Threat | Adversary | Asset at risk |
|---|---|---|---|
| T1 | Reading stored or intercepted ciphertext | ADV1, ADV2 | A1 |
| T2 | Tampering with the ciphertext or the authentication tag | ADV1, ADV2 | A1, A4 |
| T3 | Adding, removing, reordering or editing recipients, `filename` or `metadata` | ADV1, ADV2 | A4 |
| T4 | Forging, transplanting or stripping the signature | ADV1, ADV2 | A4 |
| T5 | Replaying a valid package or serving an older version (rollback) | ADV1, ADV2 | A1, A4 |
| T6 | Substituting a recipient or signer public key | ADV2 | A1 |
| T7 | Offline guessing of the Key Store password | ADV3 | A2, A3 |
| T8 | Malformed or hostile container input (parser abuse) | ADV1, ADV2 | A1 |
| T9 | Hostile `filename` or oversized `metadata` | ADV1, ADV2 | A4 |
| T10 | Importing an invalid or unsuitable public key | ADV2 | A1, A2 |

**Attack Scenarios (How each threat would be carried out):**

| ID | Threat | Attacker | What the attacker does | If there were no defense |
|---|---|---|---|---|
| S1 | T1 | ADV1 | Copies every container stored on the server and tries to read the files. | The provider would read all documents. |
| S2 | T2 | ADV1 | Flips one byte of the ciphertext or the tag of a stored package and returns it to the recipient. | The recipient would receive a corrupted or altered file without noticing. |
| S3 | T3 | ADV1 | Removes a recipient, adds another one, reorders the list or edits `filename` / `metadata` of a package. | The sender would appear to have authorized different people or described a different file. |
| S4 | T4 | ADV2 | Copies the signature of a valid package and attaches it to a malicious container. | The forged file would be accepted as if the sender had produced it. |
| S5 | T4 | ADV1 | Deletes the signature of a package and delivers it unsigned. | An unsigned file would pass as authentic. |
| S6 | T5 | ADV1 | Keeps an old valid package and delivers it again later, or serves it instead of the newest version. | An outdated or duplicated package would be accepted as the current one. |
| S7 | T6 | ADV2 | Replaces the recipient's public key with their own before the sender encrypts. | The attacker, not the recipient, could decrypt the file. |
| S8 | T7 | ADV3 | Steals a powered-off device, copies the Key Store and tries passwords offline. | A weak password would give the attacker the private key. |
| S9 | T8 | ADV1 | Sends a hostile container: duplicate JSON keys, missing or extra fields, invalid base64, very large fields. | The application could crash, run out of memory or interpret the container differently from the signer. |
| S10 | T9 | ADV1 | Sets `filename` to a path such as `../../x` or attaches a very large `metadata`. | A file could be written outside the intended folder or memory could be exhausted. |
| S11 | T10 | ADV2 | Hands over a public key file of the wrong type, a corrupted PEM or a key that does not match the expected fingerprint. | An unsuitable key would be used silently. |

**Attacker Capabilities:**

- **Attackers CAN:** Read the ciphertext, delete or alter the package in the untrusted environment, attempt offline brute-force attacks on the Key Store, and analyze exposed public metadata.
- **Attackers CANNOT:** Access the memory of the application while encryption/decryption processes are running in the Trusted zones, nor mathematically reverse standard cryptographic primitives without the key.

## 5. Trust Assumptions

- **Trusted Senders and Recipients:** It is assumed that users' operating systems are free of malware or keyloggers capable of extracting plaintext keys directly from memory.
- **Authentic Public Keys:** It is assumed that the process where the application obtains the "recipient public key" uses a secure and reliable mechanism to prevent identity spoofing.
- **Secure Randomness:** It is assumed that the local operating system provides a cryptographically secure source of entropy (CSPRNG) for generating keys, IVs, and nonces.
- **Untrusted Central Infrastructure:** It is explicitly assumed that the "UNTRUSTED ENVIRONMENT" (including the network and central storage) is completely compromised and provides no native privacy or data retention guarantees.

## 6. Attack Surface Review

| Entry Point / Interface | What could go wrong? | Security Property at Risk | Design Constraint |
|---|---|---|---|
| CLI / Application Input | Malformed inputs when selecting a file ("Select file"), resulting in buffer overflow vulnerabilities. | System Integrity | Strict validation of paths and inputs in the application code. |
| Package Retrieval (Read Ciphertext) | The storage delivers an old or corrupted package to the "TRUSTED: RECIPIENT" (Replay attack). | Data Integrity / Freshness | Inclusion of timestamps or nonces validated during verification. |
| Key Store Access | Brute-force attacks against the "protected private key reference." | Key Confidentiality | Use of robust key derivation functions (e.g., Argon2id) and strong passwords. |
| Signature Verification (Step 5) | An attacker separates the signature from a valid document and attaches it to a malicious one, causing the receiver to accept it. | Authenticity / Non-repudiation | The digital signature must be calculated over the entire package and its intrinsic metadata. |
| Package parsing (container JSON) | Hostile container: duplicate keys, extra or missing fields, invalid base64, very large fields, deep nesting. | System Integrity / Availability | The parser accepts only the exact set of fields, rejects duplicate keys and non-canonical base64, enforces size limits, and reports every failure with one generic error. |
| Metadata processing (`filename`, `metadata`) | The sender-controlled `filename` contains a path such as `../../x`, or `metadata` is huge or is changed in transit. | Integrity / System Integrity | `filename` is untrusted and never used to build an output path (the caller chooses it); `filename` and `metadata` are size-limited and authenticated, so a change breaks the tag and the signature. |
| Public key import | A key of the wrong type, a corrupted PEM, a substituted key or a key that does not match the expected fingerprint. | Authenticity / Key Confidentiality | Imports accept only the expected key type and reject malformed PEM; the key fingerprint (SHA-256 of the raw public key) is computed deterministically so it can be compared out of band; recipient IDs cannot imitate a fingerprint. |

## 7. Design Constraints and Traceability

### 7.1 Design Constraints

Each constraint is a concrete design decision of the project. "Status" tells whether it is already implemented (deliverable in parentheses), planned, or only an assumption.

| ID | Design constraint | Status |
|---|---|---|
| C1 | Each file is encrypted once with AES-256-GCM under a fresh 256-bit key (DEK) and a random 96-bit nonce. | Implemented (D2, D3) |
| C2 | The DEK is wrapped separately for each recipient (ECIES: ephemeral X25519, HKDF-SHA256, AES-256-GCM); the header, `filename`, `metadata` and the full recipient list are bound as AAD. | Implemented (D3) |
| C3 | The sender signs the SHA-256 digest of the whole container except the signature with Ed25519; the recipient verifies the signature and the `signer_id` before decrypting. | Implemented (D5) |
| C4 | Every failure while opening a container is reported with one generic error that does not chain the cause, and nothing is written to disk on failure. | Implemented (D2, D3, D5) |
| C5 | Strict container parsing: exact field set, duplicate keys rejected, strict base64, and size limits for `metadata` and plaintext. | Implemented (D2, D3) |
| C6 | `filename` is untrusted: it is never used to build an output path. | Implemented (D3) |
| C7 | Public keys are imported only if they are of the expected type; the key fingerprint is the SHA-256 of the raw public key; recipient IDs may not look like a fingerprint. | Implemented (D3, D5) |
| C8 | Private keys are stored only in a password-protected Key Store (Argon2id, AES-256-GCM, with the format, KDF parameters, salt and metadata authenticated); the password is not stored and decrypted keys are not cached. | Implemented (D6) |
| C9 | Replay and rollback detection: a unique, signed container identifier checked by the recipient. | Planned |
| C10 | Key rotation and revocation workflow for private keys. | Planned |
| C11 | Public keys of senders and recipients are authentic: they are obtained and confirmed out of band (for example by comparing fingerprints). | Assumption, not enforced by the software |

### 7.2 Traceability Matrix

Each row follows one chain: asset → threat → attack scenario → security requirement → design constraint.

| Asset | Threat | Scenario | Security requirement | Design constraint |
|---|---|---|---|---|
| A1 | T1 | S1 | SR1 | C1, C2 |
| A1, A4 | T2 | S2 | SR2 | C1, C3, C4 |
| A4 | T3 | S3 | SR2, SR5 | C2, C3 |
| A4 | T4 | S4, S5 | SR3, SR5 | C3, C4 |
| A1, A4 | T5 | S6 | SR2 | C3 (the timestamp is signed), C9 (planned) |
| A1 | T6 | S7 | SR1, SR3 | C7, C11 |
| A2, A3 | T7 | S8 | SR4 | C8, C10 (planned) |
| A1 | T8 | S9 | SR2 | C4, C5 |
| A4 | T9 | S10 | SR5 | C5, C6 |
| A1, A2 | T10 | S11 | SR1, SR3 | C7 |

Coverage check: every asset (A1–A4), every security requirement (SR1–SR5), every scenario (S1–S11) and every constraint (C1–C11) appears at least once.

## 8. CLI Interface Proposal

To operate the vault in alignment with the architectural diagram, the system will expose the following console commands:

1. **`generate-keys`**: Creates the "private key material" and secures it in the local Key Store using a user-provided password.
2. **`encrypt`**: Executes steps 1 to 4 ("Protect file", "Select recipient public key", "Sign package"). Takes a local file, applies hybrid encryption, and generates the secure package to be sent to storage.
3. **`decrypt`**: Executes steps 5 to 8 ("Verify package", "Recover key", "Decrypt and verify"). Requires the recipient's password to unlock the Key Store, processes the encrypted container, and returns the original file in plaintext.
