# Cryptographic design decisions

Every primitive comes from the `cryptography` library (version 44 or newer). Nothing is implemented from scratch. Full designs: [D2](../D2-Symmetric-Encryption/docs/design_d2.md), [D3](../D3-Hybrid-Encryption/docs/hybrid_design_d3.md), [D5](../D5-Digital-Signatures/docs/signature_design_d5.md), [D6](../D6-Key-Management/docs/key_management_d6.md).

## Summary

| Purpose | Choice | Parameters |
|---|---|---|
| File encryption (D2) | AES-256-GCM | New 256-bit key (DEK) per file, random 96-bit nonce, 128-bit tag |
| Sharing with several recipients (D3) | ECIES built from X25519, HKDF-SHA256 and AES-256-GCM | One ephemeral X25519 key pair per recipient and per file; the DEK is wrapped once per recipient |
| Authenticity (D5) | Ed25519 over the SHA-256 of the canonical container | Signing key pair separate from the X25519 key |
| Key protection (D6) | Argon2id and AES-256-GCM | 3 iterations, 4 lanes, 64 MiB, 16-byte random salt, 256-bit derived key |
| Key identity | SHA-256 of the raw 32-byte public key | The same value is the recipient fingerprint, the signer id and the `key_id` |

## Decisions and reasons

**AEAD: AES-256-GCM (D2).** One primitive gives confidentiality and integrity, so there is no "encrypt, then MAC" to get wrong. CBC with a separate hash was rejected because it needs padding and an unpredictable IV and has a history of padding-oracle attacks. ChaCha20-Poly1305 was evaluated and discarded: AES-GCM is hardware-accelerated on almost every PC and having one algorithm removes configuration options that could be misused. The algorithm name is stored in the header, is authenticated, and any other value is rejected (no downgrade).

**Nonce strategy.** The key is new for every file and the nonce is 96 random bits from `os.urandom`, so a (key, nonce) pair is never repeated. The Python `random` module is forbidden, and a test parses the source code and fails if it appears (`test_module_does_not_use_insecure_rng`). Uniqueness is also tested (`test_nonces_and_wrapped_deks_never_repeat`).

**Metadata and AAD (D2, D3).** The header, the algorithm identifiers, the timestamp, `filename`, `metadata` and the whole recipient list are readable but authenticated as the AAD of the file encryption. Changing, adding, removing or reordering any of them makes the tag fail for every recipient. `filename` is never trusted: the caller always chooses the output path.

**Hybrid encryption and recipients (D3).** The file is encrypted once; only the 32-byte DEK is wrapped for each recipient, so adding a reader does not touch the ciphertext and public-key work does not grow with file size. For each recipient the sender generates a fresh ephemeral X25519 key `E`, computes the shared secret with the recipient public key `pk`, derives a key-encryption key with HKDF-SHA256 (`info` = a domain label, `E` and `pk`) and wraps the DEK with AES-256-GCM using the same context as AAD. The wrapped entry is 60 bytes (nonce, wrapped DEK and tag). Because every wrap has its own ephemeral key, two wraps of the same DEK cannot be correlated, and binding `E` and `pk` stops a wrap from being reused with another key.

**RSA was removed.** The first version of D3 used RSA-OAEP. After review it was replaced by ECIES on X25519: smaller keys, no padding, and no RSA remains in the code (a test checks that containers never mention it, and a legacy RSA container is rejected).

**Recipient identification (D3).** A recipient is found by `id` or by fingerprint, never by trial decryption. The 64-hex-character form is reserved for fingerprints, and an `id` with that form is rejected, so at most one entry can match.

**Signatures: Ed25519 (D5).** The sender signs the SHA-256 of the canonical JSON of the whole container except `signature`, after encrypting. The signature therefore covers the ciphertext, the recipients, the metadata, `signer_id`, `container_id` and the optional `document_id` and `document_version`; it cannot be stripped, moved to another container or edited. Ed25519 is deterministic (no per-signature nonce to get wrong), has small keys and verifies fast. `signer_id` is the fingerprint of the signing key.

**Verify before decrypting (D5, D6).** The order is fixed: strict parse, trusted signer, signature, replay guard, and only then key unwrap and decryption. A forged container never reaches the decryption code, and replay and tampering produce the same generic error.

**Replay and rollback (D5).** Each container carries a signed random `container_id`; a signer may add a signed `document_id` and an increasing `document_version`. A recipient that uses a `ReplayGuard` refuses a container it already accepted and a version that is not newer than the newest accepted. The container is recorded only after a successful decryption. The guard is optional and lives on the recipient's device (assumption AS5).

**KDF: Argon2id (D6).** Memory-hard, so every password guess costs 64 MiB, which makes offline guessing on GPUs expensive (scenario S8, a stolen powered-off device). The values are the second profile recommended by RFC 9106; the first one needs 2 GiB of RAM, too much for a laptop. The parameters are stored with the keystore, and limits on them are checked when it is opened.

**Key storage (D6).** The private key (PKCS#8) is encrypted with AES-256-GCM under the derived key. The AAD binds the format name, `metadata`, `kdf_parameters` and the salt, so editing any of the four keystore files makes the unlock fail. The password is never stored and unlocked keys are never cached.

## Errors

Every failure while opening a container raises one `DecryptionFailedError` without a chained cause, and every keystore failure (wrong password, modified file, malformed input) raises one `KeystoreAccessError`. Messages never contain keys, passwords or plaintext. Nothing is written when a check fails.
