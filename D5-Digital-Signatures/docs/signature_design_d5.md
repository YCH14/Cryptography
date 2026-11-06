# D5: Digital Signatures and Origin Authentication

## 1. Signature Design
- **Algorithm:** Ed25519 (RFC 8032) chosen for constant-time operations, deterministic signatures, compact 64-byte signatures, and 32-byte public keys.
- **Signed Payload:** Canonical JSON binding all security-relevant metadata, the recipient list, nonce, ciphertext, and tag.
- **Hashing:** Compresses arbitrary-size inputs into a deterministic, collision-resistant digest for signing.

## 2. Security Decisions
- **Encrypt-then-Sign:** Avoids the Cryptographic Doom Principle. Ensures recipients verify authenticity before touching decryption routines, preventing chosen-ciphertext and oracle attacks.
- **Verification First:** Any malformed or unauthorized container is rejected immediately without allocating decryption resources or writing files to disk.
- **Metadata Binding:** Prevents replay, recipient stripping, and context-swap attacks.
