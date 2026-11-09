# D5 – Signatures & Authentication

This deliverable adds an Ed25519 digital signature on top of the D3 hybrid
container, so a recipient can verify who created a file and detect any change
before decrypting it.

Flow: **Encrypt (D3) → Add metadata → Hash → Sign → Store**, and on the
receiving side **Read → Hash → Verify → Decrypt**.

## Signature Design

### Algorithm

**Ed25519** (RFC 8032), using the `cryptography` library. The signer has an
Ed25519 key pair, separate from the RSA keys used to wrap the file key in D3.

### Container

The D3 container is kept as is and two fields are added:

```text
{ metadata, recipients, ciphertext, tag, signature, signer_id, ... }
```

(`...` are the other D3 fields: `magic`, `version`, `algorithm`,
`key_wrap_algorithm`, `timestamp`, `filename`, `nonce`.)

- `signer_id`: identifies the signer. It is the SHA-256 fingerprint (hex) of the
  signer's raw 32-byte Ed25519 public key, built the same way as the D3
  recipient fingerprint.
- `signature`: the 64-byte Ed25519 signature encoded as Base64 (RFC 4648), the
  same encoding the container already uses for its binary fields.

### What data is signed

The SHA-256 hash of the canonical JSON (sorted keys, compact separators, same
rules as D3) of the whole container **except the `signature` field**. This
covers:

- the encrypted content from D2/D3: `ciphertext`, `tag` and `nonce`;
- the D3 structure: the `recipients` list (`id`, `fingerprint`, `encrypted_dek`);
- all the security-relevant metadata that is also bound as AAD: `magic`,
  `version`, `algorithm`, `key_wrap_algorithm`, `timestamp`, `filename` and
  `metadata`;
- `signer_id`, so the claimed signer cannot be swapped.

### Why hashing is required before signing

The container has an arbitrary size, and the signature must be made over one
fixed-size value. Hashing with SHA-256 turns the whole canonical container into
a 32-byte digest, and the digest is what gets signed. Because the hash is
collision resistant, changing even one bit of any signed field changes the
digest, so the signature no longer verifies. Without the hash step, the signer
would have to sign the raw bytes directly, with no fixed-size value to compare.

### Verification workflow

1. Read the container.
2. If there is no `signature`, reject.
3. Check that `signer_id` matches the expected signer public key.
4. Recompute the SHA-256 hash of the container (without `signature`) and verify
   the Ed25519 signature with the signer's public key.
5. If it is valid, decrypt with the D3 code. If it is invalid, reject with a
   generic error and nothing is decrypted.

## Security Decisions

### Why sign the ciphertext and not the plaintext?

The recipient must be able to check the signature **before** decrypting, so the
signature has to be over data that is available before decryption: the
ciphertext and the metadata. Signing the plaintext would force the recipient to
decrypt first, and it would not cover the `recipients` list and the metadata,
which are stored outside the plaintext. The plaintext is also never stored in
the container, so signing it would leave the stored container itself unsigned.

### What happens if the signature is not verified first?

The recipient would run decryption on a container that may have been forged or
modified. An attacker who cannot make a valid signature could still make the
recipient process attacker-controlled data (a changed `recipients` list,
changed metadata, or a different ciphertext). Verifying first means a forged or
tampered container is rejected immediately with a generic error and no
decryption or output file is produced.

### What happens if the metadata is excluded from the signature?

An attacker could change the metadata (for example `filename`, `timestamp`,
`metadata`, or the algorithm identifiers) without breaking the signature, and
the recipient would still see the container as "signed by the sender". The same
applies to the `recipients` list: it could be altered while the signature stays
valid. For this reason the signature covers the ciphertext and all the metadata
and recipients, the same data bound as AAD in D3.

## Tests

`tests/signatures/test_signatures.py` covers the five required cases:

| # | Case | Expected result |
|---|------|-----------------|
| 1 | Valid signature | accepted and decrypted |
| 2 | Modified ciphertext | rejected (`SignatureVerificationError`) |
| 3 | Modified metadata | rejected (`SignatureVerificationError`) |
| 4 | Wrong public key | rejected (`SignatureVerificationError`) |
| 5 | Signature removed | rejected (`MissingSignatureError`) |
