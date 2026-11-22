# D5 – Signatures & Authentication

This deliverable adds an Ed25519 digital signature on top of the D3 hybrid
container, so a recipient can verify who created a file and detect any change
before decrypting it.

Flow: **Encrypt (D3) → Add metadata → Hash → Sign → Store**, and on the
receiving side **Read → Hash → Verify → Decrypt**.

## Signature Design

### Algorithm

**Ed25519** (RFC 8032), using the `cryptography` library. The signer has an
Ed25519 key pair, separate from the X25519 keys used to wrap the file key in D3 (ECIES).

### Container

The D3 container is kept as is and these fields are added:

```text
{ metadata, recipients, ciphertext, tag, signature, signer_id, container_id,
  [document_id, document_version], ... }
```

(`...` are the other D3 fields: `magic`, `version`, `algorithm`,
`key_wrap_algorithm`, `timestamp`, `filename`, `nonce`.)

- `signer_id`: identifies the signer. It is the SHA-256 fingerprint (hex) of the
  signer's raw 32-byte Ed25519 public key, built the same way as the D3
  recipient fingerprint.
- `signature`: the 64-byte Ed25519 signature encoded as Base64 (RFC 4648), the
  same encoding the container already uses for its binary fields.
- `container_id`: 16 random bytes from the operating system, written as 32
  lowercase hex characters. The signer creates a new one every time it signs, so
  the same content signed twice gives two different identifiers. It is what lets
  a recipient recognise a container it has already accepted.
- `document_id` and `document_version` (optional, always together): the signer's
  name for the logical document (1 to 128 printable characters) and an integer
  of at least 1 that grows with every new version of it. They let a recipient
  recognise an older version of a document.

### What data is signed

The SHA-256 hash of the canonical JSON (sorted keys, compact separators, same
rules as D3) of the whole container **except the `signature` field**. This
covers:

- the encrypted content from D2/D3: `ciphertext`, `tag` and `nonce`;
- the D3 structure: the `recipients` list (`id`, `fingerprint`, `ephemeral_public_key`, `encrypted_dek`);
- all the security-relevant metadata that is also bound as AAD: `magic`,
  `version`, `algorithm`, `key_wrap_algorithm`, `timestamp`, `filename` and
  `metadata`;
- `signer_id`, so the claimed signer cannot be swapped;
- `container_id` and, when present, `document_id` and `document_version`, so none
  of them can be changed, removed or added without breaking the signature.

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
5. If the signature is invalid, reject with a generic error and nothing is
   decrypted.
6. Check that `container_id` is well formed (and `document_id` /
   `document_version`, if present). A container signed without a valid
   `container_id` is rejected even if the signature is correct.
7. If the recipient uses a `ReplayGuard`: refuse a container that was already
   accepted and an older version of a document (see below). This happens after
   the signature check and before decryption.
8. Decrypt with the D3 code. Only after the decryption succeeds, record the
   container in the guard.

## Replay and Rollback Protection

A valid signature proves who created a container. It does not prove that this is
the first time the recipient receives it, or that it is the latest version. The
storage is untrusted (D1, adversary ADV1 and ADV2), so it can deliver the same
container again (**replay**) or deliver an older version of a document instead
of the newest one (**rollback**). D5 handles both with a `ReplayGuard` that the
recipient keeps on its own side.

### How it works

- **Replay.** Every container has a signed, random `container_id`. The guard
  keeps, for each `signer_id`, the identifiers of the containers it accepted. A
  container whose identifier is already in the record is refused with
  `ReplayDetectedError`.
- **Rollback.** The signer can label a container with `document_id` and
  `document_version`. The guard keeps, for each `signer_id` and `document_id`,
  the highest version accepted. A container with an equal or lower version is
  refused with `RollbackDetectedError`. Skipping version numbers is allowed;
  going back is not.
- **Order of checks.** The guard is consulted after the signature is verified,
  so someone without the signer's key can never add entries to the record. The
  container is recorded only after it was decrypted, so a failed decryption (for
  example with the wrong private key) does not use up the container or advance
  the version.
- **Errors.** Both errors are subclasses of `SignatureVerificationError`, with
  the same fixed message and no chained cause, like the other verification
  errors. `ReplayStoreError` is raised if the record cannot be read or written
  or is corrupted, and the container is not accepted in that case.

### The record

`ReplayGuard(path)` keeps one JSON file (`format` `VRG1`) with the accepted
`container_id` values and the highest `document_version` per document. It is
written atomically (temporary file and `os.replace`) with permissions `0600`.
It holds only identifiers and numbers, never keys or plaintext.

### Limits

- The guard is **optional**: `verify_and_decrypt` without a `replay_guard`
  detects neither replay nor rollback, as before.
- The record belongs to the recipient's trusted side. If an attacker can delete
  or edit it, the recipient forgets what it accepted. This is outside the D1
  threat model, which assumes the attacker controls the storage and the network
  but not the recipient's device.
- Rollback is detected only after the recipient has accepted a newer version. If
  the storage serves an old version first and the newer one was never seen, the
  old one looks valid. The storage can also hide new versions or delay
  containers; D5 does not prevent that (denial of service is out of scope in D1).
- Rollback detection needs the signer to use `document_id` and `document_version`
  consistently. Containers without them are protected against replay only.
- The `timestamp` of the container is signed but is not used as proof of
  freshness: it is written by the signer and no trusted clock is assumed.
- The record only grows. Each accepted container adds about 40 bytes, which is
  enough for a personal vault. A limit or an expiry rule would be needed for a
  large deployment.

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

## Signing Key Management

D5 verifies that a container was signed by the holder of a specific Ed25519
key. It does not decide whether that key should be trusted. This section
describes how signing keys are meant to be distributed, replaced and revoked,
and says clearly which parts the code does today and which parts are the
responsibility of the people using it.

### Distribution of trusted signing keys

The recipient needs the sender's Ed25519 public key before verifying: the key
is passed to `verify_and_decrypt` by the caller. The code does not download
keys, look them up in a directory or accept a key found inside a container.
The trusted key is therefore whatever the recipient decides to pass in.

To make that decision safely, the recipient obtains the public key through a
channel the attacker does not control (in person, a signed message, a trusted
repository) and compares its `signer_id` with the sender through a second,
independent channel before trusting it. If the recipient is given a false key,
the packages signed by the attacker verify correctly under that key: the
signature proves who holds the key, not that the key belongs to the right
person. No certificate authority is used in this design.

A signing public key is exchanged as a file with one accepted encoding: an Ed25519 key in PEM (`SubjectPublicKeyInfo`), saved with `save_signer_public_key_file` and read with `load_signer_public_key_file`. The file must have the `.pem` extension, be a regular file of at most 16 KiB and contain exactly one PEM block; text around the block, a second block, a private key, an X25519 or RSA key and any other format are refused. A file that passes these checks is only a well-formed key, not a trusted one: the recipient still compares its `signer_id` through another channel.

### Replacement of a signing key

A sender replaces the signing key when it is lost, exposed or rotated. The new
key has a different `signer_id`, because the identifier is derived from the
public key. The sender publishes the new public key and its `signer_id`, and
the recipient confirms them through an independent channel, as in the first
distribution. Nothing in the container announces a new key, and the recipient
is not told about it automatically.

Containers signed with the old key still verify when the recipient supplies the
old public key, since each container carries the `signer_id` of the key that
signed it. The recipient may therefore keep old public keys to read old
containers, but must mark them as "old" so they are not used to accept new ones.

### Revocation of a signing key

A signing key is compromised when someone other than its owner may have used
it (lost device, stolen keystore file, leaked password). From that moment the
attacker can produce containers that verify correctly. The sender must tell
the recipients, through an independent channel, which `signer_id` to stop
trusting and from when.

The current code has no revocation list: it accepts any container whose
signature matches the key it is given. Revocation is done by the recipient
removing the key from the set it trusts. The `timestamp` in a container is
signed, but it is written by the signer, so the holder of a compromised key can
write any date. It cannot be used to prove that a container was created before
the compromise. For this reason, containers signed by a revoked key are treated
as untrusted unless the recipient has another proof of when they were received.
A revocation workflow implemented in code is planned in the key management work
(D6).

### Key fingerprint versus authenticated identity

The `signer_id` is the SHA-256 of the raw public key. It identifies a key. By
itself it does not show who owns that key, that the owner is the person the
recipient expects, or that the key has not been revoked. A valid signature
together with a matching `signer_id` proves only that the container was signed
by the holder of that key. Linking the key to a real person is a decision of
the recipient, made when it confirms the fingerprint out of band. The
"authenticity of the sender" in this project always depends on that decision.

### Storage of the private signing key

The Ed25519 private key is stored in the encrypted keystore of
`D6-Key-Management` (Argon2id and AES-256-GCM), and is decrypted only at the
moment of signing. Replay of a valid container and delivery of an older
version are handled by the `ReplayGuard` described above.

## Tests

`tests/signatures/test_signatures.py` covers the five required cases plus one check for the ECIES ephemeral key:

| # | Case | Expected result |
|---|------|-----------------|
| 1 | Valid signature | accepted and decrypted |
| 2 | Modified ciphertext | rejected (`SignatureVerificationError`) |
| 3 | Modified metadata | rejected (`SignatureVerificationError`) |
| 4 | Wrong public key | rejected (`SignatureVerificationError`) |
| 5 | Signature removed | rejected (`MissingSignatureError`) |
| 6 | Modified ECIES ephemeral public key of a recipient | rejected (`SignatureVerificationError`) |

Replay and rollback have their own tests:

| File | Cases |
|------|-------|
| `tests/signatures/test_container_id.py` | `container_id` present, unique per signing, covered by the signature; missing or malformed ids rejected even when re-signed |
| `tests/signatures/test_replay.py` | first delivery accepted; the same container twice rejected (also after a restart); a new container with the same content accepted; independent signers; failed decryption and invalid signatures leave the record untouched; corrupted record not ignored; generic error; no guard, no detection |
| `tests/signatures/test_signer_key_files.py` | Ed25519 public key files: round trip, one PEM block, X25519 and RSA keys refused, a private key refused, only `.pem`, no overwriting, too large, folder and missing file refused |
| `tests/signatures/test_rollback.py` | versions in order accepted; older or equal version rejected; independent documents and signers; unversioned containers unaffected; invalid signing arguments refused; document fields covered by the signature; malformed fields rejected even when re-signed |
