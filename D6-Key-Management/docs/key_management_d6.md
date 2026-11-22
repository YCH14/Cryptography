# D6 – Key Management

This deliverable protects the private keys of the vault. A private key is never stored in plaintext: it is encrypted with a key derived from the user's password with **Argon2id**, and kept in a keystore directory with a documented format. It also covers backup and recovery, the key lifecycle, and how this fits the D1 threat model.

The two kinds of private key it protects are the X25519 key that unwraps file keys (D3, ECIES) and the Ed25519 key that signs containers (D5). Each private key has its own keystore. RSA keys are not supported: `create_keystore` refuses them, and a keystore that declares an RSA key (created by an earlier version of this deliverable) does not open. To move to the current version, create a new X25519 keystore and re-share the files that still matter with D3.

## Key Management Design

### KDF selection and parameters

**Argon2id** (RFC 9106), through `cryptography.hazmat.primitives.kdf.argon2.Argon2id`.

| Parameter | Value |
|---|---|
| Iterations (`t`) | 3 |
| Lanes (`p`) | 4 |
| Memory (`m`) | 65536 KiB (64 MiB) |
| Salt | 16 random bytes from `os.urandom`, new for every keystore |
| Output | 32 bytes, used as the AES-256-GCM key |

Why Argon2id:

- It is memory-hard: every password guess needs 64 MiB of memory, which makes large parallel guessing on GPUs or custom hardware more expensive than with a plain hash.
- RFC 9106 says to choose Argon2id if you do not know the difference between the Argon2 variants or if side-channel attacks are a concern.
- Our D1 threat model already names Argon2id for key store access (Attack Surface Review, "Key Store Access").
- It is in `cryptography` 44 or newer, the version the project already requires, so there is no new dependency.

The values are the second option recommended by RFC 9106 (`t=3`, `p=4`, 64 MiB). The first option needs 2 GiB of RAM, which is too much for a laptop. Opening a keystore takes about 0.1 s on the machine where we ran the tests; a laptop will differ. The parameters are stored in the keystore (`kdf_parameters`), so they can be raised later without changing the format. When reading them, the code only accepts bounded values (at most 10 iterations, 16 lanes and 1 GiB), so a modified file cannot make the program allocate unbounded memory.

### Key storage format

A keystore is a directory with four files:

```text
keystore/
 ├── encrypted_private_key
 ├── salt
 ├── kdf_parameters
 └── metadata
```

| File | Content |
|---|---|
| `encrypted_private_key` | `nonce` (12 bytes) followed by the AES-256-GCM ciphertext and its 16-byte tag. The plaintext is the private key as PKCS#8 DER, the format chosen in our key-format document. |
| `salt` | The 16 random salt bytes, raw. |
| `kdf_parameters` | JSON: `kdf` (`"argon2id"`), `iterations`, `lanes`, `memory_cost_kib`, `length`. |
| `metadata` | JSON: `version` (1), `owner`, `key_type` (`"X25519"` or `"Ed25519"`), `key_id`, `created` (UTC time). |

Both JSON files are written as canonical JSON (sorted keys, compact), the same rule as the D3 container.

**Encryption.** `AES-256-GCM(derived key, nonce, PKCS#8 DER, AAD)`, with a fresh 96-bit random nonce. The AAD is the canonical JSON of the format name (`VKS1`), `metadata`, `kdf_parameters` and the salt. So every file except the ciphertext itself is authenticated: if anyone changes any of the four files, the GCM tag does not verify and the keystore does not open. Inside the keystore the key is a PKCS#8 structure, but the encryption layer is ours (Argon2id plus AES-GCM) and not the PKCS#8 encrypted form, because the assignment asks for explicit `salt` and `kdf_parameters` files.

**Key identity.** `key_id` follows one rule for both key types: the SHA-256 of the raw 32-byte public key. For X25519 this is the D3 recipient fingerprint; for Ed25519 it is the D5 `signer_id`. After decrypting, the code recomputes the `key_id` from the private key and rejects the keystore if it differs from `metadata`. `metadata` also records the `key_type`, and `unlock_private_key(..., expected_key_type=...)` refuses a keystore that holds the other type, so an X25519 key is only used to unwrap file keys and an Ed25519 key is only used to sign.

**Files on disk.** Files are created with mode 0600 (on systems that support it). The keystore is built in a temporary directory and renamed into place, and an existing keystore is never overwritten.

**Key files outside the keystore.** Public keys are shared as files, and a private key can be exported, so these files have one accepted encoding: PEM, `SubjectPublicKeyInfo` for a public key (X25519 for D3, Ed25519 for D5) and encrypted PKCS#8 for an exported private key. A key file must have the `.pem` extension, be a regular file (not a link, a folder or a device) of at most 16 KiB, and contain exactly one PEM block with the expected label. Text before or after the block, a second block, non-ASCII bytes, DER and any other key type (RSA, or Ed25519 where X25519 is expected) are refused before the key is used. The extension is a guard against mistakes and not a security boundary, because any file can be renamed; what protects the import is the check of content, size, kind of file and key type. A private key is never written in the clear (`save_private_key_pem` needs a password), key files are created without overwriting an existing file or link, and a private key file has mode 0600. The place for a private key is the keystore above; the exported file is only for moving a key, and it is encrypted too.

### Access flow

1. The system asks for the password with `getpass` (or receives it as an argument).
2. It reads the four files and checks their structure.
3. It derives the key with Argon2id from the password, the salt and `kdf_parameters`.
4. It decrypts with AES-256-GCM, using `metadata`, `kdf_parameters` and the salt as AAD.
5. It loads the PKCS#8 key and checks `key_type` and `key_id`.
6. It returns the key object to the caller.

The password is never stored, and nothing is kept in a module-level cache: the key exists only while the caller holds the returned object. Any failure in steps 2 to 5 raises the same `KeystoreAccessError`, with one fixed message and without chaining the cause, so the error does not tell an attacker whether the password was wrong or a file was modified.

### Backup strategy

- **What is backed up:** the four keystore files, copied as they are with `backup_keystore`. A backup holds only the encrypted key, so it is exactly as protected as the keystore. The password is never part of a backup.
- **Where:** on a different medium or location than the keystore (for example an external drive or a separate storage account). Because the backup is encrypted, it can sit on storage that is not fully trusted; D1 already treats storage as hostile for containers.
- **Restore:** `restore_keystore(backup, destination, password)` copies the backup to a temporary directory, opens it there with the password, and moves it into place only if it opens. A corrupted or modified backup is rejected and nothing is restored.
- **No password recovery:** the password is not stored anywhere, so if it is lost, the key cannot be recovered from the keystore or from any backup. This is deliberate.
- **Changing the password:** unlock the key, then call `create_keystore` with the new password into a new directory and replace the old one. A backup made before the change still opens with the old password, so old backups must be replaced too.

### Key lifecycle

| Stage | Definition | How the system handles it |
|---|---|---|
| Generation | A new key pair is created. | `generate_x25519_keypair` (D3) or `generate_ed25519_keypair` (D5), then `create_keystore` right away. The private key is never written anywhere else. The public key and its `key_id` are what gets shared. |
| Usage | The key is used to unwrap file keys (X25519) or sign (Ed25519). | `unlock_private_key` asks for the password, decrypts the key for this operation only, and the caller drops it afterwards. `expected_key_type` keeps each key to its purpose. |
| Rotation | The key is replaced by a new one, for example on a schedule or after a password change. | `Keyring.rotate` stores the new key in its own keystore (a new `key_id`), makes it the active key and retires the previous one. New files are encrypted for, and signed with, the new key. The retired key stays in the keyring so files made before the rotation can still be opened. See "Rotation, revocation and historical access". |
| Revocation and compromise response | The key, or the keystore together with the password, is believed to be known to an attacker, or the key must not be used any more. | `Keyring.revoke` marks the key as revoked, with a date and a reason (and `compromised=True` when it may be known to someone else). The key is never used for new work. The owner rotates, sends the revocation notice to the people who trusted the key, and recovers the files that still matter to share them again with the new key. See the same section. |
| Expiration (optional) | A key stops being valid after a date. | Not enforced. `metadata` stores `created`, so a policy can be added later without changing the format. |

### Rotation, revocation and historical access

Each key keeps its own keystore, exactly as described above. A **keyring** groups the versions of one key of one type (X25519 for D3, or Ed25519 for D5) for one user:

```text
keyring/
 ├── keyring.json        manifest: owner, key type, and for each key: key_id, status, dates, reason
 └── keys/
      ├── <key_id>/      a keystore (encrypted_private_key, salt, kdf_parameters, metadata)
      └── <key_id>/
```

The manifest holds only public facts. Each keystore can have its own password, so a rotation can also change the password.

| Status | Meaning | New work (sign, receive) | Opening old files |
|---|---|---|---|
| `active` | The current key. There is at most one. | Yes | Yes |
| `retired` | Replaced by a newer key with `Keyring.rotate`. | No | Yes |
| `revoked` | Declared unusable with `Keyring.revoke`. | No | Only if the owner asks explicitly (`allow_revoked=True`) |

**Rotation.** `rotate(new_key, password)` creates the keystore of the new key, marks it `active` and retires the previous active key. Files that already exist are not touched: they stay encrypted for the old key, which is still in the keyring.

**Historical access.** A D3 container lists the fingerprint of every recipient key, and the fingerprint is the `key_id`. `find_key_for_container` looks up which key of the keyring a container was made for, and `decrypt` opens it with that key, whether it is the active key or a retired one. A key that was rotated away therefore keeps opening the files made before the rotation, and the new key does not need to know about them.

**Responding to a compromised key.** The steps are in this order:

1. `revoke(key_id, reason, compromised=True)`. The key is not used for new work from now on, and `unlock` refuses it unless the owner says `allow_revoked=True`.
2. `rotate(new_key, password)` to get a new active key.
3. Send `revocation_notice(key_id)` to the people who trusted the key, through a trusted channel (see below).
4. Recover the files that still matter with `decrypt(..., allow_revoked=True)` and share them again with the new key with D3. The old key is kept only for this recovery.

A revocation does not undo what already happened: an attacker who copied files encrypted for a compromised key can still open them. What it does is stop the owner, and the recipients who received the notice, from using or trusting that key again.

**Trusted signing keys of other people.** D5 verifies with the public key the caller provides, and the `signer_id` only identifies a key. `TrustedSigners` is the recipient's own file of the signing keys it decided to trust:

- *Distribution.* `add(name, public_key, expected_fingerprint=...)` refuses a key whose `signer_id` is not the fingerprint that the signer gave through another channel (in person, by phone, in a signed message).
- *Replacement.* `replace(old_signer_id, new_public_key, expected_fingerprint=...)` trusts the new key and marks the old one as `superseded`. Containers signed with the old key before the replacement still verify.
- *Revocation.* `revoke(signer_id, reason)` or `import_revocation(notice)` marks the key as `revoked`. `verify_with_trusted_signers` then refuses every container signed with it (`UntrustedSignerError`), including ones signed before the compromise, because the container's `timestamp` is written by the signer and cannot prove when it was made.
- A signer that is unknown or revoked is refused before the signature is checked. A trusted one goes through the normal D5 check: signature first, then the replay check if a guard is given, then decryption.
- *Replay and rollback.* `verify_with_trusted_signers(..., replay_guard=guard)` passes a D5 `ReplayGuard` to the check. A container that was already accepted (`ReplayDetectedError`), or an older version of a document that was already accepted (`RollbackDetectedError`), is refused after the signature is verified and before decryption, and a container is recorded only after it was decrypted. The trust check comes first, so a revoked signer is refused as `UntrustedSignerError` even for a container that was accepted before. Without a guard, replay and rollback are not detected (D1, AS5).

The revocation notice is not signed: a compromised key cannot vouch for its own revocation, so the notice has to reach the recipient through a trusted channel, the same way the key did. A forged notice could otherwise make a recipient stop trusting a valid key.

### Access control via keys

- Only the holder of the private key that matches a recipient entry can decrypt. D3 wraps the file key per recipient with ECIES (an ephemeral X25519 key, HKDF-SHA256 and AES-256-GCM), and the keystore only protects the X25519 private key that opens that wrapping.
- The identity of a key is the same everywhere: the `key_id` stored in `metadata` is the fingerprint used in the D3 recipient entry (X25519) or the `signer_id` used in D5 (Ed25519), both computed the same way, and it is checked after decryption. A keystore cannot hold a key that does not match its own `key_id`.

### Security assumptions

- The password is chosen by the user and kept secret. The system does not enforce a password policy.
- The operating system is free of malware and keyloggers that read keys from memory or capture the password (D1, Trust Assumptions).
- The operating system provides a secure source of randomness (D1, Trust Assumptions).
- Attackers can read, copy and modify the keystore and its backups, and can guess passwords offline (D1, Attacker Capabilities).
- Public keys are obtained through a reliable channel (D1, Trust Assumptions).
- The replay record of the `ReplayGuard` and the trusted signers file are on the recipient's own device, which is assumed to be trusted (D1, AS5 and AS6).

## Threat Model Alignment (D1)

**What if an attacker steals the keystore?** The attacker has the four files but no password. The key inside is encrypted with AES-256-GCM under an Argon2id-derived key, so the attacker has to guess the password offline, and each guess costs 64 MiB of memory and three passes of Argon2id. The attacker cannot modify the files to help: any change makes the tag fail. If the password is strong, the private key stays confidential, and a stolen keystore alone cannot decrypt anything shared with the owner.

**What if a password is weak?** The key is exactly as safe as the password. Argon2id makes each guess more expensive but cannot stop an attacker from trying the most common passwords first, so a keystore protected by a guessable password can be opened offline, and from then on the attacker has the key. The system does not check password strength; the user must choose a long passphrase.

**What if a device is compromised?** If the device is infected while the user is working (malware, keylogger, memory dump), the password and the decrypted key can be taken, and the keystore gives no protection. D1 states this as an assumption: the operating system is free of malware. A device that is only stolen while powered off is the case of a stolen keystore, described above.

| The system protects against | The system does NOT protect against |
|---|---|
| A stolen keystore or backup without the password | Weak or reused passwords |
| Any modification of the four keystore files | Malware, keyloggers or memory reading on a running device |
| Moving the encrypted key into another keystore | A lost password: there is no recovery |
| Using an X25519 key to sign or an Ed25519 key to decrypt | Data an attacker copied before a key was rotated |
| Overwriting an existing keystore by mistake | A revocation notice that arrives through an untrusted channel |
| Using a revoked or retired key for new work, or accepting files signed by a revoked signer | Someone who can write to the keyring manifest or to the trusted signers file changing a status |
| A trusted signer's container delivered again, or an older version of a document (with a `ReplayGuard`) | Someone who can delete or edit the replay record, or a recipient that does not use a guard |
| A corrupted backup being restored | Old backups that still open with an old password |

## Security Discussion

**Why encrypt private keys?** Every other protection in the vault depends on them: whoever has a private key can decrypt the files shared with its owner (D3) or sign in the owner's name (D5). D1 lists private keys as a critical asset. A keystore sits on a disk, in a backup or in a cloud folder, places D1 treats as reachable by attackers, and a plaintext key file would give a thief permanent access with a single copy. Encrypting it means the attacker needs two things, the files and the password.

**What happens if the password is weak?** The Argon2id cost slows down each guess, but a short or common password is still found by guessing, offline and without the system noticing. After that, the attacker has the private key, and everything described above for a compromised key applies: the files shared with that key can be read and signatures can be forged until the key is rotated. This is the main limit of password-based protection.

**What are the limitations of the system?**

- The key is only as strong as the password, and no password policy is enforced.
- A password that is lost cannot be recovered, and there is no escrow.
- Python cannot reliably wipe memory, so the decrypted key and the password stay in memory until they are freed.
- A compromised device defeats the keystore (D1 assumption).
- Key files are checked for encoding, key type, size and kind of file, but who can read or replace them is decided by the permissions of the operating system. A public key file that was swapped is still a valid key: only the fingerprint comparison through another channel detects it.
- Revocation is local, plus a notice that the owner sends through a trusted channel. There is no revocation service, no signed or timestamped revocation list, and no way to know that a recipient received the notice.
- The keyring manifest and the trusted signers file are plain JSON on the device. Someone who can write to them can change a status (for example, mark a revoked key as active again) but cannot read or use a key without its password. The statuses are checks made by this software, not a cryptographic barrier.
- A revoked key is kept (so files can be recovered) and is as exposed as before: the revocation does not protect files an attacker already copied.
- There is no limit on guessing, because the attack is offline; only the cost of Argon2id slows it down.
- Argon2id needs a `cryptography` build whose OpenSSL supports it; otherwise the library raises `UnsupportedAlgorithm`.
- One keystore holds one key, so a user with an X25519 key and an Ed25519 key has two keyrings (and every rotation adds a keystore).

## Tests

`tests/keystore/test_keystore.py` covers the five required cases, plus checks for the D3 and D5 integration, the password prompt and the identity rules.

| # | Case | Expected result | Tests |
|---|------|-----------------|-------|
| 1 | Correct password | Key unlocked, and it decrypts a D3 container (X25519) or signs a D5 container (Ed25519) | `test_correct_password_access_granted`, `test_ed25519_key_works_with_d5`, `test_password_is_asked_when_not_given` |
| 2 | Wrong password | `KeystoreAccessError`, no chained cause | `test_wrong_password_denied` |
| 3 | Modified keystore | `KeystoreAccessError` after changing any of the four files, removing one, or swapping the encrypted key from another keystore | `test_modified_keystore_fails`, `test_encrypted_key_swapped_from_another_keystore_fails` |
| 4 | Backup, then restore | The restored keystore opens with the password; a corrupted backup is not restored | `test_backup_restore_works`, `test_corrupted_backup_is_not_restored` |
| 5 | Stolen keystore alone | No file contains the key in the clear; password guesses fail; another key cannot open the shared container | `test_stolen_keystore_alone_cannot_decrypt` |

Further checks cover the key types: `key_id` is the SHA-256 of the raw public key for both types (`test_key_id_is_sha256_of_raw_public_key`), an RSA private key is refused (`test_rsa_private_key_is_refused`), a keystore in the same format that holds an RSA key does not open (`test_keystore_holding_an_rsa_key_does_not_open`), and an Ed25519 keystore survives backup and restore (`test_ed25519_backup_restore_works`).


Rotation, revocation and the trusted signers have their own tests:

| File | Cases |
|------|-------|
| `tests/keystore/test_keyring.py` | create and open a keyring; first key active; rotation retires the previous key and keeps one active; each key has its own password; duplicate and wrong-type keys refused; manifest holds no key material; files made before a rotation still open with the retired key |
| `tests/keystore/test_revocation.py` | revoking active and retired keys; a revoked key is not unlocked unless `allow_revoked=True`, and still needs the password; reason required; no double revocation; notice content; historical `decrypt` after a rotation; the compromised-key flow (revoke, recover, share again) |
| `tests/keystore/test_trust.py` | key accepted only with a matching fingerprint; unknown and revoked signers refused; replacement keeps old containers valid; revocation, also from the owner's notice; forged signer id fails the signature; generic error; malformed files not ignored |
| `tests/keystore/test_trust_replay.py` | trusted signer with a `ReplayGuard`: first delivery accepted, replay refused, older document version refused, newer version accepted, record kept between guard objects, unknown or revoked signer refused before the replay check and not recorded, failed decryption or tampering does not use up the container |
| `tests/hybrid/test_key_files.py` | key files round trip; a private key file needs a password and is encrypted; only `.pem` files; an existing file or link is not overwritten; files that are too large, folders, links and missing files refused; anything but one PEM block refused (text around it, two blocks, wrong label, not base64, non-ASCII, DER, empty); public and private keys of another type refused |
| `tests/signatures/test_signer_key_files.py` | Ed25519 public key files: round trip, one PEM block, X25519 and RSA keys refused, a private key refused, only `.pem`, no overwriting, too large, folder and missing file refused |
| `tests/keystore/test_signer_key_import.py` | a signer key file is trusted only with the fingerprint confirmed through another channel; a swapped file does not match |
| `tests/signatures/` | the D5 suite, including `test_container_id.py`, `test_replay.py` and `test_rollback.py`, now identical to D5 |

## Sources

- [RFC 9106: Argon2](https://datatracker.ietf.org/doc/rfc9106/): the parameter options (Section 4) and the 16-byte salt (Section 3.1).
- [`cryptography` 46.0.0 key derivation docs](https://cryptography.io/en/46.0.0/hazmat/primitives/key-derivation-functions/): `Argon2id`, added in version 44.0.0, and its parameters.
- Our D1 document, `secure-digital-document-vault-design.md`: assets, adversaries, assumptions and the attack surface table.
