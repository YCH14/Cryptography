# D6 – Key Management

This deliverable protects the private keys of the vault. A private key is never stored in plaintext: it is encrypted with a key derived from the user's password with **Argon2id**, and kept in a keystore directory with a documented format. It also covers backup and recovery, the key lifecycle, and how this fits the D1 threat model.

The two kinds of private key it protects are the RSA key that unwraps file keys (D3) and the Ed25519 key that signs containers (D5). Each private key has its own keystore.

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
| `metadata` | JSON: `version` (1), `owner`, `key_type` (`"RSA"` or `"Ed25519"`), `key_id`, `created` (UTC time). |

Both JSON files are written as canonical JSON (sorted keys, compact), the same rule as the D3 container.

**Encryption.** `AES-256-GCM(derived key, nonce, PKCS#8 DER, AAD)`, with a fresh 96-bit random nonce. The AAD is the canonical JSON of the format name (`VKS1`), `metadata`, `kdf_parameters` and the salt. So every file except the ciphertext itself is authenticated: if anyone changes any of the four files, the GCM tag does not verify and the keystore does not open. Inside the keystore the key is a PKCS#8 structure, but the encryption layer is ours (Argon2id plus AES-GCM) and not the PKCS#8 encrypted form, because the assignment asks for explicit `salt` and `kdf_parameters` files.

**Key identity.** `key_id` follows the rule we already use: for RSA, the SHA-256 of the DER SPKI (the D3 fingerprint); for Ed25519, the SHA-256 of the raw 32-byte public key (the D5 `signer_id`). After decrypting, the code recomputes the `key_id` from the private key and rejects the keystore if it differs from `metadata`. `metadata` also records the `key_type`, and `unlock_private_key(..., expected_key_type=...)` refuses a keystore that holds the other type, so an RSA key is only used to decrypt and an Ed25519 key is only used to sign.

**Files on disk.** Files are created with mode 0600 (on systems that support it). The keystore is built in a temporary directory and renamed into place, and an existing keystore is never overwritten.

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
| Generation | A new key pair is created. | `generate_rsa_keypair` (D3, at least 2048 bits) or `generate_ed25519_keypair` (D5), then `create_keystore` right away. The private key is never written anywhere else. The public key and its `key_id` are what gets shared. |
| Usage | The key is used to decrypt (RSA) or sign (Ed25519). | `unlock_private_key` asks for the password, decrypts the key for this operation only, and the caller drops it afterwards. `expected_key_type` keeps each key to its purpose. |
| Rotation (conceptual) | The key is replaced by a new one, for example on a schedule or after a password change. | Generate a new pair and a new keystore (a new `key_id`). New files are encrypted for, and signed with, the new keys. The old keystore is kept only to open files made before the rotation, or those files are re-shared to the new key with D3. |
| Compromise response (conceptual) | The key or the keystore, together with the password, is believed to be known to an attacker. | Stop using the key; generate a new pair and a new keystore; tell recipients out of band that the old `key_id` is no longer trusted (this project has no revocation service); re-share the files that still matter with D3; treat signatures made by the old key as untrusted from the time of the suspected compromise. Files the attacker already copied can still be opened with the old key. |
| Expiration (optional) | A key stops being valid after a date. | Not enforced. `metadata` stores `created`, so a policy can be added later without changing the format. |

### Access control via keys

- Only the holder of the private key that matches a recipient entry can decrypt. D3 is unchanged: the file key is still wrapped per recipient with RSA-OAEP, and the keystore only protects the RSA private key that opens that wrapping.
- The identity of a key is the same everywhere: the `key_id` stored in `metadata` is the fingerprint used in the D3 recipient entry (RSA) or the `signer_id` used in D5 (Ed25519), and it is checked after decryption. A keystore cannot hold a key that does not match its own `key_id`.

### Security assumptions

- The password is chosen by the user and kept secret. The system does not enforce a password policy.
- The operating system is free of malware and keyloggers that read keys from memory or capture the password (D1, Trust Assumptions).
- The operating system provides a secure source of randomness (D1, Trust Assumptions).
- Attackers can read, copy and modify the keystore and its backups, and can guess passwords offline (D1, Attacker Capabilities).
- Public keys are obtained through a reliable channel (D1, Trust Assumptions).

## Threat Model Alignment (D1)

**What if an attacker steals the keystore?** The attacker has the four files but no password. The key inside is encrypted with AES-256-GCM under an Argon2id-derived key, so the attacker has to guess the password offline, and each guess costs 64 MiB of memory and three passes of Argon2id. The attacker cannot modify the files to help: any change makes the tag fail. If the password is strong, the private key stays confidential, and a stolen keystore alone cannot decrypt anything shared with the owner.

**What if a password is weak?** The key is exactly as safe as the password. Argon2id makes each guess more expensive but cannot stop an attacker from trying the most common passwords first, so a keystore protected by a guessable password can be opened offline, and from then on the attacker has the key. The system does not check password strength; the user must choose a long passphrase.

**What if a device is compromised?** If the device is infected while the user is working (malware, keylogger, memory dump), the password and the decrypted key can be taken, and the keystore gives no protection. D1 states this as an assumption: the operating system is free of malware. A device that is only stolen while powered off is the case of a stolen keystore, described above.

| The system protects against | The system does NOT protect against |
|---|---|
| A stolen keystore or backup without the password | Weak or reused passwords |
| Any modification of the four keystore files | Malware, keyloggers or memory reading on a running device |
| Moving the encrypted key into another keystore | A lost password: there is no recovery |
| Using an RSA key to sign or an Ed25519 key to decrypt | Data an attacker copied before a key was rotated |
| Overwriting an existing keystore by mistake | Revoking a key: there is no revocation service |
| A corrupted backup being restored | Old backups that still open with an old password |

## Security Discussion

**Why encrypt private keys?** Every other protection in the vault depends on them: whoever has a private key can decrypt the files shared with its owner (D3) or sign in the owner's name (D5). D1 lists private keys as a critical asset. A keystore sits on a disk, in a backup or in a cloud folder, places D1 treats as reachable by attackers, and a plaintext key file would give a thief permanent access with a single copy. Encrypting it means the attacker needs two things, the files and the password.

**What happens if the password is weak?** The Argon2id cost slows down each guess, but a short or common password is still found by guessing, offline and without the system noticing. After that, the attacker has the private key, and everything described above for a compromised key applies: the files shared with that key can be read and signatures can be forged until the key is rotated. This is the main limit of password-based protection.

**What are the limitations of the system?**

- The key is only as strong as the password, and no password policy is enforced.
- A password that is lost cannot be recovered, and there is no escrow.
- Python cannot reliably wipe memory, so the decrypted key and the password stay in memory until they are freed.
- A compromised device defeats the keystore (D1 assumption).
- There is no revocation service: rotation and compromise response rely on telling recipients out of band.
- There is no limit on guessing, because the attack is offline; only the cost of Argon2id slows it down.
- Argon2id needs a `cryptography` build whose OpenSSL supports it; otherwise the library raises `UnsupportedAlgorithm`.
- One keystore holds one key, so a user with an RSA key and an Ed25519 key has two keystores.

## Tests

`tests/keystore/test_keystore.py` covers the five required cases, plus checks for the D3 and D5 integration, the password prompt and the identity rules.

| # | Case | Expected result | Tests |
|---|------|-----------------|-------|
| 1 | Correct password | Key unlocked, and it decrypts a D3 container (RSA) or signs a D5 container (Ed25519) | `test_correct_password_access_granted`, `test_ed25519_key_works_with_d5`, `test_password_is_asked_when_not_given` |
| 2 | Wrong password | `KeystoreAccessError`, no chained cause | `test_wrong_password_denied` |
| 3 | Modified keystore | `KeystoreAccessError` after changing any of the four files, removing one, or swapping the encrypted key from another keystore | `test_modified_keystore_fails`, `test_encrypted_key_swapped_from_another_keystore_fails` |
| 4 | Backup, then restore | The restored keystore opens with the password; a corrupted backup is not restored | `test_backup_restore_works`, `test_corrupted_backup_is_not_restored` |
| 5 | Stolen keystore alone | No file contains the key in the clear; password guesses fail; another key cannot open the shared container | `test_stolen_keystore_alone_cannot_decrypt` |

## Sources

- [RFC 9106: Argon2](https://datatracker.ietf.org/doc/rfc9106/): the parameter options (Section 4) and the 16-byte salt (Section 3.1).
- [`cryptography` 46.0.0 key derivation docs](https://cryptography.io/en/46.0.0/hazmat/primitives/key-derivation-functions/): `Argon2id`, added in version 44.0.0, and its parameters.
- Our D1 document, `secure-digital-document-vault-design.md`: assets, adversaries, assumptions and the attack surface table.
