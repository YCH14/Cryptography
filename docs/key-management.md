# Key management strategy

Full design: [`D6-Key-Management/docs/key_management_d6.md`](../D6-Key-Management/docs/key_management_d6.md). This page summarizes it.

## Keys

A user has two independent key pairs: an **X25519** pair that unwraps file keys (D3) and an **Ed25519** pair that signs containers (D5). Only these two types are accepted; the keystore and the key import code refuse an RSA key. The identity of a key (`key_id`) is the SHA-256 of its raw 32-byte public key, so it is the same value as the recipient fingerprint and the signer id, and the code recomputes it after unlocking.

## Storage

Each private key lives in a keystore directory of four files:

| File | Content |
|---|---|
| `encrypted_private_key` | 12-byte nonce, then AES-256-GCM ciphertext and tag of the PKCS#8 key |
| `salt` | 16 random bytes |
| `kdf_parameters` | Argon2id parameters: 3 iterations, 4 lanes, 65536 KiB |
| `metadata` | Version, owner, key type, `key_id`, creation time |

The key is derived from the password with Argon2id. The format name, `metadata`, `kdf_parameters` and the salt are the AAD of the encryption, so a change to any file makes the unlock fail. The keystore is built in a temporary folder and renamed, files are created with owner-only permissions where the system supports it, an existing keystore is never overwritten, and a private key is never written to a file without a password. Passwords are read with `getpass` and the command line requires at least 8 characters.

## Sharing public keys

Public keys travel as `.pem` files: a regular file of at most 16 KiB with exactly one PEM block of the expected type. **A key is accepted only together with its fingerprint, confirmed through another channel** (`contacts add` for encryption keys, `trust add` for signing keys). A mismatch refuses the key. This is the only protection against a substituted key (threat T6), and it is a human step: the software enforces it but cannot create trust.

## Lifecycle

| Operation | What happens |
|---|---|
| Rotate | A new key becomes active; the old one is retired but kept, so old files still open |
| Revoke | The key is blocked for normal use and a revocation notice is written. Recovering an old file needs an explicit decision (`--allow-revoked`, or the question in the menu) |
| Trusted signers | The recipient keeps a file of signing keys it trusts. A key is added only with the confirmed fingerprint; it can be replaced (the old key becomes superseded) or revoked, and a revocation notice from the owner can be imported |
| Own signing key | `init` and `rotate sign` make the owner trust their own signing key, so they can open what they encrypted |
| Backup and restore | `backup` copies the encrypted keystore (never the replay record); `restore` refuses to restore on top of an existing identity (the library function also unlocks the backup with the password before using it; the command line only checks the key files, so open a file afterwards to confirm the password) |

After a compromise the order is: revoke the key, rotate to a new one, share the new public key with a fingerprint through another channel, and re-encrypt what still matters.

## Limits

- A lost password cannot be recovered: only the owner of the password can open the keystore.
- A compromised endpoint can read unlocked keys from memory (out of scope).
- Trust depends on people comparing fingerprints correctly.
