## Summary

<!-- Which deliverable/change does this PR implement? -->

## Cryptography checklist (reviewer)

- [ ] Only `cryptography` primitives are used (nothing hand-rolled).
- [ ] All randomness comes from `os.urandom` / `secrets` (never `random`, never fixed seeds).
- [ ] No (key, nonce) pair can ever repeat; a new DEK per file.
- [ ] Format metadata and parameters are bound as AAD.
- [ ] Decryption failures raise a generic `DecryptionFailedError`, without chaining the cause.
- [ ] No plaintext is written without verification; no temporary files or leftovers after a failure.
- [ ] No keys, real containers or secrets in the diff.
- [ ] New/updated tests and CI is green.
- [ ] Documentation (`docs/`) updated, including the threat model.

## Authorship and review

- Author: @
- Reviewer (different from the author): @
- Was any content generated with an AI tool? State which tool and which parts.

### Only if the PR touches hybrid encryption (D3)

- [ ] Only the DEK is encrypted with the public key (RSA-OAEP-SHA256); the file is always encrypted with AEAD.
- [ ] The recipient list, `id`, `fingerprint`, `encrypted_dek` and algorithm identifiers are bound as AAD.
- [ ] `id` and `fingerprint` occupy disjoint spaces and the entry lookup is deterministic, with no fallback.
- [ ] Tests cover: 2 recipients, unauthorized user, tampered recipient list, wrong private key and removed recipient.
