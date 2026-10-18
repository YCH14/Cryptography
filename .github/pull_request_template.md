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
