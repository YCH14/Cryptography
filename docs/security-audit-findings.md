# Security audit findings

This is the record of what our own reviews found, how each finding was handled and where the evidence is. It is a self-review done by the team, not an external audit. Severities are our own assessment.

## How the system was reviewed

- Every pull request had a review by someone other than its author (see the repository history).
- The attack scenarios S1 to S11 of the threat model were turned into tests and run by hand (changed byte, replay, stripped signature, untrusted signer, non-recipient, wrong password, wrong fingerprint).
- The command line was tried interactively by hand with two users, and a scripted exploration fed random answers to the menu (150 runs) looking for unhandled exceptions.
- The test suite (550 tests) runs in CI on Python 3.11 and 3.12.

## Findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| F1 | High | The command line opened containers **without a signature** with only a warning, so anyone able to modify a stored file could remove the signature and deliver it unsigned (scenario S5) | Fixed in PR #28 |
| F2 | Medium | `encrypt` did not sign unless asked, so a signature was easy to forget | Fixed in PR #28 |
| F3 | Medium | A contact could be added without a fingerprint (the tool only printed a reminder to confirm it), which left key substitution (S7) to chance | Fixed in PR #28: the fingerprint is required |
| F4 | Medium | Key files had no single accepted encoding (instructor feedback): any PEM, any size, links and overwrites | Fixed in PR #27 |
| F5 | Medium | Replayed containers and older versions of a document were accepted (S6) | Fixed in PRs #20 and #22 |
| F6 | Medium | Output files were written after a separate existence check: a link placed in between was followed, and files were created with the default permissions, so other users on the machine could read them | Fixed in PR #28: exclusive creation, owner-only mode, never through a link |
| F7 | Medium | RSA-OAEP key wrapping did not meet the project constraint and carried padding and key-size cost | Replaced by ECIES on X25519 in PRs #16, #18 and #19 |
| F8 | Low | In D3 a recipient `id` could equal the fingerprint of another recipient, so the lookup was ambiguous | Fixed in D3: the fingerprint form is reserved and the lookup is deterministic (`tests/hybrid/test_key_identification.py`) |
| F9 | Medium | In the interactive menu, a mistyped answer to a yes/no question counted as "no": a typo on "sign the file?" produced an unsigned file without warning. Found by hand in manual testing | Fixed in PR #29: the question is asked again |
| F10 | Low | `revoke` revoked a key before checking that the revocation notice could be written, which could leave a revoked key without its notice | Fixed in PR #29 |
| F11 | Low | A test searched random base64 for the word "rsa" and failed intermittently | Fixed in PR #23 |
| F12 | Low | CLI tests wrote the revocation notice into the current directory, leaving files in the repository | Fixed in the documentation PR (tests now run in a temporary folder) |

Evidence for F1 to F3 and F6 is in `D6-Key-Management/tests/cli/test_cli_hardening.py`; for F4 in `tests/hybrid/test_key_files.py` and `tests/signatures/test_signer_key_files.py`; for F5 in `tests/signatures/test_replay.py`, `test_rollback.py` and `tests/keystore/test_trust_replay.py`; for F7 in `tests/hybrid/test_ecies.py`; for F9 and F10 in `tests/cli/test_cli_hardening.py` (menu tests and `test_revoke_never_revokes_when_the_notice_cannot_be_written`).

A review of the keystore module found no defects: private keys are never written in plaintext, the format is authenticated, all failures share one error, and restore checks the backup before replacing anything.

## Open items and residual risks

These are known and accepted for this delivery.

| ID | Item | Why it remains |
|---|---|---|
| R1 | With `--force`, the command line deletes the old output file before writing the new one; if the write fails, the old file is lost. A write to a temporary file followed by an atomic rename would fix it | Needs a change to the writer; low impact because `--force` is explicit |
| R2 | The command line writes with a single `os.write` and does not loop over partial writes or remove a partial file | Same writer; the library functions do clean up |
| R3 | `decrypt` asks for the password before it refuses an unsigned file | Usability only; nothing is decrypted |
| R4 | File modes (`0600`, `0700`) have no effect on Windows | Platform limit; the keystore is still encrypted |
| R5 | A file opened with `--allow-unsigned` skips the replay check, because it has no `container_id` to record | Inherent to unsigned files; the output says that the origin was not checked |
| R6 | Replay protection is a local file: whoever can delete it makes the recipient forget (assumption AS5) | Design limit, documented in D1 |
| R7 | A signer id names a key, not a person, and trust depends on people comparing fingerprints (assumption AS6) | There is no certificate authority in this design |
| R8 | A compromised endpoint can read unlocked keys from memory | Out of scope in D1 |
| R9 | The storage can still delete, withhold or delay containers (availability) | Out of scope in D1 |
