"""Scripted demo of the Secure Digital Document Vault.

Runs the real command line (``python -m vault``) for three users, Alice, Bob and Carol, in a fresh
temporary folder, and shows the normal flow followed by every failure case of the threat model.

    python examples/demo.py          (from the repository root, with `cryptography` installed)

The password is fixed in this script so that it can run without typing. A real user is asked for it
with a hidden prompt, and a password must never be written in a script.
"""

from __future__ import annotations

import contextlib
import getpass
import io
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "D6-Key-Management"))

from vault.cli import Workspace, main  # noqa: E402

PASSWORD = {"value": "correct horse battery"}
getpass.getpass = lambda prompt="": PASSWORD["value"]
ALICE, BOB, CAROL = "alice", "bob", "carol"


def vault(home: str, *args: str, show: bool = True) -> int:
    """Run ``python -m vault --home HOME ARGS`` and print what it said."""
    if show:
        print("\n$ python -m vault --home", home, *args)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = main(["--home", home, *args])
    if show:
        print((out.getvalue() + err.getvalue()).strip()[-900:])
        print("-> exit status", status)
    return status


def key_id(home: str, kind: str) -> str:
    return Workspace(home).ring(kind).active_entry().key_id


def title(text: str) -> None:
    print(f"\n{'=' * 8} {text}")


def main_demo() -> None:
    os.chdir(tempfile.mkdtemp(prefix="vault-demo-"))
    print("Working folder:", os.getcwd())
    Path("report.pdf").write_bytes(b"%PDF-1.7 quarterly report (demo content)")

    title("1. Every user creates keys (an X25519 key to decrypt, an Ed25519 key to sign)")
    for name in (ALICE, BOB, CAROL):
        vault(name, "init", "--owner", name, show=False)
    print("Created:", ALICE, BOB, CAROL)

    title("2. Sharing: public keys travel as files, fingerprints through another channel")
    vault(ALICE, "export", "encrypt", "--out", "alice-enc.pem", show=False)
    vault(ALICE, "export", "sign", "--out", "alice-sign.pem", show=False)
    vault(BOB, "export", "encrypt", "--out", "bob-enc.pem", show=False)
    vault(ALICE, "contacts", "add", "bob", "bob-enc.pem", "--fingerprint", key_id(BOB, "encrypt"))
    vault(BOB, "contacts", "add", "alice", "alice-enc.pem", "--fingerprint", key_id(ALICE, "encrypt"), show=False)
    vault(BOB, "trust", "add", "alice", "alice-sign.pem", "--fingerprint", key_id(ALICE, "sign"))

    title("3. Encryption: the file is encrypted once, signed, and readable by Alice and Bob")
    vault(ALICE, "encrypt", "report.pdf", "--to", "bob")
    vault(BOB, "inspect", "report.pdf.vault")

    title("4. Secure storage: the private keys on disk are encrypted (Argon2id + AES-256-GCM)")
    keystore = Path(ALICE, "x25519", "keys", key_id(ALICE, "encrypt"))
    for name in ("kdf_parameters", "metadata"):
        print(f"\n{name}:", (keystore / name).read_text())
    print("\nencrypted_private_key (first 48 bytes):", (keystore / "encrypted_private_key").read_bytes()[:48].hex())

    title("5. Sharing works only for the recipient")
    print("Carol is not a recipient:")
    vault(CAROL, "decrypt", "report.pdf.vault", "--out", "carol.pdf")
    print("\nBob is a recipient, and trusts Alice's signing key:")
    vault(BOB, "decrypt", "report.pdf.vault", "--out", "bob.pdf")
    print("Decrypted file equals the original:", Path("bob.pdf").read_bytes() == Path("report.pdf").read_bytes())

    title("6. Failure handling: every case exits with status 1 and writes no file")
    print("\n-- replay: the same container delivered again")
    vault(BOB, "decrypt", "report.pdf.vault", "--out", "replay.pdf")

    print("\n-- wrong password")
    PASSWORD["value"] = "not the password"
    vault(BOB, "decrypt", "report.pdf.vault", "--out", "wrong.pdf", "--no-replay-check")
    PASSWORD["value"] = "correct horse battery"

    print("\n-- one changed byte in the encrypted file")
    raw = bytearray(Path("report.pdf.vault").read_bytes())
    raw[raw.index(b'"ciphertext"') + 20] ^= 1
    Path("modified.vault").write_bytes(bytes(raw))
    vault(BOB, "decrypt", "modified.vault", "--out", "modified.pdf", "--no-replay-check")

    print("\n-- one changed character in the signature")
    document = json.loads(Path("report.pdf.vault").read_text())
    sig = document["signature"]
    document["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    Path("badsig.vault").write_text(json.dumps(document))
    vault(BOB, "decrypt", "badsig.vault", "--out", "badsig.pdf", "--no-replay-check")

    print("\n-- the signature removed")
    document = json.loads(Path("report.pdf.vault").read_text())
    for field in ("signature", "signer_id", "container_id"):
        document.pop(field)
    Path("unsigned.vault").write_text(json.dumps(document))
    vault(BOB, "decrypt", "unsigned.vault", "--out", "unsigned.pdf", "--no-replay-check")

    print("\n-- a contact with a wrong fingerprint")
    vault(ALICE, "contacts", "add", "bobby", "bob-enc.pem", "--fingerprint", "ab" * 32)

    leftovers = [n for n in ("carol.pdf", "replay.pdf", "wrong.pdf", "modified.pdf", "badsig.pdf", "unsigned.pdf") if os.path.exists(n)]
    print("\nFiles created by the failed attempts (must be empty):", leftovers)


if __name__ == "__main__":
    main_demo()
