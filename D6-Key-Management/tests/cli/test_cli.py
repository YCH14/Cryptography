"""Tests for the command-line interface (vault.cli): two users exchange files end to end."""

from __future__ import annotations

import getpass
from pathlib import Path

import pytest

from vault.cli import main

PW = "correct horse battery"


@pytest.fixture(autouse=True)
def passwords(monkeypatch):
    """Answer every getpass prompt with PW (the confirmation prompt gets PW too)."""
    answers = {"value": PW}
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": answers["value"])
    return answers


def run(home: Path, *args: str) -> int:
    return main(["--home", str(home), *args])


@pytest.fixture
def users(tmp_path):
    alice, bob = tmp_path / "alice", tmp_path / "bob"
    assert run(alice, "init", "--owner", "alice") == 0
    assert run(bob, "init", "--owner", "bob") == 0
    return alice, bob, tmp_path


def exchange_keys(alice: Path, bob: Path, tmp: Path) -> None:
    """Bob gets Alice's encryption key; Alice gets Bob's. Bob also trusts Alice's signing key."""
    assert run(alice, "export", "encrypt", "--out", str(tmp / "alice-enc.pem")) == 0
    assert run(alice, "export", "sign", "--out", str(tmp / "alice-sign.pem")) == 0
    assert run(bob, "export", "encrypt", "--out", str(tmp / "bob-enc.pem")) == 0
    assert run(alice, "contacts", "add", "bob", str(tmp / "bob-enc.pem"),
               "--fingerprint", enc_fingerprint(bob)) == 0
    assert run(bob, "contacts", "add", "alice", str(tmp / "alice-enc.pem"),
               "--fingerprint", enc_fingerprint(alice)) == 0


def enc_fingerprint(home: Path) -> str:
    from vault.cli import Workspace

    return Workspace(home).ring("encrypt").active_entry().key_id


def alice_sign_fingerprint(alice: Path) -> str:
    from vault.cli import Workspace

    return Workspace(alice).ring("sign").active_entry().key_id


def test_init_creates_keys_and_refuses_second_identity(users, capsys):
    alice, _, _ = users
    assert run(alice, "init", "--owner", "alice") == 1
    assert "Ya existe" in capsys.readouterr().err
    assert run(alice, "keys") == 0
    out = capsys.readouterr().out
    assert "active" in out and "cifrado" in out and "firma" in out


def test_init_rejects_short_password(tmp_path, passwords, capsys):
    passwords["value"] = "short"
    assert run(tmp_path / "x", "init", "--owner", "x") == 1
    assert "al menos" in capsys.readouterr().err
    assert not (tmp_path / "x" / "x25519").exists()


def test_encrypt_for_self_and_decrypt_roundtrip(users):
    alice, _, tmp = users
    doc = tmp / "note.txt"
    doc.write_bytes(b"top secret")
    assert run(alice, "encrypt", str(doc)) == 0
    vault = tmp / "note.txt.vault"
    assert vault.exists() and b"top secret" not in vault.read_bytes()
    doc.unlink()
    assert run(alice, "decrypt", str(vault)) == 0
    assert doc.read_bytes() == b"top secret"


def test_decrypt_never_overwrites_without_force(users, capsys):
    alice, _, tmp = users
    doc = tmp / "note.txt"
    doc.write_bytes(b"one")
    assert run(alice, "encrypt", str(doc)) == 0
    doc.write_bytes(b"two")
    assert run(alice, "decrypt", str(tmp / "note.txt.vault")) == 1
    assert doc.read_bytes() == b"two"
    assert run(alice, "encrypt", str(doc)) == 1  # the .vault file exists too
    assert "ya existe" in capsys.readouterr().err
    assert run(alice, "decrypt", str(tmp / "note.txt.vault"), "--force") == 0
    assert doc.read_bytes() == b"one"


def test_wrong_password_is_refused(users, passwords, capsys):
    alice, _, tmp = users
    doc = tmp / "a.txt"
    doc.write_bytes(b"x")
    assert run(alice, "encrypt", str(doc)) == 0
    doc.unlink()
    passwords["value"] = "not the password"
    assert run(alice, "decrypt", str(tmp / "a.txt.vault")) == 1
    assert "Contraseña incorrecta" in capsys.readouterr().err
    assert not doc.exists()


def test_share_with_contact_and_stranger_cannot_open(users, tmp_path, capsys):
    alice, bob, tmp = users
    exchange_keys(alice, bob, tmp)
    carol = tmp / "carol"
    assert run(carol, "init", "--owner", "carol") == 0
    doc = tmp / "plan.txt"
    doc.write_bytes(b"for bob")
    assert run(alice, "encrypt", str(doc), "--to", "bob", "--out", str(tmp / "plan.vault")) == 0
    out = tmp / "from-alice.txt"
    assert run(bob, "trust", "add", "alice", str(tmp / "alice-sign.pem"),
               "--fingerprint", alice_sign_fingerprint(alice)) == 0
    assert run(bob, "decrypt", str(tmp / "plan.vault"), "--out", str(out)) == 0
    assert out.read_bytes() == b"for bob"
    assert run(carol, "decrypt", str(tmp / "plan.vault"), "--out", str(tmp / "c.txt")) == 1
    assert not (tmp / "c.txt").exists()


def test_signed_file_needs_trusted_signer_then_replay_is_detected(users, capsys):
    alice, bob, tmp = users
    exchange_keys(alice, bob, tmp)
    doc = tmp / "contract.txt"
    doc.write_bytes(b"signed content")
    assert run(alice, "encrypt", str(doc), "--to", "bob", "--out", str(tmp / "c.vault")) == 0
    capsys.readouterr()

    # Bob does not trust Alice yet.
    assert run(bob, "decrypt", str(tmp / "c.vault"), "--out", str(tmp / "o1.txt")) == 1
    assert "no confías" in capsys.readouterr().err
    # A wrong fingerprint is refused; the right one is accepted.
    assert run(bob, "trust", "add", "alice", str(tmp / "alice-sign.pem"), "--fingerprint", "00" * 32) == 1
    fp = alice_sign_fingerprint(alice)
    assert run(bob, "trust", "add", "alice", str(tmp / "alice-sign.pem"), "--fingerprint", fp) == 0
    assert run(bob, "trust", "list") == 0
    assert "alice" in capsys.readouterr().out

    assert run(bob, "decrypt", str(tmp / "c.vault"), "--out", str(tmp / "o1.txt")) == 0
    assert (tmp / "o1.txt").read_bytes() == b"signed content"
    # The same container again is a replay.
    assert run(bob, "decrypt", str(tmp / "c.vault"), "--out", str(tmp / "o2.txt")) == 1
    assert "ya fue aceptado" in capsys.readouterr().err
    assert run(bob, "decrypt", str(tmp / "c.vault"), "--out", str(tmp / "o2.txt"), "--no-replay-check") == 0


def test_tampered_container_is_refused(users):
    alice, _, tmp = users
    doc = tmp / "a.txt"
    doc.write_bytes(b"data")
    assert run(alice, "encrypt", str(doc)) == 0
    vault = tmp / "a.txt.vault"
    raw = bytearray(vault.read_bytes())
    raw[raw.index(b'"ciphertext"') + 20] ^= 0x01
    vault.write_bytes(bytes(raw))
    doc.unlink()
    assert run(alice, "decrypt", str(vault)) == 1
    assert not doc.exists()


def test_rotate_keeps_old_files_readable_and_revoke_blocks_use(users, capsys):
    alice, _, tmp = users
    doc = tmp / "old.txt"
    doc.write_bytes(b"made before rotation")
    assert run(alice, "encrypt", str(doc)) == 0
    assert run(alice, "rotate", "encrypt") == 0
    doc.unlink()
    assert run(alice, "decrypt", str(tmp / "old.txt.vault")) == 0
    assert doc.read_bytes() == b"made before rotation"

    from vault.cli import Workspace

    old_id = Workspace(alice).ring("encrypt").entries()[0].key_id
    assert run(alice, "revoke", "encrypt", "--key", old_id[:10], "--reason", "stolen laptop",
               "--compromised", "--out", str(tmp / "notice.txt")) == 0
    assert b"stolen laptop" in (tmp / "notice.txt").read_bytes()
    doc.unlink()
    assert run(alice, "decrypt", str(tmp / "old.txt.vault"), "--no-replay-check") == 1
    assert not doc.exists()
    assert run(alice, "decrypt", str(tmp / "old.txt.vault"), "--allow-revoked", "--no-replay-check") == 0
    assert doc.read_bytes() == b"made before rotation"


def test_revocation_notice_stops_trusting_signer(users, capsys):
    alice, bob, tmp = users
    exchange_keys(alice, bob, tmp)
    fp = alice_sign_fingerprint(alice)
    assert run(bob, "trust", "add", "alice", str(tmp / "alice-sign.pem"), "--fingerprint", fp) == 0
    assert run(alice, "revoke", "sign", "--reason", "lost", "--out", str(tmp / "n.txt")) == 0
    assert run(bob, "trust", "import-revocation", str(tmp / "n.txt")) == 0
    capsys.readouterr()
    run(bob, "trust", "list")
    assert "revoked" in capsys.readouterr().out


def test_contact_with_wrong_fingerprint_or_bad_name_is_refused(users):
    alice, bob, tmp = users
    assert run(bob, "export", "encrypt", "--out", str(tmp / "bob.pem")) == 0
    good = enc_fingerprint(bob)
    assert run(alice, "contacts", "add", "bob", str(tmp / "bob.pem"), "--fingerprint", "ab" * 32) == 1
    assert run(alice, "contacts", "add", "../evil", str(tmp / "bob.pem"), "--fingerprint", good) == 1
    assert run(alice, "contacts", "add", "alice", str(tmp / "bob.pem"), "--fingerprint", good) == 1
    assert not list((alice / "contacts").glob("*.pem"))


def test_signing_key_is_not_accepted_as_a_contact(users):
    alice, _, tmp = users
    assert run(alice, "export", "sign", "--out", str(tmp / "sign.pem")) == 0
    assert run(alice, "contacts", "add", "x", str(tmp / "sign.pem"),
               "--fingerprint", alice_sign_fingerprint(alice)) == 1


def test_backup_and_restore(users):
    alice, _, tmp = users
    doc = tmp / "d.txt"
    doc.write_bytes(b"keep me")
    assert run(alice, "encrypt", str(doc)) == 0
    assert run(alice, "backup", str(tmp / "bk")) == 0
    assert run(alice, "backup", str(tmp / "bk")) == 1  # destination exists
    restored = tmp / "restored"
    assert run(restored, "restore", str(tmp / "bk")) == 0
    doc.unlink()
    assert run(restored, "decrypt", str(tmp / "d.txt.vault")) == 0
    assert doc.read_bytes() == b"keep me"
    assert run(restored, "restore", str(tmp / "bk")) == 1  # never overwrites


def test_commands_need_an_identity(tmp_path, capsys):
    assert run(tmp_path / "empty", "keys") == 1
    assert "Todavía no hay una identidad" in capsys.readouterr().err


def test_interactive_menu_encrypts_and_decrypts(users, monkeypatch, capsys):
    alice, _, tmp = users
    doc = tmp / "menu.txt"
    doc.write_bytes(b"via menu")
    # 1) encrypt: file, recipients (none), sign? no ; 0) exit
    typed = iter([
        "1", str(doc), "-", "y",
        "0",
    ])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(typed))
    assert run(alice) == 0
    assert (tmp / "menu.txt.vault").exists()
    doc.unlink()
    typed = iter(["2", str(tmp / "menu.txt.vault"), "0"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(typed))
    assert run(alice) == 0
    assert doc.read_bytes() == b"via menu"


def test_menu_survives_errors(users, monkeypatch, capsys):
    alice, _, tmp = users
    typed = iter(["1", str(tmp / "missing.txt"), "-", "n", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(typed))
    assert run(alice) == 0
    assert "No encuentro el archivo" in capsys.readouterr().out
