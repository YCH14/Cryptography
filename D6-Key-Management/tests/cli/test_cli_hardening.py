"""Hardening of the command line: signed by default, unsigned refused, strict files."""

from __future__ import annotations

import base64
import getpass
import json
import os
import stat
from pathlib import Path

import pytest

from vault.cli import Workspace, main

PW = "correct horse battery"


@pytest.fixture(autouse=True)
def passwords(monkeypatch):
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": PW)


def run(home: Path, *args: str) -> int:
    return main(["--home", str(home), *args])


@pytest.fixture
def alice(tmp_path):
    home = tmp_path / "alice"
    assert run(home, "init", "--owner", "alice") == 0
    return home


def make_vault(alice: Path, tmp: Path, *extra: str) -> Path:
    doc = tmp / "note.txt"
    doc.write_bytes(b"secret")
    assert run(alice, "encrypt", str(doc), *extra) == 0
    doc.unlink()
    return tmp / "note.txt.vault"


def test_encrypt_signs_by_default_and_owner_opens_it(alice, tmp_path, capsys):
    vault = make_vault(alice, tmp_path)
    assert "signature" in json.loads(vault.read_bytes())
    assert run(alice, "decrypt", str(vault)) == 0
    assert (tmp_path / "note.txt").read_bytes() == b"secret"


def test_stripped_signature_is_refused(alice, tmp_path, capsys):
    vault = make_vault(alice, tmp_path)
    document = json.loads(vault.read_bytes())
    for field in ("signature", "signer_id", "signature_algorithm", "container_id"):
        document.pop(field, None)
    vault.write_bytes(json.dumps(document).encode())
    assert run(alice, "decrypt", str(vault)) == 1
    assert "no está firmado" in capsys.readouterr().err
    assert not (tmp_path / "note.txt").exists()


def test_signature_only_stripped_is_refused(alice, tmp_path):
    vault = make_vault(alice, tmp_path)
    document = json.loads(vault.read_bytes())
    document.pop("signature")
    vault.write_bytes(json.dumps(document).encode())
    assert run(alice, "decrypt", str(vault)) == 1
    assert not (tmp_path / "note.txt").exists()


def test_unsigned_needs_explicit_flags_on_both_sides(alice, tmp_path, capsys):
    vault = make_vault(alice, tmp_path, "--no-sign")
    assert "signature" not in json.loads(vault.read_bytes())
    assert "NO" in capsys.readouterr().out
    assert run(alice, "decrypt", str(vault)) == 1
    assert run(alice, "decrypt", str(vault), "--allow-unsigned") == 0
    assert (tmp_path / "note.txt").read_bytes() == b"secret"


def test_signing_key_rotation_keeps_new_files_openable(alice, tmp_path):
    assert run(alice, "rotate", "sign") == 0
    vault = make_vault(alice, tmp_path)
    assert run(alice, "decrypt", str(vault)) == 0


def test_revoked_signing_key_is_no_longer_trusted(alice, tmp_path):
    vault = make_vault(alice, tmp_path)
    assert run(alice, "revoke", "sign", "--reason", "lost", "--out", str(tmp_path / "n.txt")) == 0
    assert run(alice, "decrypt", str(vault), "--no-replay-check") == 1


def test_contact_requires_fingerprint(alice, tmp_path):
    with pytest.raises(SystemExit):
        run(alice, "contacts", "add", "bob", str(tmp_path / "x.pem"))


def test_files_are_created_private_and_never_follow_links(alice, tmp_path):
    vault = make_vault(alice, tmp_path)
    if os.name != "nt":
        assert stat.S_IMODE(vault.stat().st_mode) == 0o600
    doc = tmp_path / "note.txt"
    target = tmp_path / "target.txt"
    target.write_bytes(b"keep")
    try:
        doc.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert run(alice, "decrypt", str(vault), "--force") == 1
    assert target.read_bytes() == b"keep"


def test_oversized_and_non_regular_inputs_are_refused(alice, tmp_path, monkeypatch):
    import vault.cli as cli

    big = tmp_path / "big.vault"
    big.write_bytes(b"x" * 2048)
    monkeypatch.setattr(cli, "MAX_CONTAINER_SIZE", 1024)
    assert run(alice, "decrypt", str(big)) == 1
    assert run(alice, "decrypt", str(tmp_path)) == 1


def test_bad_signer_key_file_is_refused(alice, tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_bytes(b"not a key")
    assert run(alice, "trust", "add", "eve", str(bad), "--fingerprint", "00" * 32) == 1
