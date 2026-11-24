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


def test_inspect_shows_public_fields_without_password(alice, tmp_path, capsys, monkeypatch):
    vault = make_vault(alice, tmp_path)
    capsys.readouterr()

    def boom(prompt=""):
        raise AssertionError("inspect must not ask for a password")

    monkeypatch.setattr(getpass, "getpass", boom)
    assert run(alice, "inspect", str(vault)) == 0
    out = capsys.readouterr().out
    assert "VLT3" in out and "alice" in out and "<- tú" in out and "Firma:          sí" in out
    assert "secret" not in out and "ciphertext" not in out


def test_inspect_works_without_identity_and_marks_unsigned(alice, tmp_path, capsys):
    vault = make_vault(alice, tmp_path, "--no-sign")
    capsys.readouterr()
    assert run(tmp_path / "nobody", "inspect", str(vault)) == 0
    out = capsys.readouterr().out
    assert "NO" in out and "<- tú" not in out


def test_inspect_refuses_other_files_and_escapes_control_characters(alice, tmp_path, capsys):
    other = tmp_path / "other.vault"
    other.write_bytes(b"hello")
    assert run(alice, "inspect", str(other)) == 1
    vault = make_vault(alice, tmp_path)
    document = json.loads(vault.read_bytes())
    document["filename"] = "evil\x1b[31m.txt"
    vault.write_bytes(json.dumps(document).encode())
    capsys.readouterr()
    assert run(alice, "inspect", str(vault)) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "x1b" in out


def _menu(monkeypatch, *answers: str) -> None:
    typed = iter(answers)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(typed))


def test_menu_decrypt_offers_to_open_an_unsigned_file(alice, tmp_path, monkeypatch, capsys):
    vault = make_vault(alice, tmp_path, "--no-sign")
    _menu(monkeypatch, "2", str(vault), "n", "0")
    assert run(alice) == 0
    assert not (tmp_path / "note.txt").exists()
    assert "No se descifró nada" in capsys.readouterr().out
    _menu(monkeypatch, "2", str(vault), "y", "0")
    assert run(alice) == 0
    assert (tmp_path / "note.txt").read_bytes() == b"secret"


def test_menu_decrypt_offers_to_skip_the_replay_check_only_after_a_replay(alice, tmp_path, monkeypatch, capsys):
    vault = make_vault(alice, tmp_path)
    _menu(monkeypatch, "2", str(vault), "0")
    assert run(alice) == 0
    (tmp_path / "note.txt").unlink()
    _menu(monkeypatch, "2", str(vault), "n", "0")
    assert run(alice) == 0
    assert not (tmp_path / "note.txt").exists()
    _menu(monkeypatch, "2", str(vault), "y", "0")
    assert run(alice) == 0
    assert (tmp_path / "note.txt").read_bytes() == b"secret"


def test_inspect_shows_creation_time(alice, tmp_path, capsys):
    vault = make_vault(alice, tmp_path)
    capsys.readouterr()
    assert run(alice, "inspect", str(vault)) == 0
    out = capsys.readouterr().out
    assert "Creado:" in out and "UTC" in out


def test_menu_encrypt_can_label_document_versions(alice, tmp_path, monkeypatch):
    doc = tmp_path / "c.txt"
    doc.write_bytes(b"v1")
    _menu(monkeypatch, "1", str(doc), "-", "y", "y", "contrato", "2", "0")
    assert run(alice) == 0
    document = json.loads((tmp_path / "c.txt.vault").read_bytes())
    assert document["document_id"] == "contrato" and document["document_version"] == 2


def test_menu_asks_again_for_a_short_or_different_password(tmp_path, monkeypatch, capsys):
    answers = iter(["1234", "correct horse battery", "other one here", "correct horse battery", "correct horse battery"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))
    _menu(monkeypatch, "y", "alice", "0")
    assert run(tmp_path / "new") == 0
    out = capsys.readouterr().out
    assert "al menos 8" in out and "no coinciden" in out
    assert Workspace(tmp_path / "new").initialized()


def test_subcommands_still_fail_at_once_on_a_short_password(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "1234")
    assert run(tmp_path / "x", "init", "--owner", "x") == 1
    assert "al menos 8" in capsys.readouterr().err


def test_menu_expands_a_tilde_in_typed_paths(alice, tmp_path, monkeypatch):
    home = tmp_path / "fakehome"
    home.mkdir()
    (home / "doc.txt").write_bytes(b"in home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    _menu(monkeypatch, "1", "~/doc.txt", "-", "y", "n", "0")
    assert run(alice) == 0
    assert (home / "doc.txt.vault").exists()


def test_menu_decrypt_asks_what_to_do_when_the_output_exists(alice, tmp_path, monkeypatch):
    vault = make_vault(alice, tmp_path)
    (tmp_path / "note.txt").write_bytes(b"original")
    _menu(monkeypatch, "2", str(vault), "n", str(tmp_path / "copy.txt"), "0")
    assert run(alice) == 0
    assert (tmp_path / "copy.txt").read_bytes() == b"secret"
    assert (tmp_path / "note.txt").read_bytes() == b"original"
    _menu(monkeypatch, "2", str(vault), "y", "n", "0")  # replace, then refuse the replay override
    assert run(alice) == 0
    assert (tmp_path / "note.txt").read_bytes() == b"original"


def test_menu_encrypt_asks_what_to_do_when_the_vault_file_exists(alice, tmp_path, monkeypatch):
    doc = tmp_path / "d.txt"
    doc.write_bytes(b"one")
    (tmp_path / "d.txt.vault").write_bytes(b"old")
    _menu(monkeypatch, "1", str(doc), "-", "y", "n", "n", str(tmp_path / "other.vault"), "0")
    assert run(alice) == 0
    assert (tmp_path / "d.txt.vault").read_bytes() == b"old"
    assert (tmp_path / "other.vault").exists()
    _menu(monkeypatch, "1", str(doc), "-", "y", "n", "y", "0")
    assert run(alice) == 0
    assert (tmp_path / "d.txt.vault").read_bytes() != b"old"


def test_menu_share_key_asks_when_the_file_exists(alice, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _menu(monkeypatch, "5", "1", "0")
    assert run(alice) == 0
    made = [p for p in tmp_path.glob("*.pub.pem")]
    assert len(made) == 1
    first = made[0].read_bytes()
    made[0].write_bytes(b"marker")
    _menu(monkeypatch, "5", "1", "n", str(tmp_path / "copy.pem"), "0")
    assert run(alice) == 0
    assert made[0].read_bytes() == b"marker" and (tmp_path / "copy.pem").read_bytes() == first


def test_revoke_never_revokes_when_the_notice_cannot_be_written(alice, tmp_path, capsys):
    notice = tmp_path / "aviso.txt"
    notice.write_text("exists")
    assert run(alice, "revoke", "encrypt", "--reason", "x", "--out", str(notice)) == 1
    capsys.readouterr()
    assert run(alice, "keys") == 0
    assert "revoked" not in capsys.readouterr().out
    assert notice.read_text() == "exists"


def test_menu_backup_asks_again_when_the_folder_exists(alice, tmp_path, monkeypatch):
    (tmp_path / "bk").mkdir()
    _menu(monkeypatch, "8", str(tmp_path / "bk"), str(tmp_path / "bk2"), "0")
    assert run(alice) == 0
    assert (tmp_path / "bk2").exists()


def test_menu_version_asks_again_on_a_non_number(alice, tmp_path, monkeypatch):
    doc = tmp_path / "c.txt"
    doc.write_bytes(b"v")
    _menu(monkeypatch, "1", str(doc), "-", "y", "y", "contrato", "abc", "0", "3", "n", "0")
    assert run(alice) == 0
    assert json.loads((tmp_path / "c.txt.vault").read_bytes())["document_version"] == 3


def test_menu_confirmation_asks_again_on_a_typo_instead_of_dropping_the_signature(alice, tmp_path, monkeypatch):
    doc = tmp_path / "t.txt"
    doc.write_bytes(b"x")
    _menu(monkeypatch, "1", str(doc), "-", "s}", "s", "n", "0")  # typo, then yes to signing
    assert run(alice) == 0
    assert "signature" in json.loads((tmp_path / "t.txt.vault").read_bytes())


def test_menu_declining_an_override_says_nothing_was_decrypted_without_mentioning_flags(alice, tmp_path, monkeypatch, capsys):
    vault = make_vault(alice, tmp_path)
    _menu(monkeypatch, "2", str(vault), "0")
    assert run(alice) == 0
    (tmp_path / "note.txt").unlink()
    capsys.readouterr()
    _menu(monkeypatch, "2", str(vault), "n", "0")
    assert run(alice) == 0
    out = capsys.readouterr()
    assert "No se descifró nada" in out.out
    assert "--" not in out.out + out.err
    assert not (tmp_path / "note.txt").exists()


def test_menu_revoke_without_an_active_key_fails_before_asking_more_and_names_menu_entries(alice, monkeypatch, capsys):
    _menu(monkeypatch, "4", "3", "1", "-", "prueba", "n", "0", "0")
    assert run(alice) == 0
    capsys.readouterr()
    asked = []
    typed = iter(["4", "3", "1", "-", "0", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt="": (asked.append(prompt), next(typed))[1])
    assert run(alice) == 0
    out = capsys.readouterr().out
    assert "Crear llave nueva" in out
    assert not any("Motivo" in p for p in asked)


def test_menu_can_restore_a_backup_into_an_empty_home(alice, tmp_path, monkeypatch, capsys):
    backup = tmp_path / "bk"
    assert run(alice, "backup", str(backup)) == 0
    new_home = tmp_path / "other-computer"
    _menu(monkeypatch, "n", "s", str(tmp_path / "not-a-backup"), "n", "s", str(backup), "0")
    assert run(new_home) == 0
    out = capsys.readouterr().out
    assert "no parece una copia de seguridad" in out and "restaurada" in out
    assert Workspace(new_home).initialized() and Workspace(new_home).owner() == "alice"
