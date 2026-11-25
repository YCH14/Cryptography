"""Command-line interface for the vault (D6 and the modules it builds on).

Run it from the ``D6-Key-Management`` folder::

    python -m vault                  # interactive menu: no commands to remember
    python -m vault encrypt a.pdf --to bob --sign   # the same actions as subcommands

Everything the menu does is also a subcommand (``python -m vault --help``), so the
tool can be scripted too.  The CLI only uses the standard library on top of the
vault modules; it does not add any cryptography of its own.

Workspace
---------
All the user's data lives in one folder (``~/.vault`` by default, or ``--home DIR``,
or the ``VAULT_HOME`` environment variable)::

    ~/.vault/
     ├── x25519/            keyring of the encryption key (D3, D6)
     ├── ed25519/           keyring of the signing key (D5, D6)
     ├── public/            public keys (PEM), one per key_id: safe to share
     ├── contacts/          public keys of the people you encrypt for
     ├── trusted_signers.json   signing keys you decided to trust (D6)
     └── replay.json        containers already accepted (D5 ReplayGuard)

Private keys are only ever stored by the keyring, encrypted under the password
(Argon2id + AES-256-GCM).  Passwords are asked with ``getpass``; they are never
accepted as command-line arguments, so they do not end up in the shell history.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import json
import os
import re
import shutil
import stat
import sys
from pathlib import Path
from typing import Callable, Optional, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vault.exceptions import (
    KeystoreAccessError,
    KeystoreError,
    ReplayDetectedError,
    RollbackDetectedError,
    UntrustedSignerError,
    VaultError,
)
from vault.hybrid import (
    MAX_PLAINTEXT_SIZE,
    encrypt_bytes_hybrid,
    export_public_key_pem,
    generate_x25519_keypair,
    get_public_key_fingerprint,
    load_public_key_file,
)
from vault.hybrid.keys import looks_like_fingerprint
from vault.keystore import KeyEntry, Keyring, TrustedSigners, verify_with_trusted_signers
from vault.signatures import (
    ReplayGuard,
    generate_ed25519_keypair,
    get_signer_id,
    load_signer_public_key_file,
    sign_container,
)

__all__ = ["main", "Workspace", "CliError"]

MIN_PASSWORD_LENGTH = 8
VAULT_SUFFIX = ".vault"
MAX_CONTAINER_SIZE = 2 * MAX_PLAINTEXT_SIZE + 1024 * 1024
"""Largest container ``decrypt`` reads: base64 and the JSON fields make it larger than the file inside."""
_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")

# "encrypt" -> the X25519 keyring (D3); "sign" -> the Ed25519 keyring (D5).
_KINDS = {"encrypt": ("x25519", "X25519"), "sign": ("ed25519", "Ed25519")}
_KIND_LABEL = {"encrypt": "encryption", "sign": "signing"}


class CliError(Exception):
    """A problem the user can fix; its message is shown as is."""


class UnsignedFileError(CliError):
    """The file has no signature (or it was removed) and the user did not ask to open it anyway."""


# ---------------------------------------------------------------------- #
# Workspace                                                              #
# ---------------------------------------------------------------------- #


class Workspace:
    """Where the user's keys, contacts and trust data live."""

    def __init__(self, home: Optional[Path] = None) -> None:
        chosen = home or os.environ.get("VAULT_HOME") or "~/.vault"
        self.home = Path(chosen).expanduser().resolve()

    contacts = property(lambda self: self.home / "contacts")
    public = property(lambda self: self.home / "public")
    trust_file = property(lambda self: self.home / "trusted_signers.json")
    replay_file = property(lambda self: self.home / "replay.json")

    def ring_path(self, kind: str) -> Path:
        return self.home / _KINDS[kind][0]

    def initialized(self) -> bool:
        return all((self.ring_path(k) / "keyring.json").is_file() for k in _KINDS)

    def require_initialized(self) -> None:
        if not self.initialized():
            raise CliError(
                f"There is no identity in {self.home} yet. "
                "Create it first (the menu offers to do it, or run: python -m vault init)."
            )

    def ring(self, kind: str) -> Keyring:
        self.require_initialized()
        return Keyring.open(self.ring_path(kind))

    def owner(self) -> str:
        return self.ring("encrypt").owner

    def public_path(self, key_id: str) -> Path:
        return self.public / f"{key_id}.pem"

    def trusted(self) -> TrustedSigners:
        return TrustedSigners(self.trust_file)


# ---------------------------------------------------------------------- #
# Small helpers                                                          #
# ---------------------------------------------------------------------- #


def _group(fingerprint: str) -> str:
    """Fingerprint in blocks of 8 characters, easier to read aloud and compare."""
    return " ".join(fingerprint[i : i + 8] for i in range(0, len(fingerprint), 8))


def _normalize_fingerprint(text: str) -> str:
    return re.sub(r"[\s:.-]", "", text).lower()


def _check_name(name: str, what: str = "The name") -> str:
    if not _NAME_RE.fullmatch(name) or looks_like_fingerprint(name):
        raise CliError(
            f"{what} must be 1 to 64 characters: letters, digits, dot, hyphen or underscore "
            "(no spaces)."
        )
    return name


_ASK_AGAIN = False
"""True while the interactive menu runs: a new password that is too short or does not match is asked
again instead of ending the action. The subcommands still fail at once (they may run in a script)."""


def _ask_password(prompt: str, *, confirm: bool = False) -> str:
    while True:
        password = getpass.getpass(prompt)
        if not confirm:
            return password
        problem = None
        if len(password) < MIN_PASSWORD_LENGTH:
            problem = f"The password must be at least {MIN_PASSWORD_LENGTH} characters long."
        elif getpass.getpass("Repeat the password: ") != password:
            problem = "The passwords do not match."
        if problem is None:
            return password
        if not _ASK_AGAIN:
            raise CliError(problem)
        print(f"{problem} Try again.")


def _write_new(path: Path, data: bytes, *, force: bool = False, private: bool = True) -> Path:
    """Write ``data`` to ``path`` without silently replacing an existing file.

    The file is created exclusively (``O_EXCL``), so a file or link that appeared after
    the check is not followed, and it is readable only by its owner unless ``private``
    is false (public keys). ``force`` replaces a regular file, never a link.
    """
    path = Path(path)
    if (path.exists() or path.is_symlink()) and not force:
        raise CliError(f"{path} already exists. Choose another name (or use --force to replace it).")
    if path.is_symlink():
        raise CliError(f"{path} is a symbolic link; it is not written through.")
    path.parent.mkdir(parents=True, exist_ok=True)
    if force and path.exists():
        path.unlink()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, 0o600 if private else 0o644)
    except FileExistsError:
        raise CliError(f"{path} already exists. Choose another name (or use --force to replace it).") from None
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)
    return path


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:  # e.g. Windows: permissions work differently
        pass


def _public_pem(public_key: object) -> bytes:
    if isinstance(public_key, Ed25519PublicKey):
        return public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    return export_public_key_pem(public_key)  # type: ignore[arg-type]


def _read_file(path: Path, limit: int = MAX_CONTAINER_SIZE) -> bytes:
    """Read a regular file (not a link, folder or device) of at most ``limit`` bytes."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise CliError(f"File not found: {path}")
    with path.open("rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise CliError(f"{path} is not a regular file.")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise CliError(f"{path} is too large (maximum {limit // 2**20} MiB).")
    return data


def _load_ed25519_public(path: Path) -> Ed25519PublicKey:
    try:
        return load_signer_public_key_file(Path(path))
    except (VaultError, ValueError) as exc:
        raise CliError(
            f"{path} is not a valid public signing key (Ed25519): it must be a small .pem file "
            "with a single PEM block."
        ) from exc


def _resolve_key(ring: Keyring, prefix: Optional[str]) -> KeyEntry:
    """Find a key of the keyring by (a prefix of) its key_id; default: the active key."""
    if prefix is None:
        entry = ring.active_entry()
        if entry is None:
            raise CliError("There is no active key. Create a new one (My keys > Create new key, or the rotate command).")
        return entry
    prefix = _normalize_fingerprint(prefix)
    if len(prefix) < 6:
        raise CliError("Type at least the first 6 characters of the key identifier.")
    matches = [e for e in ring.entries() if e.key_id.startswith(prefix)]
    if not matches:
        raise CliError("No key matches that identifier. See the list with 'keys'.")
    if len(matches) > 1:
        raise CliError("That identifier is ambiguous: type more characters.")
    return matches[0]


def _new_key(ws: Workspace, kind: str, password: str) -> KeyEntry:
    """Generate a key of ``kind``, make it the active one and save its public half."""
    ring = ws.ring(kind)
    if kind == "encrypt":
        private_key = generate_x25519_keypair().private_key
    else:
        private_key, _ = generate_ed25519_keypair()
    entry = ring.rotate(private_key, password)
    _private_dir(ws.public)
    ws.public_path(entry.key_id).write_bytes(_public_pem(private_key.public_key()))
    return entry


def _describe(entry: KeyEntry) -> str:
    text = f"{entry.key_id[:16]}…  {entry.status:<8}  created {entry.created[:10]}"
    if entry.status == "revoked":
        text += f"  revoked {str(entry.revoked_at)[:10]}: {entry.reason}"
        if entry.compromised:
            text += " (COMPROMISED)"
    return text


# ---------------------------------------------------------------------- #
# Actions                                                                #
# ---------------------------------------------------------------------- #


def _trust_own_signing_key(ws: Workspace, entry: KeyEntry, previous_id: Optional[str] = None) -> None:
    """Make the user trust their own signing key, so files they signed can be opened by them."""
    public_key = _load_ed25519_public(ws.public_path(entry.key_id))
    trusted = ws.trusted()
    if previous_id is not None and trusted.status(previous_id) == "trusted":
        trusted.replace(previous_id, public_key, expected_fingerprint=entry.key_id)
    else:
        trusted.add(ws.owner(), public_key, expected_fingerprint=entry.key_id)


def do_init(ws: Workspace, owner: str) -> None:
    _check_name(owner, "Your name")
    if ws.initialized():
        raise CliError(f"An identity already exists in {ws.home}.")
    password = _ask_password("Choose a password to protect your keys: ", confirm=True)
    _private_dir(ws.home)
    created = []
    try:
        for kind, (folder, key_type) in _KINDS.items():
            Keyring.create(ws.home / folder, owner, key_type)
            created.append(ws.home / folder)
        _new_key(ws, "encrypt", password)
        _trust_own_signing_key(ws, _new_key(ws, "sign", password))
    except BaseException:
        for folder in created:
            shutil.rmtree(folder, ignore_errors=True)
        (ws.home / "trusted_signers.json").unlink(missing_ok=True)
        raise
    ws.contacts.mkdir(exist_ok=True)
    print(f"Done, {owner}. Your keys were created in {ws.home}")
    print("Your encryption key and your signing key are protected with your password.")
    print("If you forget it there is no way to recover them. Make a backup (the 'backup' command).")
    show_fingerprints(ws)


def show_fingerprints(ws: Workspace) -> None:
    for kind in _KINDS:
        entry = ws.ring(kind).active_entry()
        if entry:
            print(f"\nFingerprint of your {_KIND_LABEL[kind]} key (compare it over another channel when sharing it):")
            print(f"  {_group(entry.key_id)}")


def do_keys(ws: Workspace) -> None:
    ws.require_initialized()
    print(f"Identity: {ws.owner()}    Folder: {ws.home}")
    for kind in _KINDS:
        print(f"\n{_KIND_LABEL[kind].capitalize()} keys:")
        entries = ws.ring(kind).entries()
        if not entries:
            print("  (none)")
        for entry in reversed(entries):
            print("  " + _describe(entry))


def do_export_public(ws: Workspace, kind: str, out: Optional[Path], force: bool) -> Path:
    entry = ws.ring(kind).active_entry()
    if entry is None:
        raise CliError("There is no active key of that type. Create a new one (My keys > Create new key, or the rotate command).")
    data = _read_file(ws.public_path(entry.key_id))
    target = Path(out) if out else Path(f"{ws.owner()}-{kind}.pub.pem")
    _write_new(target, data, force=force, private=False)
    print(f"Public {_KIND_LABEL[kind]} key saved to {target}")
    print("Send it to whoever needs it; it is public. Also tell them this fingerprint over ANOTHER channel")
    print("(in person, by phone) so they can check that nobody changed it:")
    print(f"  {_group(entry.key_id)}")
    return target


def do_contact_add(ws: Workspace, name: str, pem: Path, fingerprint: str, force: bool) -> None:
    _check_name(name)
    if name.lower() == ws.owner().lower():
        raise CliError("That name is yours; choose another one for the contact.")
    if not fingerprint:
        raise CliError("The fingerprint is missing: ask that person for it over another channel (in person, by phone).")
    try:
        public_key = load_public_key_file(Path(pem))
    except (VaultError, ValueError) as exc:
        raise CliError(f"{pem} is not a valid public encryption key (X25519).") from exc
    actual = get_public_key_fingerprint(public_key)
    if _normalize_fingerprint(fingerprint) != actual:
        raise CliError("The fingerprint does not match: the contact was not added. The key may have been changed.")
    ws.contacts.mkdir(exist_ok=True)
    _write_new(ws.contacts / f"{name}.pem", _public_pem(public_key), force=force, private=False)
    print(f"Contact '{name}' added. Fingerprint:\n  {_group(actual)}")


def _contact_key(ws: Workspace, name: str):
    _check_name(name)
    path = ws.contacts / f"{name}.pem"
    if not path.is_file():
        raise CliError(f"You have no contact named '{name}'. Add it first.")
    return load_public_key_file(path)


def do_contact_list(ws: Workspace) -> None:
    files = sorted(ws.contacts.glob("*.pem")) if ws.contacts.is_dir() else []
    if not files:
        print("You have no contacts yet.")
    for path in files:
        print(f"  {path.stem:<20} {_group(get_public_key_fingerprint(load_public_key_file(path)))}")


def do_contact_remove(ws: Workspace, name: str) -> None:
    _contact_key(ws, name)
    (ws.contacts / f"{name}.pem").unlink()
    print(f"Contact '{name}' removed.")


def do_encrypt(
    ws: Workspace,
    src: Path,
    to: Sequence[str],
    out: Optional[Path] = None,
    *,
    sign: bool = True,
    include_self: bool = True,
    document_id: Optional[str] = None,
    version: Optional[int] = None,
    force: bool = False,
) -> Path:
    ws.require_initialized()
    src = Path(src)
    if not src.is_file():
        raise CliError(f"File not found: {src}")
    if src.stat().st_size > MAX_PLAINTEXT_SIZE:
        raise CliError(f"The file is too large (maximum {MAX_PLAINTEXT_SIZE // 2**20} MiB).")
    target = Path(out) if out else src.with_name(src.name + VAULT_SUFFIX)
    if target.exists() and not force:
        raise CliError(f"{target} already exists. Choose another name (or use --force to replace it).")

    owner = ws.owner()
    recipients = []
    names = list(dict.fromkeys(to))
    if owner in names:
        names.remove(owner)
        include_self = True
    if include_self:
        entry = ws.ring("encrypt").active_entry()
        if entry is None:
            raise CliError("You have no active encryption key. Create a new one (My keys > Create new key, or the rotate command).")
        recipients.append((owner, load_public_key_file(ws.public_path(entry.key_id))))
    recipients += [(name, _contact_key(ws, name)) for name in names]
    if not recipients:
        raise CliError("Choose at least one recipient.")

    signing_key = None
    if sign:
        signing_key = ws.ring("sign").unlock_active(
            _ask_password("Password of your signing key: ")
        )
    container = encrypt_bytes_hybrid(src.read_bytes(), recipients, filename=src.name)
    if signing_key is not None:
        container = sign_container(
            container, signing_key, document_id=document_id, document_version=version
        )
    _write_new(target, container, force=force)
    who = ", ".join(name for name, _ in recipients)
    print(f"Encrypted file: {target}")
    print(f"  Can be opened by: {who}")
    if sign:
        print("  Signed: yes")
    else:
        print("  Signed: NO. Whoever opens it cannot check who created it and must agree to open it unsigned (--allow-unsigned).")
    return target


def _no_duplicate_keys(pairs: list) -> dict:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _safe(value: object, limit: int = 80) -> str:
    """Text for the terminal: control characters (escape sequences, newlines) are shown escaped."""
    text = str(value)
    text = "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in text)
    return text if len(text) <= limit else text[:limit] + "…"


def do_inspect(ws: Workspace, src: Path) -> None:
    """Show the public fields of a .vault file. Nothing is decrypted or verified, and no password is asked."""
    raw = _read_file(src)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (ValueError, UnicodeDecodeError):
        document = None
    if (
        not isinstance(document, dict)
        or document.get("magic") != "VLT3"
        or not isinstance(document.get("recipients"), list)
    ):
        raise CliError(f"{src} does not look like a vault file.")

    own: set = set()
    if ws.initialized():
        own = {entry.key_id for entry in ws.ring("encrypt").entries()}
    recipients = [r for r in document["recipients"] if isinstance(r, dict)]

    print(f"File: {_safe(src)}  ({len(raw)} bytes)")
    print(f"  Format:         {_safe(document.get('magic'))} v{_safe(document.get('version'))}")
    print(f"  Encryption:     {_safe(document.get('algorithm'))}, per-recipient key with {_safe(document.get('key_wrap_algorithm'))}")
    print(f"  Stored name:    {_safe(document.get('filename'))}")
    stamp = document.get("timestamp")
    if type(stamp) is int and 0 <= stamp < 4_102_444_800:
        print(f"  Created:        {datetime.fromtimestamp(stamp, timezone.utc):%Y-%m-%d %H:%M} UTC")
    metadata = document.get("metadata")
    if isinstance(metadata, dict) and metadata:
        print("  Metadata:       " + _safe(json.dumps(metadata, sort_keys=True, ensure_ascii=False), 200))
    print(f"  Recipients ({len(recipients)}):")
    for r in recipients[:20]:
        fingerprint = str(r.get("fingerprint", ""))
        mark = "   <- you" if fingerprint in own else ""
        print(f"    - {_safe(r.get('id'), 40)}  {_safe(fingerprint[:16])}…{mark}")
    if len(recipients) > 20:
        print(f"    … and {len(recipients) - 20} more")
    if "signature" in document or "signer_id" in document:
        print("  Signature:      yes")
        print(f"    Signer:       {_safe(str(document.get('signer_id', ''))[:16])}…")
        print(f"    Container:    {_safe(document.get('container_id'))}")
        if "document_id" in document:
            print(f"    Document:     {_safe(document.get('document_id'))}  version {_safe(document.get('document_version'))}")
    else:
        print("  Signature:      NO (opening it requires accepting it unsigned: --allow-unsigned)")
    print("These are only the public fields of the file: the signature was not verified and nothing was decrypted.")


def _decrypt_target(src: Path, out: Optional[Path] = None) -> Path:
    """Where the decrypted file goes: ``out``, or the name of the .vault file without the suffix."""
    if out:
        return Path(out)
    if src.name.endswith(VAULT_SUFFIX) and len(src.name) > len(VAULT_SUFFIX):
        return src.with_name(src.name[: -len(VAULT_SUFFIX)])
    return src.with_name(src.name + ".decrypted")


def do_decrypt(
    ws: Workspace,
    src: Path,
    out: Optional[Path] = None,
    *,
    force: bool = False,
    replay_check: bool = True,
    allow_revoked: bool = False,
    allow_unsigned: bool = False,
) -> Path:
    ws.require_initialized()
    container = _read_file(src)
    src = Path(src)
    target = _decrypt_target(src, out)
    if target.exists() and not force:
        raise CliError(
            f"{target} already exists and would be overwritten. Give another output name "
            "(or use --force to replace it)."
        )

    ring = ws.ring("encrypt")
    password = _ask_password("Password of your keys: ")
    try:
        document = json.loads(container)
    except ValueError:
        document = None
    # Anything that carries a signature field is verified. A container without one is refused
    # unless the user asks for it: otherwise stripping the signature would skip the check.
    signed = isinstance(document, dict) and ("signer_id" in document or "signature" in document)
    if not signed and not allow_unsigned:
        raise UnsignedFileError(
            "The file is not signed, or its signature was removed, so it cannot be checked who created it. "
            "It was not decrypted. If you are sure of its origin by other means, use --allow-unsigned."
        )

    if signed:
        entry = ring.find_key_for_container(container)
        if entry is None:
            # Same generic failure as any other container that is not for us.
            plaintext = ring.decrypt(container, password)  # raises DecryptionFailedError
        else:
            private_key = ring.unlock(entry.key_id, password, allow_revoked=allow_revoked)
            guard = ReplayGuard(ws.replay_file) if replay_check else None
            plaintext = verify_with_trusted_signers(
                container, ws.trusted(), entry.key_id, private_key, guard
            )
    else:
        plaintext = ring.decrypt(container, password, allow_revoked=allow_revoked)

    _write_new(target, plaintext, force=force)
    print(f"Decrypted file: {target}")
    if signed:
        print("  The signature is valid and comes from a signer you trust.")
    else:
        print("  Warning: you opened it with --allow-unsigned; it was not checked who created it.")
    return target


def do_rotate(ws: Workspace, kind: str) -> None:
    ws.require_initialized()
    print(f"A new {_KIND_LABEL[kind]} key will be created; the previous one is kept to open old files.")
    password = _ask_password("Password for the new key: ", confirm=True)
    previous = ws.ring(kind).active_entry()
    entry = _new_key(ws, kind, password)
    if kind == "sign":
        _trust_own_signing_key(ws, entry, previous.key_id if previous else None)
    print(f"New key is active. Fingerprint:\n  {_group(entry.key_id)}")
    if kind == "sign":
        print("Anyone who trusted your previous signing key must confirm your new fingerprint again.")
    else:
        print("Share your public key again (the 'export' command) so people encrypt for your new key.")


def do_revoke(
    ws: Workspace,
    kind: str,
    key_prefix: Optional[str],
    reason: str,
    compromised: bool,
    notice_out: Optional[Path] = None,
    force: bool = False,
) -> Path:
    ring = ws.ring(kind)
    entry = _resolve_key(ring, key_prefix)
    target = Path(notice_out) if notice_out else Path(f"revocation-{kind}-{entry.key_id[:8]}.txt")
    if (target.exists() or target.is_symlink()) and not force:
        # Checked before revoking: otherwise the key would be revoked and the notice never written.
        raise CliError(f"{target} already exists. Choose another name (or use --force to replace it).")
    ring.revoke(entry.key_id, reason, compromised=compromised)
    if kind == "sign" and ws.trust_file.exists() and ws.trusted().status(entry.key_id) in ("trusted", "superseded"):
        ws.trusted().revoke(entry.key_id, reason)
    notice = ring.revocation_notice(entry.key_id)
    _write_new(target, notice, force=force)
    print(f"Key {entry.key_id[:16]}… revoked.")
    print(f"Revocation notice saved to {target}")
    print("Send it over a trusted channel to those who trust that key.")
    if ring.active_entry() is None:
        print("You no longer have an active key of this type: create a new one (My keys > Create new key, or the rotate command).")
    if compromised:
        print("Since others may know it, recover your files with that key and share them again")
        print("with the new key (decrypt with --allow-revoked).")
    return target


def do_trust_add(ws: Workspace, name: str, pem: Path, fingerprint: str) -> None:
    _check_name(name)
    public_key = _load_ed25519_public(pem)
    ws.home.mkdir(parents=True, exist_ok=True)
    signer_id = ws.trusted().add(
        name, public_key, expected_fingerprint=_normalize_fingerprint(fingerprint)
    )
    print(f"You now trust the signatures of '{name}' ({_group(signer_id)}).")


def do_trust_replace(ws: Workspace, old_prefix: str, pem: Path, fingerprint: str) -> None:
    trusted = ws.trusted()
    old = _match_signer(trusted, old_prefix)
    new_id = trusted.replace(
        old, _load_ed25519_public(pem), expected_fingerprint=_normalize_fingerprint(fingerprint)
    )
    print(f"Key replaced. New fingerprint:\n  {_group(new_id)}")


def _match_signer(trusted: TrustedSigners, prefix: str) -> str:
    prefix = _normalize_fingerprint(prefix)
    matches = [s for s in trusted.signer_ids() if len(prefix) >= 6 and s.startswith(prefix)]
    if len(matches) != 1:
        raise CliError("I cannot find a single signer with that identifier. See the list with 'trust list'.")
    return matches[0]


def do_trust_list(ws: Workspace) -> None:
    trusted = ws.trusted()
    ids = trusted.signer_ids() if ws.trust_file.exists() else []
    if not ids:
        print("You do not trust any signer yet.")
    names = json.loads(ws.trust_file.read_text("utf-8"))["signers"] if ids else {}
    for signer_id in ids:
        print(f"  {names[signer_id]['name']:<20} {trusted.status(signer_id):<11} {_group(signer_id)}")


def do_trust_revoke(ws: Workspace, prefix: str, reason: str) -> None:
    trusted = ws.trusted()
    trusted.revoke(_match_signer(trusted, prefix), reason)
    print("Signer revoked: their files will no longer be accepted.")


def do_trust_import(ws: Workspace, notice: Path) -> None:
    signer_id = ws.trusted().import_revocation(_read_file(notice))
    print(f"Revocation imported: {_group(signer_id)} is no longer trusted.")


def do_backup(ws: Workspace, dest: Path) -> None:
    ws.require_initialized()
    dest = Path(dest)
    if dest.exists():
        raise CliError(f"{dest} already exists. Choose a new folder.")
    shutil.copytree(ws.home, dest, ignore=shutil.ignore_patterns("replay.json"))
    print(f"Backup saved to {dest}")
    print("The private keys remain encrypted with your password. Keep the backup somewhere other than this computer.")


def do_restore(ws: Workspace, src: Path) -> None:
    src = Path(src)
    if ws.initialized():
        raise CliError(f"There is already an identity in {ws.home}; it is not overwritten.")
    for kind in _KINDS:
        try:
            Keyring.open(src / _KINDS[kind][0])
        except VaultError as exc:
            raise CliError(f"{src} does not look like a valid backup.") from exc
    if ws.home.exists() and any(ws.home.iterdir()):
        raise CliError(f"{ws.home} is not empty; it is not restored on top.")
    shutil.copytree(src, ws.home, dirs_exist_ok=True)
    print(f"Identity '{ws.owner()}' restored in {ws.home}. Try opening a file to check the password.")


# ---------------------------------------------------------------------- #
# Interactive menu                                                       #
# ---------------------------------------------------------------------- #


def _ask(prompt: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        answer = input(f"{prompt}{suffix}: ").strip()
        if answer.startswith(("'", '"')) and answer.endswith(answer[0]) and len(answer) > 1:
            answer = answer[1:-1]  # file dragged into the terminal
        if answer:
            return answer
        if default is not None:
            return default


def _ask_path(prompt: str, default: Optional[str] = None) -> Path:
    """A path typed in the menu. The shell expands ``~`` before Python sees it, but the menu does not."""
    return Path(_ask(prompt, default)).expanduser()


def _ask_int(prompt: str, default: Optional[str] = None) -> int:
    while True:
        answer = _ask(prompt, default)
        if answer.isdigit() and int(answer) >= 1:
            return int(answer)
        print("Type a whole number, 1 or higher.")


def _free_target(default: Path, *, what: str = "file") -> tuple[Optional[Path], bool]:
    """For the menu: if ``default`` already exists, ask whether to replace it or to use another name.

    Returns ``(out, force)`` for the ``do_*`` function. The command-line flags that say the same
    (``--out``, ``--force``) do not exist in the menu, so it asks.
    """
    if not (default.exists() or default.is_symlink()):
        return None, False
    print(f"\n{default} already exists.")
    if _confirm(f"Replace that {what}?"):
        return None, True
    while True:
        other = _ask_path(f"New name for the {what}")
        if not (other.exists() or other.is_symlink()):
            return other, False
        print(f"{other} exists too.")


def _confirm(prompt: str, default: bool = False) -> bool:
    while True:
        answer = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Answer y (yes) or n (no).")  # a typo must never silently pick the other option


def _menu(title: str, options: Sequence[tuple[str, Callable[[], None]]], *, back: str = "Back") -> None:
    while True:
        print(f"\n== {title} ==")
        for number, (label, _) in enumerate(options, 1):
            print(f"  {number}) {label}")
        print(f"  0) {back}")
        choice = input("Choose an option: ").strip()
        if choice == "0":
            return
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            try:
                options[int(choice) - 1][1]()
            except (CliError, VaultError, OSError, ValueError) as exc:
                print(f"\nError: {_friendly(exc)}")
            except (KeyboardInterrupt, EOFError):
                print("\nCancelled.")
        else:
            print("Invalid option.")


def _pick_kind() -> str:
    return "sign" if _ask("Which key? 1) encryption  2) signing", "1") == "2" else "encrypt"


def _ui_init(ws: Workspace) -> None:
    print("\nLet's create your identity: one key to encrypt and another to sign.")
    do_init(ws, _ask("Your name (no spaces, e.g. alice)"))


def _ui_encrypt(ws: Workspace) -> None:
    ws.require_initialized()
    src = _ask_path("File to encrypt")
    do_contact_list(ws)
    raw = _ask("Who is it for? Contact names separated by commas (empty = only for you)", "-")
    to = [] if raw == "-" else [n.strip() for n in raw.split(",") if n.strip()]
    sign = _confirm("Sign it so the recipient can check it is yours? (recommended)", True)
    document_id, version = None, None
    if sign and _confirm("Is it a version of a document you will keep updating? (protects against old versions)"):
        document_id = _ask("Document name (e.g. contract)")
        version = _ask_int("Version number (1, 2, 3...)", "1")
    out, force = _free_target(src.with_name(src.name + VAULT_SUFFIX), what="encrypted file")
    do_encrypt(ws, src, to, out, sign=sign, document_id=document_id, version=version, force=force)


def _ui_decrypt(ws: Workspace) -> None:
    """Decrypt from the menu. The three overrides of the command line are offered here, one at a time,
    and only after the safe attempt failed for that reason and the user confirms."""
    src = _ask_path("The .vault file to decrypt")
    options = {"allow_unsigned": False, "replay_check": True, "allow_revoked": False}
    target = _decrypt_target(src)
    if target.exists():
        print(f"\n{target} already exists.")
        if _confirm("Replace it with the decrypted file?"):
            options["force"] = True
        else:
            options["out"] = _ask_path("New name for the decrypted file")
    questions = {
        "unsigned": ("This file is not signed (or its signature was removed): it cannot be checked who created it. "
                     "Open it anyway?", "allow_unsigned", True),
        "replay": ("This file was already accepted before. Open it again without the replay protection?",
                   "replay_check", False),
        "revoked": ("That key is revoked. Use it only to recover old files?", "allow_revoked", True),
    }
    for _ in range(3):
        try:
            do_decrypt(ws, src, **options)
            return
        except UnsignedFileError as exc:
            reason, error = "unsigned", exc
        except ReplayDetectedError as exc:
            reason, error = "replay", exc
        except KeystoreAccessError:
            raise
        except KeystoreError as exc:
            if "revoked" not in str(exc):
                raise
            reason, error = "revoked", exc
        question, option, value = questions[reason]
        if options[option] == value:
            raise error
        if not _confirm(question):
            # Not the library's message: it points at command-line flags the menu does not have.
            print("\nNothing was decrypted.")
            return
        options[option] = value
    do_decrypt(ws, src, **options)


def _ui_inspect(ws: Workspace) -> None:
    do_inspect(ws, _ask_path("The .vault file to look at"))


def _ui_keys(ws: Workspace) -> None:
    def rotate() -> None:
        do_rotate(ws, _pick_kind())

    def revoke() -> None:
        kind = _pick_kind()
        do_keys(ws)
        prefix = _ask("First characters of the key to revoke (empty = the active one)", "-")
        key = _resolve_key(ws.ring(kind), None if prefix == "-" else prefix)  # fail before asking more
        reason = _ask("Reason")
        compromised = _confirm("Could it have fallen into someone else's hands?")
        out, force = _free_target(Path(f"revocation-{kind}-{key.key_id[:8]}.txt"), what="revocation notice")
        do_revoke(ws, kind, key.key_id, reason, compromised, out, force)

    _menu(
        "My keys",
        [
            ("View my keys", lambda: do_keys(ws)),
            ("Create new key (rotate)", rotate),
            ("Revoke a key", revoke),
        ],
    )


def _ui_share(ws: Workspace) -> None:
    kind = _pick_kind()
    out, force = _free_target(Path(f"{ws.owner()}-{kind}.pub.pem"), what="public key file")
    do_export_public(ws, kind, out, force)


def _ui_contacts(ws: Workspace) -> None:
    def add() -> None:
        name = _ask("Contact name")
        pem = _ask_path("Their public encryption key file (.pem)")
        fp = _ask("Fingerprint that person gave you over another channel (required)")
        force = False
        if (ws.contacts / f"{name}.pem").exists():
            print(f"\nYou already have a contact named '{name}'.")
            if not _confirm("Replace their key with this one? (only if that person changed keys)"):
                return
            force = True
        do_contact_add(ws, name, pem, fp, force)

    _menu(
        "Contacts (who I can encrypt for)",
        [
            ("View contacts", lambda: do_contact_list(ws)),
            ("Add contact", add),
            ("Remove contact", lambda: do_contact_remove(ws, _ask("Name"))),
        ],
    )


def _ui_trust(ws: Workspace) -> None:
    def add() -> None:
        name = _ask("Signer name")
        pem = _ask_path("Their public signing key file (.pem)")
        fp = _ask("Signing fingerprint that person gave you over another channel (required)")
        do_trust_add(ws, name, pem, fp)

    def revoke() -> None:
        do_trust_revoke(ws, _ask("First characters of the identifier"), _ask("Reason"))

    _menu(
        "Trusted signers",
        [
            ("View signers", lambda: do_trust_list(ws)),
            ("Trust a new signer", add),
            ("Stop trusting a signer", revoke),
            ("Import a revocation notice", lambda: do_trust_import(ws, _ask_path("Notice file"))),
        ],
    )


def _ui_backup(ws: Workspace) -> None:
    while True:
        dest = _ask_path("New folder where the backup will be saved")
        if not (dest.exists() or dest.is_symlink()):
            break
        print(f"{dest} already exists; type a folder name that does not exist.")
    do_backup(ws, dest)
    print("To restore it on another computer: open this program in a folder without an identity, answer that you do not want to create one, and choose restore.")


def run_menu(ws: Workspace) -> None:
    global _ASK_AGAIN
    _ASK_AGAIN = True
    try:
        _run_menu(ws)
    finally:
        _ASK_AGAIN = False


def _run_menu(ws: Workspace) -> None:
    print("=== Encrypted document vault ===")
    while not ws.initialized():
        print(f"\nI did not find an identity in {ws.home}.")
        if not _confirm("Create one now?", True):
            if not _confirm("Restore a backup you already have?"):
                return
            try:
                do_restore(ws, _ask_path("Backup folder"))
            except (CliError, VaultError, OSError) as exc:
                print(f"\nError: {_friendly(exc)}")
            continue
        try:
            _ui_init(ws)
        except (CliError, VaultError, OSError) as exc:
            print(f"\nError: {_friendly(exc)}")
    _menu(
        f"Main menu ({ws.owner()})",
        [
            ("Encrypt a file", lambda: _ui_encrypt(ws)),
            ("Decrypt a file", lambda: _ui_decrypt(ws)),
            ("View the details of an encrypted file (without decrypting)", lambda: _ui_inspect(ws)),
            ("My keys (view, rotate, revoke)", lambda: _ui_keys(ws)),
            ("Share my public key", lambda: _ui_share(ws)),
            ("Contacts (who I can encrypt for)", lambda: _ui_contacts(ws)),
            ("Trusted signers", lambda: _ui_trust(ws)),
            ("Backup", lambda: _ui_backup(ws)),
        ],
        back="Exit",
    )


# ---------------------------------------------------------------------- #
# Error messages                                                         #
# ---------------------------------------------------------------------- #


def _friendly(exc: BaseException) -> str:
    """Message for the user.  Failures to open a container stay generic on purpose (D3)."""
    if isinstance(exc, UntrustedSignerError):
        return (
            "The file is signed by someone you do not trust (or whose key was revoked). "
            "If it is who you expect, add them as a trusted signer (with their fingerprint)."
        )
    if isinstance(exc, ReplayDetectedError):
        return (
            "This file was already accepted before (replay protection). "
            "If you only lost the result, use --no-replay-check."
        )
    if isinstance(exc, RollbackDetectedError):
        return "You already accepted an equal or newer version of this document: this is an old version."
    if isinstance(exc, KeystoreAccessError):
        return "Wrong password, or the keys were modified."
    if isinstance(exc, OSError):
        return f"{exc.strerror or exc}: {getattr(exc, 'filename', '') or ''}".strip(": ")
    return str(exc)


# ---------------------------------------------------------------------- #
# Argument parsing                                                       #
# ---------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vault",
        description="Encrypted document vault. With no arguments it opens an interactive menu.",
    )
    parser.add_argument("--home", type=Path, help="data folder (default ~/.vault or $VAULT_HOME)")
    sub = parser.add_subparsers(dest="command", metavar="command")

    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        return sub.add_parser(name, help=help_text, description=help_text)

    kind_arg = lambda p: p.add_argument("kind", choices=list(_KINDS), help="encrypt = encryption key, sign = signing key")

    p = add("init", "create your identity (encryption and signing keys)")
    p.add_argument("--owner", required=True, help="your name, without spaces")
    add("keys", "list your keys and their status")
    p = add("export", "save your public key so you can share it")
    kind_arg(p)
    p.add_argument("--out", type=Path)
    p.add_argument("--force", action="store_true")
    p = add("rotate", "create a new key and keep the previous one")
    kind_arg(p)
    p = add("revoke", "revoke a key and generate the revocation notice")
    kind_arg(p)
    p.add_argument("--key", help="first characters of the identifier (default: the active key)")
    p.add_argument("--reason", required=True)
    p.add_argument("--compromised", action="store_true", help="the key may have fallen into other hands")
    p.add_argument("--out", type=Path, help="revocation notice file")
    p.add_argument("--force", action="store_true")

    contacts = add("contacts", "recipients you can encrypt for").add_subparsers(dest="action", required=True)
    p = contacts.add_parser("add", help="add someone's public encryption key")
    p.add_argument("name")
    p.add_argument("pem", type=Path)
    p.add_argument("--fingerprint", required=True, help="fingerprint that person gave you over another channel")
    p.add_argument("--force", action="store_true")
    contacts.add_parser("list", help="list contacts")
    p = contacts.add_parser("remove", help="remove a contact")
    p.add_argument("name")

    p = add("encrypt", "encrypt a file for one or more contacts")
    p.add_argument("file", type=Path)
    p.add_argument("--to", default="", help="contacts separated by commas")
    p.add_argument("--no-self", action="store_true", help="do not include me as a recipient")
    p.add_argument("--no-sign", action="store_true", help="do not sign (by default it is always signed)")
    p.add_argument("--document-id", help="document name (detects old versions)")
    p.add_argument("--version", type=int, help="document version number")
    p.add_argument("--out", type=Path)
    p.add_argument("--force", action="store_true")

    p = add("decrypt", "decrypt a .vault file")
    p.add_argument("file", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--force", action="store_true")
    p.add_argument("--no-replay-check", action="store_true", help="do not reject files already accepted before")
    p.add_argument("--allow-revoked", action="store_true", help="use a revoked key to recover old files")
    p.add_argument("--allow-unsigned", action="store_true", help="open an unsigned file (it is not checked who created it)")

    p = add("inspect", "show the public fields of a .vault file without decrypting it")
    p.add_argument("file", type=Path)

    trust = add("trust", "signers you trust").add_subparsers(dest="action", required=True)
    p = trust.add_parser("add", help="trust someone's signing key")
    p.add_argument("name")
    p.add_argument("pem", type=Path)
    p.add_argument("--fingerprint", required=True, help="signing fingerprint received over another channel")
    p = trust.add_parser("replace", help="replace a signer's key with a new one")
    p.add_argument("old", help="first characters of the previous identifier")
    p.add_argument("pem", type=Path)
    p.add_argument("--fingerprint", required=True)
    trust.add_parser("list", help="list signers")
    p = trust.add_parser("revoke", help="stop trusting a signer")
    p.add_argument("signer")
    p.add_argument("--reason", required=True)
    p = trust.add_parser("import-revocation", help="import a revocation notice")
    p.add_argument("notice", type=Path)

    p = add("backup", "copy your folder (the keys stay encrypted)")
    p.add_argument("dest", type=Path)
    p = add("restore", "restore a backup")
    p.add_argument("src", type=Path)
    return parser


def _dispatch(ws: Workspace, args: argparse.Namespace) -> None:
    command = args.command
    if command == "init":
        do_init(ws, args.owner)
    elif command == "keys":
        do_keys(ws)
    elif command == "export":
        do_export_public(ws, args.kind, args.out, args.force)
    elif command == "rotate":
        do_rotate(ws, args.kind)
    elif command == "revoke":
        do_revoke(ws, args.kind, args.key, args.reason, args.compromised, args.out, args.force)
    elif command == "contacts":
        if args.action == "add":
            do_contact_add(ws, args.name, args.pem, args.fingerprint, args.force)
        elif args.action == "list":
            do_contact_list(ws)
        else:
            do_contact_remove(ws, args.name)
    elif command == "encrypt":
        to = [n.strip() for n in args.to.split(",") if n.strip()]
        do_encrypt(
            ws, args.file, to, args.out, sign=not args.no_sign, include_self=not args.no_self,
            document_id=args.document_id, version=args.version, force=args.force,
        )
    elif command == "decrypt":
        do_decrypt(
            ws, args.file, args.out, force=args.force,
            replay_check=not args.no_replay_check, allow_revoked=args.allow_revoked,
            allow_unsigned=args.allow_unsigned,
        )
    elif command == "inspect":
        do_inspect(ws, args.file)
    elif command == "trust":
        if args.action == "add":
            do_trust_add(ws, args.name, args.pem, args.fingerprint)
        elif args.action == "replace":
            do_trust_replace(ws, args.old, args.pem, args.fingerprint)
        elif args.action == "list":
            do_trust_list(ws)
        elif args.action == "revoke":
            do_trust_revoke(ws, args.signer, args.reason)
        else:
            do_trust_import(ws, args.notice)
    elif command == "backup":
        do_backup(ws, args.dest)
    elif command == "restore":
        do_restore(ws, args.src)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point.  Returns the process exit code (0 ok, 1 error, 130 cancelled)."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    ws = Workspace(args.home)
    try:
        if args.command is None:
            run_menu(ws)
        else:
            _dispatch(ws, args)
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.", file=sys.stderr)
        return 130
    except (CliError, VaultError, OSError, ValueError) as exc:
        print(f"Error: {_friendly(exc)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
