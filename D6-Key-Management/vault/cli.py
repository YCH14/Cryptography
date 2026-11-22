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
import getpass
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Callable, Optional, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vault.exceptions import (
    KeystoreAccessError,
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
    sign_container,
)

__all__ = ["main", "Workspace", "CliError"]

MIN_PASSWORD_LENGTH = 8
VAULT_SUFFIX = ".vault"
_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")

# "encrypt" -> the X25519 keyring (D3); "sign" -> the Ed25519 keyring (D5).
_KINDS = {"encrypt": ("x25519", "X25519"), "sign": ("ed25519", "Ed25519")}
_KIND_LABEL = {"encrypt": "cifrado", "sign": "firma"}


class CliError(Exception):
    """A problem the user can fix; its message is shown as is."""


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
                f"Todavía no hay una identidad en {self.home}. "
                "Créala primero con la opción 'Crear mi identidad' (o: python -m vault init)."
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


def _check_name(name: str, what: str = "El nombre") -> str:
    if not _NAME_RE.fullmatch(name) or looks_like_fingerprint(name):
        raise CliError(
            f"{what} debe tener de 1 a 64 caracteres: letras, números, punto, guion o guion bajo "
            "(sin espacios)."
        )
    return name


def _ask_password(prompt: str, *, confirm: bool = False) -> str:
    password = getpass.getpass(prompt)
    if confirm:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise CliError(f"La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres.")
        if getpass.getpass("Repite la contraseña: ") != password:
            raise CliError("Las contraseñas no coinciden.")
    return password


def _write_new(path: Path, data: bytes, *, force: bool = False) -> Path:
    """Write ``data`` to ``path`` without silently replacing an existing file."""
    path = Path(path)
    if path.exists() and not force:
        raise CliError(f"{path} ya existe. Elige otro nombre (o usa --force para reemplazarlo).")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
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


def _read_file(path: Path) -> bytes:
    path = Path(path)
    if not path.is_file():
        raise CliError(f"No encuentro el archivo: {path}")
    return path.read_bytes()


def _load_ed25519_public(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(_read_file(path))
    except ValueError as exc:
        raise CliError(f"{path} no es una llave pública PEM válida.") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise CliError(f"{path} no es una llave pública de firma (Ed25519).")
    return key


def _resolve_key(ring: Keyring, prefix: Optional[str]) -> KeyEntry:
    """Find a key of the keyring by (a prefix of) its key_id; default: the active key."""
    if prefix is None:
        entry = ring.active_entry()
        if entry is None:
            raise CliError("No hay una llave activa. Crea una con 'rotate'.")
        return entry
    prefix = _normalize_fingerprint(prefix)
    if len(prefix) < 6:
        raise CliError("Escribe al menos los primeros 6 caracteres del identificador de la llave.")
    matches = [e for e in ring.entries() if e.key_id.startswith(prefix)]
    if not matches:
        raise CliError("Ninguna llave coincide con ese identificador. Mira la lista con 'keys'.")
    if len(matches) > 1:
        raise CliError("Ese identificador es ambiguo: escribe más caracteres.")
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
    text = f"{entry.key_id[:16]}…  {entry.status:<8}  creada {entry.created[:10]}"
    if entry.status == "revoked":
        text += f"  revocada {str(entry.revoked_at)[:10]}: {entry.reason}"
        if entry.compromised:
            text += " (COMPROMETIDA)"
    return text


# ---------------------------------------------------------------------- #
# Actions                                                                #
# ---------------------------------------------------------------------- #


def do_init(ws: Workspace, owner: str) -> None:
    _check_name(owner, "Tu nombre")
    if ws.initialized():
        raise CliError(f"Ya existe una identidad en {ws.home}.")
    password = _ask_password("Elige una contraseña para proteger tus llaves: ", confirm=True)
    _private_dir(ws.home)
    created = []
    try:
        for kind, (folder, key_type) in _KINDS.items():
            Keyring.create(ws.home / folder, owner, key_type)
            created.append(ws.home / folder)
        _new_key(ws, "encrypt", password)
        _new_key(ws, "sign", password)
    except BaseException:
        for folder in created:
            shutil.rmtree(folder, ignore_errors=True)
        raise
    ws.contacts.mkdir(exist_ok=True)
    print(f"Listo, {owner}. Se crearon tus llaves en {ws.home}")
    print("Tu llave de cifrado y tu llave de firma quedaron protegidas con tu contraseña.")
    print("Si la olvidas no hay forma de recuperarlas. Guarda una copia de seguridad (opción 'backup').")
    show_fingerprints(ws)


def show_fingerprints(ws: Workspace) -> None:
    for kind in _KINDS:
        entry = ws.ring(kind).active_entry()
        if entry:
            print(f"\nHuella de tu llave de {_KIND_LABEL[kind]} (compárala por otro canal al compartirla):")
            print(f"  {_group(entry.key_id)}")


def do_keys(ws: Workspace) -> None:
    ws.require_initialized()
    print(f"Identidad: {ws.owner()}    Carpeta: {ws.home}")
    for kind in _KINDS:
        print(f"\nLlaves de {_KIND_LABEL[kind]}:")
        entries = ws.ring(kind).entries()
        if not entries:
            print("  (ninguna)")
        for entry in reversed(entries):
            print("  " + _describe(entry))


def do_export_public(ws: Workspace, kind: str, out: Optional[Path], force: bool) -> Path:
    entry = ws.ring(kind).active_entry()
    if entry is None:
        raise CliError("No hay una llave activa de ese tipo. Crea una con 'rotate'.")
    data = _read_file(ws.public_path(entry.key_id))
    target = Path(out) if out else Path(f"{ws.owner()}-{kind}.pub.pem")
    _write_new(target, data, force=force)
    print(f"Llave pública de {_KIND_LABEL[kind]} guardada en {target}")
    print("Envíala a quien la necesite; es pública. Dile también esta huella por OTRO canal")
    print("(en persona, llamada) para que pueda comprobar que nadie la cambió:")
    print(f"  {_group(entry.key_id)}")
    return target


def do_contact_add(ws: Workspace, name: str, pem: Path, fingerprint: Optional[str], force: bool) -> None:
    _check_name(name)
    if name == ws.owner():
        raise CliError("Ese nombre es el tuyo; elige otro para el contacto.")
    try:
        public_key = load_public_key_file(Path(pem))
    except (VaultError, ValueError) as exc:
        raise CliError(f"{pem} no es una llave pública de cifrado (X25519) válida.") from exc
    actual = get_public_key_fingerprint(public_key)
    if fingerprint is not None and _normalize_fingerprint(fingerprint) != actual:
        raise CliError("La huella no coincide: no se agregó el contacto. La llave pudo ser cambiada.")
    ws.contacts.mkdir(parents=True, exist_ok=True)
    _write_new(ws.contacts / f"{name}.pem", _public_pem(public_key), force=force)
    print(f"Contacto '{name}' agregado. Huella:\n  {_group(actual)}")
    if fingerprint is None:
        print("Confirma esta huella con esa persona por otro canal antes de cifrarle documentos.")


def _contact_key(ws: Workspace, name: str):
    _check_name(name)
    path = ws.contacts / f"{name}.pem"
    if not path.is_file():
        raise CliError(f"No tienes un contacto llamado '{name}'. Agrégalo primero.")
    return load_public_key_file(path)


def do_contact_list(ws: Workspace) -> None:
    files = sorted(ws.contacts.glob("*.pem")) if ws.contacts.is_dir() else []
    if not files:
        print("No tienes contactos todavía.")
    for path in files:
        print(f"  {path.stem:<20} {_group(get_public_key_fingerprint(load_public_key_file(path)))}")


def do_contact_remove(ws: Workspace, name: str) -> None:
    _contact_key(ws, name)
    (ws.contacts / f"{name}.pem").unlink()
    print(f"Contacto '{name}' eliminado.")


def do_encrypt(
    ws: Workspace,
    src: Path,
    to: Sequence[str],
    out: Optional[Path] = None,
    *,
    sign: bool = False,
    include_self: bool = True,
    document_id: Optional[str] = None,
    version: Optional[int] = None,
    force: bool = False,
) -> Path:
    ws.require_initialized()
    src = Path(src)
    if not src.is_file():
        raise CliError(f"No encuentro el archivo: {src}")
    if src.stat().st_size > MAX_PLAINTEXT_SIZE:
        raise CliError(f"El archivo es demasiado grande (máximo {MAX_PLAINTEXT_SIZE // 2**20} MiB).")
    target = Path(out) if out else src.with_name(src.name + VAULT_SUFFIX)
    if target.exists() and not force:
        raise CliError(f"{target} ya existe. Elige otro nombre (o usa --force para reemplazarlo).")

    owner = ws.owner()
    recipients = []
    names = list(dict.fromkeys(to))
    if owner in names:
        names.remove(owner)
        include_self = True
    if include_self:
        entry = ws.ring("encrypt").active_entry()
        if entry is None:
            raise CliError("No tienes una llave de cifrado activa. Crea una con 'rotate'.")
        recipients.append((owner, load_public_key_file(ws.public_path(entry.key_id))))
    recipients += [(name, _contact_key(ws, name)) for name in names]
    if not recipients:
        raise CliError("Elige al menos un destinatario.")

    signing_key = None
    if sign:
        signing_key = ws.ring("sign").unlock_active(
            _ask_password("Contraseña de tu llave de firma: ")
        )
    container = encrypt_bytes_hybrid(src.read_bytes(), recipients, filename=src.name)
    if signing_key is not None:
        container = sign_container(
            container, signing_key, document_id=document_id, document_version=version
        )
    _write_new(target, container, force=force)
    who = ", ".join(name for name, _ in recipients)
    print(f"Archivo cifrado: {target}")
    print(f"  Pueden abrirlo: {who}")
    print(f"  Firmado: {'sí' if sign else 'no'}")
    return target


def do_decrypt(
    ws: Workspace,
    src: Path,
    out: Optional[Path] = None,
    *,
    force: bool = False,
    replay_check: bool = True,
    allow_revoked: bool = False,
) -> Path:
    ws.require_initialized()
    container = _read_file(src)
    src = Path(src)
    if out:
        target = Path(out)
    elif src.name.endswith(VAULT_SUFFIX) and len(src.name) > len(VAULT_SUFFIX):
        target = src.with_name(src.name[: -len(VAULT_SUFFIX)])
    else:
        target = src.with_name(src.name + ".descifrado")
    if target.exists() and not force:
        raise CliError(
            f"{target} ya existe y se sobrescribiría. Indica otro nombre de salida "
            "(o usa --force para reemplazarlo)."
        )

    ring = ws.ring("encrypt")
    password = _ask_password("Contraseña de tus llaves: ")
    try:
        document = json.loads(container)
    except ValueError:
        document = None
    signed = isinstance(document, dict) and "signer_id" in document

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
    print(f"Archivo descifrado: {target}")
    if signed:
        print("  La firma es válida y viene de un firmante en el que confías.")
    else:
        print("  Aviso: el archivo no está firmado; no se puede comprobar quién lo creó.")
    return target


def do_rotate(ws: Workspace, kind: str) -> None:
    ws.require_initialized()
    print(f"Se creará una llave nueva de {_KIND_LABEL[kind]}; la anterior se conserva para abrir archivos viejos.")
    password = _ask_password("Contraseña para la llave nueva: ", confirm=True)
    entry = _new_key(ws, kind, password)
    print(f"Llave nueva activa. Huella:\n  {_group(entry.key_id)}")
    if kind == "sign":
        print("Quien confiaba en tu llave de firma anterior debe volver a confirmar tu huella nueva.")
    else:
        print("Vuelve a compartir tu llave pública (opción 'export') para que te cifren con la nueva.")


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
    ring.revoke(entry.key_id, reason, compromised=compromised)
    notice = ring.revocation_notice(entry.key_id)
    target = Path(notice_out) if notice_out else Path(f"revocacion-{kind}-{entry.key_id[:8]}.txt")
    _write_new(target, notice, force=force)
    print(f"Llave {entry.key_id[:16]}… revocada.")
    print(f"Aviso de revocación guardado en {target}")
    print("Envíalo por un canal confiable a quienes confían en esa llave.")
    if ring.active_entry() is None:
        print("Ya no tienes llave activa de este tipo: crea una nueva con 'rotate'.")
    if compromised:
        print("Como pudo ser conocida por otros, recupera tus archivos con esa llave y compártelos de nuevo")
        print("con la llave nueva (descifrar con --allow-revoked).")
    return target


def do_trust_add(ws: Workspace, name: str, pem: Path, fingerprint: str) -> None:
    _check_name(name)
    public_key = _load_ed25519_public(pem)
    ws.home.mkdir(parents=True, exist_ok=True)
    signer_id = ws.trusted().add(
        name, public_key, expected_fingerprint=_normalize_fingerprint(fingerprint)
    )
    print(f"Ahora confías en las firmas de '{name}' ({_group(signer_id)}).")


def do_trust_replace(ws: Workspace, old_prefix: str, pem: Path, fingerprint: str) -> None:
    trusted = ws.trusted()
    old = _match_signer(trusted, old_prefix)
    new_id = trusted.replace(
        old, _load_ed25519_public(pem), expected_fingerprint=_normalize_fingerprint(fingerprint)
    )
    print(f"Llave reemplazada. Nueva huella:\n  {_group(new_id)}")


def _match_signer(trusted: TrustedSigners, prefix: str) -> str:
    prefix = _normalize_fingerprint(prefix)
    matches = [s for s in trusted.signer_ids() if len(prefix) >= 6 and s.startswith(prefix)]
    if len(matches) != 1:
        raise CliError("No encuentro un firmante único con ese identificador. Mira la lista con 'trust list'.")
    return matches[0]


def do_trust_list(ws: Workspace) -> None:
    trusted = ws.trusted()
    ids = trusted.signer_ids() if ws.trust_file.exists() else []
    if not ids:
        print("No confías en ningún firmante todavía.")
    names = json.loads(ws.trust_file.read_text("utf-8"))["signers"] if ids else {}
    for signer_id in ids:
        print(f"  {names[signer_id]['name']:<20} {trusted.status(signer_id):<11} {_group(signer_id)}")


def do_trust_revoke(ws: Workspace, prefix: str, reason: str) -> None:
    trusted = ws.trusted()
    trusted.revoke(_match_signer(trusted, prefix), reason)
    print("Firmante revocado: sus archivos ya no se aceptarán.")


def do_trust_import(ws: Workspace, notice: Path) -> None:
    signer_id = ws.trusted().import_revocation(_read_file(notice))
    print(f"Revocación importada: {_group(signer_id)} ya no es de confianza.")


def do_backup(ws: Workspace, dest: Path) -> None:
    ws.require_initialized()
    dest = Path(dest)
    if dest.exists():
        raise CliError(f"{dest} ya existe. Elige una carpeta nueva.")
    shutil.copytree(ws.home, dest, ignore=shutil.ignore_patterns("replay.json"))
    print(f"Copia de seguridad en {dest}")
    print("Las llaves privadas siguen cifradas con tu contraseña. Guárdala en un lugar distinto al de tu equipo.")


def do_restore(ws: Workspace, src: Path) -> None:
    src = Path(src)
    if ws.initialized():
        raise CliError(f"Ya hay una identidad en {ws.home}; no se sobrescribe.")
    for kind in _KINDS:
        try:
            Keyring.open(src / _KINDS[kind][0])
        except VaultError as exc:
            raise CliError(f"{src} no parece una copia de seguridad válida.") from exc
    if ws.home.exists() and any(ws.home.iterdir()):
        raise CliError(f"{ws.home} no está vacía; no se restaura encima.")
    shutil.copytree(src, ws.home, dirs_exist_ok=True)
    print(f"Identidad de '{ws.owner()}' restaurada en {ws.home}. Prueba abrir un archivo para comprobar la contraseña.")


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


def _confirm(prompt: str, default: bool = False) -> bool:
    answer = input(f"{prompt} [{'S/n' if default else 's/N'}]: ").strip().lower()
    return default if not answer else answer in {"s", "si", "sí", "y", "yes"}


def _menu(title: str, options: Sequence[tuple[str, Callable[[], None]]], *, back: str = "Volver") -> None:
    while True:
        print(f"\n== {title} ==")
        for number, (label, _) in enumerate(options, 1):
            print(f"  {number}) {label}")
        print(f"  0) {back}")
        choice = input("Elige una opción: ").strip()
        if choice == "0":
            return
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            try:
                options[int(choice) - 1][1]()
            except (CliError, VaultError, OSError, ValueError) as exc:
                print(f"\nError: {_friendly(exc)}")
            except (KeyboardInterrupt, EOFError):
                print("\nCancelado.")
        else:
            print("Opción no válida.")


def _pick_kind() -> str:
    return "sign" if _ask("¿Qué llave? 1) cifrado  2) firma", "1") == "2" else "encrypt"


def _ui_init(ws: Workspace) -> None:
    print("\nVamos a crear tu identidad: una llave para cifrar y otra para firmar.")
    do_init(ws, _ask("Tu nombre (sin espacios, ej. alice)"))


def _ui_encrypt(ws: Workspace) -> None:
    ws.require_initialized()
    src = Path(_ask("Archivo a cifrar"))
    do_contact_list(ws)
    raw = _ask("¿Para quién? Nombres de contactos separados por coma (vacío = solo para ti)", "-")
    to = [] if raw == "-" else [n.strip() for n in raw.split(",") if n.strip()]
    sign = _confirm("¿Firmarlo para que el destinatario compruebe que es tuyo?", True)
    do_encrypt(ws, src, to, sign=sign)


def _ui_decrypt(ws: Workspace) -> None:
    src = Path(_ask("Archivo .vault a descifrar"))
    do_decrypt(ws, src)


def _ui_keys(ws: Workspace) -> None:
    def rotate() -> None:
        do_rotate(ws, _pick_kind())

    def revoke() -> None:
        kind = _pick_kind()
        do_keys(ws)
        prefix = _ask("Primeros caracteres de la llave a revocar (vacío = la activa)", "-")
        reason = _ask("Motivo")
        compromised = _confirm("¿Pudo caer en manos de otra persona?")
        do_revoke(ws, kind, None if prefix == "-" else prefix, reason, compromised)

    _menu(
        "Mis llaves",
        [
            ("Ver mis llaves", lambda: do_keys(ws)),
            ("Crear llave nueva (rotar)", rotate),
            ("Revocar una llave", revoke),
        ],
    )


def _ui_share(ws: Workspace) -> None:
    kind = _pick_kind()
    do_export_public(ws, kind, None, False)


def _ui_contacts(ws: Workspace) -> None:
    def add() -> None:
        name = _ask("Nombre del contacto")
        pem = Path(_ask("Archivo de su llave pública de cifrado (.pem)"))
        fp = _ask("Huella que esa persona te dio por otro canal (vacío = omitir)", "-")
        do_contact_add(ws, name, pem, None if fp == "-" else fp, False)

    _menu(
        "Contactos (a quién puedo cifrarle)",
        [
            ("Ver contactos", lambda: do_contact_list(ws)),
            ("Agregar contacto", add),
            ("Eliminar contacto", lambda: do_contact_remove(ws, _ask("Nombre"))),
        ],
    )


def _ui_trust(ws: Workspace) -> None:
    def add() -> None:
        name = _ask("Nombre del firmante")
        pem = Path(_ask("Archivo de su llave pública de firma (.pem)"))
        fp = _ask("Huella de firma que te dio por otro canal (obligatoria)")
        do_trust_add(ws, name, pem, fp)

    def revoke() -> None:
        do_trust_revoke(ws, _ask("Primeros caracteres del identificador"), _ask("Motivo"))

    _menu(
        "Firmantes de confianza",
        [
            ("Ver firmantes", lambda: do_trust_list(ws)),
            ("Confiar en un firmante nuevo", add),
            ("Dejar de confiar en un firmante", revoke),
            ("Importar un aviso de revocación", lambda: do_trust_import(ws, Path(_ask("Archivo del aviso")))),
        ],
    )


def _ui_backup(ws: Workspace) -> None:
    do_backup(ws, Path(_ask("Carpeta nueva donde guardar la copia")))


def run_menu(ws: Workspace) -> None:
    print("=== Bóveda de documentos cifrados ===")
    if not ws.initialized():
        print(f"\nNo encontré una identidad en {ws.home}.")
        if _confirm("¿Crear una ahora?", True):
            try:
                _ui_init(ws)
            except (CliError, VaultError, OSError) as exc:
                print(f"\nError: {_friendly(exc)}")
        if not ws.initialized():
            return
    _menu(
        f"Menú principal ({ws.owner()})",
        [
            ("Cifrar un archivo", lambda: _ui_encrypt(ws)),
            ("Descifrar un archivo", lambda: _ui_decrypt(ws)),
            ("Mis llaves (ver, rotar, revocar)", lambda: _ui_keys(ws)),
            ("Compartir mi llave pública", lambda: _ui_share(ws)),
            ("Contactos (a quién puedo cifrarle)", lambda: _ui_contacts(ws)),
            ("Firmantes de confianza", lambda: _ui_trust(ws)),
            ("Copia de seguridad", lambda: _ui_backup(ws)),
        ],
        back="Salir",
    )


# ---------------------------------------------------------------------- #
# Error messages                                                         #
# ---------------------------------------------------------------------- #


def _friendly(exc: BaseException) -> str:
    """Message for the user.  Failures to open a container stay generic on purpose (D3)."""
    if isinstance(exc, UntrustedSignerError):
        return (
            "El archivo está firmado por alguien en quien no confías (o cuya llave fue revocada). "
            "Agrégalo con 'trust add' si es quien esperas."
        )
    if isinstance(exc, ReplayDetectedError):
        return (
            "Este archivo ya fue aceptado antes (protección contra repetición). "
            "Si solo perdiste el resultado, usa --no-replay-check."
        )
    if isinstance(exc, RollbackDetectedError):
        return "Ya aceptaste una versión igual o más nueva de este documento: esta es una versión vieja."
    if isinstance(exc, KeystoreAccessError):
        return "Contraseña incorrecta, o las llaves fueron modificadas."
    if isinstance(exc, OSError):
        return f"{exc.strerror or exc}: {getattr(exc, 'filename', '') or ''}".strip(": ")
    return str(exc)


# ---------------------------------------------------------------------- #
# Argument parsing                                                       #
# ---------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vault",
        description="Bóveda de documentos cifrados. Sin argumentos abre un menú interactivo.",
    )
    parser.add_argument("--home", type=Path, help="carpeta de datos (por defecto ~/.vault o $VAULT_HOME)")
    sub = parser.add_subparsers(dest="command", metavar="comando")

    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        return sub.add_parser(name, help=help_text, description=help_text)

    kind_arg = lambda p: p.add_argument("kind", choices=list(_KINDS), help="encrypt = llave de cifrado, sign = llave de firma")

    p = add("init", "crea tu identidad (llaves de cifrado y de firma)")
    p.add_argument("--owner", required=True, help="tu nombre, sin espacios")
    add("keys", "lista tus llaves y su estado")
    p = add("export", "guarda tu llave pública para compartirla")
    kind_arg(p)
    p.add_argument("--out", type=Path)
    p.add_argument("--force", action="store_true")
    p = add("rotate", "crea una llave nueva y conserva la anterior")
    kind_arg(p)
    p = add("revoke", "revoca una llave y genera el aviso de revocación")
    kind_arg(p)
    p.add_argument("--key", help="primeros caracteres del identificador (por defecto, la llave activa)")
    p.add_argument("--reason", required=True)
    p.add_argument("--compromised", action="store_true", help="la llave pudo caer en manos de otros")
    p.add_argument("--out", type=Path, help="archivo del aviso de revocación")
    p.add_argument("--force", action="store_true")

    contacts = add("contacts", "destinatarios a quienes puedes cifrar").add_subparsers(dest="action", required=True)
    p = contacts.add_parser("add", help="agrega la llave pública de cifrado de alguien")
    p.add_argument("name")
    p.add_argument("pem", type=Path)
    p.add_argument("--fingerprint", help="huella que esa persona te dio por otro canal")
    p.add_argument("--force", action="store_true")
    contacts.add_parser("list", help="lista contactos")
    p = contacts.add_parser("remove", help="elimina un contacto")
    p.add_argument("name")

    p = add("encrypt", "cifra un archivo para uno o más contactos")
    p.add_argument("file", type=Path)
    p.add_argument("--to", default="", help="contactos separados por coma")
    p.add_argument("--no-self", action="store_true", help="no incluirme como destinatario")
    p.add_argument("--sign", action="store_true", help="firmar con tu llave de firma")
    p.add_argument("--document-id", help="nombre del documento (detecta versiones viejas)")
    p.add_argument("--version", type=int, help="número de versión del documento")
    p.add_argument("--out", type=Path)
    p.add_argument("--force", action="store_true")

    p = add("decrypt", "descifra un archivo .vault")
    p.add_argument("file", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--force", action="store_true")
    p.add_argument("--no-replay-check", action="store_true", help="no rechazar archivos ya aceptados antes")
    p.add_argument("--allow-revoked", action="store_true", help="usar una llave revocada para recuperar archivos viejos")

    trust = add("trust", "firmantes en los que confías").add_subparsers(dest="action", required=True)
    p = trust.add_parser("add", help="confía en la llave de firma de alguien")
    p.add_argument("name")
    p.add_argument("pem", type=Path)
    p.add_argument("--fingerprint", required=True, help="huella de firma recibida por otro canal")
    p = trust.add_parser("replace", help="cambia la llave de un firmante por una nueva")
    p.add_argument("old", help="primeros caracteres del identificador anterior")
    p.add_argument("pem", type=Path)
    p.add_argument("--fingerprint", required=True)
    trust.add_parser("list", help="lista firmantes")
    p = trust.add_parser("revoke", help="deja de confiar en un firmante")
    p.add_argument("signer")
    p.add_argument("--reason", required=True)
    p = trust.add_parser("import-revocation", help="importa un aviso de revocación")
    p.add_argument("notice", type=Path)

    p = add("backup", "copia tu carpeta (las llaves siguen cifradas)")
    p.add_argument("dest", type=Path)
    p = add("restore", "restaura una copia de seguridad")
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
            ws, args.file, to, args.out, sign=args.sign, include_self=not args.no_self,
            document_id=args.document_id, version=args.version, force=args.force,
        )
    elif command == "decrypt":
        do_decrypt(
            ws, args.file, args.out, force=args.force,
            replay_check=not args.no_replay_check, allow_revoked=args.allow_revoked,
        )
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
        print("\nCancelado.", file=sys.stderr)
        return 130
    except (CliError, VaultError, OSError, ValueError) as exc:
        print(f"Error: {_friendly(exc)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
