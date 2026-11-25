# Examples

## Scripted demo

`demo.py` runs the real command line (`python -m vault`) for three users (Alice, Bob and Carol) in a fresh temporary folder. It never touches your own keys.

```bash
# from the repository root
python -m pip install -r D6-Key-Management/requirements.txt
python examples/demo.py
```

What it shows, in order:

1. Each user creates an X25519 key (to decrypt) and an Ed25519 key (to sign), protected by a password.
2. Public keys are exchanged as files; each fingerprint is checked, as if it had been confirmed through another channel.
3. Alice encrypts and signs a file for Bob. `inspect` lists the recipients and signer without opening anything.
4. The keystore on disk: KDF parameters and metadata are readable, `encrypted_private_key` is ciphertext.
5. Carol (not a recipient) cannot decrypt; Bob decrypts and the signature is reported as valid and trusted.
6. Failure cases, each one exits with status 1 and creates no output file: replayed container, wrong password, one modified byte, one modified signature, signature removed, contact with a wrong fingerprint.

The password is fixed inside the script only so the demo runs unattended. Real use always asks for it with a hidden prompt.

## Manual walkthrough (two terminals)

Use the interactive menu (Spanish) or the subcommands. Both users work in their own folder (`--home`).

```bash
cd D6-Key-Management
python -m vault --home alice init --owner alice
python -m vault --home bob   init --owner bob

python -m vault --home bob   export encrypt --out bob-enc.pem
python -m vault --home alice export sign    --out alice-sign.pem
python -m vault --home bob   contacts list          # shows Bob's fingerprint: read it to Alice by another channel

python -m vault --home alice contacts add bob bob-enc.pem --fingerprint <bob fingerprint>
python -m vault --home bob   trust add alice alice-sign.pem --fingerprint <alice signing fingerprint>

python -m vault --home alice encrypt report.pdf --to bob
python -m vault --home bob   decrypt report.pdf.vault --out report-decrypted.pdf
```

Run `python -m vault` with no arguments for the menu.

## Inspecting the keystore (for the video demo)

Each private key lives in `<home>/<x25519|ed25519>/keys/<key_id>/` as four files: `encrypted_private_key`, `salt`, `kdf_parameters` and `metadata`. Only `encrypted_private_key` is secret material and it is AES-256-GCM ciphertext under a key derived with Argon2id. Open the files to show that no private key is readable, then run `decrypt` with a wrong password: it fails with "Contraseña incorrecta, o las llaves fueron modificadas" and writes nothing.
