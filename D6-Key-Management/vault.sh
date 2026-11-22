#!/usr/bin/env sh
# Launcher for Linux / macOS: prepares a virtual environment on first run, then opens the vault CLI.
# Usage: ./vault.sh            (interactive menu)
#        ./vault.sh encrypt file.pdf --to bob --sign
set -e
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
    echo "Preparando el entorno (solo la primera vez)..."
    python3 -m venv .venv
    .venv/bin/python -m pip install -q -r requirements.txt
fi
exec .venv/bin/python -m vault "$@"
