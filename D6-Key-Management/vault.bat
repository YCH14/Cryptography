@echo off
rem Launcher for Windows: prepares a virtual environment on first run, then opens the vault CLI.
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
    echo Preparando el entorno (solo la primera vez)...
    python -m venv .venv || exit /b 1
    .venv\Scripts\python.exe -m pip install -q -r requirements.txt || exit /b 1
)
.venv\Scripts\python.exe -m vault %*
