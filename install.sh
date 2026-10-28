#!/usr/bin/env bash
# Fresh installation only: refuse all existing target files.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${MINTVAULT_INSTALL_DIR:-${HOME}/.local/share/mintvault}"
BIN_DIR="${MINTVAULT_BIN_DIR:-${HOME}/.local/bin}"
DESKTOP_DIR="${MINTVAULT_DESKTOP_DIR:-${HOME}/.local/share/applications}"
if ! python3 -c "import cryptography, gi; gi.require_version('Gtk', '3.0'); from gi.repository import Gtk"; then
    echo 'Missing Python, cryptography or GTK dependencies.' >&2
    exit 1
fi
mkdir -p -- "${INSTALL_DIR}" "${BIN_DIR}" "${DESKTOP_DIR}" "${INSTALL_DIR}/mintvault"
MINTVAULT_INSTALL_DIR="${INSTALL_DIR}" MINTVAULT_BIN_DIR="${BIN_DIR}" MINTVAULT_DESKTOP_DIR="${DESKTOP_DIR}" \
    python3 "${SCRIPT_DIR}/install_safe.py" "${SCRIPT_DIR}"
echo 'MintVault installed successfully.'
