#!/usr/bin/env bash
# Скрипт запуска защищённого хранилища MintVault
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${SCRIPT_DIR}:${PYTHONPATH:-}"

exec python3 -m mintvault "$@"
