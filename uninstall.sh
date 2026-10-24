#!/usr/bin/env bash
# Скрипт удаления приложения MintVault из пользовательского окружения Linux Mint.
# ВАЖНО: Пользовательские зашифрованные хранилища (*.mvault) и настройки НЕ затрагиваются и НЕ удаляются!
set -euo pipefail

INSTALL_DIR="${MINTVAULT_INSTALL_DIR:-${HOME}/.local/share/mintvault}"
BIN_DIR="${MINTVAULT_BIN_DIR:-${HOME}/.local/bin}"
DESKTOP_DIR="${MINTVAULT_DESKTOP_DIR:-${HOME}/.local/share/applications}"

if [[ -z "${INSTALL_DIR}" || "${INSTALL_DIR}" == "/" || "${INSTALL_DIR}" == "${HOME}" || "${INSTALL_DIR}" == "/usr" || "${INSTALL_DIR}" == "/etc" ]]; then
    echo "ОШИБКА: Отказ удаления небезопасного пути INSTALL_DIR='${INSTALL_DIR}'." >&2
    exit 1
fi

echo "=== Удаление программы MintVault ==="
if [[ -d "${INSTALL_DIR}/mintvault" || "$(basename "${INSTALL_DIR}")" == "mintvault" ]]; then
    rm -rf "${INSTALL_DIR}"
fi
rm -f "${BIN_DIR}/mintvault"
rm -f "${DESKTOP_DIR}/mintvault.desktop"

echo "Программа MintVault удалена. Все ваши файлы хранилищ (*.mvault) сохранены на своих местах."
