#!/usr/bin/env bash
# Автоматизированный скрипт локальной установки MintVault для пользователя Linux Mint
# Работает без прав root (устанавливает в ~/.local/share/mintvault и ~/.local/bin/mintvault),
# создаёт ярлык в меню приложений Cinnamon/MATE/Xfce.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${MINTVAULT_INSTALL_DIR:-${HOME}/.local/share/mintvault}"
BIN_DIR="${MINTVAULT_BIN_DIR:-${HOME}/.local/bin}"
DESKTOP_DIR="${MINTVAULT_DESKTOP_DIR:-${HOME}/.local/share/applications}"

if [[ -z "${INSTALL_DIR}" || "${INSTALL_DIR}" == "/" || "${INSTALL_DIR}" == "${HOME}" ]]; then
    echo "ОШИБКА: Небезопасный каталог установки INSTALL_DIR='${INSTALL_DIR}'." >&2
    exit 1
fi

echo "=== Установка MintVault (Защищённое хранилище файлов для Linux Mint) ==="

# 1. Проверка системного окружения без установки системных пакетов от root
echo "[1/4] Проверка зависимостей Python 3, GTK 3, OpenSSL и libargon2..."
if ! python3 -c "
import sys
import cryptography
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
" 2>/dev/null; then
    echo "ОШИБКА: Не найдены обязательные системные пакеты Python3 / GTK3 / cryptography." >&2
    echo "На Linux Mint установите их из официального репозитория командой:" >&2
    echo "  sudo apt update && sudo apt install -y python3-cryptography python3-gi gir1.2-gtk-3.0 libargon2-1 libsodium23" >&2
    exit 1
fi

# 2. Подготовка новой версии отдельно, чтобы ошибка копирования не оставила
# установленную программу наполовину обновлённой.
echo "[2/4] Подготовка файлов приложения для ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}" "${BIN_DIR}" "${DESKTOP_DIR}"
STAGE_DIR="$(mktemp -d "${INSTALL_DIR}/.mintvault-update.XXXXXX")"
BACKUP_DIR="${INSTALL_DIR}/.mintvault-previous.$$"
cleanup() {
    rm -rf "${STAGE_DIR}"
    if [[ -d "${BACKUP_DIR}" && ! -d "${INSTALL_DIR}/mintvault" ]]; then
        mv "${BACKUP_DIR}" "${INSTALL_DIR}/mintvault"
    fi
}
trap cleanup EXIT
cp -r "${SCRIPT_DIR}/mintvault" "${STAGE_DIR}/"
cp "${SCRIPT_DIR}/requirements.txt" "${STAGE_DIR}/"
cp "${SCRIPT_DIR}/run_mintvault.sh" "${STAGE_DIR}/"
chmod 755 "${STAGE_DIR}/run_mintvault.sh"
if [[ -e "${INSTALL_DIR}/mintvault" ]]; then
    mv "${INSTALL_DIR}/mintvault" "${BACKUP_DIR}"
fi
if ! mv "${STAGE_DIR}/mintvault" "${INSTALL_DIR}/mintvault"; then
    if [[ -d "${BACKUP_DIR}" ]]; then
        mv "${BACKUP_DIR}" "${INSTALL_DIR}/mintvault"
    fi
    echo "ОШИБКА: Не удалось установить новую версию; предыдущая версия восстановлена." >&2
    exit 1
fi
rm -rf "${BACKUP_DIR}"
mv "${STAGE_DIR}/requirements.txt" "${INSTALL_DIR}/requirements.txt"
mv "${STAGE_DIR}/run_mintvault.sh" "${INSTALL_DIR}/run_mintvault.sh"

# 3. Создание исполняемой команды в ~/.local/bin/mintvault
echo "[3/4] Создание стартового скрипта ${BIN_DIR}/mintvault..."
cat > "${BIN_DIR}/mintvault" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="${INSTALL_DIR}:\${PYTHONPATH:-}"
exec python3 -m mintvault "\$@"
EOF
chmod 755 "${BIN_DIR}/mintvault"

# 4. Создание ярлыка .desktop для меню Linux Mint (Cinnamon / MATE / Xfce)
echo "[4/4] Создание ярлыка меню приложений ${DESKTOP_DIR}/mintvault.desktop..."
cat > "${DESKTOP_DIR}/mintvault.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=MintVault
Name[ru]=MintVault — Защищённое хранилище
Comment=Local encrypted file vault (AES-256-GCM + Argon2id)
Comment[ru]=Локальное криптографическое хранилище секретных файлов (AES-256-GCM + Argon2id)
Exec="${BIN_DIR}/mintvault" gui %f
Icon=security-high
Terminal=false
Categories=Utility;Security;FileTools;GTK;
StartupNotify=true
MimeType=application/x-mintvault;
EOF
chmod 644 "${DESKTOP_DIR}/mintvault.desktop"

echo ""
echo "Установка успешно завершена!"
echo "• Команда запуска из терминала: ${BIN_DIR}/mintvault"
echo "• Ярлык в меню Linux Mint: ${DESKTOP_DIR}/mintvault.desktop"
echo "• Проверка окружения: ${BIN_DIR}/mintvault doctor"
