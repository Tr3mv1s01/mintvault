"""
Интерфейс командной строки (CLI) и единая точка входа приложения MintVault (`cli.py`).

Позволяет:
- Запускать графический интерфейс (`mintvault` или `mintvault gui [путь_к_хранилищу]`).
- Выполнять диагностику, проверку целостности, резервное копирование и базовые операции из терминала или скриптов.
- Гарантировать отсутствие паролей в аргументах командной строки и логах (пароль запрашивается интерактивно через `getpass` или передаётся через файловый дескриптор STDIN в автоматизированных тестах).
"""

import argparse
import getpass
import logging
import sys
from pathlib import Path
from typing import List, Optional

from . import __app_name__, __version__
from .crypto import is_argon2id_available
from .exceptions import MintVaultError
from .vault import SecureVault


def configure_safe_logging(verbose: bool = False) -> None:
    """
    Настраивает системное логирование приложения.
    Никогда не выводит пароли, мастер-ключи или содержимое пользовательских файлов.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _read_secret_interactive(prompt: str = "Введите пароль хранилища: ") -> str:
    try:
        if not sys.stdin.isatty():
            return sys.stdin.readline().rstrip("\r\n")
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt) as exc:
        raise MintVaultError("Ввод пароля был прерван пользователем.") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mintvault",
        description=f"{__app_name__} v{__version__} — Защищённое локальное хранилище секретных файлов для Linux Mint.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{__app_name__} {__version__}",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Включить подробные диагностические сообщения (без секретных данных).",
    )

    subparsers = parser.add_subparsers(dest="command", help="Доступные команды (по умолчанию запускается GUI)")

    # GUI
    p_gui = subparsers.add_parser("gui", help="Запустить графический интерфейс приложения")
    p_gui.add_argument("vault", nargs="?", help="Необязательный путь к файлу хранилища (.mvault)")

    # Информация о среде и самопроверка
    subparsers.add_parser("doctor", help="Проверить системное окружение, криптобиблиотеки и готовность к работе")

    # Создание хранилища
    p_init = subparsers.add_parser("init", help="Создать новое зашифрованное хранилище (.mvault)")
    p_init.add_argument("vault", help="Путь к создаваемому файлу хранилища (.mvault)")
    p_init.add_argument("--no-recovery-key", action="store_true", help="Не создавать аварийный ключ восстановления")

    # Просмотр списка файлов
    p_list = subparsers.add_parser("list", help="Показать список объектов в хранилище")
    p_list.add_argument("vault", help="Путь к файлу хранилища (.mvault)")
    p_list.add_argument("--search", default="", help="Поиск по имени файла")
    p_list.add_argument("--recovery", action="store_true", help="Использовать ключ восстановления вместо пароля")

    # Добавление файлов
    p_add = subparsers.add_parser("add", help="Добавить файлы или папки в хранилище (оригиналы сохраняются)")
    p_add.add_argument("vault", help="Путь к файлу хранилища (.mvault)")
    p_add.add_argument("sources", nargs="+", help="Пути к добавляемым файлам и каталогам")

    # Извлечение файлов
    p_extract = subparsers.add_parser("extract", help="Извлечь файлы из хранилища в указанный каталог")
    p_extract.add_argument("vault", help="Путь к файлу хранилища (.mvault)")
    p_extract.add_argument("--dest", required=True, help="Целевой каталог для извлечения")
    p_extract.add_argument("targets", nargs="*", help="Виртуальные пути внутри хранилища (если не указаны — извлечь всё)")
    p_extract.add_argument("--recovery", action="store_true", help="Использовать ключ восстановления вместо пароля")

    # Проверка целостности
    p_verify = subparsers.add_parser("verify", help="Проверить целостность заголовка, индекса и всех блоков файлов")
    p_verify.add_argument("vault", help="Путь к файлу хранилища (.mvault)")
    p_verify.add_argument("--header-only", action="store_true", help="Проверить только структуру заголовка без пароля")

    # Резервная копия
    p_backup = subparsers.add_parser("backup", help="Создать проверенную резервную копию файла хранилища")
    p_backup.add_argument("vault", help="Путь к исходному файлу хранилища (.mvault)")
    p_backup.add_argument("destination", help="Путь для сохранения резервной копии")

    p_backup.add_argument("--recovery", action="store_true", help="Использовать ключ восстановления")

    return parser


def run_doctor() -> int:
    print(f"=== Диагностика окружения {__app_name__} v{__version__} ===")
    print(f"Версия Python: {sys.version.split()[0]}")
    print(f"Нативная поддержка Argon2id (libargon2): {'ДА' if is_argon2id_available() else 'НЕТ (используется Scrypt)'}")
    try:
        import cryptography
        print(f"Библиотека cryptography (OpenSSL AEAD AES-256-GCM): ДА (v{cryptography.__version__})")
    except Exception as exc:
        print(f"Библиотека cryptography: ОШИБКА ({exc})")
        return 1

    try:
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk  # noqa: F401
        print("Графическая подсистема GTK 3 (PyGObject): ДОСТУПНА")
    except Exception as exc:
        print(f"Графическая подсистема GTK 3: НЕДОСТУПНА ({exc})")
        return 1

    print("Статус: Проверенные компоненты окружения доступны; безопасность системы не оценивалась.")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_safe_logging(verbose=args.verbose)

    cmd = args.command or "gui"

    try:
        if cmd == "gui":
            from .gui import run_gui
            vault_arg = getattr(args, "vault", None)
            return run_gui(initial_vault_path=vault_arg)

        if cmd == "doctor":
            return run_doctor()

        if cmd == "init":
            pwd = _read_secret_interactive("Введите новый мастер-пароль: ")
            try:
                if sys.stdin.isatty():
                    pwd2 = _read_secret_interactive("Повторите мастер-пароль: ")
                    if pwd != pwd2:
                        print("Ошибка: введённые пароли не совпадают.", file=sys.stderr)
                        return 2
                vault, rec_key = SecureVault.create(
                    vault_path=args.vault,
                    password=pwd,
                    create_recovery_key=not args.no_recovery_key,
                )
                vault.close()
                print(f"Хранилище успешно создано: {Path(args.vault).resolve()}")
                print("ВАЖНО: Забытый пароль невозможно восстановить без аварийного ключа!")
                if rec_key:
                    print(f"Аварийный ключ восстановления (сохраните его в надёжном месте):\n{rec_key}")
                return 0
            finally:
                pwd = ""

        if cmd == "list":
            secret = _read_secret_interactive(
                "Введите ключ восстановления: " if args.recovery else "Введите пароль хранилища: "
            )
            try:
                with SecureVault(args.vault) as vault:
                    vault.unlock(secret, use_recovery_key=args.recovery)
                    entries = vault.list_entries(search_query=args.search)
                    if not entries:
                        print("Хранилище пусто (или ничего не найдено).")
                    else:
                        for e in entries:
                            t_str = "DIR " if e.entry_type == "dir" else "FILE"
                            print(f"[{t_str}] {e.virtual_path} ({e.size} байт)")
                return 0
            finally:
                secret = ""

        if cmd == "add":
            secret = _read_secret_interactive("Введите пароль хранилища: ")
            try:
                with SecureVault(args.vault) as vault:
                    vault.unlock(secret)
                    added = vault.add_paths(args.sources)
                    print(f"Добавлено объектов: {len(added)}. Исходные файлы сохранены без изменений.")
                return 0
            finally:
                secret = ""

        if cmd == "extract":
            secret = _read_secret_interactive(
                "Введите ключ восстановления: " if args.recovery else "Введите пароль хранилища: "
            )
            try:
                with SecureVault(args.vault) as vault:
                    vault.unlock(secret, use_recovery_key=args.recovery)
                    targets = args.targets or [e.virtual_path for e in vault.list_entries()]
                    extracted = vault.extract_entries(targets, args.dest)
                    print(f"Извлечено и проверено объектов: {len(extracted)} -> {Path(args.dest).resolve()}")
                return 0
            finally:
                secret = ""

        if cmd == "verify":
            with SecureVault(args.vault) as vault:
                if not args.header_only:
                    secret = _read_secret_interactive("Введите пароль хранилища для полной проверки: ")
                    try:
                        vault.unlock(secret)
                    finally:
                        secret = ""
                rep = vault.verify_integrity()
                if rep.is_valid and args.header_only:
                    print("Структура заголовка проверена. Криптографическая целостность содержимого НЕ подтверждена.")
                    return 0
                if rep.is_valid:
                    print(
                        f"ЦЕЛОСТНОСТЬ ПОДТВЕРЖДЕНА: проверено файлов {rep.verified_files}/{rep.total_files}, "
                        f"папок {rep.total_dirs}."
                    )
                    return 0
                else:
                    print("ОШИБКА ЦЕЛОСТНОСТИ ХРАНИЛИЩА:", file=sys.stderr)
                    for err in rep.errors:
                        print(f" - {err}", file=sys.stderr)
                    return 3

        if cmd == "backup":
            secret = _read_secret_interactive(
                "Введите ключ восстановления: " if args.recovery else "Введите пароль хранилища: "
            )
            try:
                with SecureVault(args.vault) as vault:
                    vault.unlock(secret, use_recovery_key=args.recovery)
                    out = vault.create_backup(args.destination)
                    print(f"Резервная копия успешно создана и проверена: {out}")
                return 0
            finally:
                secret = ""

        parser.print_help()
        return 1

    except MintVaultError as exc:
        print(f"Ошибка MintVault: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Непредвиденная ошибка: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
