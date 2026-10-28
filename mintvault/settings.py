"""
Модуль управления пользовательскими настройками MintVault (`settings.py`).

Обеспечивает:
- Локальное хранение настроек в профиле пользователя Linux по стандарту XDG (`$XDG_CONFIG_HOME/mintvault/settings.json`).
- Безопасные права доступа (`0700` на каталог, `0600` на файл конфигурации), защиту от симлинков (`os.O_NOFOLLOW`) и проверку владельца (`uid`).
- Строгую валидацию каждого параметра при чтении и записи с безопасным откатом к значениям по умолчанию.
- Сохранение через временный файл, `os.fsync` и атомарный обмен с сохранением предыдущего объекта.
- Полный запрет хранения паролей, ключей восстановления, мастер-ключей и любых секретных данных.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import logging
import os
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .fs_utils import fsync_directory

logger = logging.getLogger("mintvault")

VALID_THEMES = ("system", "light", "dark")
VALID_LANGUAGES = ("ru", "en")
VALID_CLOSE_ACTIONS = ("lock_and_close", "ask")
VALID_DUPLICATE_ACTIONS = ("ask", "replace", "keep_both", "skip", "error")

MIN_FONT_SCALE = 85
MAX_FONT_SCALE = 150

MIN_AUTO_LOCK_MINUTES = 0
MAX_AUTO_LOCK_MINUTES = 480

MIN_LARGE_EXTRACTION_THRESHOLD = 1
MAX_LARGE_EXTRACTION_THRESHOLD = 10000

FORBIDDEN_SECRET_KEYS = frozenset({
    "password",
    "passwd",
    "passphrase",
    "secret",
    "master_key",
    "recovery_key",
    "kek",
    "private_key",
    "token",
    "key_slots",
})


@dataclass
class AppSettings:
    """
    Типизированная структура пользовательских настроек приложения MintVault.
    Значения по умолчанию выбраны по принципу максимальной безопасности (fail-safe defaults).
    """

    # 4.1. Внешний вид
    theme: str = "system"  # "system" | "light" | "dark"
    ui_font_scale: int = 100  # 85..150 (%)

    # 4.2. Поведение при добавлении файлов и работе с оригиналами
    duplicate_file_action: str = "ask"  # "ask" | "replace" | "keep_both" | "skip" | "error"
    extract_conflict_action: str = "ask"  # "ask" | "skip" | "keep_both" | "replace" | "error"
    ask_before_deleting_originals: bool = True
    offer_delete_originals_after_add: bool = False

    # 4.3. Язык интерфейса
    language: str = "ru"  # "ru" | "en"

    # 4.4. Дополнительные настройки безопасности и удобства
    confirm_before_vault_delete: bool = True
    confirm_large_extraction: bool = True
    large_extraction_threshold: int = 10
    close_unlocked_action: str = "lock_and_close"  # "lock_and_close" | "ask"
    auto_lock_minutes: int = 10  # 0 = выключено, 1..480 минут
    notify_long_operations: bool = True
    default_backup_dir: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def copy(self) -> "AppSettings":
        return copy.deepcopy(self)


def _validate_bool(val: Any, default: bool) -> Tuple[bool, bool]:
    if isinstance(val, bool):
        return val, True
    return default, False


def _validate_int_range(val: Any, default: int, min_val: int, max_val: int) -> Tuple[int, bool]:
    if isinstance(val, bool) or not isinstance(val, int):
        return default, False
    if min_val <= val <= max_val:
        return val, True
    return default, False


def _validate_choice(val: Any, default: str, allowed: Tuple[str, ...]) -> Tuple[str, bool]:
    if isinstance(val, str) and val in allowed:
        return val, True
    return default, False


def _validate_backup_dir(val: Any) -> Tuple[str, bool]:
    if not isinstance(val, str):
        return "", False
    cleaned = val.strip()
    if not cleaned:
        return "", True
    if "\x00" in cleaned or "\n" in cleaned or "\r" in cleaned:
        return "", False
    try:
        p = Path(cleaned).expanduser()
        if not p.is_absolute():
            return "", False
        if p.exists() or p.is_symlink():
            st = os.lstat(str(p))
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                return "", False
        return str(p), True
    except OSError:
        return "", False


def sanitize_and_validate_settings(raw_data: Any) -> Tuple[AppSettings, list[str]]:
    """
    Проверяет словарь настроек, отбрасывает повреждённые, конфликтующие или запрещённые поля
    и возвращает гарантированно безопасный экземпляр `AppSettings` и список предупреждений.
    """
    defaults = AppSettings()
    warnings: list[str] = []

    if not isinstance(raw_data, dict):
        warnings.append("Корень файла настроек не является JSON-объектом. Применены настройки по умолчанию.")
        return defaults, warnings

    for key in list(raw_data.keys()):
        if not isinstance(key, str):
            continue
        low_key = key.lower()
        if low_key in FORBIDDEN_SECRET_KEYS or "password" in low_key or "secret" in low_key or "master_key" in low_key:
            warnings.append(f"Запрещённое поле '{key}' удалено из настроек безопасности.")

    theme, ok = _validate_choice(raw_data.get("theme", defaults.theme), defaults.theme, VALID_THEMES)
    if not ok and "theme" in raw_data:
        warnings.append("Некорректное значение 'theme'; использовано 'system'.")

    ui_font_scale, ok = _validate_int_range(
        raw_data.get("ui_font_scale", defaults.ui_font_scale),
        defaults.ui_font_scale,
        MIN_FONT_SCALE,
        MAX_FONT_SCALE,
    )
    if not ok and "ui_font_scale" in raw_data:
        warnings.append("Некорректное значение 'ui_font_scale'; использовано 100.")

    dup_act, ok = _validate_choice(
        raw_data.get("duplicate_file_action", defaults.duplicate_file_action),
        defaults.duplicate_file_action,
        VALID_DUPLICATE_ACTIONS,
    )
    if not ok and "duplicate_file_action" in raw_data:
        warnings.append("Некорректное значение 'duplicate_file_action'; использовано 'ask'.")

    ext_act, ok = _validate_choice(
        raw_data.get("extract_conflict_action", defaults.extract_conflict_action),
        defaults.extract_conflict_action,
        VALID_DUPLICATE_ACTIONS,
    )
    if not ok and "extract_conflict_action" in raw_data:
        warnings.append("Некорректное значение 'extract_conflict_action'; использовано 'ask'.")

    ask_del, ok = _validate_bool(
        raw_data.get("ask_before_deleting_originals", defaults.ask_before_deleting_originals),
        defaults.ask_before_deleting_originals,
    )
    if not ok and "ask_before_deleting_originals" in raw_data:
        warnings.append("Некорректное значение 'ask_before_deleting_originals'; включено по умолчанию.")

    offer_del, ok = _validate_bool(
        raw_data.get("offer_delete_originals_after_add", defaults.offer_delete_originals_after_add),
        defaults.offer_delete_originals_after_add,
    )
    if not ok and "offer_delete_originals_after_add" in raw_data:
        warnings.append("Некорректное значение 'offer_delete_originals_after_add'; выключено по умолчанию.")

    language, ok = _validate_choice(raw_data.get("language", defaults.language), defaults.language, VALID_LANGUAGES)
    if not ok and "language" in raw_data:
        warnings.append("Некорректное значение 'language'; использован 'ru'.")

    confirm_vdel, ok = _validate_bool(
        raw_data.get("confirm_before_vault_delete", defaults.confirm_before_vault_delete),
        defaults.confirm_before_vault_delete,
    )
    if not ok and "confirm_before_vault_delete" in raw_data:
        warnings.append("Некорректное значение 'confirm_before_vault_delete'; включено по умолчанию.")

    confirm_lext, ok = _validate_bool(
        raw_data.get("confirm_large_extraction", defaults.confirm_large_extraction),
        defaults.confirm_large_extraction,
    )
    if not ok and "confirm_large_extraction" in raw_data:
        warnings.append("Некорректное значение 'confirm_large_extraction'; включено по умолчанию.")

    lext_thresh, ok = _validate_int_range(
        raw_data.get("large_extraction_threshold", defaults.large_extraction_threshold),
        defaults.large_extraction_threshold,
        MIN_LARGE_EXTRACTION_THRESHOLD,
        MAX_LARGE_EXTRACTION_THRESHOLD,
    )
    if not ok and "large_extraction_threshold" in raw_data:
        warnings.append("Некорректное значение 'large_extraction_threshold'; использовано 10.")

    close_act, ok = _validate_choice(
        raw_data.get("close_unlocked_action", defaults.close_unlocked_action),
        defaults.close_unlocked_action,
        VALID_CLOSE_ACTIONS,
    )
    if not ok and "close_unlocked_action" in raw_data:
        warnings.append("Некорректное значение 'close_unlocked_action'; использовано 'lock_and_close'.")

    auto_lock, ok = _validate_int_range(
        raw_data.get("auto_lock_minutes", defaults.auto_lock_minutes),
        defaults.auto_lock_minutes,
        MIN_AUTO_LOCK_MINUTES,
        MAX_AUTO_LOCK_MINUTES,
    )
    if not ok and "auto_lock_minutes" in raw_data:
        warnings.append("Некорректное значение 'auto_lock_minutes'; использовано значение по умолчанию.")

    notify_long, ok = _validate_bool(
        raw_data.get("notify_long_operations", defaults.notify_long_operations),
        defaults.notify_long_operations,
    )
    if not ok and "notify_long_operations" in raw_data:
        warnings.append("Некорректное значение 'notify_long_operations'; включено по умолчанию.")

    backup_dir, ok = _validate_backup_dir(raw_data.get("default_backup_dir", defaults.default_backup_dir))
    if not ok and "default_backup_dir" in raw_data:
        warnings.append("Некорректный путь 'default_backup_dir'; сброшено.")

    settings = AppSettings(
        theme=theme,
        ui_font_scale=ui_font_scale,
        duplicate_file_action=dup_act,
        extract_conflict_action=ext_act,
        ask_before_deleting_originals=ask_del,
        offer_delete_originals_after_add=offer_del,
        language=language,
        confirm_before_vault_delete=confirm_vdel,
        confirm_large_extraction=confirm_lext,
        large_extraction_threshold=lext_thresh,
        close_unlocked_action=close_act,
        auto_lock_minutes=auto_lock,
        notify_long_operations=notify_long,
        default_backup_dir=backup_dir,
    )
    return settings, warnings


def get_default_config_dir() -> Path:
    """
    Возвращает каталог конфигурации пользователя по стандарту XDG Base Directory.
    Поддерживает переопределение через `MINTVAULT_CONFIG_DIR` для изолированного тестирования.
    """
    override = os.environ.get("MINTVAULT_CONFIG_DIR", "").strip()
    if override:
        return Path(override).expanduser().absolute()

    xdg_config = os.environ.get("XDG_CONFIG_HOME", "").strip()
    if xdg_config and os.path.isabs(xdg_config):
        base = Path(xdg_config)
    else:
        base = Path.home() / ".config"
    return base / "mintvault"


class SettingsManager:
    """
    Безопасный менеджер загрузки, валидации и атомарного сохранения пользовательских настроек.
    """

    def __init__(self, config_dir: Optional[str | Path] = None) -> None:
        self.config_dir: Path = Path(config_dir).expanduser().absolute() if config_dir else get_default_config_dir()
        self.config_file: Path = self.config_dir / "settings.json"
        self.last_warnings: list[str] = []
        self._settings: AppSettings = AppSettings()

    @property
    def settings(self) -> AppSettings:
        return self._settings

    def _ensure_safe_config_dir(self) -> None:
        if self.config_dir.is_symlink():
            raise PermissionError(f"Каталог настроек '{self.config_dir}' не может быть символической ссылкой.")
        if not self.config_dir.exists():
            self.config_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        # Pin the directory before changing or checking permissions. A failure
        # to make it private is a security error, not a cosmetic warning.
        fd = os.open(str(self.config_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode):
                raise PermissionError(f"Путь '{self.config_dir}' не является безопасным каталогом.")
            if hasattr(os, "getuid") and st.st_uid != os.getuid():
                raise PermissionError(f"Каталог настроек '{self.config_dir}' принадлежит другому пользователю.")
            if (st.st_mode & 0o077) != 0:
                os.fchmod(fd, 0o700)
                if os.fstat(fd).st_mode & 0o077:
                    raise PermissionError(f"Не удалось закрыть доступ к каталогу настроек '{self.config_dir}'.")
        finally:
            os.close(fd)

    def load(self) -> AppSettings:
        """
        Читает и валидирует настройки с диска.
        При отсутствии файла создаёт его с безопасными настройками по умолчанию.
        При повреждении файла сохраняет резервную копию повреждённого файла и восстанавливает значения по умолчанию.
        """
        self.last_warnings = []
        try:
            self._ensure_safe_config_dir()
        except Exception as exc:
            self.last_warnings.append(f"Не удалось подготовить каталог настроек: {exc}")
            self._settings = AppSettings()
            return self._settings

        if not self.config_file.exists() and not self.config_file.is_symlink():
            self._settings = AppSettings()
            try:
                self.save(self._settings)
            except Exception as exc:
                self.last_warnings.append(f"Не удалось создать первичный файл настроек: {exc}")
            return self._settings

        try:
            st = os.lstat(str(self.config_file))
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                raise PermissionError("Файл настроек является символической ссылкой или специальным файлом.")
            if hasattr(os, "getuid") and st.st_uid != os.getuid():
                raise PermissionError("Файл настроек принадлежит другому пользователю.")
            if st.st_size > 256 * 1024:
                raise ValueError("Файл настроек превышает допустимый размер (256 КиБ).")

            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(self.config_file), flags)
            try:
                fst = os.fstat(fd)
                if not stat.S_ISREG(fst.st_mode) or fst.st_ino != st.st_ino:
                    raise PermissionError("Обнаружена подмена файла настроек при открытии.")
                if (fst.st_mode & 0o077) != 0:
                    os.fchmod(fd, 0o600)
                    if os.fstat(fd).st_mode & 0o077:
                        raise PermissionError("Не удалось закрыть доступ к файлу настроек.")
                with os.fdopen(fd, "rb") as fp:
                    raw_bytes = fp.read(256 * 1024 + 1)
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise

            raw_obj = json.loads(raw_bytes.decode("utf-8"))
            validated, warnings = sanitize_and_validate_settings(raw_obj)
            self.last_warnings.extend(warnings)
            self._settings = validated

            if warnings:
                try:
                    self.save(self._settings)
                except OSError as exc:
                    self.last_warnings.append(f"Не удалось сохранить исправленные настройки: {exc}")
            return self._settings

        except Exception as exc:
            self.last_warnings.append(f"Файл настроек повреждён или некорректен ({exc}). Восстановлены безопасные значения.")
            logger.warning("Восстановление настроек по умолчанию из-за ошибки чтения конфигурации: %s", exc)
            # Preserve the exact file under a new name before replacing it.
            # Never unlink a symlink or overwrite an existing backup.
            preserved = False
            try:
                st_bad = os.lstat(str(self.config_file))
                if stat.S_ISREG(st_bad.st_mode) and (not hasattr(os, "getuid") or st_bad.st_uid == os.getuid()):
                    corrupt_bak = self.config_dir / f"settings.json.corrupt.{int(time.time())}.{uuid.uuid4().hex}.bak"
                    os.link(str(self.config_file), str(corrupt_bak), follow_symlinks=False)
                    fsync_directory(self.config_dir)
                    preserved = True
            except OSError as backup_error:
                self.last_warnings.append(f"Не удалось сохранить повреждённый файл настроек: {backup_error}")

            self._settings = AppSettings()
            if preserved:
                try:
                    self.save(self._settings)
                except OSError as save_error:
                    self.last_warnings.append(f"Не удалось восстановить настройки: {save_error}")
            return self._settings

    def save(self, new_settings: Optional[AppSettings] = None) -> AppSettings:
        """
        Валидирует и атомарно сохраняет настройки в `settings.json` с правами `0600`.
        Никогда не сохраняет секретные поля.
        """
        target = new_settings if new_settings is not None else self._settings
        raw_dict = target.to_dict() if isinstance(target, AppSettings) else dict(target)
        clean_settings, warnings = sanitize_and_validate_settings(raw_dict)
        self.last_warnings = warnings
        self._settings = clean_settings

        self._ensure_safe_config_dir()

        payload = {
            "config_version": 1,
            **clean_settings.to_dict(),
        }
        encoded = (json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")

        # The displaced object is retained: a checked os.replace can otherwise
        # destroy a file substituted by another process immediately afterwards.
        from .vault import _exchange_files, _file_identity, _move_noreplace
        tmp_path = self.config_dir / f".settings.json.tmp.{os.getpid()}.{uuid.uuid4().hex}"
        recovery = self.config_dir / f".settings.json.recovery.{uuid.uuid4().hex}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        parent_fd = os.open(str(self.config_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                previous = os.stat(self.config_file.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                previous = None
            if previous is not None and (not stat.S_ISREG(previous.st_mode) or
                (hasattr(os, "getuid") and previous.st_uid != os.getuid())):
                raise PermissionError("Файл настроек не является обычным файлом пользователя; он сохранён без изменений.")
            fd = os.open(tmp_path.name, flags, 0o600, dir_fd=parent_fd)
            with os.fdopen(fd, "wb") as fp:
                fp.write(encoded)
                fp.flush()
                os.fsync(fp.fileno())
                candidate = _file_identity(os.fstat(fp.fileno()))
            if _file_identity(os.stat(tmp_path.name, dir_fd=parent_fd, follow_symlinks=False)) != candidate:
                raise OSError("Временный файл настроек подменён; операция отменена.")
            if previous is None:
                _move_noreplace(parent_fd, tmp_path.name, self.config_file.name)
            else:
                if _file_identity(os.stat(self.config_file.name, dir_fd=parent_fd, follow_symlinks=False)) != _file_identity(previous):
                    raise OSError("Файл настроек изменился; операция отменена.")
                _move_noreplace(parent_fd, tmp_path.name, recovery.name)
                moved = os.stat(recovery.name, dir_fd=parent_fd, follow_symlinks=False)
                if _file_identity(moved)[:4] != candidate[:4]:
                    raise OSError(f"Временный файл настроек подменён; объект сохранён: {recovery}")
                os.fsync(parent_fd)
                _exchange_files(parent_fd, recovery.name, self.config_file.name)
                os.fsync(parent_fd)
                displaced = os.stat(recovery.name, dir_fd=parent_fd, follow_symlinks=False)
                if _file_identity(displaced)[:4] != _file_identity(previous)[:4]:
                    raise OSError(f"Файл настроек подменён; вытесненный объект сохранён: {recovery}")
            os.fsync(parent_fd)
            if _file_identity(os.stat(self.config_file.name, dir_fd=parent_fd, follow_symlinks=False))[:4] != candidate[:4]:
                raise OSError("Файл настроек изменён при публикации; проверьте файлы восстановления.")
            return self._settings
        finally:
            os.close(parent_fd)
