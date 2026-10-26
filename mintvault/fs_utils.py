"""
Безопасный файловый слой MintVault (`fs_utils.py`).

Отвечает за:
- Проверку файловых объектов по принципу безопасного отказа (запрет символических ссылок, FIFO, сокетов, устройств).
- Безопасное открытие исходных файлов через `os.O_NOFOLLOW | os.O_NONBLOCK` с проверкой `os.fstat` (защита от TOCTOU-гонок).
- Нормализацию и валидацию виртуальных путей внутри хранилища (защита от Path Traversal, `..`, `\`, абсолютных путей, нулевых байтов и превышения длины).
- Безопасный расчёт целевого пути при извлечении (`os.path.commonpath`), проверку отсутствия симлинков в промежуточных каталогах и атомарную публикацию без перезаписи (`os.link` + `os.unlink`).
- Контроль свободного места на диске перед началом записи.
- Безопасную синхронизацию файлов и родительских каталогов (`os.fsync`) перед атомарным переименованием (`os.replace`).
"""

import errno
import fcntl
import os
import posixpath
import shutil
import stat
from pathlib import Path
from typing import BinaryIO, List, Optional, Tuple

from .exceptions import (
    FileOverwriteError,
    InsufficientDiskSpaceError,
    PathTraversalError,
    UnsafeFileObjectError,
)

MAX_FILENAME_BYTES = 255
MAX_VIRTUAL_PATH_BYTES = 4096


def validate_safe_source_object(path: str | Path) -> os.stat_result:
    """
    Проверяет исходный файл или каталог с использованием `os.lstat` (без перехода по ссылкам).
    По принципу безопасного отказа (fail-safe) отклоняет символические ссылки, именованные каналы (FIFO),
    сокеты и блочные/символьные устройства.
    """
    p_str = str(path)
    try:
        st = os.lstat(p_str)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Файл или каталог не найден: {p_str}") from exc
    except PermissionError as exc:
        raise PermissionError(f"Нет прав доступа для чтения объекта: {p_str}") from exc
    except OSError as exc:
        raise OSError(f"Ошибка доступа к файловому объекту '{p_str}': {exc}") from exc

    mode = st.st_mode
    if stat.S_ISLNK(mode):
        raise UnsafeFileObjectError(
            f"Отказ по соображениям безопасности: '{p_str}' является символической ссылкой. "
            "Символические ссылки не добавляются в хранилище во избежание раскрытия внешних файлов."
        )
    if stat.S_ISFIFO(mode):
        raise UnsafeFileObjectError(
            f"Отказ по соображениям безопасности: '{p_str}' является именованным каналом (FIFO)."
        )
    if stat.S_ISSOCK(mode):
        raise UnsafeFileObjectError(
            f"Отказ по соображениям безопасности: '{p_str}' является сокетом."
        )
    if stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
        raise UnsafeFileObjectError(
            f"Отказ по соображениям безопасности: '{p_str}' является файлом устройства."
        )
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        raise UnsafeFileObjectError(
            f"Отказ по соображениям безопасности: '{p_str}' имеет неподдерживаемый тип объекта."
        )

    if stat.S_ISREG(mode):
        if not os.access(p_str, os.R_OK):
            raise PermissionError(f"Отсутствуют права на чтение файла: {p_str}")
    elif stat.S_ISDIR(mode):
        if not os.access(p_str, os.R_OK | os.X_OK):
            raise PermissionError(f"Отсутствуют права на чтение/обход каталога: {p_str}")

    return st


def open_safe_regular_file_for_read(
    path: str | Path,
    expected_stat: Optional[os.stat_result] = None,
) -> Tuple[BinaryIO, os.stat_result]:
    """
    Атомарно открывает обычный файл только для чтения с флагами `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`,
    проверяет дескриптор через `os.fstat(fd)` (отклоняя симлинки, FIFO, устройства и подмену inode),
    сбрасывает `O_NONBLOCK` и возвращает открытый файловый объект и его `stat_result`.
    Защищает от TOCTOU-гонок между проверкой пути и открытием файла.
    """
    p_str = str(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(p_str, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UnsafeFileObjectError(
                f"Отказ по соображениям безопасности: '{p_str}' является символической ссылкой."
            ) from exc
        if exc.errno == errno.ENOENT:
            raise FileNotFoundError(f"Файл не найден: {p_str}") from exc
        if exc.errno in (errno.EACCES, errno.EPERM):
            raise PermissionError(f"Нет прав доступа для чтения файла: {p_str}") from exc
        raise

    try:
        fst = os.fstat(fd)
        mode = fst.st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise UnsafeFileObjectError(
                f"Отказ по соображениям безопасности: '{p_str}' не является обычным файлом."
            )
        if expected_stat is not None:
            if (
                fst.st_ino != expected_stat.st_ino
                or fst.st_dev != expected_stat.st_dev
                or fst.st_size != expected_stat.st_size
                or fst.st_mtime_ns != expected_stat.st_mtime_ns
            ):
                raise UnsafeFileObjectError(
                    f"Исходный файл '{p_str}' был изменён или подменён перед чтением. Операция прервана."
                )
        # Сбрасываем O_NONBLOCK для штатного потокового чтения обычного файла
        try:
            cur_fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, cur_fl & ~ getattr(os, "O_NONBLOCK", 0))
        except OSError:
            pass
        return os.fdopen(fd, "rb"), fst
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def normalize_virtual_path(virtual_path: str) -> str:
    """
    Нормализует относительный путь внутри хранилища (использует POSIX-разделитель '/').
    Строго блокирует пустые пути, нулевые байты, обратные слеши, абсолютные пути,
    сегменты '..' или '.', а также имена длиннее 255 байт.
    Поддерживает полную кодировку UTF-8, русские буквы, пробелы и печатные специальные символы.
    """
    if not virtual_path or not isinstance(virtual_path, str):
        raise PathTraversalError("Виртуальный путь внутри хранилища не может быть пустым.")
    if "\x00" in virtual_path:
        raise PathTraversalError("Виртуальный путь содержит недопустимый нулевой байт.")
    if "\\" in virtual_path:
        raise PathTraversalError(f"Обратные слеши запрещены в виртуальном пути: '{virtual_path}'")
    if virtual_path.startswith("/"):
        raise PathTraversalError(f"Абсолютные пути внутри хранилища запрещены: '{virtual_path}'")

    cleaned = virtual_path.strip("/")
    if not cleaned:
        raise PathTraversalError("Недопустимый корневой виртуальный путь.")

    parts = cleaned.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise PathTraversalError(
                f"Обнаружен опасный сегмент пути '{part}' в виртуальном пути '{virtual_path}'."
            )
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in part):
            raise PathTraversalError(
                f"Виртуальный путь содержит недопустимые управляющие символы: '{virtual_path}'."
            )
        if len(part.encode("utf-8")) > MAX_FILENAME_BYTES:
            raise PathTraversalError(
                f"Имя объекта превышает максимальную длину ФС (255 байт UTF-8): '{part[:40]}...'"
            )

    norm = posixpath.normpath(cleaned)
    if norm.startswith("..") or norm.startswith("/") or norm == ".":
        raise PathTraversalError(f"Небезопасный нормализованный путь: '{norm}'")
    if len(norm.encode("utf-8")) > MAX_VIRTUAL_PATH_BYTES:
        raise PathTraversalError("Общая длина виртуального пути превышает допустимый предел (4096 байт).")

    return norm


def verify_no_symlink_components(root_path: Path, target_path: Path) -> None:
    """
    Проверяет через `os.lstat`, что сам `root_path` и ни один промежуточный каталог
    между `root_path` и `target_path` не является символической ссылкой.
    """
    st_root = os.lstat(str(root_path))
    if stat.S_ISLNK(st_root.st_mode) or not stat.S_ISDIR(st_root.st_mode):
        raise PathTraversalError(f"Корневой каталог назначения '{root_path}' не является безопасным каталогом.")

    rel_parts = target_path.relative_to(root_path).parts
    curr = root_path
    for part in rel_parts[:-1]:
        curr = curr / part
        try:
            st = os.lstat(str(curr))
            if stat.S_ISLNK(st.st_mode):
                raise PathTraversalError(
                    f"Промежуточный каталог '{curr}' является символической ссылкой. Операция прервана."
                )
            if not stat.S_ISDIR(st.st_mode):
                raise FileOverwriteError(
                    f"Промежуточный путь '{curr}' занят файлом и не является каталогом."
                )
        except FileNotFoundError:
            pass


def ensure_safe_directory_tree(root_path: Path, target_dir: Path, mode: int = 0o755) -> None:
    """
    Безопасно пошагово создаёт промежуточные каталоги внутри `root_path`,
    проверяя каждый сегмент через `os.lstat` и защищая от подмены симлинками.
    """
    verify_no_symlink_components(root_path, target_dir / "_placeholder")
    rel_parts = target_dir.relative_to(root_path).parts
    curr = root_path
    for part in rel_parts:
        curr = curr / part
        try:
            st = os.lstat(str(curr))
            if stat.S_ISLNK(st.st_mode):
                raise PathTraversalError(
                    f"Обнаружена символическая ссылка в пути назначения: '{curr}'."
                )
            if not stat.S_ISDIR(st.st_mode):
                raise FileOverwriteError(
                    f"Путь '{curr}' уже существует и не является каталогом."
                )
        except FileNotFoundError:
            curr.mkdir(mode=mode, exist_ok=False)
            st_new = os.lstat(str(curr))
            if stat.S_ISLNK(st_new.st_mode) or not stat.S_ISDIR(st_new.st_mode):
                raise PathTraversalError(f"Ошибка проверки созданного каталога '{curr}'.")


def atomic_publish_extracted_file(tmp_path: Path, final_path: Path) -> None:
    """
    Атомарно публикует проверенный временный файл `tmp_path` под именем `final_path`
    БЕЗ перезаписи существующего файла (защита от TOCTOU).
    Использует системный вызов `os.link(tmp_path, final_path)` + `os.unlink(tmp_path)`,
    который на уровне ядра Linux гарантированно возвращает `FileExistsError` (`EEXIST`),
    если `final_path` уже существует (включая симлинки).
    """
    try:
        os.link(str(tmp_path), str(final_path))
        os.unlink(str(tmp_path))
        return
    except FileExistsError as exc:
        raise FileOverwriteError(
            f"Целевой файл уже существует и не будет перезаписан: {final_path}"
        ) from exc
    except OSError as exc:
        # Нет переносимого атомарного аналога link(..., EEXIST) в стандартной
        # библиотеке. Не заменяем его lstat()+os.replace(): между вызовами
        # может появиться пользовательский файл, который os.replace затрёт.
        # При неподдерживаемых hardlink операция безопасно завершается ошибкой.
        if exc.errno in (errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV):
            raise OSError(
                exc.errno,
                "Файловая система не поддерживает безопасную публикацию без перезаписи",
                str(final_path),
            ) from exc
        raise


def make_unique_disk_path(candidate: Path, reserved_paths: Optional[set[Path]] = None) -> Path:
    """
    Подбирает свободное имя файла на диске вида 'IMG_4687 (1).MOV', 'IMG_4687 (2).MOV',
    не перезаписывая существующие файлы.
    """
    parent = candidate.parent
    stem, ext = os.path.splitext(candidate.name)
    if not stem:
        stem, ext = candidate.name, ""
    counter = 1
    while True:
        suffix = f" ({counter})"
        max_stem_bytes = 250 - len(suffix.encode("utf-8")) - len(ext.encode("utf-8"))
        stem_bytes = stem.encode("utf-8")
        if len(stem_bytes) > max_stem_bytes:
            stem = stem_bytes[:max_stem_bytes].decode("utf-8", errors="ignore")
        alt = parent / f"{stem}{suffix}{ext}"
        if reserved_paths is not None and alt in reserved_paths:
            counter += 1
            continue
        try:
            os.lstat(str(alt))
            counter += 1
        except FileNotFoundError:
            return alt


def resolve_safe_extraction_path(
    dest_root: str | Path,
    target_rel_path: str,
    allow_existing: bool = False,
) -> Path:
    """
    Безопасно вычисляет целевой путь на диске для извлечения объекта из хранилища.
    Защищает от Path Traversal (обхода каталогов) и проверяет, что ни один промежуточный
    компонент внутри dest_root не является символической ссылкой.
    Если `allow_existing=False` (по умолчанию), также проверяет отсутствие целевого объекта на диске.
    """
    norm_rel = normalize_virtual_path(target_rel_path)
    raw_root = Path(dest_root)
    if raw_root.is_symlink():
        raise PathTraversalError(f"Целевой каталог для извлечения не может быть символической ссылкой: {dest_root}")
    root_path = raw_root.resolve()
    if not root_path.exists() or not root_path.is_dir():
        raise FileNotFoundError(f"Целевой каталог для извлечения не существует: {dest_root}")

    candidate = root_path.joinpath(*norm_rel.split("/"))
    abs_root = os.path.abspath(str(root_path))
    abs_candidate = os.path.abspath(str(candidate))
    if os.path.commonpath([abs_root, abs_candidate]) != abs_root or abs_candidate == abs_root:
        raise PathTraversalError(
            f"Попытка извлечения файла за пределы целевого каталога заблокирована: '{target_rel_path}'"
        )

    verify_no_symlink_components(root_path, candidate)

    try:
        st_cand = os.lstat(str(candidate))
        if stat.S_ISLNK(st_cand.st_mode):
            raise PathTraversalError(
                f"Целевой путь '{candidate}' является символической ссылкой. Извлечение заблокировано."
            )
        if not allow_existing:
            raise FileOverwriteError(
                f"Целевой объект уже существует и не будет перезаписан: {candidate}"
            )
    except FileNotFoundError:
        pass

    return candidate


def collect_source_items(source_path: str | Path, base_virtual_prefix: str = "") -> List[Tuple[Path, str, str, os.stat_result]]:
    """
    Рекурсивно обходит выбранный пользователем файл или каталог.
    Не следует по символическим ссылкам (`followlinks=False`).
    Если внутри каталога обнаруживается симлинк или спецфайл — немедленно выбрасывает UnsafeFileObjectError
    до начала модификации хранилища.

    Возвращает список кортежей:
      (абсолютный_путь_источника, виртуальный_путь_в_хранилище, тип_объекта ('file' | 'dir'), stat_result)
    """
    src = Path(source_path)
    st = validate_safe_source_object(src)
    root_name = src.name
    if not root_name or root_name in (".", ".."):
        raise PathTraversalError(f"Некорректное имя добавляемого объекта: '{source_path}'")

    virt_root = f"{base_virtual_prefix.strip('/')}/{root_name}".strip("/") if base_virtual_prefix else root_name
    virt_root = normalize_virtual_path(virt_root)

    items: List[Tuple[Path, str, str, os.stat_result]] = []

    if stat.S_ISREG(st.st_mode):
        items.append((src, virt_root, "file", st))
        return items

    items.append((src, virt_root, "dir", st))

    def _walk_dir(current_fs_dir: Path, current_virt_dir: str) -> None:
        try:
            with os.scandir(str(current_fs_dir)) as it:
                entries = sorted(list(it), key=lambda e: e.name)
        except OSError as exc:
            raise OSError(f"Ошибка чтения каталога '{current_fs_dir}': {exc}") from exc

        for entry in entries:
            entry_path = Path(entry.path)
            entry_st = validate_safe_source_object(entry_path)
            child_virt = normalize_virtual_path(f"{current_virt_dir}/{entry.name}")
            if stat.S_ISDIR(entry_st.st_mode):
                items.append((entry_path, child_virt, "dir", entry_st))
                _walk_dir(entry_path, child_virt)
            elif stat.S_ISREG(entry_st.st_mode):
                items.append((entry_path, child_virt, "file", entry_st))

    _walk_dir(src, virt_root)
    return items


def check_disk_space(target_dir: str | Path, required_bytes: int, safety_margin_bytes: int = 2 * 1024 * 1024) -> None:
    """
    Проверяет наличие достаточного свободного места на файловой системе перед выполнением записи.
    Позволяет переопределить лимит в тестах через переменную окружения MINTVAULT_SIMULATE_FREE_BYTES.
    """
    sim_free = os.environ.get("MINTVAULT_SIMULATE_FREE_BYTES")
    if sim_free is not None:
        free_bytes = int(sim_free)
    else:
        usage = shutil.disk_usage(str(target_dir))
        free_bytes = usage.free

    total_needed = max(0, required_bytes) + safety_margin_bytes
    if free_bytes < total_needed:
        raise InsufficientDiskSpaceError(
            f"Недостаточно свободного места на диске '{target_dir}': "
            f"требуется {total_needed:,} байт, доступно {free_bytes:,} байт."
        )


def fsync_directory(dir_path: str | Path) -> None:
    """Принудительно сбрасывает метаданные каталога на диск (POSIX fsync)."""
    try:
        fd = os.open(str(dir_path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass
