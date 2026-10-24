"""
Управление форматом хранилища и транзакционное ядро MintVault (`vault.py`).

Бинарный формат контейнера `.mvault`:
  [0..8]    MAGIC: b"MVAULT01" (8 байт)
  [8..12]   VERSION: uint32 BE = 1 (4 байта)
  [12..16]  HEADER_LEN: uint32 BE (4 байта)
  [16..24]  INDEX_OFFSET: uint64 BE (8 байт)
  [24..32]  INDEX_LEN: uint64 BE (8 байт)
  [32..32+HEADER_LEN] Заголовок хранилища в формате UTF-8 JSON (включая слоты ключей и AEAD-тег заголовка)
  [32+HEADER_LEN .. INDEX_OFFSET] Зашифрованные потоки файлов (каждый чанк защищён AES-256-GCM)
  [INDEX_OFFSET .. INDEX_OFFSET+INDEX_LEN] Зашифрованный индекс хранилища (AES-256-GCM)

Безопасность транзакций (Copy-on-Write):
  Любое изменение хранилища (добавление файлов, удаление объектов, смена пароля)
  выполняется путём сборки нового контейнера во временном файле `.<vault_name>.mvault.tmp.<pid>`
  в том же каталоге, полного сброса буферов (`flush` + `os.fsync`), криптографической верификации
  записанного заголовка и индекса и только после этого — атомарной замены `os.replace(tmp_path, vault_path)`.
  Исходное рабочее хранилище никогда не перезаписывается до успешного завершения новой операции!
"""

import copy
import dataclasses
import errno
import fcntl
import hashlib
import json
import logging
import os
import shutil
import stat
import struct
import threading
import time
import uuid
from pathlib import Path
from typing import Any, BinaryIO, Callable, Dict, List, Optional, Tuple

from .crypto import (
    AES_GCM_NONCE_SIZE,
    AES_GCM_TAG_SIZE,
    MASTER_KEY_SIZE,
    SALT_SIZE,
    compute_header_mac,
    create_key_slot,
    decrypt_file_stream,
    decrypt_index_bytes,
    encrypt_file_stream,
    encrypt_index_bytes,
    generate_recovery_key,
    normalize_recovery_key,
    unwrap_key_slot,
    validate_kdf_params,
    verify_header_mac,
    zero_memory,
)
from .exceptions import (
    AuthenticationError,
    FileOverwriteError,
    IntegrityError,
    MintVaultError,
    OperationCancelledError,
    PathTraversalError,
    UnsafeFileObjectError,
    VaultBusyError,
    VaultFormatError,
    VaultLockedError,
)
from .fs_utils import (
    atomic_publish_extracted_file,
    check_disk_space,
    collect_source_items,
    ensure_safe_directory_tree,
    fsync_directory,
    make_unique_disk_path,
    normalize_virtual_path,
    open_safe_regular_file_for_read,
    resolve_safe_extraction_path,
    validate_safe_source_object,
    verify_no_symlink_components,
)
from .models import IntegrityReport, VaultEntry, WrappedKeySlot

MAGIC_BYTES = b"MVAULT01"
FORMAT_VERSION = 1
SUPPORTED_CIPHER = "AES-256-GCM"
FIXED_PREAMBLE_FMT = ">8sIIQQ"
FIXED_PREAMBLE_SIZE = struct.calcsize(FIXED_PREAMBLE_FMT)  # 32 байта
MAX_HEADER_SIZE = 4 * 1024 * 1024  # 4 МБ
MAX_INDEX_SIZE = 64 * 1024 * 1024  # 64 МБ
MAX_KEY_SLOTS = 4
MIN_ENCRYPTED_BLOB_SIZE = 5 + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE  # 33 байта

# Настраиваем безопасный логгер, который гарантированно не логирует пароли, ключи или содержимое файлов
logger = logging.getLogger("mintvault")


def _canonical_header_bytes(header_dict: Dict[str, Any]) -> bytes:
    """Формирует каноническое байтовое представление заголовка без поля header_mac_hex для проверки подлинности."""
    clean = {k: v for k, v in header_dict.items() if k != "header_mac_hex"}
    return json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _is_pid_running(pid: int) -> bool:
    """Проверяет, существует ли активный процесс с указанным PID в системе."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _extract_pid_from_temp_name(name: str, prefix: str) -> Optional[int]:
    """Извлекает PID из имени временного файла `.<vault_name>.tmp.<pid>[.<uuid>]`."""
    if not name.startswith(prefix):
        return None
    tail = name[len(prefix) :]
    pid_part = tail.split(".", 1)[0]
    if pid_part.isdigit():
        return int(pid_part)
    return None


def _validate_and_parse_index(
    index_data: Any,
    expected_vault_uuid: str,
    data_start: int,
    index_offset: int,
) -> Dict[str, VaultEntry]:
    """
    Выполняет строгую структурную и логическую валидацию расшифрованного индекса хранилища:
    - проверяет `format_version` и привязку `vault_uuid` к заголовку;
    - проверяет уникальность `entry_id` и нормализованных виртуальных путей `virtual_path`;
    - проверяет допустимость полей каждого файла и папки;
    - проверяет, что все зашифрованные блобы файлов строго покрывают секцию данных `[data_start, index_offset)`
      без пересечений, выходов за границы и неаутентифицированных зазоров.
    """
    if not isinstance(index_data, dict):
        raise IntegrityError("Расшифрованный индекс хранилища повреждён (не является объектом JSON).")

    idx_version = index_data.get("format_version")
    if isinstance(idx_version, bool) or idx_version != FORMAT_VERSION:
        raise IntegrityError(
            f"Неподдерживаемая или повреждённая версия формата внутри индекса: {idx_version}."
        )

    idx_uuid = index_data.get("vault_uuid")
    if not isinstance(idx_uuid, str) or idx_uuid != expected_vault_uuid:
        raise IntegrityError(
            "Идентификатор хранилища (vault_uuid) в индексе не совпадает с заголовком!"
        )

    raw_entries = index_data.get("entries")
    if not isinstance(raw_entries, list):
        raise IntegrityError("Поле 'entries' в индексе хранилища повреждено.")

    entries_map: Dict[str, VaultEntry] = {}
    seen_entry_ids: set[str] = set()
    file_ranges: List[Tuple[int, int, str]] = []

    for item in raw_entries:
        entry = VaultEntry.from_dict(item)
        if len(entry.entry_id) > 128:
            raise IntegrityError("Недопустимая длина идентификатора записи entry_id в индексе.")
        if entry.entry_id in seen_entry_ids:
            raise IntegrityError(f"Обнаружено дублирование идентификатора записи '{entry.entry_id}' в индексе.")
        seen_entry_ids.add(entry.entry_id)

        norm_vp = normalize_virtual_path(entry.virtual_path)
        if norm_vp in entries_map:
            raise IntegrityError(f"Обнаружено дублирование виртуального пути '{norm_vp}' в индексе.")
        entry.virtual_path = norm_vp

        if entry.entry_type == "dir":
            if (
                entry.size != 0
                or entry.blob_offset != 0
                or entry.blob_length != 0
                or entry.chunk_count != 0
                or entry.sha256 != ""
            ):
                raise IntegrityError(f"Некорректные метаданные каталога '{norm_vp}' в индексе.")
        elif entry.entry_type == "file":
            if entry.size < 0:
                raise IntegrityError(f"Отрицательный размер файла '{norm_vp}' в индексе.")
            if entry.chunk_count < 1:
                raise IntegrityError(f"Некорректное число блоков ({entry.chunk_count}) у файла '{norm_vp}'.")
            if entry.blob_length < MIN_ENCRYPTED_BLOB_SIZE:
                raise IntegrityError(f"Некорректная длина зашифрованного потока у файла '{norm_vp}'.")
            if entry.blob_offset < data_start or entry.blob_offset + entry.blob_length > index_offset:
                raise IntegrityError(
                    f"Смещение данных файла '{norm_vp}' в индексе выходит за пределы секции данных."
                )
            try:
                salt_bytes = bytes.fromhex(entry.file_salt_hex)
            except ValueError as exc:
                raise IntegrityError(f"Повреждена соль файла '{norm_vp}' в индексе.") from exc
            if len(salt_bytes) != SALT_SIZE:
                raise IntegrityError(f"Неверная длина соли файла '{norm_vp}' в индексе.")

            try:
                sha_bytes = bytes.fromhex(entry.sha256)
            except ValueError as exc:
                raise IntegrityError(f"Повреждён SHA-256 хеш файла '{norm_vp}' в индексе.") from exc
            if len(sha_bytes) != 32:
                raise IntegrityError(f"Неверная длина SHA-256 хеша файла '{norm_vp}' в индексе.")

            file_ranges.append((entry.blob_offset, entry.blob_offset + entry.blob_length, norm_vp))
        else:
            raise IntegrityError(f"Неизвестный тип записи '{entry.entry_type}' для '{norm_vp}' в индексе.")

        entries_map[norm_vp] = entry

    # Проверяем непрерывность и отсутствие пересечений или посторонних данных в секции блобов
    file_ranges.sort(key=lambda r: r[0])
    expected_cursor = data_start
    for start_off, end_off, vp_name in file_ranges:
        if start_off < expected_cursor:
            raise IntegrityError(
                f"Обнаружено пересечение зашифрованных блоков данных для файла '{vp_name}'."
            )
        if start_off > expected_cursor:
            raise IntegrityError(
                f"Обнаружены неаутентифицированные данные (зазор) перед блоком файла '{vp_name}'."
            )
        expected_cursor = end_off

    if expected_cursor != index_offset:
        raise IntegrityError(
            "Граница секции зашифрованных файлов не совпадает со смещением индекса (обнаружены лишние данные)."
        )

    return entries_map


def _make_unique_copy_virtual_path(virt_path: str, existing_paths: set[str] | Dict[str, Any]) -> str:
    """Формирует уникальное имя копии внутри хранилища: например, 'doc.txt' -> 'doc (1).txt'."""
    parent = posixpath_dirname(virt_path)
    base = posixpath_basename(virt_path)
    stem, ext = os.path.splitext(base)
    if not stem:
        stem, ext = base, ""
    counter = 1
    while True:
        suffix = f" ({counter})"
        max_stem_bytes = 250 - len(suffix.encode("utf-8")) - len(ext.encode("utf-8"))
        stem_bytes = stem.encode("utf-8")
        if len(stem_bytes) > max_stem_bytes:
            stem = stem_bytes[:max_stem_bytes].decode("utf-8", errors="ignore")
        cand_name = f"{stem}{suffix}{ext}"
        cand_vp = f"{parent}/{cand_name}" if parent else cand_name
        norm_cand = normalize_virtual_path(cand_vp)
        if norm_cand not in existing_paths:
            return norm_cand
        counter += 1


class SecureVault:
    """
    Класс управления защищённым хранилищем MintVault.
    Потокобезопасен внутри процесса (через RLock) и межпроцессно защищён через POSIX lock (`fcntl.flock`).
    """

    def __init__(self, vault_path: str | Path) -> None:
        raw_p = Path(vault_path)
        if raw_p.is_symlink():
            raise UnsafeFileObjectError(
                f"Отказ по соображениям безопасности: путь хранилища '{vault_path}' является символической ссылкой."
            )
        self.vault_path = raw_p.resolve()
        self._lock = threading.RLock()
        self._lock_file_fd: Optional[int] = None
        self._master_key: Optional[bytearray] = None
        self._header: Optional[Dict[str, Any]] = None
        self._entries: Dict[str, VaultEntry] = {}  # virtual_path -> VaultEntry
        self._is_unlocked: bool = False
        self._last_added_sources: Dict[str, Tuple[Path, os.stat_result]] = {}

    @property
    def is_unlocked(self) -> bool:
        with self._lock:
            return self._is_unlocked and self._master_key is not None

    @property
    def vault_uuid(self) -> str:
        with self._lock:
            if not self._header:
                return ""
            return str(self._header.get("vault_uuid", ""))

    def _acquire_operation_lock(self) -> None:
        """Захватывает эксклюзивную межпроцессную блокировку файла `.lock`."""
        if self._lock_file_fd is not None:
            return
        lock_path = self.vault_path.parent / f".{self.vault_path.name}.lock"
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(lock_path), flags, 0o600)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise UnsafeFileObjectError(
                    f"Файл блокировки '{lock_path}' является символической ссылкой!"
                ) from exc
            raise VaultBusyError(f"Не удалось создать файл блокировки хранилища: {exc}") from exc
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode):
                raise UnsafeFileObjectError(f"Объект блокировки '{lock_path}' не является обычным файлом.")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock_file_fd = fd
        except BlockingIOError as exc:
            os.close(fd)
            raise VaultBusyError(
                "Хранилище в данный момент занято другой операцией или открыто в другом окне программы."
            ) from exc
        except Exception:
            os.close(fd)
            raise

    def _release_operation_lock(self) -> None:
        """Освобождает межпроцессную блокировку."""
        if self._lock_file_fd is not None:
            try:
                fcntl.flock(self._lock_file_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self._lock_file_fd)
            except OSError:
                pass
            self._lock_file_fd = None

    def find_orphaned_temp_files(self) -> List[Path]:
        """
        Обнаруживает незавершённые временные файлы транзакций (`.<vault_name>.tmp.*`),
        оставшиеся после аварийного завершения процесса или отключения питания.
        Не следует по символическим ссылкам (`os.lstat`) и пропускает активные транзакции других живых процессов.
        """
        parent = self.vault_path.parent
        if not parent.exists():
            return []
        prefix = f".{self.vault_path.name}.tmp."
        keep_orphan_sim = os.environ.get("MINTVAULT_KEEP_ORPHAN_ON_CRASH") == "1"
        current_uid = os.getuid() if hasattr(os, "getuid") else None
        orphans: List[Path] = []
        try:
            for item in parent.iterdir():
                if not item.name.startswith(prefix):
                    continue
                try:
                    st = os.lstat(str(item))
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                    continue
                if current_uid is not None and st.st_uid != current_uid:
                    continue
                pid = _extract_pid_from_temp_name(item.name, prefix)
                # Если файл создан другим живым процессом, не считаем его осиротевшим
                if pid is not None and pid != os.getpid() and _is_pid_running(pid) and not keep_orphan_sim:
                    continue
                orphans.append(item)
        except OSError:
            return []
        return sorted(orphans)

    def cleanup_orphaned_temp_files(self) -> int:
        """
        Безопасно удаляет осиротевшие временные файлы прерванных транзакций,
        проверяя принадлежность, отсутствие симлинков и состояние процесса,
        сохраняя нетронутым основное рабочее хранилище.
        """
        with self._lock:
            orphans = self.find_orphaned_temp_files()
            removed = 0
            current_uid = os.getuid() if hasattr(os, "getuid") else None
            for orphan in orphans:
                try:
                    st = os.lstat(str(orphan))
                    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                        continue
                    if current_uid is not None and st.st_uid != current_uid:
                        continue
                    orphan.unlink()
                    removed += 1
                except OSError:
                    pass
            if removed > 0:
                fsync_directory(self.vault_path.parent)
                logger.info("Удалено незавершённых временных файлов транзакций: %d", removed)
            return removed

    @classmethod
    def create(
        cls,
        vault_path: str | Path,
        password: str,
        create_recovery_key: bool = True,
        kdf_time_cost: int = 3,
        kdf_memory_kib: int = 65536,
        kdf_parallelism: int = 2,
    ) -> Tuple["SecureVault", Optional[str]]:
        """
        Создаёт новое зашифрованное хранилище.
        Возвращает кортеж `(экземпляр SecureVault в разблокированном состоянии, ключ_восстановления_или_None)`.
        """
        if not password or len(password.strip()) == 0:
            raise ValueError("Пароль хранилища не может быть пустым.")

        raw_target = Path(vault_path)
        if raw_target.is_symlink():
            raise FileOverwriteError(f"Целевой путь хранилища является символической ссылкой: {vault_path}")
        target_path = raw_target.resolve()
        if target_path.exists() or target_path.is_symlink():
            raise FileOverwriteError(f"Файл хранилища уже существует: {target_path}")

        if not target_path.parent.exists():
            raise FileNotFoundError(f"Родительский каталог не существует: {target_path.parent}")

        check_disk_space(target_path.parent, 64 * 1024)

        vault = cls(target_path)
        with vault._lock:
            vault._acquire_operation_lock()
            pwd_bytes = bytearray(password.encode("utf-8"))
            master_key = bytearray(os.urandom(MASTER_KEY_SIZE))
            recovery_key_str: Optional[str] = None
            rec_bytes: Optional[bytearray] = None

            try:
                vault_uuid = str(uuid.uuid4())
                slots: List[Dict[str, Any]] = []

                pwd_slot = create_key_slot(
                    master_key=master_key,
                    secret_bytes=pwd_bytes,
                    slot_type="password",
                    time_cost=kdf_time_cost,
                    memory_cost_kib=kdf_memory_kib,
                    parallelism=kdf_parallelism,
                )
                slots.append(pwd_slot.to_dict())

                if create_recovery_key:
                    recovery_key_str = generate_recovery_key()
                    rec_bytes = bytearray(normalize_recovery_key(recovery_key_str))
                    rec_slot = create_key_slot(
                        master_key=master_key,
                        secret_bytes=rec_bytes,
                        slot_type="recovery",
                        time_cost=kdf_time_cost,
                        memory_cost_kib=kdf_memory_kib,
                        parallelism=kdf_parallelism,
                    )
                    slots.append(rec_slot.to_dict())

                now = time.time()
                header_dict: Dict[str, Any] = {
                    "format_version": FORMAT_VERSION,
                    "vault_uuid": vault_uuid,
                    "created_at": now,
                    "updated_at": now,
                    "cipher": SUPPORTED_CIPHER,
                    "key_slots": slots,
                }
                header_dict["header_mac_hex"] = compute_header_mac(
                    master_key, _canonical_header_bytes(header_dict), vault_uuid
                )

                vault._master_key = master_key
                vault._header = header_dict
                vault._entries = {}
                vault._is_unlocked = True

                vault._write_atomic_transaction(new_entries={}, source_files_map={})
                logger.info("Создано новое хранилище: %s", target_path.name)
                return vault, recovery_key_str
            except Exception:
                zero_memory(master_key)
                vault._master_key = None
                vault._header = None
                vault._is_unlocked = False
                vault._release_operation_lock()
                raise
            finally:
                zero_memory(pwd_bytes)
                if rec_bytes is not None:
                    zero_memory(rec_bytes)

    @staticmethod
    def inspect_header(vault_path: str | Path) -> Dict[str, Any]:
        """
        Читает и проверяет базовую структуру заголовка хранилища без расшифровки (в заблокированном виде).
        Позволяет узнать версию формата, доступные типы слотов (пароль / ключ восстановления) и смещения.
        Также проверяет допустимость границ параметров KDF во всех ключевых слотах.
        """
        raw_p = Path(vault_path)
        st = validate_safe_source_object(raw_p)
        p = raw_p.resolve()
        if not stat.S_ISREG(st.st_mode):
            raise VaultFormatError(f"Объект '{p}' не является обычным файлом хранилища.")
        if st.st_size < FIXED_PREAMBLE_SIZE:
            raise VaultFormatError("Файл слишком мал и не является корректным хранилищем MintVault.")

        fp, fst = open_safe_regular_file_for_read(p, expected_stat=st)
        with fp as f:
            preamble = f.read(FIXED_PREAMBLE_SIZE)
            if len(preamble) != FIXED_PREAMBLE_SIZE:
                raise VaultFormatError("Не удалось прочитать преамбулу файла хранилища.")
            magic, version, header_len, index_offset, index_len = struct.unpack(FIXED_PREAMBLE_FMT, preamble)
            if magic != MAGIC_BYTES:
                raise VaultFormatError("Неверная сигнатура файла: это не хранилище MintVault.")
            if version != FORMAT_VERSION:
                raise VaultFormatError(
                    f"Неподдерживаемая версия формата хранилища: {version} (ожидалась версия {FORMAT_VERSION})."
                )
            if header_len == 0 or header_len > MAX_HEADER_SIZE:
                raise VaultFormatError("Повреждён размер заголовка хранилища.")
            if index_len == 0 or index_len > MAX_INDEX_SIZE:
                raise VaultFormatError("Повреждён размер индекса хранилища.")
            if FIXED_PREAMBLE_SIZE + header_len > index_offset:
                raise VaultFormatError("Нарушена структура секций файла хранилища (смещение индекса некорректно).")
            if index_offset + index_len != fst.st_size:
                raise IntegrityError(
                    "Размер файла хранилища не совпадает со структурой заголовка (файл усечён или повреждён)."
                )

            raw_header = f.read(header_len)
            if len(raw_header) != header_len:
                raise VaultFormatError("Не удалось прочитать заголовок хранилища полностью.")
            try:
                header_dict = json.loads(raw_header.decode("utf-8"))
            except Exception as exc:
                raise VaultFormatError("Заголовок хранилища повреждён (ошибка декодирования JSON).") from exc

            if not isinstance(header_dict, dict):
                raise VaultFormatError("Заголовок хранилища должен быть JSON-объектом.")

            hdr_ver = header_dict.get("format_version")
            if isinstance(hdr_ver, bool) or hdr_ver != FORMAT_VERSION:
                raise VaultFormatError(
                    f"Неподдерживаемая или повреждённая версия формата в заголовке: {hdr_ver}."
                )

            cipher = header_dict.get("cipher")
            if cipher != SUPPORTED_CIPHER:
                raise VaultFormatError(f"Неподдерживаемый шифр контейнера: {cipher}")

            vault_uuid = header_dict.get("vault_uuid")
            if not isinstance(vault_uuid, str) or not (1 <= len(vault_uuid.strip()) <= 128):
                raise VaultFormatError("Отсутствует или повреждён идентификатор хранилища (vault_uuid).")

            mac_hex = header_dict.get("header_mac_hex")
            if not isinstance(mac_hex, str) or len(mac_hex) != (AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE) * 2:
                raise IntegrityError("Отсутствует или повреждён аутентификационный тег заголовка (header_mac_hex).")

            raw_slots = header_dict.get("key_slots")
            if not isinstance(raw_slots, list) or not (1 <= len(raw_slots) <= MAX_KEY_SLOTS):
                raise VaultFormatError("Некорректный список ключевых слотов в заголовке хранилища.")

            for slot_dict in raw_slots:
                slot_obj = WrappedKeySlot.from_dict(slot_dict)
                validate_kdf_params(slot_obj.kdf)

            return {
                "header": header_dict,
                "header_len": header_len,
                "index_offset": index_offset,
                "index_len": index_len,
                "file_size": fst.st_size,
            }

    def unlock(self, secret: str, use_recovery_key: bool = False) -> None:
        """
        Разблокирует хранилище с помощью пароля пользователя или ключа восстановления.
        Проверяет криптографическую подлинность заголовка и расшифровывает индекс файлов.
        """
        if not secret:
            raise AuthenticationError("Пароль или ключ восстановления не может быть пустым.")

        with self._lock:
            if self.is_unlocked:
                return

            self._acquire_operation_lock()
            secret_buf: Optional[bytearray] = None
            master_key: Optional[bytearray] = None
            try:
                info = self.inspect_header(self.vault_path)
                header_dict = info["header"]
                index_offset = info["index_offset"]
                index_len = info["index_len"]

                if use_recovery_key:
                    secret_buf = bytearray(normalize_recovery_key(secret))
                    target_slot_type = "recovery"
                else:
                    secret_buf = bytearray(secret.encode("utf-8"))
                    target_slot_type = "password"

                matching_slots = [
                    WrappedKeySlot.from_dict(s)
                    for s in header_dict.get("key_slots", [])
                    if s.get("slot_type") == target_slot_type
                ]
                if not matching_slots:
                    raise AuthenticationError(
                        f"В хранилище не настроен слот доступа типа '{target_slot_type}'."
                    )

                last_err: Optional[Exception] = None
                for slot in matching_slots:
                    try:
                        master_key = unwrap_key_slot(slot, secret_buf)
                        break
                    except AuthenticationError as err:
                        last_err = err

                if master_key is None:
                    raise last_err or AuthenticationError("Неверный пароль или ключ восстановления.")

                # Проверяем аутентификационный тег заголовка
                vault_uuid = str(header_dict["vault_uuid"])
                mac_hex = str(header_dict.get("header_mac_hex", ""))
                verify_header_mac(master_key, _canonical_header_bytes(header_dict), vault_uuid, mac_hex)

                # Читаем и расшифровываем индекс
                fp, _ = open_safe_regular_file_for_read(self.vault_path)
                with fp as f:
                    f.seek(index_offset)
                    enc_index = f.read(index_len)
                plain_index_bytes = decrypt_index_bytes(master_key, enc_index, vault_uuid)
                try:
                    index_data = json.loads(plain_index_bytes.decode("utf-8"))
                except Exception as exc:
                    raise IntegrityError("Расшифрованный индекс хранилища имеет некорректный формат.") from exc

                data_start = FIXED_PREAMBLE_SIZE + info["header_len"]
                entries_map = _validate_and_parse_index(
                    index_data=index_data,
                    expected_vault_uuid=vault_uuid,
                    data_start=data_start,
                    index_offset=index_offset,
                )

                self._master_key = master_key
                self._header = header_dict
                self._entries = entries_map
                self._is_unlocked = True
                logger.info("Хранилище успешно разблокировано: %s", self.vault_path.name)
            except Exception:
                if master_key is not None:
                    zero_memory(master_key)
                self._master_key = None
                self._header = None
                self._entries = {}
                self._is_unlocked = False
                self._release_operation_lock()
                raise
            finally:
                if secret_buf is not None:
                    zero_memory(secret_buf)

    def lock(self) -> None:
        """
        Безопасно блокирует хранилище: затирает мастер-ключ в оперативной памяти нулями,
        очищает список расшифрованных метаданных и освобождает файловую блокировку.
        """
        with self._lock:
            if self._master_key is not None:
                zero_memory(self._master_key)
                self._master_key = None
            self._entries.clear()
            self._last_added_sources.clear()
            self._header = None
            self._is_unlocked = False
            self._release_operation_lock()
            logger.info("Хранилище заблокировано и ключи очищены из памяти: %s", self.vault_path.name)

    def close(self) -> None:
        """Синоним безопасного закрытия и блокировки хранилища."""
        self.lock()

    def __enter__(self) -> "SecureVault":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _require_unlocked(self) -> None:
        if not self.is_unlocked or self._master_key is None or self._header is None:
            raise VaultLockedError("Хранилище заблокировано. Сначала выполните разблокировку.")

    def list_entries(self, search_query: str = "") -> List[VaultEntry]:
        """
        Возвращает отсортированный список объектов внутри хранилища.
        Поддерживает регистронезависимый поиск по имени или виртуальному пути (включая русские символы).
        """
        with self._lock:
            self._require_unlocked()
            all_items = [dataclasses.replace(e) for e in sorted(self._entries.values(), key=lambda x: x.virtual_path)]
            if not search_query or not search_query.strip():
                return all_items
            q = search_query.strip().casefold()
            return [
                e for e in all_items
                if q in e.virtual_path.casefold() or q in posixpath_basename(e.virtual_path).casefold()
            ]

    def find_conflicts(
        self,
        source_paths: List[str | Path],
        virtual_dest_folder: str = "",
    ) -> List[str]:
        """
        Проверяет список добавляемых путей и возвращает список виртуальных путей,
        которые уже существуют в хранилище и вызовут конфликт имён.
        """
        with self._lock:
            self._require_unlocked()
            if not source_paths:
                return []
            conflicts: List[str] = []
            seen: set[str] = set()
            prefix = virtual_dest_prefix(virtual_dest_folder)
            for sp in source_paths:
                sp_path = Path(sp)
                validate_safe_source_object(sp_path)
                if sp_path.resolve() == self.vault_path:
                    raise UnsafeFileObjectError("Нельзя добавить сам файл активного хранилища внутрь себя.")
                items = collect_source_items(sp_path, base_virtual_prefix=prefix)
                for _src, virt_path, entry_type, _st in items:
                    if virt_path in self._entries:
                        existing = self._entries[virt_path]
                        if existing.entry_type == "dir" and entry_type == "dir":
                            continue
                        if virt_path not in seen:
                            seen.add(virt_path)
                            conflicts.append(virt_path)
            return conflicts

    def add_paths(
        self,
        source_paths: List[str | Path],
        virtual_dest_folder: str = "",
        cancel_check: Optional[Callable[[], bool]] = None,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
        on_conflict: str = "error",
    ) -> List[VaultEntry]:
        """
        Добавляет выбранные файлы и каталоги в хранилище.
        КРИТИЧЕСКОЕ ПРАВИЛО: оригинальные файлы на диске НЕ удаляются и НЕ изменяются (только чтение).
        Если во время чтения исходный файл изменился (размер, inode или mtime), операция безопасно прерывается.
        Запись в хранилище происходит транзакционно через временный файл и атомарный `os.replace`.
        """
        with self._lock:
            self._require_unlocked()
            if not source_paths:
                return []

            collected: List[Tuple[Path, str, str, os.stat_result]] = []
            for sp in source_paths:
                sp_path = Path(sp)
                validate_safe_source_object(sp_path)
                if sp_path.resolve() == self.vault_path:
                    raise UnsafeFileObjectError("Нельзя добавить сам файл активного хранилища внутрь себя.")
                items = collect_source_items(sp_path, base_virtual_prefix=virtual_dest_prefix(virtual_dest_folder))
                collected.extend(items)

            # Создаём глубокую копию текущих записей, чтобы при ошибке транзакции не повредить состояние в памяти
            new_entries_plan: Dict[str, VaultEntry] = {
                vp: dataclasses.replace(entry) for vp, entry in self._entries.items()
            }
            source_files_map: Dict[str, Tuple[Path, os.stat_result]] = {}
            added_virt_paths: List[str] = []
            added_source_snapshots: Dict[str, Tuple[Path, os.stat_result]] = {}
            now = time.time()

            if on_conflict not in ("error", "replace", "keep_both", "skip"):
                raise ValueError(f"Недопустимый режим разрешения конфликтов: {on_conflict}")

            renamed_dirs_map: Dict[str, str] = {}

            for src_path, virt_path, entry_type, st in collected:
                # Если родительская папка была переименована в режиме keep_both, обновляем префикс
                for old_dir_vp, new_dir_vp in sorted(renamed_dirs_map.items(), key=lambda x: len(x[0]), reverse=True):
                    if virt_path.startswith(old_dir_vp + "/"):
                        virt_path = new_dir_vp + virt_path[len(old_dir_vp):]
                        break

                if virt_path in new_entries_plan:
                    existing = new_entries_plan[virt_path]
                    if existing.entry_type == "dir" and entry_type == "dir":
                        continue
                    if on_conflict == "skip":
                        continue
                    elif on_conflict == "keep_both":
                        orig_vp = virt_path
                        virt_path = _make_unique_copy_virtual_path(virt_path, new_entries_plan)
                        if entry_type == "dir":
                            renamed_dirs_map[orig_vp] = virt_path
                    elif on_conflict == "replace" and existing.entry_type == "file" and entry_type == "file":
                        # Заменяем существующий файл новой версией
                        if existing.entry_id in source_files_map:
                            del source_files_map[existing.entry_id]
                    else:
                        raise FileOverwriteError(
                            f"Объект с именем '{virt_path}' уже существует в хранилище. "
                            "Удалите старую версию из хранилища или переименуйте добавляемый файл."
                        )

                safe_mode = (st.st_mode & 0o777) if entry_type == "dir" else (st.st_mode & 0o666)
                if safe_mode == 0:
                    safe_mode = 0o755 if entry_type == "dir" else 0o600

                entry = VaultEntry(
                    entry_id=str(uuid.uuid4()),
                    virtual_path=virt_path,
                    entry_type=entry_type,
                    size=st.st_size if entry_type == "file" else 0,
                    mtime=st.st_mtime,
                    mode=safe_mode,
                    sha256="",
                    added_at=now,
                )
                new_entries_plan[virt_path] = entry
                added_virt_paths.append(virt_path)
                added_source_snapshots[virt_path] = (src_path, st)
                if entry_type == "file":
                    source_files_map[entry.entry_id] = (src_path, st)

            if not added_virt_paths:
                self._last_added_sources = {}
                return []

            current_vault_size = self.vault_path.stat().st_size if self.vault_path.exists() else 0
            new_files_bytes = sum(st.st_size for _, st in source_files_map.values())
            estimated_total = current_vault_size + new_files_bytes + (len(source_files_map) + 1) * 4096
            check_disk_space(self.vault_path.parent, estimated_total)

            self._write_atomic_transaction(
                new_entries=new_entries_plan,
                source_files_map=source_files_map,
                cancel_check=cancel_check,
                progress_cb=progress_cb,
            )
            self._entries = new_entries_plan
            self._last_added_sources = added_source_snapshots
            added_entries = [dataclasses.replace(self._entries[vp]) for vp in added_virt_paths]
            logger.info("В хранилище добавлено объектов: %d", len(added_entries))
            return added_entries

    def verify_entries_integrity(
        self,
        entries: List[VaultEntry],
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> None:
        """
        Выполняет криптографическую проверку конкретных записей внутри сохранённого контейнера на диске:
        проверяет заголовок контейнера, индекс и потоково расшифровывает все блоки указанных файлов
        с проверкой тегов AES-256-GCM и итогового SHA-256.
        При малейшем несоответствии выбрасывает `IntegrityError`.
        """
        with self._lock:
            self._require_unlocked()
            assert self._master_key is not None

            info = self.inspect_header(self.vault_path)
            header_dict = info["header"]
            vault_uuid = str(header_dict["vault_uuid"])
            verify_header_mac(
                self._master_key,
                _canonical_header_bytes(header_dict),
                vault_uuid,
                str(header_dict.get("header_mac_hex", "")),
            )

            fp, _ = open_safe_regular_file_for_read(self.vault_path)
            with fp as vault_fp:
                vault_fp.seek(info["index_offset"])
                enc_index = vault_fp.read(info["index_len"])
                plain_index = decrypt_index_bytes(self._master_key, enc_index, vault_uuid)
                index_data = json.loads(plain_index.decode("utf-8"))
                disk_entries = _validate_and_parse_index(
                    index_data=index_data,
                    expected_vault_uuid=vault_uuid,
                    data_start=FIXED_PREAMBLE_SIZE + info["header_len"],
                    index_offset=info["index_offset"],
                )

                for req_entry in entries:
                    if req_entry.virtual_path not in disk_entries:
                        raise IntegrityError(
                            f"Запись '{req_entry.virtual_path}' отсутствует в записанном индексе хранилища."
                        )
                    disk_e = disk_entries[req_entry.virtual_path]
                    if disk_e.entry_id != req_entry.entry_id:
                        raise IntegrityError(
                            f"Несовпадение идентификатора записи для '{req_entry.virtual_path}'."
                        )
                    if disk_e.entry_type == "file":
                        computed_sha = decrypt_file_stream(
                            master_key=self._master_key,
                            entry_id=disk_e.entry_id,
                            file_salt=bytes.fromhex(disk_e.file_salt_hex),
                            expected_chunk_count=disk_e.chunk_count,
                            expected_plain_size=disk_e.size,
                            expected_sha256=disk_e.sha256,
                            src_stream=vault_fp,
                            blob_offset=disk_e.blob_offset,
                            blob_length=disk_e.blob_length,
                            dst_stream=None,
                            cancel_check=cancel_check,
                        )
                        if computed_sha.lower() != req_entry.sha256.lower():
                            raise IntegrityError(
                                f"Контрольная сумма файла '{req_entry.virtual_path}' в хранилище не совпадает с ожидаемой."
                            )

    def safe_delete_verified_originals(
        self,
        selected_source_paths: List[str | Path],
        added_entries: List[VaultEntry],
        user_confirmed: bool = False,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> Tuple[int, List[str]]:
        """
        Отдельная, явно подтверждаемая операция безопасного удаления исходных файлов с диска
        ПОСЛЕ успешного добавления и криптографической верификации в контейнере.

        Гарантии безопасности:
        1. Без `user_confirmed=True` немедленно отказывает в выполнении (`PermissionError`).
        2. Сначала выполняет полную криптографическую проверку всех `added_entries` в файле хранилища на диске.
           Если проверка целостности контейнера не пройдена — ни один исходный файл не удаляется.
        3. Для каждого исходного файла проверяет через `os.lstat` и `open_safe_regular_file_for_read`,
           что это тот же самый обычный файл (`st_dev`, `st_ino`, `st_size`, `st_mtime_ns`) и его SHA-256
           совпадает с зашифрованной копией в хранилище (защита от симлинков и подмены файла через гонку).
        4. Никогда не удаляет каталоги целиком через `shutil.rmtree`: удаляет только проверенные файлы,
           а пустые каталоги удаляет через `os.rmdir` только в том случае, если сам каталог был выбран пользователем.
        """
        if not user_confirmed:
            raise PermissionError(
                "Удаление оригинальных файлов запрещено без явного подтверждения пользователя."
            )

        with self._lock:
            self._require_unlocked()
            if not added_entries:
                return 0, []

            # Шаг 1: Полная криптографическая проверка целостности добавленных записей на диске
            self.verify_entries_integrity(added_entries, cancel_check=cancel_check)

            # Определяем, какие корневые пути пользователь явно передавал при добавлении
            explicit_roots: set[Path] = set()
            for sp in selected_source_paths:
                try:
                    st_sp = os.lstat(str(sp))
                    if not stat.S_ISLNK(st_sp.st_mode):
                        explicit_roots.add(Path(sp).resolve())
                except OSError:
                    pass

            deleted_files = 0
            skipped_warnings: List[str] = []
            dirs_to_cleanup: List[Tuple[Path, os.stat_result]] = []

            for entry in added_entries:
                if cancel_check and cancel_check():
                    raise OperationCancelledError("Удаление оригиналов отменено пользователем.")

                snap = self._last_added_sources.get(entry.virtual_path)
                if snap is None:
                    skipped_warnings.append(
                        f"Пропущен '{entry.virtual_path}': отсутствует снимок исходного пути."
                    )
                    continue

                src_path, initial_st = snap
                if entry.entry_type == "dir":
                    dirs_to_cleanup.append((src_path, initial_st))
                    continue

                try:
                    fp, cur_st = open_safe_regular_file_for_read(src_path, expected_stat=initial_st)
                    with fp:
                        h = hashlib.sha256()
                        while chunk := fp.read(256 * 1024):
                            h.update(chunk)
                        disk_sha = h.hexdigest()

                    if disk_sha.lower() != entry.sha256.lower():
                        skipped_warnings.append(
                            f"Пропущен '{src_path}': контрольная сумма файла изменилась."
                        )
                        continue

                    # Повторно сверяем lstat непосредственно перед unlink
                    st_pre_unlink = os.lstat(str(src_path))
                    if (
                        stat.S_ISLNK(st_pre_unlink.st_mode)
                        or not stat.S_ISREG(st_pre_unlink.st_mode)
                        or st_pre_unlink.st_ino != initial_st.st_ino
                        or st_pre_unlink.st_dev != initial_st.st_dev
                    ):
                        skipped_warnings.append(
                            f"Пропущен '{src_path}': обнаружена подмена объекта перед удалением."
                        )
                        continue

                    os.unlink(str(src_path))
                    deleted_files += 1
                except Exception as exc:
                    skipped_warnings.append(f"Не удалось удалить '{src_path}': {exc}")

            # Удаляем пустые каталоги (снизу вверх) ТОЛЬКО если они входили в выбранные пользователем папки
            for dir_path, init_dir_st in sorted(
                dirs_to_cleanup,
                key=lambda item: len(str(item[0])),
                reverse=True,
            ):
                try:
                    resolved_dir = dir_path.resolve()
                    is_under_explicit_dir = any(
                        resolved_dir == root or str(resolved_dir).startswith(str(root) + os.sep)
                        for root in explicit_roots
                    )
                    if not is_under_explicit_dir:
                        continue
                    cur_dir_st = os.lstat(str(dir_path))
                    if (
                        not stat.S_ISLNK(cur_dir_st.st_mode)
                        and stat.S_ISDIR(cur_dir_st.st_mode)
                        and cur_dir_st.st_ino == init_dir_st.st_ino
                        and cur_dir_st.st_dev == init_dir_st.st_dev
                    ):
                        os.rmdir(str(dir_path))
                except OSError:
                    # Если в каталоге остались другие файлы, os.rmdir безопасно не удалит его
                    pass

            return deleted_files, skipped_warnings

    def delete_entries(
        self,
        virtual_paths: List[str],
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> int:
        """
        Удаляет выбранные файлы или каталоги (вместе со всеми вложенными в каталог объектами) из хранилища.
        Пересобирает контейнер без удалённых блобов в транзакционном режиме Copy-on-Write,
        чтобы зашифрованные блоки удалённых файлов не оставались в файле хранилища.
        """
        with self._lock:
            self._require_unlocked()
            if not virtual_paths:
                return 0

            norm_targets = [normalize_virtual_path(p) for p in virtual_paths]
            to_delete_keys = set()

            for vp in self._entries:
                for target in norm_targets:
                    if vp == target or vp.startswith(target + "/"):
                        to_delete_keys.add(vp)

            if not to_delete_keys:
                raise FileNotFoundError("Выбранные объекты не найдены в хранилище.")

            remaining_entries = {
                vp: dataclasses.replace(entry)
                for vp, entry in self._entries.items()
                if vp not in to_delete_keys
            }

            estimated_size = sum(
                e.blob_length for e in remaining_entries.values() if e.entry_type == "file"
            ) + 65536
            check_disk_space(self.vault_path.parent, estimated_size)

            self._write_atomic_transaction(
                new_entries=remaining_entries,
                source_files_map={},
                cancel_check=cancel_check,
            )
            self._entries = remaining_entries
            logger.info("Из хранилища удалено объектов: %d", len(to_delete_keys))
            return len(to_delete_keys)

    def find_extraction_conflicts(
        self,
        virtual_paths: List[str],
        destination_dir: str | Path,
        preserve_structure: bool = True,
    ) -> List[Path]:
        """
        Проверяет выбранные для извлечения объекты и возвращает список путей файлов в папке назначения,
        которые уже существуют на диске.
        Существующие на диске обычные папки конфликтом не считаются (в них можно дописывать файлы).
        """
        with self._lock:
            self._require_unlocked()
            raw_dest = Path(destination_dir)
            if raw_dest.is_symlink():
                raise PathTraversalError(f"Целевой каталог не может быть символической ссылкой: {destination_dir}")
            dest_root = raw_dest.resolve()
            if not dest_root.exists() or not dest_root.is_dir():
                raise FileNotFoundError(f"Целевой каталог для извлечения не найден: {dest_root}")

            norm_targets = [normalize_virtual_path(p) for p in virtual_paths]
            conflicts: List[Path] = []
            seen_vp: set[str] = set()
            seen_conflicts: set[Path] = set()

            for target in norm_targets:
                matched = [
                    e for vp, e in sorted(self._entries.items())
                    if vp == target or vp.startswith(target + "/")
                ]
                parent_prefix = posixpath_dirname(target)
                for entry in matched:
                    if entry.virtual_path in seen_vp:
                        continue
                    seen_vp.add(entry.virtual_path)
                    if preserve_structure or not parent_prefix:
                        rel_out = entry.virtual_path
                    else:
                        rel_out = entry.virtual_path[len(parent_prefix) :].lstrip("/")
                    out_path = resolve_safe_extraction_path(dest_root, rel_out, allow_existing=True)
                    try:
                        st = os.lstat(str(out_path))
                        # Если мы извлекаем папку и на диске уже есть обычная папка — это не конфликт
                        if entry.entry_type == "dir" and stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                            continue
                        if out_path not in seen_conflicts:
                            seen_conflicts.add(out_path)
                            conflicts.append(out_path)
                    except FileNotFoundError:
                        pass
            return conflicts

    def extract_entries(
        self,
        virtual_paths: List[str],
        destination_dir: str | Path,
        preserve_structure: bool = True,
        cancel_check: Optional[Callable[[], bool]] = None,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
        on_conflict: str = "error",
    ) -> List[Path]:
        """
        Извлекает и расшифровывает выбранные объекты (файлы и папки) в указанный пользователем каталог.
        Поддерживает режимы `on_conflict`:
        - 'error' (по умолчанию): запрещает перезапись существующих файлов (выбрасывает `FileOverwriteError`).
        - 'skip': пропускает уже существующие на диске файлы и выгружает только недостающие.
        - 'keep_both': сохраняет конфликтующий файл рядом под новым именем вида `файл (1).ext`.
        - 'replace': расшифровывает и проверяет файл во временный файл, после чего атомарно заменяет существующий файл.
        """
        if on_conflict not in ("error", "skip", "keep_both", "replace"):
            raise ValueError(f"Недопустимый режим разрешения конфликтов при извлечении: {on_conflict}")

        with self._lock:
            self._require_unlocked()
            assert self._master_key is not None

            raw_dest = Path(destination_dir)
            if raw_dest.is_symlink():
                raise PathTraversalError(f"Целевой каталог не может быть символической ссылкой: {destination_dir}")
            dest_root = raw_dest.resolve()
            if not dest_root.exists() or not dest_root.is_dir():
                raise FileNotFoundError(f"Целевой каталог для извлечения не найден: {dest_root}")
            if not os.access(str(dest_root), os.W_OK | os.X_OK):
                raise PermissionError(f"Нет прав на запись в целевой каталог: {dest_root}")

            norm_targets = [normalize_virtual_path(p) for p in virtual_paths]
            selected_entries: List[Tuple[VaultEntry, str]] = []

            for target in norm_targets:
                matched = [
                    e for vp, e in sorted(self._entries.items())
                    if vp == target or vp.startswith(target + "/")
                ]
                if not matched:
                    raise FileNotFoundError(f"Объект '{target}' не найден в хранилище.")

                parent_prefix = posixpath_dirname(target)
                for entry in matched:
                    if preserve_structure or not parent_prefix:
                        rel_out = entry.virtual_path
                    else:
                        rel_out = entry.virtual_path[len(parent_prefix) :].lstrip("/")
                    selected_entries.append((entry, rel_out))

            unique_plan: List[Tuple[VaultEntry, Path, bool]] = []
            seen_vp: set[str] = set()
            seen_out_paths: Dict[Path, VaultEntry] = {}
            reserved_paths: set[Path] = set()
            total_bytes_to_extract = 0

            for entry, rel_out in selected_entries:
                if entry.virtual_path in seen_vp:
                    continue
                seen_vp.add(entry.virtual_path)
                out_path = resolve_safe_extraction_path(dest_root, rel_out, allow_existing=True)

                if entry.entry_type == "dir":
                    try:
                        st_existing = os.lstat(str(out_path))
                        if not stat.S_ISDIR(st_existing.st_mode):
                            if on_conflict == "skip":
                                continue
                            raise FileOverwriteError(
                                f"Невозможно создать каталог, путь занят файлом: {out_path}"
                            )
                    except FileNotFoundError:
                        pass
                    seen_out_paths[out_path] = entry
                    reserved_paths.add(out_path)
                    unique_plan.append((entry, out_path, False))
                    continue

                # Обработка файла (entry.entry_type == "file")
                disk_exists = False
                try:
                    st_existing = os.lstat(str(out_path))
                    disk_exists = True
                    if stat.S_ISDIR(st_existing.st_mode):
                        if on_conflict == "skip":
                            continue
                        elif on_conflict == "keep_both":
                            out_path = make_unique_disk_path(out_path, reserved_paths)
                            disk_exists = False
                        else:
                            raise FileOverwriteError(
                                f"Целевой путь '{out_path}' занят существующим каталогом."
                            )
                except FileNotFoundError:
                    disk_exists = False

                in_plan_conflict = out_path in seen_out_paths

                if disk_exists or in_plan_conflict:
                    if on_conflict == "error":
                        raise FileOverwriteError(
                            f"Целевой объект уже существует и не будет перезаписан: {out_path}"
                        )
                    elif on_conflict == "skip":
                        continue
                    elif on_conflict == "keep_both":
                        out_path = make_unique_disk_path(out_path, reserved_paths)
                        disk_exists = False
                    elif on_conflict == "replace":
                        if in_plan_conflict:
                            raise FileOverwriteError(
                                f"Конфликт имён внутри одного задания извлечения: {out_path}"
                            )

                seen_out_paths[out_path] = entry
                reserved_paths.add(out_path)
                total_bytes_to_extract += entry.size
                unique_plan.append((entry, out_path, disk_exists and on_conflict == "replace"))

            check_disk_space(dest_root, total_bytes_to_extract)

            extracted_paths: List[Path] = []
            bytes_done = 0
            dirs_to_fsync: set[Path] = set()

            fp, _ = open_safe_regular_file_for_read(self.vault_path)
            with fp as vault_fp:
                for entry, out_path, allow_replace_existing in unique_plan:
                    if cancel_check and cancel_check():
                        raise OperationCancelledError("Извлечение файлов отменено пользователем.")

                    if entry.entry_type == "dir":
                        ensure_safe_directory_tree(dest_root, out_path, mode=entry.mode & 0o777 or 0o755)
                        dirs_to_fsync.add(out_path)
                        extracted_paths.append(out_path)
                        continue

                    ensure_safe_directory_tree(dest_root, out_path.parent, mode=0o755)
                    verify_no_symlink_components(dest_root, out_path)

                    if not allow_replace_existing:
                        try:
                            os.lstat(str(out_path))
                            raise FileOverwriteError(
                                f"Целевой файл уже существует и не будет перезаписан: {out_path}"
                            )
                        except FileNotFoundError:
                            pass

                    tmp_extract_path = (
                        out_path.parent / f".{out_path.name}.mvault_extract.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
                    )
                    open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                    try:
                        fd = os.open(str(tmp_extract_path), open_flags, 0o600)
                        with os.fdopen(fd, "wb") as dst_fp:
                            def _file_progress(curr: int, tot: int) -> None:
                                if progress_cb:
                                    progress_cb(bytes_done + curr, total_bytes_to_extract, entry.virtual_path)

                            decrypt_file_stream(
                                master_key=self._master_key,
                                entry_id=entry.entry_id,
                                file_salt=bytes.fromhex(entry.file_salt_hex),
                                expected_chunk_count=entry.chunk_count,
                                expected_plain_size=entry.size,
                                expected_sha256=entry.sha256,
                                src_stream=vault_fp,
                                blob_offset=entry.blob_offset,
                                blob_length=entry.blob_length,
                                dst_stream=dst_fp,
                                cancel_check=cancel_check,
                                progress_cb=_file_progress,
                            )
                            dst_fp.flush()

                        verify_no_symlink_components(dest_root, out_path)
                        os.chmod(str(tmp_extract_path), entry.mode & 0o666 or 0o600)
                        os.utime(str(tmp_extract_path), (entry.mtime, entry.mtime))

                        if allow_replace_existing:
                            try:
                                st_now = os.lstat(str(out_path))
                                if stat.S_ISLNK(st_now.st_mode) or stat.S_ISDIR(st_now.st_mode):
                                    raise PathTraversalError(
                                        f"Небезопасный целевой объект для замены: {out_path}"
                                    )
                            except FileNotFoundError:
                                pass
                            os.replace(str(tmp_extract_path), str(out_path))
                        else:
                            atomic_publish_extracted_file(tmp_extract_path, out_path)

                        dirs_to_fsync.add(out_path.parent)
                        extracted_paths.append(out_path)
                        bytes_done += entry.size
                    except Exception:
                        if tmp_extract_path.exists() or tmp_extract_path.is_symlink():
                            try:
                                tmp_extract_path.unlink()
                            except OSError:
                                pass
                        raise
            # Один fsync на каждую уникальную папку в конце (batch-режим)
            for d in dirs_to_fsync:
                fsync_directory(d)

            return extracted_paths

    def verify_integrity(
        self,
        cancel_check: Optional[Callable[[], bool]] = None,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
    ) -> IntegrityReport:
        """
        Выполняет полную проверку целостности хранилища:
        - Если хранилище заблокировано: проверяет преамбулу, структуру секций, границы индекса, JSON заголовка и параметры KDF.
        - Если хранилище разблокировано: дополнительно выполняет криптографическую проверку AEAD-тега заголовка,
          валидацию индекса (включая отсутствие дубликатов, Path Traversal и зазоров) и потоковую проверку
          ВСЕХ чанков каждого зашифрованного файла (включая сверку SHA-256).
        Возвращает подробный объект `IntegrityReport`.
        """
        with self._lock:
            report = IntegrityReport(
                is_valid=False,
                vault_path=str(self.vault_path),
                format_version=FORMAT_VERSION,
                header_ok=False,
                index_ok=False,
            )

            orphans = self.find_orphaned_temp_files()
            if orphans:
                report.warnings.append(
                    f"Обнаружено {len(orphans)} временных файлов прерванных операций (основное хранилище не затронуто)."
                )

            try:
                info = self.inspect_header(self.vault_path)
                report.header_ok = True
                report.format_version = int(info["header"].get("format_version", FORMAT_VERSION))
            except Exception as exc:
                report.errors.append(f"Ошибка структуры заголовка: {exc}")
                return report

            if not self.is_unlocked or self._master_key is None:
                report.warnings.append(
                    "Хранилище заблокировано: выполнена структурная проверка заголовка. "
                    "Для полной криптографической проверки всех блоков файлов разблокируйте хранилище."
                )
                report.is_valid = True
                return report

            try:
                header_dict = info["header"]
                vault_uuid = str(header_dict["vault_uuid"])
                verify_header_mac(
                    self._master_key,
                    _canonical_header_bytes(header_dict),
                    vault_uuid,
                    str(header_dict.get("header_mac_hex", "")),
                )
            except Exception as exc:
                report.header_ok = False
                report.errors.append(f"Нарушена криптографическая целостность заголовка: {exc}")
                return report

            try:
                fp, _ = open_safe_regular_file_for_read(self.vault_path)
                with fp as f:
                    f.seek(info["index_offset"])
                    enc_index = f.read(info["index_len"])
                plain_index = decrypt_index_bytes(self._master_key, enc_index, vault_uuid)
                index_data = json.loads(plain_index.decode("utf-8"))
                entries_map = _validate_and_parse_index(
                    index_data=index_data,
                    expected_vault_uuid=vault_uuid,
                    data_start=FIXED_PREAMBLE_SIZE + info["header_len"],
                    index_offset=info["index_offset"],
                )
                report.index_ok = True
            except Exception as exc:
                report.errors.append(f"Нарушена целостность индекса хранилища: {exc}")
                return report

            entries = list(entries_map.values())
            report.total_entries = len(entries)
            file_entries = [e for e in entries if e.entry_type == "file"]
            dir_entries = [e for e in entries if e.entry_type == "dir"]
            report.total_files = len(file_entries)
            report.total_dirs = len(dir_entries)

            total_bytes = sum(e.size for e in file_entries)
            bytes_checked = 0

            fp, _ = open_safe_regular_file_for_read(self.vault_path)
            with fp as vault_fp:
                for entry in file_entries:
                    if cancel_check and cancel_check():
                        raise OperationCancelledError("Проверка целостности отменена пользователем.")
                    try:
                        def _cb(curr: int, tot: int) -> None:
                            if progress_cb:
                                progress_cb(bytes_checked + curr, max(1, total_bytes), entry.virtual_path)

                        decrypt_file_stream(
                            master_key=self._master_key,
                            entry_id=entry.entry_id,
                            file_salt=bytes.fromhex(entry.file_salt_hex),
                            expected_chunk_count=entry.chunk_count,
                            expected_plain_size=entry.size,
                            expected_sha256=entry.sha256,
                            src_stream=vault_fp,
                            blob_offset=entry.blob_offset,
                            blob_length=entry.blob_length,
                            dst_stream=None,
                            cancel_check=cancel_check,
                            progress_cb=_cb,
                        )
                        report.verified_files += 1
                        bytes_checked += entry.size
                    except OperationCancelledError:
                        raise
                    except Exception as exc:
                        report.corrupted_entries.append(entry.virtual_path)
                        report.errors.append(f"Файл '{entry.virtual_path}': {exc}")

            report.is_valid = (
                report.header_ok
                and report.index_ok
                and len(report.corrupted_entries) == 0
                and len(report.errors) == 0
            )
            return report

    def create_backup(self, backup_dest_path: str | Path) -> Path:
        """
        Создаёт консистентную резервную копию файла хранилища через временный файл и `os.fsync`,
        затем проверяет заголовок созданной резервной копии и публикует без перезаписи.
        """
        with self._lock:
            if not self.vault_path.exists():
                raise FileNotFoundError("Файл хранилища не существует.")

            raw_dest = Path(backup_dest_path)
            if raw_dest.is_symlink():
                raise FileOverwriteError(f"Целевой путь резервной копии является символической ссылкой: {backup_dest_path}")
            dest = raw_dest.resolve()
            if dest == self.vault_path:
                raise FileOverwriteError("Путь резервной копии не может совпадать с основным файлом хранилища.")
            if dest.exists() or dest.is_symlink():
                raise FileOverwriteError(f"Файл резервной копии уже существует: {dest}")
            if not dest.parent.exists() or not dest.parent.is_dir():
                raise FileNotFoundError(f"Каталог для сохранения резервной копии не существует: {dest.parent}")

            acquired_temp_lock = False
            if self._lock_file_fd is None:
                self._acquire_operation_lock()
                acquired_temp_lock = True

            try:
                st_vault = validate_safe_source_object(self.vault_path)
                check_disk_space(dest.parent, st_vault.st_size)

                tmp_backup = dest.parent / f".{dest.name}.backup_tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}"
                open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                try:
                    src_f, _ = open_safe_regular_file_for_read(self.vault_path, expected_stat=st_vault)
                    with src_f:
                        fd = os.open(str(tmp_backup), open_flags, 0o600)
                        with os.fdopen(fd, "wb") as dst_f:
                            shutil.copyfileobj(src_f, dst_f, length=256 * 1024)
                            dst_f.flush()
                            os.fsync(dst_f.fileno())

                    self.inspect_header(tmp_backup)
                    atomic_publish_extracted_file(tmp_backup, dest)
                    fsync_directory(dest.parent)
                    logger.info("Создана резервная копия хранилища: %s", dest)
                    return dest
                except Exception:
                    if tmp_backup.exists() or tmp_backup.is_symlink():
                        try:
                            tmp_backup.unlink()
                        except OSError:
                            pass
                    raise
            finally:
                if acquired_temp_lock:
                    self._release_operation_lock()

    def _write_atomic_transaction(
        self,
        new_entries: Dict[str, VaultEntry],
        source_files_map: Dict[str, Tuple[Path, os.stat_result]],
        cancel_check: Optional[Callable[[], bool]] = None,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
    ) -> None:
        """
        Внутренний метод атомарной записи хранилища (Copy-on-Write).
        Не изменяет `self._header` и существующие `self._entries` до успешного `os.replace`.
        """
        assert self._master_key is not None
        assert self._header is not None

        candidate_header = copy.deepcopy(self._header)
        candidate_header["updated_at"] = time.time()
        vault_uuid = str(candidate_header["vault_uuid"])
        candidate_header["header_mac_hex"] = compute_header_mac(
            self._master_key, _canonical_header_bytes(candidate_header), vault_uuid
        )
        header_bytes = json.dumps(candidate_header, indent=2, ensure_ascii=True).encode("utf-8")
        header_len = len(header_bytes)

        tmp_path = self.vault_path.parent / f".{self.vault_path.name}.tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}"
        old_vault_exists = self.vault_path.exists()

        total_existing_bytes = sum(
            e.blob_length for e in new_entries.values()
            if e.entry_type == "file" and e.entry_id not in source_files_map
        )
        total_new_bytes = sum(st.st_size for _, st in source_files_map.values()) + total_existing_bytes
        processed_new_bytes = 0
        open_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)

        try:
            fd = os.open(str(tmp_path), open_flags, 0o600)
            with os.fdopen(fd, "wb+") as tmp_fp:
                # 1. Резервируем место под 32-байтовую преамбулу и записываем заголовок
                tmp_fp.write(b"\x00" * FIXED_PREAMBLE_SIZE)
                tmp_fp.write(header_bytes)

                # 2. Записываем потоки данных всех файлов
                old_fp: Optional[BinaryIO] = None
                if old_vault_exists:
                    old_fp, _ = open_safe_regular_file_for_read(self.vault_path)
                try:
                    for vp in sorted(new_entries.keys()):
                        if cancel_check and cancel_check():
                            raise OperationCancelledError("Операция записи отменена пользователем.")

                        if os.environ.get("MINTVAULT_SIMULATE_CRASH_DURING_WRITE") == "1":
                            raise IOError("Симуляция аварийного сбоя питания/диска во время записи временного файла!")

                        entry = new_entries[vp]
                        if entry.entry_type == "dir":
                            entry.blob_offset = 0
                            entry.blob_length = 0
                            entry.chunk_count = 0
                            continue

                        if entry.entry_id in source_files_map:
                            src_path, initial_st = source_files_map[entry.entry_id]
                            blob_start = tmp_fp.tell()
                            src_fp, _ = open_safe_regular_file_for_read(src_path, expected_stat=initial_st)
                            with src_fp:
                                def _f_prog(curr: int, tot: int) -> None:
                                    if progress_cb:
                                        progress_cb(
                                            processed_new_bytes + curr,
                                            max(1, total_new_bytes),
                                            entry.virtual_path,
                                        )

                                file_salt, enc_len, chunk_cnt, sha256_hex = encrypt_file_stream(
                                    master_key=self._master_key,
                                    entry_id=entry.entry_id,
                                    src_stream=src_fp,
                                    dst_stream=tmp_fp,
                                    total_size=initial_st.st_size,
                                    cancel_check=cancel_check,
                                    progress_cb=_f_prog,
                                )
                                fst_after = os.fstat(src_fp.fileno())

                            current_st_after = os.lstat(str(src_path))
                            if (
                                fst_after.st_size != initial_st.st_size
                                or fst_after.st_mtime_ns != initial_st.st_mtime_ns
                                or current_st_after.st_ino != initial_st.st_ino
                                or current_st_after.st_size != initial_st.st_size
                                or current_st_after.st_mtime_ns != initial_st.st_mtime_ns
                            ):
                                raise MintVaultError(
                                    f"Исходный файл '{src_path}' был изменён другим процессом во время чтения! "
                                    "Во избежание сохранения неконсистентных данных операция отменена."
                                )

                            entry.blob_offset = blob_start
                            entry.blob_length = enc_len
                            entry.chunk_count = chunk_cnt
                            entry.file_salt_hex = file_salt.hex()
                            entry.sha256 = sha256_hex
                            processed_new_bytes += initial_st.st_size
                        else:
                            if old_fp is None:
                                raise IntegrityError("Внутренняя ошибка: отсутствует исходный контейнер для копирования блоков.")
                            old_fp.seek(entry.blob_offset)
                            new_offset = tmp_fp.tell()
                            remaining = entry.blob_length
                            while remaining > 0:
                                if cancel_check and cancel_check():
                                    raise OperationCancelledError("Операция отменена пользователем.")
                                chunk = old_fp.read(min(256 * 1024, remaining))
                                if not chunk:
                                    raise IntegrityError(
                                        f"Неожиданный конец исходного хранилища при копировании записи '{entry.virtual_path}'."
                                    )
                                tmp_fp.write(chunk)
                                remaining -= len(chunk)
                                processed_new_bytes += len(chunk)
                                if progress_cb:
                                    progress_cb(
                                        processed_new_bytes,
                                        max(1, total_new_bytes),
                                        entry.virtual_path,
                                    )
                            entry.blob_offset = new_offset
                finally:
                    if old_fp is not None:
                        old_fp.close()

                # 3. Сериализуем и шифруем индекс хранилища
                index_offset = tmp_fp.tell()
                index_payload = {
                    "format_version": FORMAT_VERSION,
                    "vault_uuid": vault_uuid,
                    "updated_at": candidate_header["updated_at"],
                    "entries": [new_entries[vp].to_dict() for vp in sorted(new_entries.keys())],
                }
                plain_index_bytes = json.dumps(index_payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
                encrypted_index = encrypt_index_bytes(self._master_key, plain_index_bytes, vault_uuid)
                index_len = len(encrypted_index)
                tmp_fp.write(encrypted_index)

                # 4. Записываем финальную преамбулу в начало файла
                tmp_fp.seek(0)
                preamble = struct.pack(
                    FIXED_PREAMBLE_FMT,
                    MAGIC_BYTES,
                    FORMAT_VERSION,
                    header_len,
                    index_offset,
                    index_len,
                )
                tmp_fp.write(preamble)
                tmp_fp.flush()
                os.fsync(tmp_fp.fileno())

            # 5. Верифицируем только что записанный временный контейнер перед заменой рабочего файла
            chk_info = self.inspect_header(tmp_path)
            verify_header_mac(
                self._master_key,
                _canonical_header_bytes(chk_info["header"]),
                vault_uuid,
                str(chk_info["header"].get("header_mac_hex", "")),
            )
            vf, _ = open_safe_regular_file_for_read(tmp_path)
            with vf:
                vf.seek(chk_info["index_offset"])
                chk_enc_idx = vf.read(chk_info["index_len"])
            chk_plain_idx = decrypt_index_bytes(self._master_key, chk_enc_idx, vault_uuid)
            if chk_plain_idx != plain_index_bytes:
                raise IntegrityError("Ошибка самопроверки записанного индекса временного файла!")

            # 6. Атомарно заменяем файл хранилища
            os.replace(str(tmp_path), str(self.vault_path))
            fsync_directory(self.vault_path.parent)
            self._header = candidate_header

        except Exception:
            if tmp_path.exists() or tmp_path.is_symlink():
                if os.environ.get("MINTVAULT_KEEP_ORPHAN_ON_CRASH") != "1":
                    try:
                        tmp_path.unlink()
                    except OSError:
                        pass
            raise


def posixpath_basename(vp: str) -> str:
    return vp.rsplit("/", 1)[-1]


def posixpath_dirname(vp: str) -> str:
    if "/" not in vp:
        return ""
    return vp.rsplit("/", 1)[0]


def virtual_dest_prefix(folder: str) -> str:
    if not folder or not folder.strip("/"):
        return ""
    return normalize_virtual_path(folder)
