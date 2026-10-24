"""
Модели данных и структуры конфигурации для хранилища MintVault.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from .exceptions import IntegrityError, VaultFormatError


def _require_int_not_bool(val: Any, field_name: str) -> int:
    if isinstance(val, bool) or not isinstance(val, int):
        raise VaultFormatError(f"Поле '{field_name}' должно быть целым числом.")
    return int(val)


def _require_str(val: Any, field_name: str) -> str:
    if not isinstance(val, str):
        raise VaultFormatError(f"Поле '{field_name}' должно быть строкой.")
    return val


@dataclass
class KDFParams:
    """Параметры функции формирования ключа Argon2id (или резервной Scrypt)."""
    algorithm: str = "argon2id"      # "argon2id" или "scrypt"
    time_cost: int = 3               # Количество итераций Argon2id (или степень N для scrypt)
    memory_cost_kib: int = 65536     # 64 МБ памяти (65536 КиБ)
    parallelism: int = 2             # Количество потоков
    salt_hex: str = ""               # 16-байтовая криптографическая соль в hex

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KDFParams":
        if not isinstance(data, dict):
            raise VaultFormatError("Некорректная структура параметров KDF в заголовке.")
        return cls(
            algorithm=_require_str(data.get("algorithm", "argon2id"), "algorithm"),
            time_cost=_require_int_not_bool(data.get("time_cost", 3), "time_cost"),
            memory_cost_kib=_require_int_not_bool(data.get("memory_cost_kib", 65536), "memory_cost_kib"),
            parallelism=_require_int_not_bool(data.get("parallelism", 2), "parallelism"),
            salt_hex=_require_str(data.get("salt_hex", ""), "salt_hex"),
        )


@dataclass
class WrappedKeySlot:
    """Зашифрованный слот мастер-ключа (для пароля или ключа восстановления)."""
    slot_type: str                   # "password" или "recovery"
    kdf: KDFParams
    nonce_hex: str                   # 12-байтовый nonce для AES-256-GCM
    ciphertext_hex: str              # Зашифрованный 32-байтовый мастер-ключ + 16-байтовый тег

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slot_type": self.slot_type,
            "kdf": self.kdf.to_dict(),
            "nonce_hex": self.nonce_hex,
            "ciphertext_hex": self.ciphertext_hex,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WrappedKeySlot":
        if not isinstance(data, dict):
            raise VaultFormatError("Некорректный формат ключевого слота в заголовке хранилища.")
        for req_key in ("slot_type", "kdf", "nonce_hex", "ciphertext_hex"):
            if req_key not in data:
                raise VaultFormatError(f"Отсутствует обязательное поле '{req_key}' в ключевом слоте.")
        slot_type = _require_str(data["slot_type"], "slot_type")
        if slot_type not in ("password", "recovery"):
            raise VaultFormatError(f"Неизвестный тип ключевого слота: '{slot_type}'.")
        return cls(
            slot_type=slot_type,
            kdf=KDFParams.from_dict(data["kdf"]),
            nonce_hex=_require_str(data["nonce_hex"], "nonce_hex"),
            ciphertext_hex=_require_str(data["ciphertext_hex"], "ciphertext_hex"),
        )


@dataclass
class VaultEntry:
    """Метаданные одного файла или каталога внутри зашифрованного индекса."""
    entry_id: str                    # Уникальный UUID объекта внутри хранилища
    virtual_path: str                # Относительный нормализованный путь внутри хранилища (UTF-8, без ведущих /)
    entry_type: str                  # "file" или "dir"
    size: int                        # Исходный размер файла в байтах (0 для каталога)
    mtime: float                     # Время последней модификации исходного файла (UNIX timestamp)
    mode: int                        # Безопасные права доступа (например, 0o600 или 0o755)
    sha256: str                      # SHA-256 открытого содержимого файла (пустая строка для каталога)
    added_at: float                  # Время добавления в хранилище
    blob_offset: int = 0             # Смещение в секции зашифрованных данных хранилища
    blob_length: int = 0             # Длина зашифрованного потока в байтах
    chunk_count: int = 0             # Количество зашифрованных блоков (чанков)
    file_salt_hex: str = ""          # Уникальная 16-байтовая соль файла для HKDF и формирования AAD

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VaultEntry":
        if not isinstance(data, dict):
            raise IntegrityError("Запись в индексе хранилища повреждена (не является объектом).")
        for req_key in ("entry_id", "virtual_path", "entry_type"):
            if req_key not in data or not isinstance(data[req_key], str) or not data[req_key]:
                raise IntegrityError(f"В записи индекса отсутствует или повреждено поле '{req_key}'.")
        try:
            size = _require_int_not_bool(data.get("size", 0), "size")
            mode = _require_int_not_bool(data.get("mode", 0o600), "mode")
            blob_offset = _require_int_not_bool(data.get("blob_offset", 0), "blob_offset")
            blob_length = _require_int_not_bool(data.get("blob_length", 0), "blob_length")
            chunk_count = _require_int_not_bool(data.get("chunk_count", 0), "chunk_count")
            mtime_val = data.get("mtime", 0.0)
            added_val = data.get("added_at", 0.0)
            if isinstance(mtime_val, bool) or not isinstance(mtime_val, (int, float)):
                raise IntegrityError("Некорректное поле 'mtime' в записи индекса.")
            if isinstance(added_val, bool) or not isinstance(added_val, (int, float)):
                raise IntegrityError("Некорректное поле 'added_at' в записи индекса.")
        except VaultFormatError as exc:
            raise IntegrityError(str(exc)) from exc

        return cls(
            entry_id=str(data["entry_id"]),
            virtual_path=str(data["virtual_path"]),
            entry_type=str(data["entry_type"]),
            size=size,
            mtime=float(mtime_val),
            mode=mode,
            sha256=_require_str(data.get("sha256", ""), "sha256"),
            added_at=float(added_val),
            blob_offset=blob_offset,
            blob_length=blob_length,
            chunk_count=chunk_count,
            file_salt_hex=_require_str(data.get("file_salt_hex", ""), "file_salt_hex"),
        )


@dataclass
class IntegrityReport:
    """Отчёт о проверке целостности хранилища."""
    is_valid: bool
    vault_path: str
    format_version: int
    header_ok: bool
    index_ok: bool
    total_entries: int = 0
    total_files: int = 0
    total_dirs: int = 0
    verified_files: int = 0
    corrupted_entries: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
