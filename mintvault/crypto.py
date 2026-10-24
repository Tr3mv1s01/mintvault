"""
Криптографическое ядро MintVault.

Использует только проверенные промышленные криптографические библиотеки:
- libargon2 (Argon2id, RFC 9106) через системную библиотеку libargon2.so.1 (или Scrypt из OpenSSL при отсутствии)
- AES-256-GCM и HKDF-SHA256 из пакета `cryptography` (OpenSSL 3.0)
- Криптографический ГПСЧ операционной системы (`os.urandom`)
- Безопасное затирание чувствительных буферов в оперативной памяти (`ctypes.memset` / `sodium_memzero`)
"""

import base64
import ctypes
import ctypes.util
import hashlib
import os
import struct
from typing import BinaryIO, Callable, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .exceptions import AuthenticationError, IntegrityError, OperationCancelledError
from .models import KDFParams, WrappedKeySlot

# Размер одного блока при потоковом шифровании больших файлов (256 КиБ)
DEFAULT_CHUNK_SIZE = 256 * 1024
# Верхний предел размера одного чанка при расшифровке (защита от OOM DoS при повреждённом заголовке чанка)
MAX_CHUNK_SIZE = 4 * 1024 * 1024

AES_GCM_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16
MASTER_KEY_SIZE = 32
SALT_SIZE = 16
MAX_SALT_SIZE = 64

# Допустимые безопасные границы параметров KDF (защита от DoS и ослабленных параметров)
MIN_KDF_TIME_COST = 1
MAX_KDF_TIME_COST = 64
MIN_KDF_MEMORY_KIB = 8192          # 8 МиБ минимум
MAX_KDF_MEMORY_KIB = 1048576       # 1 ГиБ максимум
MIN_KDF_PARALLELISM = 1
MAX_KDF_PARALLELISM = 16

# Флаги чанков потока
CHUNK_FLAG_NORMAL = 0x00
CHUNK_FLAG_FINAL = 0x01


def _load_argon2_lib() -> Optional[ctypes.CDLL]:
    """Загружает системную библиотеку libargon2.so.1 на Linux Mint / Debian / Ubuntu."""
    for name in ("libargon2.so.1", "libargon2.so", ctypes.util.find_library("argon2")):
        if not name:
            continue
        try:
            lib = ctypes.CDLL(name)
            lib.argon2id_hash_raw.argtypes = [
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_char_p,
                ctypes.c_size_t,
                ctypes.c_char_p,
                ctypes.c_size_t,
            ]
            lib.argon2id_hash_raw.restype = ctypes.c_int
            return lib
        except Exception:
            continue
    return None


def _load_sodium_lib() -> Optional[ctypes.CDLL]:
    """Загружает системную библиотеку libsodium для гарантированного затирания памяти."""
    for name in ("libsodium.so.23", "libsodium.so", ctypes.util.find_library("sodium")):
        if not name:
            continue
        try:
            lib = ctypes.CDLL(name)
            lib.sodium_memzero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            lib.sodium_memzero.restype = None
            return lib
        except Exception:
            continue
    return None


_ARGON2_LIB = _load_argon2_lib()
_SODIUM_LIB = _load_sodium_lib()


def is_argon2id_available() -> bool:
    """Проверяет доступность нативной библиотеки Argon2id."""
    return _ARGON2_LIB is not None


def zero_memory(buf: Optional[bytearray]) -> None:
    """
    Принудительно затирает изменяемый буфер (bytearray) нулями в оперативной памяти.
    Минимизирует время жизни мастер-ключей, производных ключей и паролей в памяти.
    """
    if buf is None or not isinstance(buf, bytearray) or len(buf) == 0:
        return
    try:
        char_array = (ctypes.c_char * len(buf)).from_buffer(buf)
        if _SODIUM_LIB is not None:
            _SODIUM_LIB.sodium_memzero(ctypes.addressof(char_array), len(buf))
        else:
            ctypes.memset(ctypes.addressof(char_array), 0, len(buf))
    except Exception:
        for i in range(len(buf)):
            buf[i] = 0


def validate_kdf_params(kdf_params: KDFParams) -> bytes:
    """
    Проверяет границы и допустимость параметров KDF ДО выполнения ресурсоёмких вычислений.
    Защищает от DoS-атак (чрезмерное потребление ОЗУ или CPU) и целочисленных переполнений
    при открытии специально сформированного контейнера.
    """
    if not isinstance(kdf_params, KDFParams):
        raise IntegrityError("Отсутствуют параметры KDF.")
    if kdf_params.algorithm not in ("argon2id", "scrypt"):
        raise IntegrityError(f"Неподдерживаемый алгоритм KDF: {kdf_params.algorithm}")

    if (
        isinstance(kdf_params.time_cost, bool)
        or not isinstance(kdf_params.time_cost, int)
        or not (MIN_KDF_TIME_COST <= kdf_params.time_cost <= MAX_KDF_TIME_COST)
    ):
        raise IntegrityError(
            f"Недопустимое значение параметра KDF time_cost: {kdf_params.time_cost} "
            f"(допустимо от {MIN_KDF_TIME_COST} до {MAX_KDF_TIME_COST})."
        )

    if (
        isinstance(kdf_params.memory_cost_kib, bool)
        or not isinstance(kdf_params.memory_cost_kib, int)
        or not (MIN_KDF_MEMORY_KIB <= kdf_params.memory_cost_kib <= MAX_KDF_MEMORY_KIB)
    ):
        raise IntegrityError(
            f"Недопустимое значение параметра KDF memory_cost_kib: {kdf_params.memory_cost_kib} "
            f"(допустимо от {MIN_KDF_MEMORY_KIB} до {MAX_KDF_MEMORY_KIB} КиБ)."
        )

    if (
        isinstance(kdf_params.parallelism, bool)
        or not isinstance(kdf_params.parallelism, int)
        or not (MIN_KDF_PARALLELISM <= kdf_params.parallelism <= MAX_KDF_PARALLELISM)
    ):
        raise IntegrityError(
            f"Недопустимое значение параметра KDF parallelism: {kdf_params.parallelism} "
            f"(допустимо от {MIN_KDF_PARALLELISM} до {MAX_KDF_PARALLELISM})."
        )

    if not isinstance(kdf_params.salt_hex, str) or not kdf_params.salt_hex:
        raise IntegrityError("Отсутствует криптографическая соль KDF.")
    try:
        salt = bytes.fromhex(kdf_params.salt_hex)
    except ValueError as exc:
        raise IntegrityError("Повреждённый hex-формат криптографической соли KDF.") from exc

    if not (SALT_SIZE <= len(salt) <= MAX_SALT_SIZE):
        raise IntegrityError(
            f"Некорректная длина криптографической соли KDF ({len(salt)} байт)."
        )
    return salt


def derive_kek(secret_bytes: bytes | bytearray, kdf_params: KDFParams) -> bytearray:
    """
    Вычисляет 32-байтовый ключ шифрования ключа (KEK) из пароля или ключа восстановления
    с помощью Argon2id (основной) или Scrypt (резервный).
    Возвращает изменяемый bytearray, который вызывающая сторона обязана очистить через zero_memory().
    """
    if not secret_bytes:
        raise ValueError("Пароль или ключ не может быть пустым.")
    if len(secret_bytes) > 4096:
        raise ValueError("Превышена максимальная длина пароля или ключа (4096 байт).")

    salt = validate_kdf_params(kdf_params)

    secret_len = len(secret_bytes)
    secret_c_buf = ctypes.create_string_buffer(secret_len)
    if isinstance(secret_bytes, bytearray):
        src_arr = (ctypes.c_char * secret_len).from_buffer(secret_bytes)
        ctypes.memmove(secret_c_buf, src_arr, secret_len)
    else:
        ctypes.memmove(secret_c_buf, secret_bytes, secret_len)

    try:
        if kdf_params.algorithm == "argon2id":
            if _ARGON2_LIB is None:
                raise RuntimeError("Библиотека libargon2 недоступна в системе.")
            out_buf = ctypes.create_string_buffer(MASTER_KEY_SIZE)
            try:
                res = _ARGON2_LIB.argon2id_hash_raw(
                    ctypes.c_uint32(kdf_params.time_cost),
                    ctypes.c_uint32(kdf_params.memory_cost_kib),
                    ctypes.c_uint32(kdf_params.parallelism),
                    ctypes.addressof(secret_c_buf),
                    secret_len,
                    salt,
                    len(salt),
                    out_buf,
                    MASTER_KEY_SIZE,
                )
                if res != 0:
                    raise IntegrityError(f"Ошибка выполнения Argon2id (код {res}).")
                return bytearray(out_buf.raw)
            finally:
                if _SODIUM_LIB is not None:
                    _SODIUM_LIB.sodium_memzero(ctypes.addressof(out_buf), MASTER_KEY_SIZE)
                else:
                    ctypes.memset(ctypes.addressof(out_buf), 0, MASTER_KEY_SIZE)
        elif kdf_params.algorithm == "scrypt":
            n_power = max(14, min(20, int(kdf_params.time_cost) + 12))
            p_val = max(MIN_KDF_PARALLELISM, min(MAX_KDF_PARALLELISM, int(kdf_params.parallelism)))
            scrypt_kdf = Scrypt(
                salt=salt,
                length=MASTER_KEY_SIZE,
                n=1 << n_power,
                r=8,
                p=p_val,
            )
            derived = scrypt_kdf.derive(secret_c_buf.raw)
            return bytearray(derived)
        else:
            raise IntegrityError(f"Неизвестный алгоритм KDF: {kdf_params.algorithm}")
    finally:
        if _SODIUM_LIB is not None:
            _SODIUM_LIB.sodium_memzero(ctypes.addressof(secret_c_buf), secret_len)
        else:
            ctypes.memset(ctypes.addressof(secret_c_buf), 0, secret_len)


def generate_recovery_key() -> str:
    """
    Генерирует криптографически стойкий 256-битный ключ восстановления
    и форматирует его в удобочитаемые группы Base32 (например: XXXX-XXXX-XXXX-...).
    """
    raw = bytearray(os.urandom(32))
    try:
        b32 = base64.b32encode(bytes(raw)).decode("ascii").rstrip("=")
        groups = [b32[i : i + 4] for i in range(0, len(b32), 4)]
        return "-".join(groups)
    finally:
        zero_memory(raw)


def normalize_recovery_key(recovery_key: str) -> bytes:
    """Нормализует введённый пользователем ключ восстановления для KDF."""
    if not isinstance(recovery_key, str):
        raise AuthenticationError("Некорректный формат ключа восстановления.")
    cleaned = "".join(ch for ch in recovery_key.upper() if ch.isalnum())
    if len(cleaned) < 32 or len(cleaned) > 128 or not cleaned.isascii():
        raise AuthenticationError("Некорректный формат ключа восстановления.")
    return cleaned.encode("ascii")


def create_key_slot(
    master_key: bytes | bytearray,
    secret_bytes: bytes | bytearray,
    slot_type: str = "password",
    time_cost: int = 3,
    memory_cost_kib: int = 65536,
    parallelism: int = 2,
) -> WrappedKeySlot:
    """
    Создаёт зашифрованный слот мастер-ключа (Key Wrapping через AES-256-GCM).
    """
    if len(master_key) != MASTER_KEY_SIZE:
        raise ValueError("Некорректный размер мастер-ключа.")
    if slot_type not in ("password", "recovery"):
        raise ValueError(f"Недопустимый тип слота: {slot_type}")

    algo = "argon2id" if is_argon2id_available() else "scrypt"
    salt = os.urandom(SALT_SIZE)
    kdf_params = KDFParams(
        algorithm=algo,
        time_cost=time_cost,
        memory_cost_kib=memory_cost_kib,
        parallelism=parallelism,
        salt_hex=salt.hex(),
    )
    validate_kdf_params(kdf_params)
    kek = derive_kek(secret_bytes, kdf_params)
    try:
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        aesgcm = AESGCM(bytes(kek))
        aad = f"MINTVAULT-KEYSLOT-V1:{slot_type}:{kdf_params.algorithm}".encode("utf-8")
        ct = aesgcm.encrypt(nonce, bytes(master_key), aad)
        return WrappedKeySlot(
            slot_type=slot_type,
            kdf=kdf_params,
            nonce_hex=nonce.hex(),
            ciphertext_hex=ct.hex(),
        )
    finally:
        zero_memory(kek)


def unwrap_key_slot(slot: WrappedKeySlot, secret_bytes: bytes | bytearray) -> bytearray:
    """
    Расшифровывает мастер-ключ из слота с проверкой подлинности AES-256-GCM.
    При неверном пароле или повреждении слота выбрасывает AuthenticationError / IntegrityError.
    """
    if not isinstance(slot, WrappedKeySlot):
        raise IntegrityError("Повреждённая структура ключевого слота.")
    try:
        nonce = bytes.fromhex(slot.nonce_hex)
        ct = bytes.fromhex(slot.ciphertext_hex)
    except ValueError as exc:
        raise IntegrityError("Повреждённый hex-формат ключевого слота хранилища.") from exc

    if len(nonce) != AES_GCM_NONCE_SIZE or len(ct) != MASTER_KEY_SIZE + AES_GCM_TAG_SIZE:
        raise IntegrityError("Повреждённый формат ключевого слота хранилища.")

    validate_kdf_params(slot.kdf)
    kek = derive_kek(secret_bytes, slot.kdf)
    try:
        aesgcm = AESGCM(bytes(kek))
        aad = f"MINTVAULT-KEYSLOT-V1:{slot.slot_type}:{slot.kdf.algorithm}".encode("utf-8")
        try:
            mk = aesgcm.decrypt(nonce, ct, aad)
        except InvalidTag as exc:
            raise AuthenticationError("Неверный пароль или ключ восстановления.") from exc
        return bytearray(mk)
    finally:
        zero_memory(kek)


def derive_subkey(master_key: bytes | bytearray, context: bytes, salt: bytes) -> bytearray:
    """
    Выводит специализированный 256-битный подключ из мастер-ключа с помощью HKDF-SHA256 (RFC 5869).
    Используется для разделения ключей заголовка, индекса и каждого отдельного файла.
    """
    if len(master_key) != MASTER_KEY_SIZE:
        raise IntegrityError("Некорректная длина мастер-ключа при выводе подключа.")
    if not salt or len(salt) < SALT_SIZE:
        raise IntegrityError("Некорректная соль для HKDF-SHA256.")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=MASTER_KEY_SIZE,
        salt=salt,
        info=context,
    )
    return bytearray(hkdf.derive(bytes(master_key)))


def compute_header_mac(master_key: bytes | bytearray, canonical_header_bytes: bytes, vault_uuid: str) -> str:
    """
    Вычисляет аутентификационный тег (AEAD AES-256-GCM) для открытого заголовка хранилища,
    защищая метаданные KDF и ключевые слоты от незаметной подмены.
    """
    salt = hashlib.sha256(vault_uuid.encode("utf-8")).digest()[:SALT_SIZE]
    subkey = derive_subkey(master_key, b"MINTVAULT-HEADER-AUTH-V1", salt)
    try:
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        aesgcm = AESGCM(bytes(subkey))
        tag = aesgcm.encrypt(nonce, b"", canonical_header_bytes)
        return (nonce + tag).hex()
    finally:
        zero_memory(subkey)


def verify_header_mac(
    master_key: bytes | bytearray,
    canonical_header_bytes: bytes,
    vault_uuid: str,
    mac_hex: str,
) -> None:
    """Проверяет целостность и подлинность заголовка хранилища."""
    if not isinstance(mac_hex, str) or not mac_hex:
        raise IntegrityError("Отсутствует тег аутентификации заголовка.")
    try:
        raw = bytes.fromhex(mac_hex)
    except ValueError as exc:
        raise IntegrityError("Повреждён тег аутентификации заголовка.") from exc
    if len(raw) != AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE:
        raise IntegrityError("Неверная длина тега аутентификации заголовка.")
    nonce = raw[:AES_GCM_NONCE_SIZE]
    tag = raw[AES_GCM_NONCE_SIZE:]
    salt = hashlib.sha256(vault_uuid.encode("utf-8")).digest()[:SALT_SIZE]
    subkey = derive_subkey(master_key, b"MINTVAULT-HEADER-AUTH-V1", salt)
    try:
        aesgcm = AESGCM(bytes(subkey))
        try:
            aesgcm.decrypt(nonce, tag, canonical_header_bytes)
        except InvalidTag as exc:
            raise IntegrityError("Заголовок хранилища был изменён или повреждён!") from exc
    finally:
        zero_memory(subkey)


def encrypt_index_bytes(master_key: bytes | bytearray, plaintext_index: bytes, vault_uuid: str) -> bytes:
    """
    Шифрует сериализованный индекс хранилища с использованием AES-256-GCM.
    Формат: [16 байт соль] + [12 байт nonce] + [шифротекст + 16 байт тег GCM].
    """
    index_salt = os.urandom(SALT_SIZE)
    subkey = derive_subkey(master_key, b"MINTVAULT-INDEX-KEY-V1", index_salt)
    try:
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        aesgcm = AESGCM(bytes(subkey))
        aad = f"MINTVAULT-INDEX-V1:{vault_uuid}".encode("utf-8")
        ct = aesgcm.encrypt(nonce, plaintext_index, aad)
        return index_salt + nonce + ct
    finally:
        zero_memory(subkey)


def decrypt_index_bytes(master_key: bytes | bytearray, encrypted_index: bytes, vault_uuid: str) -> bytes:
    """
    Расшифровывает и проверяет подлинность индекса хранилища.
    """
    min_len = SALT_SIZE + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE
    if len(encrypted_index) < min_len:
        raise IntegrityError("Секция индекса хранилища повреждена или усечена.")
    index_salt = encrypted_index[:SALT_SIZE]
    nonce = encrypted_index[SALT_SIZE : SALT_SIZE + AES_GCM_NONCE_SIZE]
    ct = encrypted_index[SALT_SIZE + AES_GCM_NONCE_SIZE :]
    subkey = derive_subkey(master_key, b"MINTVAULT-INDEX-KEY-V1", index_salt)
    try:
        aesgcm = AESGCM(bytes(subkey))
        aad = f"MINTVAULT-INDEX-V1:{vault_uuid}".encode("utf-8")
        try:
            return aesgcm.decrypt(nonce, ct, aad)
        except InvalidTag as exc:
            raise IntegrityError(
                "Не удалось проверить целостность индекса хранилища: данные повреждены или подменены."
            ) from exc
    finally:
        zero_memory(subkey)


def encrypt_file_stream(
    master_key: bytes | bytearray,
    entry_id: str,
    src_stream: BinaryIO,
    dst_stream: BinaryIO,
    total_size: int,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    cancel_check: Optional[Callable[[], bool]] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Tuple[bytes, int, int, str]:
    """
    Потоково шифрует содержимое файла без загрузки всего файла в ОЗУ.
    Каждый чанк шифруется AES-256-GCM с уникальным 12-байтовым nonce и строгим AAD,
    включающим: идентификатор записи, соль файла, индекс чанка, флаг последнего блока и длину чанка.
    """
    if chunk_size <= 0 or chunk_size > MAX_CHUNK_SIZE:
        raise ValueError(f"Недопустимый размер блока шифрования: {chunk_size}")

    file_salt = os.urandom(SALT_SIZE)
    subkey = derive_subkey(master_key, f"MINTVAULT-FILE-KEY-V1:{entry_id}".encode("utf-8"), file_salt)
    sha256_hasher = hashlib.sha256()
    total_encrypted_bytes = 0
    chunk_index = 0
    processed_plain = 0

    try:
        aesgcm = AESGCM(bytes(subkey))
        prev_chunk = src_stream.read(chunk_size)
        if prev_chunk is None:
            prev_chunk = b""

        while True:
            if cancel_check and cancel_check():
                raise OperationCancelledError("Шифрование файла отменено пользователем.")

            next_chunk = src_stream.read(chunk_size)
            is_final = (not next_chunk)
            flag = CHUNK_FLAG_FINAL if is_final else CHUNK_FLAG_NORMAL

            sha256_hasher.update(prev_chunk)
            nonce = os.urandom(AES_GCM_NONCE_SIZE)
            aad = (
                f"MINTVAULT-CHUNK-V1:{entry_id}:{file_salt.hex()}:{chunk_index}:{flag}:{len(prev_chunk)}"
            ).encode("utf-8")
            ct = aesgcm.encrypt(nonce, prev_chunk, aad)

            chunk_header = struct.pack(">IB", len(prev_chunk), flag)
            record = chunk_header + nonce + ct
            dst_stream.write(record)

            total_encrypted_bytes += len(record)
            chunk_index += 1
            processed_plain += len(prev_chunk)

            if progress_cb:
                progress_cb(processed_plain, max(total_size, processed_plain))

            if is_final:
                break
            prev_chunk = next_chunk

        return file_salt, total_encrypted_bytes, chunk_index, sha256_hasher.hexdigest()
    finally:
        zero_memory(subkey)


def decrypt_file_stream(
    master_key: bytes | bytearray,
    entry_id: str,
    file_salt: bytes,
    expected_chunk_count: int,
    expected_plain_size: int,
    expected_sha256: str,
    src_stream: BinaryIO,
    blob_offset: int,
    blob_length: int,
    dst_stream: Optional[BinaryIO] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> str:
    """
    Потоково расшифровывает и проверяет целостность файла из хранилища.
    Если dst_stream равен None, выполняет полную криптографическую проверку целостности
    без сохранения на диск (режим проверки хранилища).
    Возвращает вычисленный SHA-256 открытого текста.
    """
    if len(file_salt) != SALT_SIZE:
        raise IntegrityError(f"Некорректная соль файла для записи {entry_id}.")
    if expected_chunk_count < 1:
        raise IntegrityError(f"Некорректное количество блоков ({expected_chunk_count}) для записи {entry_id}.")
    if expected_plain_size < 0:
        raise IntegrityError(f"Отрицательный ожидаемый размер файла для записи {entry_id}.")
    if blob_offset < 0 or blob_length < 5 + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE:
        raise IntegrityError(f"Некорректные границы зашифрованного потока для записи {entry_id}.")

    subkey = derive_subkey(master_key, f"MINTVAULT-FILE-KEY-V1:{entry_id}".encode("utf-8"), file_salt)
    sha256_hasher = hashlib.sha256()
    src_stream.seek(blob_offset)
    bytes_remaining = blob_length
    chunk_index = 0
    total_plain_written = 0
    saw_final_flag = False

    try:
        aesgcm = AESGCM(bytes(subkey))
        while bytes_remaining > 0:
            if cancel_check and cancel_check():
                raise OperationCancelledError("Расшифровка файла отменена пользователем.")

            if chunk_index >= expected_chunk_count:
                raise IntegrityError(
                    f"Превышено ожидаемое количество блоков ({expected_chunk_count}) в записи {entry_id}."
                )

            if bytes_remaining < 5 + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE:
                raise IntegrityError(f"Повреждён или усечён заголовок блока #{chunk_index} файла {entry_id}.")

            hdr = src_stream.read(5)
            if len(hdr) != 5:
                raise IntegrityError(f"Неожиданный конец файла хранилища при чтении блока #{chunk_index}.")
            plain_len, flag = struct.unpack(">IB", hdr)

            # Защита от DoS (выделения гигабайт памяти при подделке заголовка чанка)
            if plain_len > MAX_CHUNK_SIZE:
                raise IntegrityError(
                    f"Размер блока #{chunk_index} ({plain_len} байт) превышает максимально допустимый предел."
                )

            # Пустой чанк (0 байт) допустим только для пустого файла из 1 финального чанка
            if plain_len == 0 and not (
                chunk_index == 0 and flag == CHUNK_FLAG_FINAL and expected_plain_size == 0
            ):
                raise IntegrityError(
                    f"Обнаружен недопустимый пустой блок #{chunk_index} в непустом файле {entry_id}."
                )

            if total_plain_written + plain_len > expected_plain_size:
                raise IntegrityError(
                    f"Сумма размеров блоков превышает ожидаемый размер файла {entry_id}."
                )

            ct_total_len = AES_GCM_NONCE_SIZE + plain_len + AES_GCM_TAG_SIZE

            if 5 + ct_total_len > bytes_remaining:
                raise IntegrityError(
                    f"Размер зашифрованного блока #{chunk_index} выходит за границы записи {entry_id}."
                )

            nonce = src_stream.read(AES_GCM_NONCE_SIZE)
            ct = src_stream.read(plain_len + AES_GCM_TAG_SIZE)
            if len(nonce) != AES_GCM_NONCE_SIZE or len(ct) != plain_len + AES_GCM_TAG_SIZE:
                raise IntegrityError(f"Неожиданный конец файла при чтении тела блока #{chunk_index}.")

            bytes_remaining -= 5 + ct_total_len

            aad = (
                f"MINTVAULT-CHUNK-V1:{entry_id}:{file_salt.hex()}:{chunk_index}:{flag}:{plain_len}"
            ).encode("utf-8")
            try:
                plain_chunk = aesgcm.decrypt(nonce, ct, aad)
            except InvalidTag as exc:
                raise IntegrityError(
                    f"Ошибка аутентификации AES-GCM в блоке #{chunk_index} записи {entry_id}: данные изменены или повреждены!"
                ) from exc

            if flag == CHUNK_FLAG_FINAL:
                saw_final_flag = True
                if bytes_remaining != 0:
                    raise IntegrityError(f"Обнаружены лишние данные после финального блока записи {entry_id}.")
            elif flag != CHUNK_FLAG_NORMAL:
                raise IntegrityError(f"Неизвестный флаг блока ({flag}) в записи {entry_id}.")

            sha256_hasher.update(plain_chunk)
            if dst_stream is not None:
                dst_stream.write(plain_chunk)

            total_plain_written += len(plain_chunk)
            chunk_index += 1

            if progress_cb:
                progress_cb(total_plain_written, max(expected_plain_size, total_plain_written))

        if not saw_final_flag:
            raise IntegrityError(f"Поток данных записи {entry_id} оборван: отсутствует финальный блок.")
        if chunk_index != expected_chunk_count:
            raise IntegrityError(
                f"Несовпадение количества блоков в записи {entry_id}: ожидалось {expected_chunk_count}, прочитано {chunk_index}."
            )
        if total_plain_written != expected_plain_size:
            raise IntegrityError(
                f"Несовпадение размера расшифрованного файла {entry_id}: ожидалось {expected_plain_size}, получено {total_plain_written}."
            )

        computed_sha256 = sha256_hasher.hexdigest()
        if computed_sha256.lower() != expected_sha256.lower():
            raise IntegrityError(
                f"Несовпадение контрольной суммы SHA-256 для записи {entry_id}!"
            )

        return computed_sha256
    finally:
        zero_memory(subkey)
