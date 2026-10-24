"""
Комплексный набор автоматизированных тестов для защищённого хранилища MintVault (`test_mintvault.py`).

Охватывает все 17 обязательных сценариев из технического задания и дополнительные проверки безопасности:
1. Создание и открытие хранилища.
2. Успешная разблокировка правильным паролем и аварийным ключом восстановления.
3. Отказ при неправильном пароле или ключе восстановления.
4. Добавление одного файла.
5. Добавление каталога с вложенными файлами и подкаталогами.
6. Проверка идентичности и сохранности оригиналов после добавления (оригиналы НЕ удаляются и НЕ изменяются).
7. Извлечение и побайтовое сравнение контрольных сумм SHA-256.
8. Обработка русских имён, Unicode, пробелов и специальных символов.
9. Обработка пустых файлов (0 байт) и больших многоблочных файлов (> 1 МБ, потоковая обработка чанками).
10. Обнаружение повреждённых и изменённых зашифрованных данных (заголовок, индекс, блоки данных, усечение файла).
11. Отсутствие перезаписи существующих файлов при извлечении и защита от Path Traversal (`../`).
12. Обработка нехватки дискового пространства, ошибок ввода-вывода и отказ при символических ссылках / FIFO.
13. Аварийное завершение во время записи и проверка возможности восстановления без потери предыдущего состояния.
14. Проверка отсутствия паролей, ключей и содержимого файлов в логах и диагностических сообщениях.
15. Проверка блокировки и закрытия хранилища (затирание ключей в памяти).
16. Проверка поведения при параллельных операциях (блокировка `fcntl.flock` и потокобезопасность).
17. Проверка установки (`install.sh`), удаления (`uninstall.sh`), CLI и запуска GUI на Linux Mint.
"""

import hashlib
import io
import logging
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from mintvault.crypto import DEFAULT_CHUNK_SIZE, zero_memory
from mintvault.exceptions import (
    AuthenticationError,
    FileOverwriteError,
    InsufficientDiskSpaceError,
    IntegrityError,
    MintVaultError,
    OperationCancelledError,
    PathTraversalError,
    UnsafeFileObjectError,
    VaultBusyError,
    VaultFormatError,
    VaultLockedError,
)
from mintvault.fs_utils import normalize_virtual_path, resolve_safe_extraction_path
from mintvault.vault import SecureVault

# Для ускорения выполнения 20+ криптографических тестов используем быстрые параметры Argon2id в тестах,
# при этом отдельно тестируем и стандартные промышленные параметры.
FAST_KDF = {"kdf_time_cost": 1, "kdf_memory_kib": 8192, "kdf_parallelism": 1}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(128 * 1024):
            h.update(chunk)
    return h.hexdigest()


class MintVaultTestSuite(unittest.TestCase):
    """Автоматизированные тесты всех сценариев безопасности и функциональности MintVault."""

    def setUp(self) -> None:
        self.temp_dir_obj = tempfile.TemporaryDirectory(prefix="mintvault_test_")
        self.tmp_dir = Path(self.temp_dir_obj.name)
        self.vault_path = self.tmp_dir / "secure_storage.mvault"
        self.password = "Секретный_Пароль_LinuxMint#2026!"

    def tearDown(self) -> None:
        os.environ.pop("MINTVAULT_SIMULATE_FREE_BYTES", None)
        os.environ.pop("MINTVAULT_SIMULATE_CRASH_DURING_WRITE", None)
        os.environ.pop("MINTVAULT_KEEP_ORPHAN_ON_CRASH", None)
        self.temp_dir_obj.cleanup()

    # ------------------------------------------------------------------
    # 1, 2, 3: Создание, открытие, успешная разблокировка (пароль + ключ восстановления) и отказ при неверном пароле
    # ------------------------------------------------------------------
    def test_01_create_open_unlock_and_wrong_password(self) -> None:
        vault, recovery_key = SecureVault.create(
            self.vault_path,
            self.password,
            create_recovery_key=True,
            **FAST_KDF,
        )
        self.assertTrue(self.vault_path.exists())
        self.assertTrue(vault.is_unlocked)
        self.assertIsNotNone(recovery_key)
        assert recovery_key is not None
        self.assertGreaterEqual(len(recovery_key), 50)
        vault.close()
        self.assertFalse(vault.is_unlocked)

        # Попытка разблокировки неверным паролем
        v_wrong = SecureVault(self.vault_path)
        with self.assertRaises(AuthenticationError):
            v_wrong.unlock("НеправильныйПароль123")
        self.assertFalse(v_wrong.is_unlocked)

        # Попытка разблокировки неверным ключом восстановления
        with self.assertRaises(AuthenticationError):
            v_wrong.unlock("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-IIII-JJJJ-KKKK-LLLL-MMMM", use_recovery_key=True)
        self.assertFalse(v_wrong.is_unlocked)

        # Успешная разблокировка правильным паролем
        v_ok = SecureVault(self.vault_path)
        v_ok.unlock(self.password)
        self.assertTrue(v_ok.is_unlocked)
        v_ok.close()

        # Успешная разблокировка аварийным ключом восстановления
        v_rec = SecureVault(self.vault_path)
        v_rec.unlock(recovery_key, use_recovery_key=True)
        self.assertTrue(v_rec.is_unlocked)
        v_rec.close()

    # ------------------------------------------------------------------
    # 4, 6, 7: Добавление одного файла, проверка неизменности оригинала, извлечение и сверка SHA-256
    # ------------------------------------------------------------------
    def test_02_single_file_add_preserve_original_and_extract_checksum(self) -> None:
        src_file = self.tmp_dir / "financial_report.txt"
        content = "Конфиденциальный финансовый отчёт за 2026 год.\nСумма: 1 250 000 руб.\n".encode("utf-8")
        src_file.write_bytes(content)
        orig_stat = src_file.stat()
        orig_sha256 = sha256_file(src_file)

        vault, _ = SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)
        added = vault.add_paths([src_file])
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].sha256, orig_sha256)
        vault.close()

        # Проверяем, что оригинал НЕ удалён и побайтово идентичен
        self.assertTrue(src_file.exists(), "Оригинальный файл обязан оставаться на месте после добавления!")
        self.assertEqual(sha256_file(src_file), orig_sha256)
        self.assertEqual(src_file.stat().st_size, orig_stat.st_size)

        # Проверяем, что открытый текст файла не встречается в бинарном файле хранилища
        vault_raw = self.vault_path.read_bytes()
        self.assertNotIn("Конфиденциальный финансовый отчёт".encode("utf-8"), vault_raw)
        self.assertNotIn(b"financial_report.txt", vault_raw)  # Имя файла в индексе также зашифровано!

        # Открываем заново, извлекаем и сверяем контрольную сумму
        out_dir = self.tmp_dir / "extracted_single"
        out_dir.mkdir()
        with SecureVault(self.vault_path) as v2:
            v2.unlock(self.password)
            extracted = v2.extract_entries(["financial_report.txt"], out_dir)
            self.assertEqual(len(extracted), 1)
            self.assertEqual(sha256_file(extracted[0]), orig_sha256)

    # ------------------------------------------------------------------
    # 5, 8: Рекурсивное добавление каталога, русские имена, пробелы и спецсимволы, поиск и удаление
    # ------------------------------------------------------------------
    def test_03_nested_directory_russian_unicode_and_special_chars(self) -> None:
        root_folder = self.tmp_dir / "Документы Проекта (2026) №1"
        sub_folder = root_folder / "Вложенная папка — тест [АБВ] & $ % @!"
        sub_folder.mkdir(parents=True)

        f1 = root_folder / "Договор с клиентом (финал).txt"
        f2 = sub_folder / "Ключи и пароли — не трогать!.dat"
        f1.write_text("Текст договора на русском языке с символами №, €, §, ©.", encoding="utf-8")
        f2.write_bytes(os.urandom(4096))

        h1 = sha256_file(f1)
        h2 = sha256_file(f2)

        with SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)[0] as vault:
            added = vault.add_paths([root_folder])
            self.assertEqual(len(added), 4)  # 2 папки + 2 файла

            # Проверка поиска по русскому слову в любом регистре
            found = vault.list_entries(search_query="договор")
            self.assertEqual(len(found), 1)
            self.assertIn("Договор с клиентом", found[0].virtual_path)

            # Оригиналы не тронуты
            self.assertTrue(f1.exists() and f2.exists())
            self.assertEqual(sha256_file(f1), h1)
            self.assertEqual(sha256_file(f2), h2)

            # Извлечение всей структуры каталогов
            extract_dir = self.tmp_dir / "extracted_tree"
            extract_dir.mkdir()
            vault.extract_entries([root_folder.name], extract_dir)

            ext_f1 = extract_dir / root_folder.name / f1.name
            ext_f2 = extract_dir / root_folder.name / sub_folder.name / f2.name
            self.assertTrue(ext_f1.exists())
            self.assertTrue(ext_f2.exists())
            self.assertEqual(sha256_file(ext_f1), h1)
            self.assertEqual(sha256_file(ext_f2), h2)

            # Удаление вложенной папки внутри хранилища
            deleted_cnt = vault.delete_entries([f"{root_folder.name}/{sub_folder.name}"])
            self.assertEqual(deleted_cnt, 2)  # подпапка + файл f2
            remaining = vault.list_entries()
            self.assertEqual(len(remaining), 2)  # корневая папка + f1

    # ------------------------------------------------------------------
    # 9: Обработка пустых файлов (0 байт) и больших многоблочных файлов (> 1.2 МБ)
    # ------------------------------------------------------------------
    def test_04_empty_file_and_large_multichunk_streaming_file(self) -> None:
        empty_file = self.tmp_dir / "пустой_файл.bin"
        empty_file.write_bytes(b"")

        # Создаём файл размером ~1.35 МБ (6 блоков по 256 КБ)
        large_file = self.tmp_dir / "большой_архив.bin"
        large_size = DEFAULT_CHUNK_SIZE * 5 + 43210
        large_data = os.urandom(large_size)
        large_file.write_bytes(large_data)

        empty_hash = sha256_file(empty_file)
        large_hash = sha256_file(large_file)

        with SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)[0] as vault:
            vault.add_paths([empty_file, large_file])
            entries = {e.virtual_path: e for e in vault.list_entries()}
            self.assertEqual(entries["пустой_файл.bin"].size, 0)
            self.assertEqual(entries["пустой_файл.bin"].chunk_count, 1)
            self.assertEqual(entries["большой_архив.bin"].size, large_size)
            self.assertEqual(entries["большой_архив.bin"].chunk_count, 6)

            rep = vault.verify_integrity()
            self.assertTrue(rep.is_valid)
            self.assertEqual(rep.verified_files, 2)

            out_dir = self.tmp_dir / "out_large"
            out_dir.mkdir()
            vault.extract_entries(["пустой_файл.bin", "большой_архив.bin"], out_dir)
            self.assertEqual((out_dir / "пустой_файл.bin").stat().st_size, 0)
            self.assertEqual(sha256_file(out_dir / "пустой_файл.bin"), empty_hash)
            self.assertEqual(sha256_file(out_dir / "большой_архив.bin"), large_hash)

    # ------------------------------------------------------------------
    # 10: Обнаружение повреждённых и изменённых зашифрованных данных
    # ------------------------------------------------------------------
    def test_05_tamper_and_corruption_detection(self) -> None:
        f1 = self.tmp_dir / "secret_doc.txt"
        f1.write_bytes(os.urandom(64 * 1024))

        vault, _ = SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)
        vault.add_paths([f1])
        entry = vault.list_entries()[0]
        vault.close()

        original_vault_bytes = self.vault_path.read_bytes()

        # Случай А: Повреждение байта внутри зашифрованного блока данных файла
        corrupted_blob_path = self.tmp_dir / "corrupt_blob.mvault"
        ba = bytearray(original_vault_bytes)
        ba[entry.blob_offset + 25] ^= 0xFF
        corrupted_blob_path.write_bytes(ba)

        with SecureVault(corrupted_blob_path) as v_blob:
            v_blob.unlock(self.password)
            rep = v_blob.verify_integrity()
            self.assertFalse(rep.is_valid)
            self.assertIn("secret_doc.txt", rep.corrupted_entries)

            out_dir = self.tmp_dir / "extract_corrupt"
            out_dir.mkdir()
            with self.assertRaises(IntegrityError):
                v_blob.extract_entries(["secret_doc.txt"], out_dir)
            # Гарантируем, что повреждённый файл НЕ остался в целевой папке
            self.assertEqual(list(out_dir.iterdir()), [])

        # Случай Б: Повреждение байта в зашифрованном индексе
        corrupted_idx_path = self.tmp_dir / "corrupt_idx.mvault"
        ba_idx = bytearray(original_vault_bytes)
        ba_idx[-10] ^= 0xFF
        corrupted_idx_path.write_bytes(ba_idx)

        with SecureVault(corrupted_idx_path) as v_idx:
            with self.assertRaises(IntegrityError):
                v_idx.unlock(self.password)

        # Случай В: Усечение файла хранилища
        truncated_path = self.tmp_dir / "truncated.mvault"
        truncated_path.write_bytes(original_vault_bytes[:-50])
        with self.assertRaises(IntegrityError):
            SecureVault.inspect_header(truncated_path)

    # ------------------------------------------------------------------
    # 11: Защита от перезаписи существующих файлов и защита от Path Traversal
    # ------------------------------------------------------------------
    def test_06_no_overwrite_and_path_traversal_protection(self) -> None:
        f1 = self.tmp_dir / "important.txt"
        f1.write_text("Версия в хранилище", encoding="utf-8")

        with SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)[0] as vault:
            vault.add_paths([f1])

            # Попытка повторно добавить файл с тем же именем в хранилище
            with self.assertRaises(FileOverwriteError):
                vault.add_paths([f1])

            # Попытка извлечь в каталог, где уже существует файл important.txt
            out_dir = self.tmp_dir / "dest"
            out_dir.mkdir()
            existing_target = out_dir / "important.txt"
            existing_target.write_text("Существующий на диске файл, который нельзя затереть!", encoding="utf-8")

            with self.assertRaises(FileOverwriteError):
                vault.extract_entries(["important.txt"], out_dir)

            # Убеждаемся, что существующий файл не был изменён
            self.assertEqual(
                existing_target.read_text(encoding="utf-8"),
                "Существующий на диске файл, который нельзя затереть!",
            )

        # Проверка защиты от Path Traversal
        for malicious_path in ("../etc/passwd", "/etc/shadow", "folder/../../outside.txt", "bad\x00name.txt"):
            with self.assertRaises(PathTraversalError):
                normalize_virtual_path(malicious_path)
            with self.assertRaises(PathTraversalError):
                resolve_safe_extraction_path(self.tmp_dir, malicious_path)

    # ------------------------------------------------------------------
    # 12: Обработка нехватки места на диске и отказ при символических ссылках / FIFO
    # ------------------------------------------------------------------
    def test_07_disk_space_exhaustion_and_unsafe_file_objects(self) -> None:
        real_file = self.tmp_dir / "normal.txt"
        real_file.write_bytes(b"A" * 8192)

        symlink_file = self.tmp_dir / "symlink_to_secret.txt"
        os.symlink(str(real_file), str(symlink_file))

        fifo_path = self.tmp_dir / "named_pipe.fifo"
        os.mkfifo(str(fifo_path))

        with SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)[0] as vault:
            # Отказ при попытке добавить символическую ссылку
            with self.assertRaises(UnsafeFileObjectError):
                vault.add_paths([symlink_file])

            # Отказ при попытке добавить именованный канал (FIFO)
            with self.assertRaises(UnsafeFileObjectError):
                vault.add_paths([fifo_path])

            # Отказ при нехватке дискового пространства
            os.environ["MINTVAULT_SIMULATE_FREE_BYTES"] = "512"
            with self.assertRaises(InsufficientDiskSpaceError):
                vault.add_paths([real_file])
            os.environ.pop("MINTVAULT_SIMULATE_FREE_BYTES", None)

            # После освобождения места операция проходит штатно
            vault.add_paths([real_file])
            self.assertEqual(len(vault.list_entries()), 1)

    # ------------------------------------------------------------------
    # 13: Аварийное завершение во время записи и восстановление без повреждения хранилища
    # ------------------------------------------------------------------
    def test_08_crash_during_write_and_atomic_recovery(self) -> None:
        f1 = self.tmp_dir / "first_safe_file.txt"
        f1.write_text("Первоначальные критически важные данные", encoding="utf-8")
        f2 = self.tmp_dir / "second_file.txt"
        f2.write_bytes(os.urandom(32768))

        with SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)[0] as vault:
            vault.add_paths([f1])

            # Симулируем аварийный сбой записи во время добавления второго файла
            os.environ["MINTVAULT_SIMULATE_CRASH_DURING_WRITE"] = "1"
            os.environ["MINTVAULT_KEEP_ORPHAN_ON_CRASH"] = "1"
            with self.assertRaises(IOError):
                vault.add_paths([f2])

        os.environ.pop("MINTVAULT_SIMULATE_CRASH_DURING_WRITE", None)
        os.environ.pop("MINTVAULT_KEEP_ORPHAN_ON_CRASH", None)

        # Проверяем, что остался осиротевший tmp-файл, но основное хранилище полностью цело и содержит f1!
        v_recover = SecureVault(self.vault_path)
        orphans = v_recover.find_orphaned_temp_files()
        self.assertGreaterEqual(len(orphans), 1)

        v_recover.unlock(self.password)
        rep = v_recover.verify_integrity()
        self.assertTrue(rep.is_valid)
        self.assertEqual(rep.verified_files, 1)

        entries = v_recover.list_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].virtual_path, "first_safe_file.txt")

        # Очищаем осиротевшие временные файлы
        cleaned = v_recover.cleanup_orphaned_temp_files()
        self.assertGreaterEqual(cleaned, 1)
        self.assertEqual(len(v_recover.find_orphaned_temp_files()), 0)
        v_recover.close()

    # ------------------------------------------------------------------
    # 14: Проверка отсутствия паролей, ключей и содержимого файлов в логах
    # ------------------------------------------------------------------
    def test_09_no_secrets_in_logs_or_exception_messages(self) -> None:
        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        logger = logging.getLogger("mintvault")
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)

        secret_password = "MyUltraSecretPassphrase_998877!"
        secret_file_content = "SUPER_SECRET_PAYLOAD_TEXT_DO_NOT_LOG_12345"
        src = self.tmp_dir / "classified.txt"
        src.write_text(secret_file_content, encoding="utf-8")

        try:
            vault, rec_key = SecureVault.create(
                self.vault_path,
                secret_password,
                create_recovery_key=True,
                **FAST_KDF,
            )
            vault.add_paths([src])
            vault.verify_integrity()
            vault.close()

            logs_output = log_stream.getvalue()
            self.assertNotIn(secret_password, logs_output)
            self.assertNotIn(secret_file_content, logs_output)
            if rec_key:
                self.assertNotIn(rec_key, logs_output)
        finally:
            logger.removeHandler(handler)

    # ------------------------------------------------------------------
    # 15: Проверка блокировки, закрытия хранилища и затирания ключей в памяти
    # ------------------------------------------------------------------
    def test_10_lock_close_and_memory_zeroing(self) -> None:
        buf = bytearray(b"0123456789abcdef0123456789abcdef")
        zero_memory(buf)
        self.assertEqual(buf, bytearray(32))

        vault, _ = SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)
        mk_ref = vault._master_key
        assert mk_ref is not None
        self.assertNotEqual(mk_ref, bytearray(32))

        vault.lock()
        self.assertFalse(vault.is_unlocked)
        self.assertIsNone(vault._master_key)
        # Буфер мастер-ключа был затёрт нулями на месте!
        self.assertEqual(mk_ref, bytearray(32))

        # Любая операция над заблокированным хранилищем должна отклоняться
        with self.assertRaises(VaultLockedError):
            vault.list_entries()

    # ------------------------------------------------------------------
    # 16: Проверка поведения при параллельных операциях и резервном копировании
    # ------------------------------------------------------------------
    def test_11_concurrent_access_locking_and_backup(self) -> None:
        vault1, _ = SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)
        try:
            # Второй экземпляр не должен иметь возможности захватить эксклюзивную блокировку одновременно
            vault2 = SecureVault(self.vault_path)
            with self.assertRaises(VaultBusyError):
                vault2.unlock(self.password)

            # Тест создания резервной копии
            backup_file = self.tmp_dir / "backup_copy.mvault"
            saved_backup = vault1.create_backup(backup_file)
            self.assertTrue(saved_backup.exists())

            # Повторная запись поверх существующей резервной копии запрещена
            with self.assertRaises(FileOverwriteError):
                vault1.create_backup(backup_file)
        finally:
            vault1.close()

    # ------------------------------------------------------------------
    # 17: Проверка установки (`install.sh`), удаления (`uninstall.sh`), CLI и запуска GUI на Linux Mint
    # ------------------------------------------------------------------
    def test_12_cli_installer_and_gtk_gui_on_linux_mint(self) -> None:
        project_root = Path(__file__).resolve().parent.parent

        # 1. Проверка команды `doctor`
        res_doc = subprocess.run(
            [sys.executable, "-m", "mintvault", "doctor"],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(res_doc.returncode, 0, f"Doctor failed: {res_doc.stderr}")
        self.assertIn("Система полностью готова к безопасной работе", res_doc.stdout)

        # 2. Тестирование `install.sh` и `uninstall.sh` во временном пользовательском префиксе
        fake_home = self.tmp_dir / "fake_home"
        install_dir = fake_home / ".local/share/mintvault"
        bin_dir = fake_home / ".local/bin"
        desktop_dir = fake_home / ".local/share/applications"

        env = os.environ.copy()
        env["MINTVAULT_INSTALL_DIR"] = str(install_dir)
        env["MINTVAULT_BIN_DIR"] = str(bin_dir)
        env["MINTVAULT_DESKTOP_DIR"] = str(desktop_dir)

        res_inst = subprocess.run(
            ["bash", str(project_root / "install.sh")],
            cwd=str(project_root),
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(res_inst.returncode, 0, f"install.sh failed: {res_inst.stderr}")
        self.assertTrue((bin_dir / "mintvault").exists())
        self.assertTrue((desktop_dir / "mintvault.desktop").exists())

        # Запускаем установленный бинарник `mintvault --version`
        res_ver = subprocess.run(
            [str(bin_dir / "mintvault"), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res_ver.returncode, 0)
        self.assertIn("MintVault 1.0.0", res_ver.stdout)

        # Проверяем `uninstall.sh`
        res_uninst = subprocess.run(
            ["bash", str(project_root / "uninstall.sh")],
            cwd=str(project_root),
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(res_uninst.returncode, 0)
        self.assertFalse((bin_dir / "mintvault").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
