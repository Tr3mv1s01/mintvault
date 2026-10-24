"""
Расширенный набор тестов безопасности, сохранности данных, обратной совместимости,
пользовательских настроек и локализации GTK 3 для MintVault (`test_security_and_settings.py`).
"""

import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from mintvault.crypto import (
    AES_GCM_NONCE_SIZE,
    AES_GCM_TAG_SIZE,
    CHUNK_FLAG_NORMAL,
    DEFAULT_CHUNK_SIZE,
    MAX_CHUNK_SIZE,
    KDFParams,
    derive_kek,
    encrypt_index_bytes,
    validate_kdf_params,
)
from mintvault.exceptions import (
    AuthenticationError,
    FileOverwriteError,
    IntegrityError,
    PathTraversalError,
    UnsafeFileObjectError,
    VaultFormatError,
)
from mintvault.fs_utils import normalize_virtual_path, open_safe_regular_file_for_read
from mintvault.i18n import TRANSLATIONS, format_size_localized
from mintvault.settings import AppSettings, SettingsManager
from mintvault.vault import (
    FIXED_PREAMBLE_FMT,
    FIXED_PREAMBLE_SIZE,
    FORMAT_VERSION,
    MAGIC_BYTES,
    SecureVault,
)

FAST_KDF = {"kdf_time_cost": 1, "kdf_memory_kib": 8192, "kdf_parallelism": 1}


class TestCryptoAndContainerSecurity(unittest.TestCase):
    """Тестирование криптографии, граничных значений KDF и защиты формата контейнера .mvault."""

    def setUp(self) -> None:
        self.temp_dir_obj = tempfile.TemporaryDirectory(prefix="mv_sec_crypto_")
        self.tmp_dir = Path(self.temp_dir_obj.name)
        self.vault_path = self.tmp_dir / "test.mvault"
        self.password = "StrongPass#2026!"

    def tearDown(self) -> None:
        self.temp_dir_obj.cleanup()

    def test_kdf_bounds_validation_prevents_dos_and_overflow(self) -> None:
        valid_salt = "aa" * 16
        for bad_time in (0, -1, 65, 100000, True):
            params = KDFParams(
                algorithm="argon2id",
                time_cost=bad_time,  # type: ignore[arg-type]
                memory_cost_kib=8192,
                parallelism=1,
                salt_hex=valid_salt,
            )
            with self.assertRaises(IntegrityError):
                validate_kdf_params(params)
            with self.assertRaises(IntegrityError):
                derive_kek(b"password", params)

        for bad_mem in (0, -1024, 1024, 4096, 2 * 1024 * 1024, 0xFFFFFFFF):
            params = KDFParams(
                algorithm="argon2id",
                time_cost=1,
                memory_cost_kib=bad_mem,
                parallelism=1,
                salt_hex=valid_salt,
            )
            with self.assertRaises(IntegrityError):
                validate_kdf_params(params)

        for bad_par in (0, -2, 17, 1024):
            params = KDFParams(
                algorithm="scrypt",
                time_cost=1,
                memory_cost_kib=8192,
                parallelism=bad_par,
                salt_hex=valid_salt,
            )
            with self.assertRaises(IntegrityError):
                validate_kdf_params(params)

        for bad_salt in ("", "abcd", "aa" * 15, "aa" * 65, "zz" * 16):
            params = KDFParams(
                algorithm="argon2id",
                time_cost=1,
                memory_cost_kib=8192,
                parallelism=1,
                salt_hex=bad_salt,
            )
            with self.assertRaises(IntegrityError):
                validate_kdf_params(params)

    def test_header_critical_fields_tampering_and_unknown_versions(self) -> None:
        vault, _ = SecureVault.create(self.vault_path, self.password, create_recovery_key=True, **FAST_KDF)
        vault.close()
        raw_bytes = self.vault_path.read_bytes()
        magic, ver, hdr_len, idx_off, idx_len = struct.unpack(
            FIXED_PREAMBLE_FMT, raw_bytes[:FIXED_PREAMBLE_SIZE]
        )
        hdr_dict = json.loads(raw_bytes[FIXED_PREAMBLE_SIZE : FIXED_PREAMBLE_SIZE + hdr_len].decode("utf-8"))
        tail_bytes = raw_bytes[FIXED_PREAMBLE_SIZE + hdr_len :]

        bad_ver_path = self.tmp_dir / "bad_ver.mvault"
        bad_preamble = struct.pack(FIXED_PREAMBLE_FMT, MAGIC_BYTES, 99, hdr_len, idx_off, idx_len)
        bad_ver_path.write_bytes(bad_preamble + raw_bytes[FIXED_PREAMBLE_SIZE:])
        with self.assertRaises(VaultFormatError):
            SecureVault.inspect_header(bad_ver_path)

        bad_magic_path = self.tmp_dir / "bad_magic.mvault"
        bad_magic_path.write_bytes(b"NOTVAULT" + raw_bytes[8:])
        with self.assertRaises(VaultFormatError):
            SecureVault.inspect_header(bad_magic_path)

        def _write_modified_header(mod_hdr: dict, name: str) -> Path:
            new_hdr_bytes = json.dumps(mod_hdr).encode("utf-8")
            diff = len(new_hdr_bytes) - hdr_len
            p = self.tmp_dir / name
            pre = struct.pack(
                FIXED_PREAMBLE_FMT,
                MAGIC_BYTES,
                FORMAT_VERSION,
                len(new_hdr_bytes),
                idx_off + diff,
                idx_len,
            )
            p.write_bytes(pre + new_hdr_bytes + tail_bytes)
            return p

        h_ver = dict(hdr_dict, format_version=2)
        with self.assertRaises(VaultFormatError):
            SecureVault.inspect_header(_write_modified_header(h_ver, "hdr_ver2.mvault"))

        h_cip = dict(hdr_dict, cipher="AES-128-CBC")
        with self.assertRaises(VaultFormatError):
            SecureVault.inspect_header(_write_modified_header(h_cip, "hdr_cip.mvault"))

        h_slots = dict(hdr_dict, key_slots=hdr_dict["key_slots"] * 5)
        with self.assertRaises(VaultFormatError):
            SecureVault.inspect_header(_write_modified_header(h_slots, "hdr_slots.mvault"))

        bad_slot = dict(hdr_dict["key_slots"][0])
        bad_slot["kdf"] = dict(bad_slot["kdf"], memory_cost_kib=99999999)
        h_kdf = dict(hdr_dict, key_slots=[bad_slot])
        with self.assertRaises(IntegrityError):
            SecureVault.inspect_header(_write_modified_header(h_kdf, "hdr_kdf_dos.mvault"))

        h_tamper = dict(hdr_dict, created_at=hdr_dict["created_at"] + 100.0)
        tamper_path = _write_modified_header(h_tamper, "hdr_tamper_mac.mvault")
        v_tamper = SecureVault(tamper_path)
        with self.assertRaises(IntegrityError):
            v_tamper.unlock(self.password)

        trailing_path = self.tmp_dir / "trailing.mvault"
        trailing_path.write_bytes(raw_bytes + b"EXTRA_JUNK")
        with self.assertRaises(IntegrityError):
            SecureVault.inspect_header(trailing_path)

    def test_chunk_reordering_truncation_and_oversized_chunk_dos(self) -> None:
        src = self.tmp_dir / "multichunk.bin"
        chunk0_plain = b"A" * DEFAULT_CHUNK_SIZE
        chunk1_plain = b"B" * DEFAULT_CHUNK_SIZE
        chunk2_plain = b"C" * 12345
        src.write_bytes(chunk0_plain + chunk1_plain + chunk2_plain)

        vault, _ = SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)
        added = vault.add_paths([src])
        entry = added[0]
        self.assertEqual(entry.chunk_count, 3)
        vault.close()

        raw = bytearray(self.vault_path.read_bytes())
        rec_size_0 = 5 + AES_GCM_NONCE_SIZE + DEFAULT_CHUNK_SIZE + AES_GCM_TAG_SIZE
        rec_size_1 = rec_size_0
        off0 = entry.blob_offset
        off1 = off0 + rec_size_0
        off2 = off1 + rec_size_1

        swapped = bytearray(raw)
        swapped[off0:off1], swapped[off1:off2] = raw[off1:off2], raw[off0:off1]
        swapped_path = self.tmp_dir / "swapped_chunks.mvault"
        swapped_path.write_bytes(swapped)

        with SecureVault(swapped_path) as v_swap:
            v_swap.unlock(self.password)
            rep = v_swap.verify_integrity()
            self.assertFalse(rep.is_valid)
            out_dir = self.tmp_dir / "out_swap"
            out_dir.mkdir()
            with self.assertRaises(IntegrityError):
                v_swap.extract_entries(["multichunk.bin"], out_dir)
            self.assertEqual(list(out_dir.iterdir()), [])

        oversized = bytearray(raw)
        struct.pack_into(">IB", oversized, off0, MAX_CHUNK_SIZE + 1024, CHUNK_FLAG_NORMAL)
        oversized_path = self.tmp_dir / "oversized_chunk.mvault"
        oversized_path.write_bytes(oversized)

        with SecureVault(oversized_path) as v_over:
            v_over.unlock(self.password)
            rep = v_over.verify_integrity()
            self.assertFalse(rep.is_valid)

    def test_index_tampering_slack_injection_and_duplicate_entries(self) -> None:
        f1 = self.tmp_dir / "doc.txt"
        f1.write_text("Secret text", encoding="utf-8")

        vault, _ = SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)
        vault.add_paths([f1])
        mk = bytearray(vault._master_key)  # type: ignore[arg-type]
        vault_uuid = vault.vault_uuid
        entry_dict = vault.list_entries()[0].to_dict()
        vault.close()

        raw = self.vault_path.read_bytes()
        _, _, hdr_len, idx_off, idx_len = struct.unpack(FIXED_PREAMBLE_FMT, raw[:FIXED_PREAMBLE_SIZE])
        hdr_and_blobs = raw[FIXED_PREAMBLE_SIZE:idx_off]

        def _build_vault_with_custom_index(idx_payload: dict, extra_gap: bytes = b"") -> Path:
            plain_idx = json.dumps(idx_payload).encode("utf-8")
            enc_idx = encrypt_index_bytes(mk, plain_idx, vault_uuid)
            new_idx_off = FIXED_PREAMBLE_SIZE + len(hdr_and_blobs) + len(extra_gap)
            pre = struct.pack(
                FIXED_PREAMBLE_FMT,
                MAGIC_BYTES,
                FORMAT_VERSION,
                hdr_len,
                new_idx_off,
                len(enc_idx),
            )
            p = self.tmp_dir / f"custom_idx_{time.time_ns()}.mvault"
            p.write_bytes(pre + hdr_and_blobs + extra_gap + enc_idx)
            return p

        valid_idx_payload = {
            "format_version": FORMAT_VERSION,
            "vault_uuid": vault_uuid,
            "updated_at": time.time(),
            "entries": [entry_dict],
        }
        slack_vault = _build_vault_with_custom_index(valid_idx_payload, extra_gap=b"UNAUTHENTICATED_SLACK_DATA")
        with self.assertRaises(IntegrityError):
            SecureVault(slack_vault).unlock(self.password)

        dup_entry = dict(entry_dict, virtual_path="doc_copy.txt")
        dup_id_payload = {
            "format_version": FORMAT_VERSION,
            "vault_uuid": vault_uuid,
            "updated_at": time.time(),
            "entries": [entry_dict, dup_entry],
        }
        with self.assertRaises(IntegrityError):
            SecureVault(_build_vault_with_custom_index(dup_id_payload)).unlock(self.password)

        bad_sha_entry = dict(entry_dict, sha256="00" * 32)
        bad_sha_payload = {
            "format_version": FORMAT_VERSION,
            "vault_uuid": vault_uuid,
            "updated_at": time.time(),
            "entries": [bad_sha_entry],
        }
        bad_sha_vault_path = _build_vault_with_custom_index(bad_sha_payload)
        with SecureVault(bad_sha_vault_path) as v_sha:
            v_sha.unlock(self.password)
            rep = v_sha.verify_integrity()
            self.assertFalse(rep.is_valid)
            out_dir = self.tmp_dir / "out_bad_sha"
            out_dir.mkdir()
            with self.assertRaises(IntegrityError):
                v_sha.extract_entries(["doc.txt"], out_dir)
            self.assertEqual(list(out_dir.iterdir()), [])

        trav_entry = dict(entry_dict, virtual_path="../../outside.txt")
        trav_payload = {
            "format_version": FORMAT_VERSION,
            "vault_uuid": vault_uuid,
            "updated_at": time.time(),
            "entries": [trav_entry],
        }
        with self.assertRaises(PathTraversalError):
            SecureVault(_build_vault_with_custom_index(trav_payload)).unlock(self.password)

    def test_backward_compatibility_with_v1_0_0_legacy_container(self) -> None:
        backup_root = Path("/working_dir/c_2f888132a4971db6/backup_orig/mintvault")
        if not backup_root.exists():
            self.skipTest("Исходная резервная копия для теста совместимости отсутствует.")

        legacy_vault_path = self.tmp_dir / "legacy_v1.mvault"
        legacy_src = self.tmp_dir / "legacy_note.txt"
        legacy_src.write_text("Данные из старого контейнера v1.0.0", encoding="utf-8")

        script = (
            "import sys\n"
            f"sys.path.insert(0, {str(backup_root)!r})\n"
            "from mintvault.vault import SecureVault\n"
            f"v, rec = SecureVault.create({str(legacy_vault_path)!r}, {self.password!r}, "
            "create_recovery_key=True, kdf_time_cost=1, kdf_memory_kib=8192, kdf_parallelism=1)\n"
            f"v.add_paths([{str(legacy_src)!r}])\n"
            "v.close()\n"
            "print(rec)\n"
        )
        res = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=20)
        self.assertEqual(res.returncode, 0, res.stderr)
        rec_key = res.stdout.strip()

        with SecureVault(legacy_vault_path) as v_new:
            v_new.unlock(self.password)
            rep = v_new.verify_integrity()
            self.assertTrue(rep.is_valid, f"Ошибки совместимости: {rep.errors}")
            out_dir = self.tmp_dir / "legacy_out"
            out_dir.mkdir()
            extracted = v_new.extract_entries(["legacy_note.txt"], out_dir)
            self.assertEqual(extracted[0].read_text(encoding="utf-8"), "Данные из старого контейнера v1.0.0")

        with SecureVault(legacy_vault_path) as v_rec:
            v_rec.unlock(rec_key, use_recovery_key=True)
            self.assertEqual(len(v_rec.list_entries()), 1)


class TestFilesystemAndDataPreservation(unittest.TestCase):
    """Тестирование файловой безопасности, TOCTOU-защиты и транзакционной сохранности данных."""

    def setUp(self) -> None:
        self.temp_dir_obj = tempfile.TemporaryDirectory(prefix="mv_sec_fs_")
        self.tmp_dir = Path(self.temp_dir_obj.name)
        self.vault_path = self.tmp_dir / "fs_test.mvault"
        self.password = "FsSafePass#2026"

    def tearDown(self) -> None:
        os.environ.pop("MINTVAULT_SIMULATE_CRASH_DURING_WRITE", None)
        self.temp_dir_obj.cleanup()

    def test_in_memory_state_preserved_after_failed_transaction(self) -> None:
        f1 = self.tmp_dir / "initial.txt"
        f1.write_text("Первоначальный файл", encoding="utf-8")
        f2 = self.tmp_dir / "aaa_before_initial.txt"
        f2.write_bytes(b"X" * 50000)

        with SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)[0] as vault:
            vault.add_paths([f1])
            orig_entry = vault.list_entries()[0]

            os.environ["MINTVAULT_SIMULATE_CRASH_DURING_WRITE"] = "1"
            with self.assertRaises(IOError):
                vault.add_paths([f2])
            os.environ.pop("MINTVAULT_SIMULATE_CRASH_DURING_WRITE", None)

            entries_after_fail = vault.list_entries()
            self.assertEqual(len(entries_after_fail), 1)
            self.assertEqual(entries_after_fail[0].blob_offset, orig_entry.blob_offset)

            out_dir = self.tmp_dir / "out_after_fail"
            out_dir.mkdir()
            extracted = vault.extract_entries(["initial.txt"], out_dir)
            self.assertEqual(extracted[0].read_text(encoding="utf-8"), "Первоначальный файл")

    def test_path_validation_backslashes_control_chars_and_long_names(self) -> None:
        for bad in (
            "..\\evil.txt",
            "folder\\..\\evil.txt",
            "line\nbreak.txt",
            "carriage\rreturn.txt",
            "a" * 256 + ".txt",
        ):
            with self.assertRaises(PathTraversalError):
                normalize_virtual_path(bad)

    def test_toctou_source_file_replacement_rejected(self) -> None:
        f_real = self.tmp_dir / "real.txt"
        f_real.write_text("Original content", encoding="utf-8")
        st_initial = os.lstat(str(f_real))

        f_other = self.tmp_dir / "other.txt"
        f_other.write_text("Modified content!", encoding="utf-8")
        os.replace(str(f_other), str(f_real))

        with self.assertRaises(UnsafeFileObjectError):
            open_safe_regular_file_for_read(f_real, expected_stat=st_initial)

    def test_extraction_collision_and_intermediate_symlink_blocked(self) -> None:
        d1 = self.tmp_dir / "dir1"
        d2 = self.tmp_dir / "dir2"
        d1.mkdir()
        d2.mkdir()
        (d1 / "same.txt").write_text("One", encoding="utf-8")
        (d2 / "same.txt").write_text("Two", encoding="utf-8")

        with SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)[0] as vault:
            vault.add_paths([d1, d2])

            out_dir = self.tmp_dir / "extract_flat"
            out_dir.mkdir()
            with self.assertRaises(FileOverwriteError):
                vault.extract_entries(["dir1/same.txt", "dir2/same.txt"], out_dir, preserve_structure=False)
            self.assertEqual(list(out_dir.iterdir()), [])

            out_sym = self.tmp_dir / "extract_sym"
            out_sym.mkdir()
            outside_dir = self.tmp_dir / "outside_target"
            outside_dir.mkdir()
            os.symlink(str(outside_dir), str(out_sym / "dir1"))

            with self.assertRaises(PathTraversalError):
                vault.extract_entries(["dir1/same.txt"], out_sym, preserve_structure=True)
            self.assertEqual(list(outside_dir.iterdir()), [])

    def test_active_process_temp_file_not_deleted_by_orphan_cleanup(self) -> None:
        vault, _ = SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)
        vault.close()

        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
        try:
            active_tmp = self.vault_path.parent / f".{self.vault_path.name}.tmp.{proc.pid}.abcd1234"
            dead_tmp = self.vault_path.parent / f".{self.vault_path.name}.tmp.999999.deadbeef"
            active_tmp.write_bytes(b"active transaction")
            dead_tmp.write_bytes(b"dead transaction")

            v = SecureVault(self.vault_path)
            orphans = v.find_orphaned_temp_files()
            self.assertIn(dead_tmp, orphans)
            self.assertNotIn(active_tmp, orphans)

            v.cleanup_orphaned_temp_files()
            self.assertFalse(dead_tmp.exists())
            self.assertTrue(active_tmp.exists(), "Активный временный файл живого процесса не должен удаляться!")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


class TestSettingsOriginalsAndGuiLocalization(unittest.TestCase):
    """Тестирование системы настроек, безопасного удаления оригиналов и локализации GTK 3."""

    def setUp(self) -> None:
        self.temp_dir_obj = tempfile.TemporaryDirectory(prefix="mv_sec_cfg_")
        self.tmp_dir = Path(self.temp_dir_obj.name)
        self.cfg_dir = self.tmp_dir / "xdg_config" / "mintvault"
        self.vault_path = self.tmp_dir / "vault.mvault"
        self.password = "CfgPass#2026"

    def tearDown(self) -> None:
        self.temp_dir_obj.cleanup()

    def test_settings_creation_persistence_validation_and_corruption_recovery(self) -> None:
        mgr = SettingsManager(config_dir=self.cfg_dir)
        s = mgr.load()

        self.assertEqual(s.theme, "system")
        self.assertEqual(s.language, "ru")
        self.assertTrue(s.ask_before_deleting_originals)
        self.assertFalse(s.offer_delete_originals_after_add)
        self.assertEqual(s.auto_lock_minutes, 0)
        self.assertTrue(mgr.config_file.exists())

        file_mode = stat.S_IMODE(os.lstat(str(mgr.config_file)).st_mode)
        dir_mode = stat.S_IMODE(os.lstat(str(self.cfg_dir)).st_mode)
        self.assertEqual(file_mode, 0o600)
        self.assertEqual(dir_mode, 0o700)

        s.theme = "dark"
        s.language = "en"
        s.ui_font_scale = 115
        s.offer_delete_originals_after_add = True
        s.auto_lock_minutes = 15
        mgr.save(s)

        mgr2 = SettingsManager(config_dir=self.cfg_dir)
        s2 = mgr2.load()
        self.assertEqual(s2.theme, "dark")
        self.assertEqual(s2.language, "en")
        self.assertEqual(s2.ui_font_scale, 115)
        self.assertTrue(s2.offer_delete_originals_after_add)
        self.assertEqual(s2.auto_lock_minutes, 15)

        raw_with_secrets = {
            "theme": "invalid_theme",
            "language": "fr",
            "ui_font_scale": 999,
            "auto_lock_minutes": -10,
            "password": "LEAKED_PASSWORD",
            "master_key": "00112233",
            "recovery_key": "AAAA-BBBB",
        }
        mgr.config_file.write_text(json.dumps(raw_with_secrets), encoding="utf-8")
        mgr3 = SettingsManager(config_dir=self.cfg_dir)
        s3 = mgr3.load()
        self.assertEqual(s3.theme, "system")
        self.assertEqual(s3.language, "ru")
        self.assertEqual(s3.ui_font_scale, 100)
        self.assertEqual(s3.auto_lock_minutes, 0)
        saved_text = mgr.config_file.read_text(encoding="utf-8")
        self.assertNotIn("LEAKED_PASSWORD", saved_text)
        self.assertNotIn("master_key", saved_text)
        self.assertNotIn("recovery_key", saved_text)

        mgr.config_file.write_text("{corrupted_json: [1, 2", encoding="utf-8")
        mgr4 = SettingsManager(config_dir=self.cfg_dir)
        s4 = mgr4.load()
        self.assertEqual(s4, AppSettings())
        backups = list(self.cfg_dir.glob("settings.json.corrupt.*.bak"))
        self.assertGreaterEqual(len(backups), 1)

    def test_safe_delete_verified_originals_security_guarantees(self) -> None:
        folder = self.tmp_dir / "work_docs"
        folder.mkdir()
        f_selected = folder / "selected.txt"
        f_unselected = folder / "keep_me.txt"
        f_selected.write_text("Selected confidential data", encoding="utf-8")
        f_unselected.write_text("Unselected file in same folder", encoding="utf-8")

        with SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)[0] as vault:
            added = vault.add_paths([f_selected])
            self.assertTrue(f_selected.exists())

            with self.assertRaises(PermissionError):
                vault.safe_delete_verified_originals([f_selected], added, user_confirmed=False)
            self.assertTrue(f_selected.exists())

            orig_vault_bytes = self.vault_path.read_bytes()
            corrupted = bytearray(orig_vault_bytes)
            corrupted[added[0].blob_offset + 22] ^= 0xFF
            self.vault_path.write_bytes(corrupted)

            with self.assertRaises(IntegrityError):
                vault.safe_delete_verified_originals([f_selected], added, user_confirmed=True)
            self.assertTrue(f_selected.exists(), "При ошибке проверки целостности оригинал обязан сохраниться!")

            self.vault_path.write_bytes(orig_vault_bytes)

            deleted_cnt, warnings = vault.safe_delete_verified_originals(
                [f_selected], added, user_confirmed=True
            )
            self.assertEqual(deleted_cnt, 1)
            self.assertEqual(warnings, [])
            self.assertFalse(f_selected.exists())
            self.assertTrue(f_unselected.exists())
            self.assertTrue(folder.exists())

    def test_safe_delete_originals_rejects_tampered_source_file(self) -> None:
        f_src = self.tmp_dir / "tampered_orig.txt"
        f_src.write_text("Version added to vault", encoding="utf-8")

        with SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)[0] as vault:
            added = vault.add_paths([f_src])
            f_src.write_text("New unsaved edits in original file!", encoding="utf-8")

            deleted_cnt, warnings = vault.safe_delete_verified_originals(
                [f_src], added, user_confirmed=True
            )
            self.assertEqual(deleted_cnt, 0)
            self.assertGreaterEqual(len(warnings), 1)
            self.assertTrue(f_src.exists(), "Изменённый после добавления исходный файл нельзя удалять!")

    def test_duplicate_file_conflict_policies_replace_keep_both_and_skip(self) -> None:
        f_doc = self.tmp_dir / "report.txt"
        f_doc.write_text("Версия 1", encoding="utf-8")

        with SecureVault.create(self.vault_path, self.password, create_recovery_key=False, **FAST_KDF)[0] as vault:
            vault.add_paths([f_doc])
            self.assertEqual(vault.find_conflicts([f_doc]), ["report.txt"])

            # 1. Режим skip (пропустить существующий)
            f_doc.write_text("Версия 2", encoding="utf-8")
            skipped_res = vault.add_paths([f_doc], on_conflict="skip")
            self.assertEqual(len(skipped_res), 0)
            self.assertEqual(len(vault.list_entries()), 1)

            # 2. Режим keep_both (оставить оба / сделать копию с номером)
            copied_res = vault.add_paths([f_doc], on_conflict="keep_both")
            self.assertEqual(len(copied_res), 1)
            self.assertEqual(copied_res[0].virtual_path, "report (1).txt")
            vps = [e.virtual_path for e in vault.list_entries()]
            self.assertEqual(vps, ["report (1).txt", "report.txt"])

            # 3. Режим replace (заменить существующий файл новой версией)
            f_doc.write_text("Версия 3 (обновлённая)", encoding="utf-8")
            replaced_res = vault.add_paths([f_doc], on_conflict="replace")
            self.assertEqual(len(replaced_res), 1)
            self.assertEqual(replaced_res[0].virtual_path, "report.txt")

            out_dir = self.tmp_dir / "out_dups"
            out_dir.mkdir()
            vault.extract_entries(["report.txt", "report (1).txt"], out_dir)
            self.assertEqual((out_dir / "report.txt").read_text(encoding="utf-8"), "Версия 3 (обновлённая)")
            self.assertEqual((out_dir / "report (1).txt").read_text(encoding="utf-8"), "Версия 2")
            self.assertTrue(vault.verify_integrity().is_valid)

    def test_translations_completeness_and_gtk_window_settings_apply(self) -> None:
        ru_keys = set(TRANSLATIONS["ru"].keys())
        en_keys = set(TRANSLATIONS["en"].keys())
        self.assertEqual(ru_keys, en_keys, f"Различие ключей перевода: {ru_keys ^ en_keys}")

        self.assertIn("Б", format_size_localized(100, "ru"))
        self.assertIn("B", format_size_localized(100, "en"))
        self.assertIn("КБ", format_size_localized(2048, "ru"))
        self.assertIn("KB", format_size_localized(2048, "en"))
        # Проверяем, что Gtk.ListStore принимает файлы > 2 ГБ (например, 2.5 ГБ и 62 ГБ) без OverflowError
        from gi.repository import GObject, Gtk
        store = Gtk.ListStore(str, str, str, str, str, str, GObject.TYPE_INT64)
        store.append(["win11.iso", "📄 Файл", "win11.iso", "2.3 ГБ", "24.10.2026", "abcd...", 2510861186])
        store.append(["huge_62gb.bin", "📄 Файл", "huge_62gb.bin", "62.0 ГБ", "24.10.2026", "ef01...", 62 * 1024 * 1024 * 1024])
        self.assertEqual(len(store), 2)


        from mintvault.gui import MintVaultWindow
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gdk

        if Gdk.Display.get_default() is None:
            xvfb = subprocess.run(["which", "xvfb-run"], capture_output=True, text=True)
            if xvfb.returncode != 0:
                return
            cmd = [
                "xvfb-run",
                "-a",
                sys.executable,
                "-c",
                (
                    "import tempfile\n"
                    "from pathlib import Path\n"
                    "from mintvault.settings import SettingsManager, AppSettings\n"
                    "from mintvault.gui import MintVaultWindow\n"
                    "from mintvault.vault import SecureVault\n"
                    "with tempfile.TemporaryDirectory() as d:\n"
                    "    mgr = SettingsManager(Path(d) / 'cfg')\n"
                    "    win = MintVaultWindow(settings_manager=mgr)\n"
                    "    assert 'Защищённое' in win.get_title()\n"
                    "    win.app_settings = mgr.save(AppSettings(theme='dark', language='en', ui_font_scale=120, auto_lock_minutes=1))\n"
                    "    win._apply_settings_to_ui()\n"
                    "    assert win.is_dark_theme is True\n"
                    "    assert 'Secure File Vault' in win.get_title()\n"
                    "    v, _ = SecureVault.create(Path(d) / 't.mvault', 'Pass1234', create_recovery_key=False, kdf_time_cost=1, kdf_memory_kib=8192, kdf_parallelism=1)\n"
                    "    win.vault = v\n"
                    "    win._last_activity_monotonic -= 120\n"
                    "    assert win._check_inactivity_auto_lock() is True\n"
                    "    assert not v.is_unlocked\n"
                ),
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            self.assertEqual(res.returncode, 0, f"GUI under xvfb failed: {res.stderr}")
            return

        mgr = SettingsManager(config_dir=self.cfg_dir)
        win = MintVaultWindow(settings_manager=mgr)
        try:
            self.assertIn("Защищённое", win.get_title())
            win.app_settings = mgr.save(
                AppSettings(theme="dark", language="en", ui_font_scale=120, auto_lock_minutes=1)
            )
            win._apply_settings_to_ui()
            self.assertTrue(win.is_dark_theme)
            self.assertIn("Secure File Vault", win.get_title())

            v, _ = SecureVault.create(
                self.vault_path, self.password, create_recovery_key=False, **FAST_KDF
            )
            win.vault = v
            win._update_lock_indicator()
            win.is_busy = True
            win._last_activity_monotonic -= 120
            self.assertFalse(win._check_inactivity_auto_lock())
            self.assertTrue(v.is_unlocked)

            win.is_busy = False
            win._last_activity_monotonic -= 120
            self.assertTrue(win._check_inactivity_auto_lock())
            self.assertFalse(v.is_unlocked)
        finally:
            if win.vault:
                win.vault.close()
            win.destroy()


if __name__ == "__main__":
    unittest.main(verbosity=2)
