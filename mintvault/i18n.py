"""
Централизованная система локализации графического интерфейса MintVault (`i18n.py`).
Поддерживает русский (`ru`) и английский (`en`) языки с переключением на лету без перезапуска.
"""

from datetime import datetime
from typing import Dict

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "ru": {
        "window_title": "{app_name} v{version} — Защищённое хранилище файлов",
        "header_subtitle": "<b>{app_name}</b> — Защита секретных файлов",
        "vault_not_selected": "Хранилище не выбрано",
        "status_locked": "🔒 ЗАБЛОКИРОВАНО",
        "status_unlocked": "🔓 РАЗБЛОКИРОВАНО",
        "btn_new_vault": "Создать хранилище",
        "tip_new_vault": "Создать новый зашифрованный контейнер (.mvault) (Ctrl+N)",
        "btn_open_vault": "Открыть хранилище",
        "tip_open_vault": "Выбрать существующий файл хранилища (.mvault) (Ctrl+O)",
        "btn_lock_vault": "Заблокировать",
        "tip_lock_vault": "Очистить ключи из памяти и заблокировать доступ (Ctrl+L)",
        "btn_settings": "⚙ Настройки",
        "tip_settings": "Открыть настройки внешнего вида, языка и безопасности",
        "btn_theme_dark": "🌙 Тёмная",
        "btn_theme_light": "☀️ Светлая",
        "tip_theme_toggle": "Быстрое переключение светлой и тёмной темы оформления",
        "status_ready": "Готово к работе. Все операции выполняются локально без подключения к сети.",
        "progress_running": "Выполнение...",
        "btn_cancel_op": "Отменить операцию",
        "status_cancel_requested": "Запрошена безопасная отмена операции, ожидайте...",
        "status_cancelled": "Операция безопасно отменена. Целостность хранилища сохранена.",
        "status_error_prefix": "Ошибка: {err}",
        "dlg_op_failed_title": "Не удалось выполнить операцию",
        "dlg_busy_title": "Операция уже выполняется",
        "dlg_busy_body": "Пожалуйста, дождитесь завершения текущей операции или отмените её.",
        # Экран приветствия
        "welcome_title": "<span size='x-large' weight='bold'>Добро пожаловать в MintVault</span>",
        "welcome_desc": (
            "Локальное защищённое хранилище для ваших конфиденциальных файлов и папок на Linux Mint.\n\n"
            "• <b>Современная криптография:</b> шифрование AES-256-GCM и формирование ключа Argon2id.\n"
            "• <b>Разделение операций:</b> добавление файлов в хранилище всегда создаёт зашифрованную копию — "
            "исходные файлы не удаляются автоматически.\n"
            "• <b>Защита от сбоев:</b> атомарная запись Copy-on-Write и встроенная проверка целостности.\n"
            "• <b>Полная автономность:</b> программа работает 100% локально без интернета и телеметрии."
        ),
        "welcome_btn_create": "➕ Создать новое хранилище (Ctrl+N)",
        "welcome_btn_open": "📂 Открыть существующее хранилище (Ctrl+O)",
        # Экран разблокировки
        "unlock_title": "<span size='large' weight='bold'>🔒 Разблокировка хранилища</span>",
        "unlock_file_info": "Файл: <b>{path}</b>\nРазмер контейнера: {size}",
        "orphan_warning_text": (
            "Обнаружены незавершённые временные файлы ({count} шт.) от прерванной ранее записи. "
            "Ваше основное хранилище не повреждено. Вы можете безопасно очистить временные файлы."
        ),
        "btn_clean_orphans": "Очистить временные файлы",
        "status_orphans_cleaned": "Удалено временных файлов прерванных операций: {count}",
        "chk_use_recovery": "Использовать аварийный ключ восстановления (если пароль утерян)",
        "lbl_enter_password": "Введите пароль хранилища:",
        "lbl_enter_recovery": "Введите 256-битный аварийный ключ восстановления:",
        "ph_password_or_rec": "Пароль...",
        "ph_recovery": "XXXX-XXXX-XXXX-...",
        "chk_show_secret": "Показать",
        "btn_unlock_submit": "🔓 Разблокировать хранилище",
        "btn_back": "Назад",
        "err_empty_secret": "<span foreground='#cf222e'>Пожалуйста, введите пароль или ключ восстановления.</span>",
        "status_vault_selected": "Выбрано хранилище {name}. Введите пароль для разблокировки.",
        "task_unlocking": "Проверка ключа (Argon2id) и расшифровка индекса хранилища...",
        "status_unlocked_ok": "Хранилище «{name}» успешно разблокировано.",
        "status_locked_ok": "Хранилище заблокировано, ключи удалены из оперативной памяти.",
        "status_auto_locked": "Хранилище автоматически заблокировано после периода бездействия ({minutes} мин.).",
        # Рабочая область
        "btn_add_files": "➕ Добавить файлы",
        "tip_add_files": "Зашифровать копию выбранных файлов в хранилище (оригиналы на диске сохраняются)",
        "btn_add_folder": "📁 Добавить папку",
        "tip_add_folder": "Рекурсивно зашифровать копию папки со всеми вложенными файлами (оригиналы сохраняются)",
        "btn_extract": "📤 Извлечь выбранное",
        "tip_extract": "Расшифровать и сохранить выбранные объекты (или всё хранилище) в указанную папку",
        "btn_delete": "🗑 Удалить из хранилища",
        "tip_delete": "Удалить выбранные объекты из хранилища с подтверждением",
        "btn_verify": "🛡 Проверить целостность",
        "tip_verify": "Проверить криптографические теги AES-GCM и контрольные суммы SHA-256 всех файлов",
        "btn_backup": "💾 Резервная копия",
        "tip_backup": "Создать проверенную резервную копию файла хранилища",
        "lbl_search": "🔍 Поиск:",
        "ph_search": "Фильтр по имени или пути...",
        "col_type": "Тип",
        "col_path": "Путь внутри хранилища",
        "col_size": "Размер",
        "col_mtime": "Изменён",
        "col_sha256": "Контрольная сумма (SHA-256)",
        "type_dir": "📁 Папка",
        "type_file": "📄 Файл",
        "empty_vault_markup": (
            "<span size='large' weight='bold'>Хранилище пока пусто</span>\n\n"
            "Нажмите <b>«Добавить файлы»</b>, <b>«Добавить папку»</b> или просто перетащите файлы мышью в это окно.\n"
            "Исходные файлы на вашем компьютере останутся в полной сохранности."
        ),
        "empty_search_markup": (
            "<span size='large' weight='bold'>Ничего не найдено по запросу «{query}»</span>\n\n"
            "Попробуйте изменить поисковый запрос или очистить поле фильтра."
        ),
        "summary_line": "Файлов: {files} | Папок: {dirs} | Общий объём исходных файлов: {size}",
        # Диалоги
        "btn_cancel": "Отмена",
        "btn_confirm": "Подтвердить",
        "btn_ok": "ОК",
        "btn_save": "Сохранить",
        "btn_browse": "Обзор...",
        "btn_choose": "Выбрать",
        # Создание хранилища
        "dlg_new_vault_title": "Создание нового защищённого хранилища",
        "dlg_new_vault_warn": (
            "<b>⚠️ Важное предупреждение о безопасности пароля:</b>\n"
            "Хранилище шифруется алгоритмом AES-256-GCM с деривацией ключа Argon2id без каких-либо лазеек. "
            "Если вы забудете пароль и потеряете аварийный ключ восстановления, "
            "<b>восстановить доступ к файлам будет математически невозможно</b>."
        ),
        "lbl_new_vault_path": "Файл нового хранилища (.mvault):",
        "default_vault_filename": "Мои_секреты.mvault",
        "fc_save_vault_title": "Выберите место сохранения хранилища",
        "lbl_master_pwd1": "Мастер-пароль (рекомендуется не менее 10 символов):",
        "lbl_master_pwd2": "Повторите мастер-пароль:",
        "chk_show_pwd": "Показать вводимый пароль",
        "chk_gen_recovery": "Сгенерировать аварийный 256-битный ключ восстановления (рекомендуется)",
        "err_specify_vault_path": "<span foreground='#cf222e'>Укажите путь к файлу хранилища.</span>",
        "err_vault_already_exists": "<span foreground='#cf222e'>Файл с таким именем уже существует. Выберите новое имя.</span>",
        "err_pwd_too_short": "<span foreground='#cf222e'>Пароль слишком короткий (минимум 6 символов).</span>",
        "err_pwd_mismatch": "<span foreground='#cf222e'>Введённые пароли не совпадают.</span>",
        "task_creating_vault": "Создание хранилища и генерация криптографических ключей...",
        "status_vault_created": "Создано и открыто новое хранилище: {name}",
        # Ключ восстановления
        "dlg_rec_key_title": "Аварийный ключ восстановления доступа",
        "btn_rec_key_saved": "Я сохранил ключ в надёжном месте",
        "dlg_rec_key_info": (
            "<b>Сохраните этот аварийный ключ восстановления!</b>\n"
            "Он позволяет разблокировать хранилище, если вы забудете основной пароль.\n"
            "Храните его отдельно от файла хранилища (например, распечатайте или сохраните на отдельную флешку)."
        ),
        "btn_save_rec_file": "💾 Сохранить ключ в текстовый файл...",
        "fc_save_rec_title": "Сохранить ключ восстановления",
        "rec_file_content": (
            "АВАРИЙНЫЙ КЛЮЧ ВОССТАНОВЛЕНИЯ MINTVAULT\n"
            "Хранилище: {vault_name}\n"
            "Дата создания: {date}\n\n"
            "Ключ восстановления:\n{recovery_key}\n\n"
            "ВНИМАНИЕ: Любой, у кого есть этот ключ и файл хранилища, сможет расшифровать файлы.\n"
        ),
        "dlg_rec_saved_title": "Ключ сохранён",
        "dlg_rec_saved_body": "Ключ восстановления записан с правами 0600 в файл:\n{path}",
        "dlg_save_err_title": "Ошибка сохранения",
        # Открытие хранилища
        "fc_open_vault_title": "Открыть файл защищённого хранилища",
        "flt_mvault_name": "Хранилища MintVault (*.mvault)",
        "flt_all_name": "Все файлы (*)",
        "dlg_open_err_title": "Не удалось открыть файл хранилища",
        # Добавление файлов и работа с оригиналами
        "fc_add_files_title": "Выберите файлы для добавления в хранилище (оригиналы сохранятся)",
        "btn_fc_add_files": "Добавить в хранилище",
        "fc_add_folder_title": "Выберите папку для добавления в хранилище (оригиналы сохранятся)",
        "btn_fc_add_folder": "Добавить папку",
        "task_adding_files": "Шифрование и транзакционное добавление файлов в хранилище...",
        "status_added_ok": "Успешно зашифровано и добавлено объектов: {count}. Исходные файлы на диске не изменены.",
        "dlg_added_notify_title": "Файлы успешно добавлены в хранилище",
        "dlg_added_notify_body": (
            "Зашифровано и сохранено объектов в хранилище: {count}.\n"
            "Оригинальные файлы на диске остались нетронутыми."
        ),
        "dlg_offer_del_orig_title": "Удалить исходные файлы с диска?",
        "dlg_offer_del_orig_body": (
            "Файлы ({count} шт.) успешно зашифрованы, записаны в хранилище и прошли проверку целостности.\n\n"
            "{preview}\n\n"
            "В настройках включено предложение удалить оригиналы после добавления.\n"
            "⚠️ ВНИМАНИЕ: Удаление исходных файлов с диска необратимо! Вы хотите оставить оригиналы или удалить их?"
        ),
        "btn_keep_originals": "Оставить оригиналы (рекомендуется)",
        "btn_delete_originals": "Удалить оригиналы с диска",
        "dlg_confirm_del_orig_title": "Подтверждение необратимого удаления оригиналов",
        "dlg_confirm_del_orig_body": (
            "Вы уверены, что хотите безвозвратно удалить исходные файлы ({count} шт.) с диска?\n\n"
            "После удаления копия файлов останется только внутри зашифрованного хранилища «{vault_name}»."
        ),
        "btn_confirm_del_orig_final": "Подтверждаю удаление оригиналов",
        "task_deleting_originals": "Проверка целостности добавленных записей и безопасное удаление оригиналов...",
        "status_originals_deleted": "Добавлено в хранилище: {added}. Проверено и удалено исходных файлов: {deleted}.",
        "dlg_orig_del_warn_title": "Частичное удаление оригиналов",
        "dlg_orig_del_warn_body": "Удалено исходных объектов: {deleted}.\nПропущено по соображениям безопасности:\n{errors}",
        # Извлечение
        "dlg_vault_empty_title": "Хранилище пусто",
        "dlg_vault_empty_body": "В хранилище нет файлов для извлечения.",
        "dlg_extract_all_title": "Извлечь все файлы хранилища?",
        "dlg_extract_all_body": "Вы не выделили отдельные строки в списке. Извлечь все объекты ({count} шт.)?",
        "btn_extract_all": "Извлечь всё",
        "dlg_extract_large_title": "Подтверждение извлечения большого числа объектов",
        "dlg_extract_large_body": "Вы собираетесь извлечь {count} объектов из хранилища. Продолжить?",
        "fc_extract_title": "Выберите папку для сохранения расшифрованных файлов",
        "btn_extract_here": "Извлечь сюда",
        "task_extracting": "Расшифровка, проверка целостности (AES-GCM + SHA-256) и сохранение файлов...",
        "status_extracted_ok": "Успешно извлечено и проверено по SHA-256 объектов: {count} в папку {dest}",
        "dlg_extracted_ok_title": "Извлечение успешно завершено",
        "dlg_extracted_ok_body": "Расшифровано и проверено объектов: {count}\nПапка назначения: {dest}",
        # Удаление из хранилища
        "dlg_no_selection_title": "Объекты не выбраны",
        "dlg_no_selection_body": "Пожалуйста, выделите в таблице файлы или папки, которые нужно удалить из хранилища.",
        "and_more_items": "… и ещё {count} объект(ов)",
        "dlg_delete_vault_title": "Подтвердите удаление из хранилища",
        "dlg_delete_vault_body": (
            "Вы действительно хотите безвозвратно удалить выбранные объекты ({count} шт.) "
            "из зашифрованного хранилища?\n\n{preview}\n\n"
            "Внимание: при удалении папки будут удалены и все вложенные в неё файлы внутри хранилища."
        ),
        "btn_confirm_delete_vault": "Удалить из хранилища",
        "task_deleting_vault": "Удаление выбранных объектов и пересборка контейнера...",
        "status_deleted_vault_ok": "Из хранилища удалено объектов: {count}.",
        # Проверка целостности
        "task_verifying": "Полная криптографическая проверка целостности всех блоков хранилища...",
        "dlg_verify_ok_title": "Хранилище полностью исправно",
        "dlg_verify_ok_body": (
            "Проверка целостности успешно завершена!\n\n"
            "• Файл хранилища: {path}\n"
            "• Заголовок и аутентификационный тег: ИСПРАВНЫ\n"
            "• Зашифрованный индекс: ИСПРАВЕН\n"
            "• Проверено файлов (AEAD + SHA-256): {verified} из {total_files}\n"
            "• Проверено папок: {total_dirs}\n"
            "• Повреждённых записей не обнаружено."
        ),
        "verify_warnings_header": "Предупреждения:",
        "status_verify_ok": "Проверка целостности пройдена: повреждений не обнаружено.",
        "dlg_verify_bad_title": "Обнаружено повреждение хранилища",
        "dlg_verify_bad_body": (
            "ВНИМАНИЕ: Обнаружены нарушения целостности данных!\n\n"
            "• Проверено исправных файлов: {verified} из {total_files}\n"
            "• Повреждённых объектов: {corrupted}\n\n"
            "Детали ошибок:\n{errors}"
        ),
        "status_verify_bad": "Внимание: проверка целостности выявила повреждения!",
        # Резервная копия
        "fc_backup_title": "Сохранить резервную копию хранилища",
        "btn_create_backup": "Создать резервную копию",
        "task_backing_up": "Создание и проверка резервной копии хранилища...",
        "status_backup_ok": "Создана и проверена резервная копия: {path}",
        "dlg_backup_ok_title": "Резервная копия создана",
        "dlg_backup_ok_body": "Резервная копия хранилища успешно сохранена и проверена:\n{path}",
        # Закрытие окна
        "dlg_busy_exit_title": "Выполняется операция",
        "dlg_busy_exit_body": (
            "В данный момент выполняется операция с хранилищем. "
            "Прервать операцию и выйти из программы? (Рабочий файл хранилища останется в предыдущем исправном состоянии)."
        ),
        "btn_abort_and_exit": "Прервать и выйти",
        "dlg_close_unlocked_title": "Хранилище разблокировано",
        "dlg_close_unlocked_body": (
            "Хранилище «{name}» сейчас разблокировано. "
            "Заблокировать хранилище, очистить ключи из памяти и закрыть программу?"
        ),
        "btn_lock_and_exit": "Заблокировать и выйти",
        # Окно настроек
        "settings_title": "Настройки MintVault",
        "settings_sec_appearance": "Внешний вид и локализация",
        "settings_lbl_theme": "Тема оформления интерфейса:",
        "settings_theme_system": "Системная (по умолчанию)",
        "settings_theme_light": "Светлая",
        "settings_theme_dark": "Тёмная",
        "settings_lbl_language": "Язык интерфейса (Language):",
        "settings_lang_ru": "Русский (Russian)",
        "settings_lang_en": "English (Английский)",
        "settings_lbl_font_scale": "Масштаб шрифта интерфейса (%):",
        "settings_sec_originals": "Поведение при добавлении файлов (работа с оригиналами)",
        "settings_originals_note": (
            "Добавление файла в MintVault всегда создаёт зашифрованную копию в контейнере .mvault.\n"
            "Шифрование копии и удаление исходного файла с диска — две разные операции."
        ),
        "settings_chk_offer_delete_originals": "Предлагать удалить оригиналы после успешного добавления в хранилище",
        "settings_chk_ask_before_deleting_originals": "Всегда запрашивать дополнительное подтверждение перед удалением оригиналов",
        "settings_warn_delete_originals_title": "Предупреждение о необратимости удаления оригиналов",
        "settings_warn_delete_originals_body": (
            "Внимание: удаление исходных файлов с диска является необратимой операцией!\n\n"
            "Даже при включении этой опции MintVault никогда не удаляет оригиналы автоматически: "
            "предложение появится только после успешной записи контейнера, криптографической проверки целостности "
            "добавленных файлов и потребует вашего явного подтверждения."
        ),
        "settings_sec_security": "Безопасность и подтверждения операций",
        "settings_chk_confirm_vault_delete": "Запрашивать подтверждение перед удалением объектов из хранилища",
        "settings_chk_confirm_large_extract": "Запрашивать подтверждение перед извлечением большого числа объектов",
        "settings_lbl_large_extract_threshold": "Порог количества объектов для предупреждения при извлечении:",
        "settings_lbl_close_action": "При закрытии окна с разблокированным хранилищем:",
        "settings_close_lock_immediately": "Автоматически блокировать и закрывать окно",
        "settings_close_ask": "Спрашивать подтверждение перед закрытием",
        "settings_lbl_auto_lock": "Автоматическая блокировка при бездействии (минут, 0 = выкл.):",
        "settings_chk_notify_long_ops": "Показывать диалог подтверждения после завершения длительных операций",
        "settings_lbl_backup_dir": "Предпочтительный каталог для резервных копий:",
        "settings_ph_backup_dir": "По умолчанию (рядом с файлом хранилища)",
        "settings_btn_clear_dir": "Сбросить",
        "settings_btn_reset_defaults": "По умолчанию",
        "status_settings_saved": "Настройки сохранены и применены.",
        "settings_lbl_dup_action": "Если добавляемый файл уже есть в хранилище:",
        "settings_dup_ask": "Спрашивать при каждом совпадении (по умолчанию)",
        "settings_dup_replace": "Заменить файл в хранилище новой версией",
        "settings_dup_keep_both": "Оставить оба (создать копию с номером)",
        "settings_dup_skip": "Пропустить (оставить старый файл без изменений)",
        "settings_dup_error": "Запрещать и выдавать ошибку",
        "dlg_dup_conflict_title": "Файл уже существует в хранилище",
        "dlg_dup_conflict_body": (
            "В хранилище уже есть следующие объекты ({count} шт.):\n\n"
            "{preview}\n\n"
            "Выберите, как поступить с совпадающими файлами:"
        ),
        "btn_dup_replace": "Заменить новыми",
        "btn_dup_keep_both": "Сделать копию (оставить оба)",
        "btn_dup_skip": "Пропустить существующие",
        "status_added_skipped": "Операция завершена: все выбранные файлы уже были в хранилище и пропущены.",
        "settings_lbl_ext_action": "Если при извлечении файл уже есть в папке назначения:",
        "dlg_ext_conflict_title": "Файлы уже существуют в папке назначения",
        "dlg_ext_conflict_body": (
            "В целевой папке уже существуют следующие файлы ({count} шт.):\n\n"
            "{preview}\n\n"
            "Как поступить с уже существующими на диске файлами?"
        ),
        "btn_ext_skip": "Пропустить существующие (докачать остальные)",
        "btn_ext_keep_both": "Сделать копию (оставить оба)",
        "btn_ext_replace": "Заменить файлы на диске",
        "status_extracted_all_skipped": "Извлечение завершено: все выбранные файлы уже существуют в папке назначения (пропущены).",
        "unit_b": "Б",
        "unit_kb": "КБ",
        "unit_mb": "МБ",
        "unit_gb": "ГБ",
        "unit_tb": "ТБ",
    },
    "en": {
        "window_title": "{app_name} v{version} — Secure File Vault",
        "header_subtitle": "<b>{app_name}</b> — Confidential File Protection",
        "vault_not_selected": "No vault selected",
        "status_locked": "🔒 LOCKED",
        "status_unlocked": "🔓 UNLOCKED",
        "btn_new_vault": "New Vault",
        "tip_new_vault": "Create a new encrypted vault container (.mvault) (Ctrl+N)",
        "btn_open_vault": "Open Vault",
        "tip_open_vault": "Open an existing vault container (.mvault) (Ctrl+O)",
        "btn_lock_vault": "Lock",
        "tip_lock_vault": "Zeroize keys in memory and lock the vault (Ctrl+L)",
        "btn_settings": "⚙ Settings",
        "tip_settings": "Configure appearance, language, and security preferences",
        "btn_theme_dark": "🌙 Dark",
        "btn_theme_light": "☀️ Light",
        "tip_theme_toggle": "Quickly toggle between light and dark interface theme",
        "status_ready": "Ready. All operations are performed locally offline.",
        "progress_running": "Processing...",
        "btn_cancel_op": "Cancel Operation",
        "status_cancel_requested": "Safe cancellation requested, please wait...",
        "status_cancelled": "Operation safely cancelled. Vault integrity preserved.",
        "status_error_prefix": "Error: {err}",
        "dlg_op_failed_title": "Operation Failed",
        "dlg_busy_title": "Operation in Progress",
        "dlg_busy_body": "Please wait for the current operation to finish or cancel it first.",
        # Welcome screen
        "welcome_title": "<span size='x-large' weight='bold'>Welcome to MintVault</span>",
        "welcome_desc": (
            "Local encrypted vault for your confidential files and folders on Linux Mint.\n\n"
            "• <b>Modern Cryptography:</b> AES-256-GCM authenticated encryption and Argon2id key derivation.\n"
            "• <b>Separate Operations:</b> adding files to the vault always creates an encrypted copy — "
            "original files are never deleted automatically.\n"
            "• <b>Crash Safety:</b> atomic Copy-on-Write transactions and built-in integrity verification.\n"
            "• <b>100% Offline:</b> operates completely locally with zero network access or telemetry."
        ),
        "welcome_btn_create": "➕ Create New Vault (Ctrl+N)",
        "welcome_btn_open": "📂 Open Existing Vault (Ctrl+O)",
        # Unlock screen
        "unlock_title": "<span size='large' weight='bold'>🔒 Unlock Vault</span>",
        "unlock_file_info": "File: <b>{path}</b>\nContainer size: {size}",
        "orphan_warning_text": (
            "Found {count} unfinished temporary file(s) from a previously interrupted write. "
            "Your main vault is intact. You can safely clean up the temporary files."
        ),
        "btn_clean_orphans": "Clean Temp Files",
        "status_orphans_cleaned": "Removed unfinished temporary files: {count}",
        "chk_use_recovery": "Use emergency recovery key (if master password is lost)",
        "lbl_enter_password": "Enter vault password:",
        "lbl_enter_recovery": "Enter 256-bit emergency recovery key:",
        "ph_password_or_rec": "Password...",
        "ph_recovery": "XXXX-XXXX-XXXX-...",
        "chk_show_secret": "Show",
        "btn_unlock_submit": "🔓 Unlock Vault",
        "btn_back": "Back",
        "err_empty_secret": "<span foreground='#cf222e'>Please enter a password or recovery key.</span>",
        "status_vault_selected": "Selected vault {name}. Enter password to unlock.",
        "task_unlocking": "Verifying key (Argon2id) and decrypting vault index...",
        "status_unlocked_ok": "Vault \"{name}\" unlocked successfully.",
        "status_locked_ok": "Vault locked and keys zeroized in RAM.",
        "status_auto_locked": "Vault automatically locked after inactivity period ({minutes} min).",
        # Workspace
        "btn_add_files": "➕ Add Files",
        "tip_add_files": "Encrypt a copy of selected files into the vault (originals on disk are preserved)",
        "btn_add_folder": "📁 Add Folder",
        "tip_add_folder": "Recursively encrypt a copy of a folder into the vault (originals are preserved)",
        "btn_extract": "📤 Extract Selected",
        "tip_extract": "Decrypt and save selected items (or entire vault) to a destination folder",
        "btn_delete": "🗑 Delete from Vault",
        "tip_delete": "Delete selected items from the encrypted vault with confirmation",
        "btn_verify": "🛡 Verify Integrity",
        "tip_verify": "Verify AES-GCM authentication tags and SHA-256 checksums of all files",
        "btn_backup": "💾 Backup Vault",
        "tip_backup": "Create a verified backup copy of the vault container",
        "lbl_search": "🔍 Search:",
        "ph_search": "Filter by name or path...",
        "col_type": "Type",
        "col_path": "Path in Vault",
        "col_size": "Size",
        "col_mtime": "Modified",
        "col_sha256": "Checksum (SHA-256)",
        "type_dir": "📁 Folder",
        "type_file": "📄 File",
        "empty_vault_markup": (
            "<span size='large' weight='bold'>Vault is currently empty</span>\n\n"
            "Click <b>\"Add Files\"</b>, <b>\"Add Folder\"</b>, or drag and drop files into this window.\n"
            "Original files on your computer will remain completely untouched."
        ),
        "empty_search_markup": (
            "<span size='large' weight='bold'>No items matching \"{query}\"</span>\n\n"
            "Try changing your search query or clearing the filter field."
        ),
        "summary_line": "Files: {files} | Folders: {dirs} | Total original size: {size}",
        # Dialogs
        "btn_cancel": "Cancel",
        "btn_confirm": "Confirm",
        "btn_ok": "OK",
        "btn_save": "Save",
        "btn_browse": "Browse...",
        "btn_choose": "Select",
        # New vault
        "dlg_new_vault_title": "Create New Encrypted Vault",
        "dlg_new_vault_warn": (
            "<b>⚠️ Important Password Security Notice:</b>\n"
            "The vault is encrypted with AES-256-GCM and Argon2id key derivation with no backdoors. "
            "If you forget your password and lose your emergency recovery key, "
            "<b>recovering your files will be mathematically impossible</b>."
        ),
        "lbl_new_vault_path": "New vault file (.mvault):",
        "default_vault_filename": "My_Secrets.mvault",
        "fc_save_vault_title": "Select location to save vault",
        "lbl_master_pwd1": "Master password (at least 10 characters recommended):",
        "lbl_master_pwd2": "Repeat master password:",
        "chk_show_pwd": "Show entered password",
        "chk_gen_recovery": "Generate 256-bit emergency recovery key (recommended)",
        "err_specify_vault_path": "<span foreground='#cf222e'>Please specify a vault file path.</span>",
        "err_vault_already_exists": "<span foreground='#cf222e'>A file with this name already exists. Choose a new name.</span>",
        "err_pwd_too_short": "<span foreground='#cf222e'>Password is too short (minimum 6 characters).</span>",
        "err_pwd_mismatch": "<span foreground='#cf222e'>Entered passwords do not match.</span>",
        "task_creating_vault": "Creating vault and generating cryptographic keys...",
        "status_vault_created": "Created and opened new vault: {name}",
        # Recovery key
        "dlg_rec_key_title": "Emergency Recovery Key",
        "btn_rec_key_saved": "I have saved the recovery key in a safe place",
        "dlg_rec_key_info": (
            "<b>Save this emergency recovery key!</b>\n"
            "It allows you to unlock the vault if you forget your master password.\n"
            "Store it separately from the vault file (e.g. print it or save it on a separate USB drive)."
        ),
        "btn_save_rec_file": "💾 Save key to text file...",
        "fc_save_rec_title": "Save Recovery Key",
        "rec_file_content": (
            "MINTVAULT EMERGENCY RECOVERY KEY\n"
            "Vault: {vault_name}\n"
            "Created: {date}\n\n"
            "Recovery Key:\n{recovery_key}\n\n"
            "WARNING: Anyone with this key and the vault file can decrypt its contents.\n"
        ),
        "dlg_rec_saved_title": "Recovery Key Saved",
        "dlg_rec_saved_body": "Recovery key written with 0600 permissions to:\n{path}",
        "dlg_save_err_title": "Save Error",
        # Open vault
        "fc_open_vault_title": "Open Encrypted Vault File",
        "flt_mvault_name": "MintVault Containers (*.mvault)",
        "flt_all_name": "All Files (*)",
        "dlg_open_err_title": "Failed to Open Vault File",
        # Add files & originals
        "fc_add_files_title": "Select files to add to vault (originals are preserved)",
        "btn_fc_add_files": "Add to Vault",
        "fc_add_folder_title": "Select folder to add to vault (originals are preserved)",
        "btn_fc_add_folder": "Add Folder",
        "task_adding_files": "Encrypting and transactionally adding files to vault...",
        "status_added_ok": "Successfully encrypted and added items: {count}. Original files on disk were not modified.",
        "dlg_added_notify_title": "Files Added to Vault",
        "dlg_added_notify_body": (
            "Encrypted and stored items in vault: {count}.\n"
            "Original files on disk remain untouched."
        ),
        "dlg_offer_del_orig_title": "Delete Original Files from Disk?",
        "dlg_offer_del_orig_body": (
            "Items ({count}) have been encrypted, committed to the vault, and passed cryptographic integrity checks.\n\n"
            "{preview}\n\n"
            "Your settings enable offering to delete originals after addition.\n"
            "⚠️ WARNING: Deleting original files from disk is irreversible! Do you want to keep or delete the originals?"
        ),
        "btn_keep_originals": "Keep Originals (Recommended)",
        "btn_delete_originals": "Delete Originals from Disk",
        "dlg_confirm_del_orig_title": "Confirm Irreversible Deletion of Originals",
        "dlg_confirm_del_orig_body": (
            "Are you sure you want to permanently delete the original files ({count}) from disk?\n\n"
            "After deletion, the only copy of these files will reside inside the encrypted vault \"{vault_name}\"."
        ),
        "btn_confirm_del_orig_final": "Confirm Delete Originals",
        "task_deleting_originals": "Verifying added entries integrity and safely deleting original files...",
        "status_originals_deleted": "Added to vault: {added}. Verified and deleted original files: {deleted}.",
        "dlg_orig_del_warn_title": "Partial Original Deletion",
        "dlg_orig_del_warn_body": "Deleted original items: {deleted}.\nSkipped for safety:\n{errors}",
        # Extract
        "dlg_vault_empty_title": "Vault is Empty",
        "dlg_vault_empty_body": "There are no files in the vault to extract.",
        "dlg_extract_all_title": "Extract All Files from Vault?",
        "dlg_extract_all_body": "No individual rows were selected. Extract all items ({count})?",
        "btn_extract_all": "Extract All",
        "dlg_extract_large_title": "Confirm Large Extraction",
        "dlg_extract_large_body": "You are about to extract {count} items from the vault. Continue?",
        "fc_extract_title": "Select destination folder for decrypted files",
        "btn_extract_here": "Extract Here",
        "task_extracting": "Decrypting, verifying integrity (AES-GCM + SHA-256), and saving files...",
        "status_extracted_ok": "Successfully extracted and SHA-256 verified items: {count} -> {dest}",
        "dlg_extracted_ok_title": "Extraction Complete",
        "dlg_extracted_ok_body": "Decrypted and verified items: {count}\nDestination folder: {dest}",
        # Delete from vault
        "dlg_no_selection_title": "No Items Selected",
        "dlg_no_selection_body": "Please select the files or folders in the table that you want to delete from the vault.",
        "and_more_items": "… and {count} more item(s)",
        "dlg_delete_vault_title": "Confirm Deletion from Vault",
        "dlg_delete_vault_body": (
            "Are you sure you want to permanently delete the selected items ({count}) "
            "from the encrypted vault?\n\n{preview}\n\n"
            "Note: deleting a folder also deletes all nested files inside it within the vault."
        ),
        "btn_confirm_delete_vault": "Delete from Vault",
        "task_deleting_vault": "Deleting selected items and rebuilding container...",
        "status_deleted_vault_ok": "Deleted items from vault: {count}.",
        # Verify integrity
        "task_verifying": "Performing full cryptographic integrity verification of all vault blocks...",
        "dlg_verify_ok_title": "Vault Integrity Verified",
        "dlg_verify_ok_body": (
            "Integrity verification completed successfully!\n\n"
            "• Vault file: {path}\n"
            "• Header & authentication tag: VALID\n"
            "• Encrypted metadata index: VALID\n"
            "• Verified files (AEAD + SHA-256): {verified} of {total_files}\n"
            "• Verified folders: {total_dirs}\n"
            "• Zero corrupted entries detected."
        ),
        "verify_warnings_header": "Warnings:",
        "status_verify_ok": "Integrity check passed: no corruption detected.",
        "dlg_verify_bad_title": "Vault Corruption Detected",
        "dlg_verify_bad_body": (
            "WARNING: Data integrity violations detected!\n\n"
            "• Verified intact files: {verified} of {total_files}\n"
            "• Corrupted items: {corrupted}\n\n"
            "Error details:\n{errors}"
        ),
        "status_verify_bad": "Warning: integrity verification detected corruption!",
        # Backup
        "fc_backup_title": "Save Vault Backup Copy",
        "btn_create_backup": "Create Backup",
        "task_backing_up": "Creating and verifying vault backup copy...",
        "status_backup_ok": "Created and verified backup copy: {path}",
        "dlg_backup_ok_title": "Backup Created",
        "dlg_backup_ok_body": "Vault backup copy was successfully saved and verified:\n{path}",
        # Window close
        "dlg_busy_exit_title": "Operation in Progress",
        "dlg_busy_exit_body": (
            "A vault operation is currently running. "
            "Cancel the operation and exit? (Your working vault file will remain in its previous intact state)."
        ),
        "btn_abort_and_exit": "Cancel and Exit",
        "dlg_close_unlocked_title": "Vault is Unlocked",
        "dlg_close_unlocked_body": (
            "Vault \"{name}\" is currently unlocked. "
            "Lock the vault, zeroize keys in memory, and close the application?"
        ),
        "btn_lock_and_exit": "Lock and Exit",
        # Settings dialog
        "settings_title": "MintVault Settings",
        "settings_sec_appearance": "Appearance & Language",
        "settings_lbl_theme": "Interface Theme:",
        "settings_theme_system": "System (Default)",
        "settings_theme_light": "Light",
        "settings_theme_dark": "Dark",
        "settings_lbl_language": "Interface Language (Язык):",
        "settings_lang_ru": "Русский (Russian)",
        "settings_lang_en": "English (Английский)",
        "settings_lbl_font_scale": "Interface Font Scale (%):",
        "settings_sec_originals": "File Addition Behavior (Handling Original Files)",
        "settings_originals_note": (
            "Adding a file to MintVault always creates an encrypted copy inside the .mvault container.\n"
            "Encrypting a copy and deleting the original file from disk are two separate operations."
        ),
        "settings_chk_offer_delete_originals": "Offer to delete original files after successful addition to vault",
        "settings_chk_ask_before_deleting_originals": "Always ask for additional confirmation before deleting original files",
        "settings_warn_delete_originals_title": "Irreversible Original Deletion Warning",
        "settings_warn_delete_originals_body": (
            "Warning: deleting original files from disk is an irreversible operation!\n\n"
            "Even with this option enabled, MintVault never deletes original files automatically: "
            "the prompt will only appear after the vault container is written, flushed to disk, and the added files "
            "pass cryptographic verification, and will still require your explicit confirmation."
        ),
        "settings_sec_security": "Security & Operation Confirmations",
        "settings_chk_confirm_vault_delete": "Ask for confirmation before deleting items from the vault",
        "settings_chk_confirm_large_extract": "Ask for confirmation before extracting a large number of items",
        "settings_lbl_large_extract_threshold": "Item count threshold for large extraction confirmation:",
        "settings_lbl_close_action": "When closing window with an unlocked vault:",
        "settings_close_lock_immediately": "Automatically lock vault and close window",
        "settings_close_ask": "Ask for confirmation before closing",
        "settings_lbl_auto_lock": "Auto-lock vault after inactivity (minutes, 0 = disabled):",
        "settings_chk_notify_long_ops": "Show completion dialog after long operations finish",
        "settings_lbl_backup_dir": "Preferred directory for vault backups:",
        "settings_ph_backup_dir": "Default (same directory as vault file)",
        "settings_btn_clear_dir": "Clear",
        "settings_btn_reset_defaults": "Restore Defaults",
        "status_settings_saved": "Settings saved and applied.",
        "settings_lbl_dup_action": "When adding a file that already exists in vault:",
        "settings_dup_ask": "Ask every time (Default)",
        "settings_dup_replace": "Replace existing file in vault with new version",
        "settings_dup_keep_both": "Keep both (create numbered copy)",
        "settings_dup_skip": "Skip (keep existing file in vault)",
        "settings_dup_error": "Abort and show error",
        "dlg_dup_conflict_title": "File Already Exists in Vault",
        "dlg_dup_conflict_body": (
            "The following items ({count}) already exist in the vault:\n\n"
            "{preview}\n\n"
            "Choose how to handle the conflicting files:"
        ),
        "btn_dup_replace": "Replace Existing",
        "btn_dup_keep_both": "Keep Both (Make Copy)",
        "btn_dup_skip": "Skip Existing",
        "status_added_skipped": "Operation complete: all selected files already existed in vault and were skipped.",
        "settings_lbl_ext_action": "When extracting a file that already exists in destination folder:",
        "dlg_ext_conflict_title": "Files Already Exist in Destination Folder",
        "dlg_ext_conflict_body": (
            "The following files ({count}) already exist in the destination folder:\n\n"
            "{preview}\n\n"
            "How would you like to handle the existing files on disk?"
        ),
        "btn_ext_skip": "Skip Existing (Extract Remaining)",
        "btn_ext_keep_both": "Keep Both (Make Copy)",
        "btn_ext_replace": "Replace Files on Disk",
        "status_extracted_all_skipped": "Extraction complete: all selected files already exist in destination folder (skipped).",
        "unit_b": "B",
        "unit_kb": "KB",
        "unit_mb": "MB",
        "unit_gb": "GB",
        "unit_tb": "TB",
    },
}


def tr(lang: str, key: str, **kwargs: object) -> str:
    """Возвращает локализованную строку для языка `lang` ('ru' или 'en') с безопасным fallback на 'ru'."""
    lang_code = lang if lang in TRANSLATIONS else "ru"
    catalog = TRANSLATIONS[lang_code]
    template = catalog.get(key) or TRANSLATIONS["ru"].get(key) or key
    if kwargs:
        try:
            return template.format(**kwargs)
        except Exception:
            return template
    return template


def format_size_localized(num_bytes: int, lang: str = "ru") -> str:
    """Форматирует размер в байтах с учётом выбранного языка интерфейса."""
    b_unit = tr(lang, "unit_b")
    if num_bytes < 1024:
        return f"{num_bytes} {b_unit}"
    units = [
        tr(lang, "unit_kb"),
        tr(lang, "unit_mb"),
        tr(lang, "unit_gb"),
        tr(lang, "unit_tb"),
    ]
    val = float(num_bytes)
    for unit in units:
        val /= 1024.0
        if val < 1024.0 or unit == units[-1]:
            return f"{val:.1f} {unit}"
    return f"{num_bytes} {b_unit}"


def format_timestamp_localized(ts: float) -> str:
    """Форматирует временную метку UNIX в локальную дату и время."""
    if ts <= 0:
        return "—"
    try:
        return datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M:%S")
    except (ValueError, OSError, OverflowError):
        return "—"
