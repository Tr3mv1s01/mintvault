"""
Графический интерфейс MintVault на базе GTK 3 (`PyGObject`) для Linux Mint (Cinnamon / MATE / Xfce).

Реализует:
- Современный минималистичный дизайн с поддержкой системной, светлой и тёмной темы, а также масштабирования шрифта.
- Полную двуязычную локализацию (Русский / English) с переключением на лету без перезапуска.
- Наглядный индикатор состояния (Заблокировано / Разблокировано) и опциональную автоблокировку при бездействии.
- Создание нового хранилища с предупреждением о невосстановимости пароля и выдачей 256-битного ключа восстановления.
- Открытие и разблокировку существующего хранилища (по паролю или по ключу восстановления).
- Обнаружение и безопасную очистку временных файлов после аварийного завершения записи.
- Добавление файлов и папок через диалоги выбора и перетаскивание мышью (Drag-and-Drop `text/uri-list`), без автоматического удаления оригиналов, с поддержкой опционального проверенного удаления оригиналов только после верификации контейнера и явного подтверждения.
- Просмотр списка объектов, живой поиск, извлечение с защитой от перезаписи, удаление с подтверждением, полную проверку целостности и создание резервной копии.
- Полноценное окно настроек GTK 3 с безопасным хранением в профиле пользователя XDG.
"""

import os
import threading
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, GLib, GObject, Gtk, Pango

from . import __app_name__, __version__
from .exceptions import (
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
)
from .i18n import format_size_localized, format_timestamp_localized, tr
from .models import IntegrityReport, VaultEntry
from .settings import (
    MAX_AUTO_LOCK_MINUTES,
    MAX_FONT_SCALE,
    MAX_LARGE_EXTRACTION_THRESHOLD,
    MIN_AUTO_LOCK_MINUTES,
    MIN_FONT_SCALE,
    MIN_LARGE_EXTRACTION_THRESHOLD,
    AppSettings,
    SettingsManager,
)
from .vault import SecureVault

LIGHT_CSS = """
window, dialog, messagedialog, filechooser {
    background-color: #f6f8fa;
    color: #1f2328;
}
.header-banner {
    background-color: #ffffff;
    border-bottom: 1px solid #d0d7de;
    padding: 10px 16px;
}
.status-badge-locked {
    background-color: #ffebe9;
    color: #cf222e;
    border: 1px solid #ff8182;
    border-radius: 6px;
    padding: 4px 10px;
    font-weight: bold;
}
.status-badge-unlocked {
    background-color: #dafbe1;
    color: #1a7f37;
    border: 1px solid #4ac26b;
    border-radius: 6px;
    padding: 4px 10px;
    font-weight: bold;
}
.card-panel {
    background-color: #ffffff;
    border: 1px solid #d0d7de;
    border-radius: 8px;
    padding: 20px;
}
.warning-box {
    background-color: #fff8c5;
    color: #574600;
    border: 1px solid #d4a72c;
    border-radius: 6px;
    padding: 10px;
}
.status-bar {
    background-color: #eaeef2;
    color: #1f2328;
    border-top: 1px solid #d0d7de;
    padding: 6px 12px;
}
treeview.view, textview.view, textview text, list, row, placessidebar, placessidebar list, placessidebar row {
    background-color: #ffffff;
    color: #1f2328;
}
placessidebar row label, placessidebar row image, filechooser label {
    color: #1f2328;
}
treeview.view:selected, list row:selected, placessidebar row:selected, placessidebar row:selected label {
    background-color: #0969da;
    color: #ffffff;
}
treeview header button {
    background-image: none;
    background-color: #eaeef2;
    color: #1f2328;
    border: none;
    border-right: 1px solid #d0d7de;
    border-bottom: 1px solid #d0d7de;
    padding: 6px 8px;
}
entry, spinbutton, combobox button {
    background-image: none;
    background-color: #ffffff;
    color: #1f2328;
    border: 1px solid #d0d7de;
    border-radius: 6px;
    padding: 4px 8px;
}
button {
    background-image: none;
    background-color: #f6f8fa;
    color: #1f2328;
    border: 1px solid #d0d7de;
    border-radius: 6px;
    padding: 5px 10px;
    box-shadow: none;
}
button:hover {
    background-color: #eaeef2;
}
button:disabled {
    background-color: #eaeef2;
    color: #8c959f;
    border-color: #d8dee4;
    opacity: 0.65;
}
.danger-button {
    background-image: none;
    background-color: #cf222e;
    color: #ffffff;
    border: 1px solid #a40e26;
    font-weight: bold;
}
.danger-button:hover {
    background-color: #a40e26;
}
.primary-button {
    background-image: none;
    background-color: #2da44e;
    color: #ffffff;
    border: 1px solid #218bff;
    border-color: #1a7f37;
    font-weight: bold;
}
.primary-button:hover {
    background-color: #2c974b;
}
scrolledwindow, viewport, filechooser box, filechooser actionbar {
    background-color: #f6f8fa;
    color: #1f2328;
}
progressbar {
    color: #1f2328;
    font-weight: bold;
}
progressbar text {
    color: #1f2328;
    font-weight: bold;
}
progressbar trough {
    background-color: #d0d7de;
    border: 1px solid #afb8c1;
    border-radius: 6px;
    min-height: 10px;
}
progressbar progress {
    background-image: none;
    background-color: #2da44e;
    border-radius: 6px;
    min-height: 10px;
}
"""

DARK_CSS = """
window, dialog, messagedialog, filechooser {
    background-color: #161b22;
    color: #e6edf3;
}
.header-banner {
    background-color: #21262d;
    border-bottom: 1px solid #30363d;
    padding: 10px 16px;
}
.status-badge-locked {
    background-color: #490202;
    color: #ff7b72;
    border: 1px solid #f85149;
    border-radius: 6px;
    padding: 4px 10px;
    font-weight: bold;
}
.status-badge-unlocked {
    background-color: #0f2d1a;
    color: #56d364;
    border: 1px solid #2ea043;
    border-radius: 6px;
    padding: 4px 10px;
    font-weight: bold;
}
.card-panel {
    background-color: #21262d;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 20px;
}
.warning-box {
    background-color: #3b2e00;
    color: #f2cc60;
    border: 1px solid #9e6a03;
    border-radius: 6px;
    padding: 10px;
}
.status-bar {
    background-color: #0d1117;
    color: #e6edf3;
    border-top: 1px solid #30363d;
    padding: 6px 12px;
}
treeview.view, textview.view, textview text, list, row, placessidebar, placessidebar list, placessidebar row {
    background-color: #0d1117;
    color: #e6edf3;
}
placessidebar row label, placessidebar row image, filechooser label, filechooser button label {
    color: #e6edf3;
}
treeview.view:selected, list row:selected, placessidebar row:selected, placessidebar row:selected label {
    background-color: #1f6feb;
    color: #ffffff;
}
treeview header button {
    background-image: none;
    background-color: #21262d;
    color: #e6edf3;
    border: none;
    border-right: 1px solid #30363d;
    border-bottom: 1px solid #30363d;
    padding: 6px 8px;
}
entry, spinbutton, combobox button {
    background-image: none;
    background-color: #0d1117;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 4px 8px;
}
button {
    background-image: none;
    background-color: #21262d;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 5px 10px;
    box-shadow: none;
}
button:hover {
    background-color: #30363d;
}
button:disabled {
    background-color: #161b22;
    color: #6e7681;
    border-color: #21262d;
    opacity: 0.6;
}
.danger-button {
    background-image: none;
    background-color: #da3633;
    color: #ffffff;
    border: 1px solid #b62324;
    font-weight: bold;
}
.danger-button:hover {
    background-color: #b62324;
}
.primary-button {
    background-image: none;
    background-color: #238636;
    color: #ffffff;
    border: 1px solid #2ea043;
    font-weight: bold;
}
.primary-button:hover {
    background-color: #2ea043;
}
scrolledwindow, viewport, filechooser box, filechooser actionbar, filechooser .path-bar-box {
    background-color: #161b22;
    color: #e6edf3;
}
progressbar {
    color: #e6edf3;
    font-weight: bold;
}
progressbar text {
    color: #e6edf3;
    font-weight: bold;
}
progressbar trough {
    background-color: #30363d;
    border: 1px solid #484f58;
    border-radius: 6px;
    min-height: 10px;
}
progressbar progress {
    background-image: none;
    background-color: #2ea043;
    border-radius: 6px;
    min-height: 10px;
}
"""


def format_size_ru(num_bytes: int) -> str:
    """Обратная совместимость: форматирование размера на русском языке."""
    return format_size_localized(num_bytes, "ru")


def format_timestamp_ru(ts: float) -> str:
    """Обратная совместимость: форматирование временной метки."""
    return format_timestamp_localized(ts)


def detect_system_dark_theme() -> bool:
    """
    Безопасно определяет, использует ли рабочее окружение GTK 3 тёмную тему по умолчанию.
    При невозможности надёжного определения возвращает False (светлая тема как безопасный fallback).
    """
    env_theme = os.environ.get("GTK_THEME", "").strip().lower()
    if env_theme:
        if "dark" in env_theme:
            return True
        if "light" in env_theme:
            return False

    try:
        gtk_settings = Gtk.Settings.get_default()
        if gtk_settings is not None:
            prefer_dark = bool(gtk_settings.get_property("gtk-application-prefer-dark-theme"))
            if prefer_dark:
                return True
            theme_name = str(gtk_settings.get_property("gtk-theme-name") or "").lower()
            if "dark" in theme_name:
                return True
    except Exception:
        pass
    return False


class MintVaultWindow(Gtk.Window):
    """Главное окно графического приложения MintVault."""

    def __init__(
        self,
        initial_vault_path: Optional[str] = None,
        settings_manager: Optional[SettingsManager] = None,
    ) -> None:
        self.settings_manager: SettingsManager = settings_manager or SettingsManager()
        self.app_settings: AppSettings = self.settings_manager.load()
        self._system_prefers_dark: bool = detect_system_dark_theme()

        super().__init__(
            title=tr(
                self.app_settings.language,
                "window_title",
                app_name=__app_name__,
                version=__version__,
            )
        )
        self.set_default_size(1060, 680)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.set_border_width(0)

        self.vault: Optional[SecureVault] = None
        self.is_dark_theme: bool = False
        self.is_busy: bool = False
        self._cancel_requested: threading.Event = threading.Event()
        self._active_worker_thread: Optional[threading.Thread] = None
        self._last_activity_monotonic: float = time.monotonic()
        self._last_unlocked_file_size: int = 0
        self._auto_lock_source_id: Optional[int] = None

        self.css_provider = Gtk.CssProvider()
        screen = Gdk.Screen.get_default()
        if screen is not None:
            Gtk.StyleContext.add_provider_for_screen(
                screen,
                self.css_provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
            )

        self._build_ui()
        self._apply_settings_to_ui()
        self.connect("delete-event", self._on_window_delete_event)
        self.connect("key-press-event", self._on_user_activity_event)
        self.connect("button-press-event", self._on_user_activity_event)
        self.connect("motion-notify-event", self._on_user_activity_event)
        self.add_events(
            Gdk.EventMask.KEY_PRESS_MASK
            | Gdk.EventMask.BUTTON_PRESS_MASK
            | Gdk.EventMask.POINTER_MOTION_MASK
        )

        self._auto_lock_source_id = GLib.timeout_add_seconds(5, self._on_auto_lock_timer_tick)

        if initial_vault_path:
            p = Path(initial_vault_path)
            if p.exists():
                self._prepare_open_vault(p)

    def _t(self, key: str, **kwargs: Any) -> str:
        return tr(self.app_settings.language, key, **kwargs)

    def _format_size(self, num_bytes: int) -> str:
        return format_size_localized(num_bytes, self.app_settings.language)

    def _record_user_activity(self) -> None:
        self._last_activity_monotonic = time.monotonic()

    def _on_user_activity_event(self, *_args: Any) -> bool:
        self._record_user_activity()
        return False

    def _on_auto_lock_timer_tick(self) -> bool:
        self._check_inactivity_auto_lock()
        return True

    def _check_inactivity_auto_lock(self) -> bool:
        """
        Проверяет превышение времени бездействия для автоматической блокировки хранилища.
        Не прерывает активную фоновую операцию, чтобы гарантировать целостность транзакций.
        Возвращает True, если была выполнена автоблокировка.
        """
        minutes = self.app_settings.auto_lock_minutes
        if minutes <= 0 or not self.vault or not self.vault.is_unlocked:
            return False
        if self.is_busy:
            self._record_user_activity()
            return False

        elapsed = time.monotonic() - self._last_activity_monotonic
        if elapsed >= minutes * 60:
            v_path = self.vault.vault_path
            self.vault.lock()
            self._prepare_open_vault(v_path)
            self.status_label.set_text(self._t("status_auto_locked", minutes=minutes))
            return True
        return False

    # ------------------------------------------------------------------
    # Построение интерфейса
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        main_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add(main_vbox)

        # 1. Верхняя панель навигации и статуса
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        header_box.get_style_context().add_class("header-banner")
        main_vbox.pack_start(header_box, False, False, 0)

        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.app_title_label = Gtk.Label(
            label=self._t("header_subtitle", app_name=__app_name__)
        )
        self.app_title_label.set_use_markup(True)
        self.app_title_label.set_xalign(0.0)
        self.vault_path_label = Gtk.Label(label=self._t("vault_not_selected"))
        self.vault_path_label.set_xalign(0.0)
        self.vault_path_label.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        title_box.pack_start(self.app_title_label, False, False, 0)
        title_box.pack_start(self.vault_path_label, False, False, 0)
        header_box.pack_start(title_box, True, True, 0)

        # Индикатор состояния (Заблокировано / Разблокировано)
        self.status_badge = Gtk.Label(label=self._t("status_locked"))
        self.status_badge.get_style_context().add_class("status-badge-locked")
        header_box.pack_start(self.status_badge, False, False, 6)

        # Кнопки управления хранилищем в верхней панели
        self.btn_new_vault = Gtk.Button(label=self._t("btn_new_vault"))
        self.btn_new_vault.set_tooltip_text(self._t("tip_new_vault"))
        self.btn_new_vault.connect("clicked", self._on_new_vault_clicked)
        header_box.pack_start(self.btn_new_vault, False, False, 0)

        self.btn_open_vault = Gtk.Button(label=self._t("btn_open_vault"))
        self.btn_open_vault.set_tooltip_text(self._t("tip_open_vault"))
        self.btn_open_vault.connect("clicked", self._on_open_vault_clicked)
        header_box.pack_start(self.btn_open_vault, False, False, 0)

        self.btn_lock_vault = Gtk.Button(label=self._t("btn_lock_vault"))
        self.btn_lock_vault.set_tooltip_text(self._t("tip_lock_vault"))
        self.btn_lock_vault.connect("clicked", self._on_lock_vault_clicked)
        self.btn_lock_vault.set_sensitive(False)
        header_box.pack_start(self.btn_lock_vault, False, False, 0)

        self.btn_theme_toggle = Gtk.Button(label=self._t("btn_theme_dark"))
        self.btn_theme_toggle.set_tooltip_text(self._t("tip_theme_toggle"))
        self.btn_theme_toggle.connect("clicked", self._on_toggle_theme_clicked)
        header_box.pack_start(self.btn_theme_toggle, False, False, 0)

        self.btn_settings = Gtk.Button(label=self._t("btn_settings"))
        self.btn_settings.set_tooltip_text(self._t("tip_settings"))
        self.btn_settings.connect("clicked", self._on_settings_clicked)
        header_box.pack_start(self.btn_settings, False, False, 0)

        # 2. Основной стек экранов (Приветствие / Разблокировка / Рабочая область)
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.NONE)
        main_vbox.pack_start(self.stack, True, True, 0)

        self._build_welcome_page()
        self._build_unlock_page()
        self._build_workspace_page()

        # 3. Нижняя строка состояния и прогресса длительных операций
        status_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        status_bar.get_style_context().add_class("status-bar")
        main_vbox.pack_start(status_bar, False, False, 0)

        self.status_label = Gtk.Label(label=self._t("status_ready"))
        self.status_label.set_xalign(0.0)
        self.status_label.set_ellipsize(Pango.EllipsizeMode.END)
        status_bar.pack_start(self.status_label, True, True, 0)

        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_show_text(True)
        self.progress_bar.set_size_request(220, -1)
        self.progress_bar.set_no_show_all(True)
        status_bar.pack_start(self.progress_bar, False, False, 0)

        self.btn_cancel_op = Gtk.Button(label=self._t("btn_cancel_op"))
        self.btn_cancel_op.get_style_context().add_class("danger-button")
        self.btn_cancel_op.connect("clicked", self._on_cancel_operation_clicked)
        self.btn_cancel_op.set_no_show_all(True)
        status_bar.pack_start(self.btn_cancel_op, False, False, 0)

        # Горячие клавиши
        accel = Gtk.AccelGroup()
        self.add_accel_group(accel)
        key_n, mod_n = Gtk.accelerator_parse("<Control>n")
        self.btn_new_vault.add_accelerator("clicked", accel, key_n, mod_n, Gtk.AccelFlags.VISIBLE)
        key_o, mod_o = Gtk.accelerator_parse("<Control>o")
        self.btn_open_vault.add_accelerator("clicked", accel, key_o, mod_o, Gtk.AccelFlags.VISIBLE)
        key_l, mod_l = Gtk.accelerator_parse("<Control>l")
        self.btn_lock_vault.add_accelerator("clicked", accel, key_l, mod_l, Gtk.AccelFlags.VISIBLE)

        self.stack.set_visible_child_name("welcome")

    def _build_welcome_page(self) -> None:
        center_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        center_box.set_valign(Gtk.Align.CENTER)
        center_box.set_halign(Gtk.Align.CENTER)
        center_box.set_margin_top(30)
        center_box.set_margin_bottom(30)
        center_box.set_margin_start(30)
        center_box.set_margin_end(30)

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        card.get_style_context().add_class("card-panel")
        card.set_size_request(620, -1)
        center_box.pack_start(card, False, False, 0)

        self.welcome_head_label = Gtk.Label(label=self._t("welcome_title"))
        self.welcome_head_label.set_use_markup(True)
        card.pack_start(self.welcome_head_label, False, False, 0)

        self.welcome_desc_label = Gtk.Label(label=self._t("welcome_desc"))
        self.welcome_desc_label.set_use_markup(True)
        self.welcome_desc_label.set_line_wrap(True)
        self.welcome_desc_label.set_xalign(0.0)
        card.pack_start(self.welcome_desc_label, False, False, 0)

        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        btn_row.set_halign(Gtk.Align.CENTER)
        card.pack_start(btn_row, False, False, 8)

        self.btn_welcome_create = Gtk.Button(label=self._t("welcome_btn_create"))
        self.btn_welcome_create.get_style_context().add_class("primary-button")
        self.btn_welcome_create.set_size_request(260, 42)
        self.btn_welcome_create.connect("clicked", self._on_new_vault_clicked)
        btn_row.pack_start(self.btn_welcome_create, False, False, 0)

        self.btn_welcome_open = Gtk.Button(label=self._t("welcome_btn_open"))
        self.btn_welcome_open.set_size_request(280, 42)
        self.btn_welcome_open.connect("clicked", self._on_open_vault_clicked)
        btn_row.pack_start(self.btn_welcome_open, False, False, 0)

        self.stack.add_named(center_box, "welcome")

    def _build_unlock_page(self) -> None:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        outer.set_valign(Gtk.Align.CENTER)
        outer.set_halign(Gtk.Align.CENTER)
        outer.set_margin_top(24)
        outer.set_margin_bottom(24)

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        card.get_style_context().add_class("card-panel")
        card.set_size_request(560, -1)
        outer.pack_start(card, False, False, 0)

        self.unlock_title_label = Gtk.Label(label=self._t("unlock_title"))
        self.unlock_title_label.set_use_markup(True)
        self.unlock_title_label.set_xalign(0.0)
        card.pack_start(self.unlock_title_label, False, False, 0)

        self.unlock_file_label = Gtk.Label(label="")
        self.unlock_file_label.set_xalign(0.0)
        self.unlock_file_label.set_line_wrap(True)
        card.pack_start(self.unlock_file_label, False, False, 0)

        # Предупреждение при обнаружении незавершённых временных файлов
        self.orphan_warning_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.orphan_warning_box.get_style_context().add_class("warning-box")
        self.orphan_warning_box.set_no_show_all(True)
        self.orphan_warning_label = Gtk.Label(label="")
        self.orphan_warning_label.set_line_wrap(True)
        self.orphan_warning_label.set_xalign(0.0)
        self.btn_clean_orphans = Gtk.Button(label=self._t("btn_clean_orphans"))
        self.btn_clean_orphans.connect("clicked", self._on_clean_orphans_clicked)
        self.orphan_warning_box.pack_start(self.orphan_warning_label, True, True, 0)
        self.orphan_warning_box.pack_start(self.btn_clean_orphans, False, False, 0)
        card.pack_start(self.orphan_warning_box, False, False, 0)

        # Выбор режима: Пароль или Ключ восстановления
        self.chk_use_recovery = Gtk.CheckButton(label=self._t("chk_use_recovery"))
        self.chk_use_recovery.connect("toggled", self._on_recovery_mode_toggled)
        card.pack_start(self.chk_use_recovery, False, False, 4)

        self.lbl_secret_prompt = Gtk.Label(label=self._t("lbl_enter_password"))
        self.lbl_secret_prompt.set_xalign(0.0)
        card.pack_start(self.lbl_secret_prompt, False, False, 0)

        secret_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.entry_unlock_secret = Gtk.Entry()
        self.entry_unlock_secret.set_visibility(False)
        self.entry_unlock_secret.set_placeholder_text(self._t("ph_password_or_rec"))
        self.entry_unlock_secret.connect("activate", self._on_unlock_submit_clicked)
        secret_row.pack_start(self.entry_unlock_secret, True, True, 0)

        self.chk_show_secret = Gtk.CheckButton(label=self._t("chk_show_secret"))
        self.chk_show_secret.connect(
            "toggled",
            lambda btn: self.entry_unlock_secret.set_visibility(btn.get_active()),
        )
        secret_row.pack_start(self.chk_show_secret, False, False, 0)
        card.pack_start(secret_row, False, False, 0)

        self.unlock_error_label = Gtk.Label(label="")
        self.unlock_error_label.set_use_markup(True)
        self.unlock_error_label.set_line_wrap(True)
        self.unlock_error_label.set_xalign(0.0)
        card.pack_start(self.unlock_error_label, False, False, 0)

        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        btn_row.set_margin_top(8)
        self.btn_unlock_submit = Gtk.Button(label=self._t("btn_unlock_submit"))
        self.btn_unlock_submit.get_style_context().add_class("primary-button")
        self.btn_unlock_submit.connect("clicked", self._on_unlock_submit_clicked)
        btn_row.pack_start(self.btn_unlock_submit, True, True, 0)

        self.btn_cancel_unlock = Gtk.Button(label=self._t("btn_back"))
        self.btn_cancel_unlock.connect("clicked", lambda *_: self._close_current_vault())
        btn_row.pack_start(self.btn_cancel_unlock, False, False, 0)
        card.pack_start(btn_row, False, False, 0)

        self.stack.add_named(outer, "unlock")

    def _build_workspace_page(self) -> None:
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        vbox.set_margin_top(10)
        vbox.set_margin_bottom(10)
        vbox.set_margin_start(12)
        vbox.set_margin_end(12)

        # Панель действий с файлами
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        vbox.pack_start(toolbar, False, False, 0)

        self.btn_add_files = Gtk.Button(label=self._t("btn_add_files"))
        self.btn_add_files.set_tooltip_text(self._t("tip_add_files"))
        self.btn_add_files.get_style_context().add_class("primary-button")
        self.btn_add_files.connect("clicked", self._on_add_files_clicked)
        toolbar.pack_start(self.btn_add_files, False, False, 0)

        self.btn_add_folder = Gtk.Button(label=self._t("btn_add_folder"))
        self.btn_add_folder.set_tooltip_text(self._t("tip_add_folder"))
        self.btn_add_folder.connect("clicked", self._on_add_folder_clicked)
        toolbar.pack_start(self.btn_add_folder, False, False, 0)

        self.btn_extract = Gtk.Button(label=self._t("btn_extract"))
        self.btn_extract.set_tooltip_text(self._t("tip_extract"))
        self.btn_extract.connect("clicked", self._on_extract_clicked)
        toolbar.pack_start(self.btn_extract, False, False, 0)

        self.btn_delete = Gtk.Button(label=self._t("btn_delete"))
        self.btn_delete.set_tooltip_text(self._t("tip_delete"))
        self.btn_delete.get_style_context().add_class("danger-button")
        self.btn_delete.connect("clicked", self._on_delete_clicked)
        toolbar.pack_start(self.btn_delete, False, False, 0)

        self.btn_verify = Gtk.Button(label=self._t("btn_verify"))
        self.btn_verify.set_tooltip_text(self._t("tip_verify"))
        self.btn_verify.connect("clicked", self._on_verify_integrity_clicked)
        toolbar.pack_start(self.btn_verify, False, False, 0)

        self.btn_backup = Gtk.Button(label=self._t("btn_backup"))
        self.btn_backup.set_tooltip_text(self._t("tip_backup"))
        self.btn_backup.connect("clicked", self._on_backup_clicked)
        toolbar.pack_start(self.btn_backup, False, False, 0)

        # Поле поиска по имени
        search_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.lbl_search = Gtk.Label(label=self._t("lbl_search"))
        search_box.pack_start(self.lbl_search, False, False, 0)
        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text(self._t("ph_search"))
        self.search_entry.set_size_request(220, -1)
        self.search_entry.connect("search-changed", lambda *_: self._refresh_file_list())
        search_box.pack_start(self.search_entry, True, True, 0)
        toolbar.pack_end(search_box, False, False, 0)

        # Стек для списка файлов и пустого состояния (Empty state)
        self.content_stack = Gtk.Stack()
        vbox.pack_start(self.content_stack, True, True, 0)

        # Таблица (TreeView) для отображения содержимого хранилища
        self.list_store = Gtk.ListStore(str, str, str, str, str, str, GObject.TYPE_INT64)
        self.tree_view = Gtk.TreeView(model=self.list_store)
        self.tree_view.set_headers_visible(True)
        self.tree_view.set_enable_search(True)
        self.tree_view.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE)

        self.tree_columns: List[Tuple[str, Gtk.TreeViewColumn]] = []
        columns_spec = [
            ("col_type", 1, 70),
            ("col_path", 0, 380),
            ("col_size", 3, 110),
            ("col_mtime", 4, 160),
            ("col_sha256", 5, 220),
        ]
        for col_key, col_idx, min_w in columns_spec:
            renderer = Gtk.CellRendererText()
            if col_idx == 0:
                renderer.set_property("ellipsize", Pango.EllipsizeMode.MIDDLE)
            col = Gtk.TreeViewColumn(self._t(col_key), renderer, text=col_idx)
            col.set_resizable(True)
            col.set_min_width(min_w)
            col.set_sort_column_id(col_idx)
            self.tree_view.append_column(col)
            self.tree_columns.append((col_key, col))

        scroll_win = Gtk.ScrolledWindow()
        scroll_win.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll_win.set_shadow_type(Gtk.ShadowType.IN)
        scroll_win.add(self.tree_view)
        self.content_stack.add_named(scroll_win, "table")

        # Пустое состояние
        empty_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        empty_box.set_valign(Gtk.Align.CENTER)
        empty_box.set_halign(Gtk.Align.CENTER)
        self.empty_state_label = Gtk.Label(label=self._t("empty_vault_markup"))
        self.empty_state_label.set_use_markup(True)
        self.empty_state_label.set_justify(Gtk.Justification.CENTER)
        empty_box.pack_start(self.empty_state_label, False, False, 0)
        self.content_stack.add_named(empty_box, "empty")

        # Настройка Drag-and-Drop
        target_entry = Gtk.TargetEntry.new("text/uri-list", 0, 0)
        vbox.drag_dest_set(Gtk.DestDefaults.ALL, [target_entry], Gdk.DragAction.COPY)
        vbox.connect("drag-data-received", self._on_drag_data_received)

        # Нижняя сводка по хранилищу
        self.summary_label = Gtk.Label(label="")
        self.summary_label.set_xalign(0.0)
        vbox.pack_start(self.summary_label, False, False, 0)

        self.stack.add_named(vbox, "workspace")

    # ------------------------------------------------------------------
    # Применение настроек темы, масштаба шрифта и локализации
    # ------------------------------------------------------------------
    def _resolve_effective_dark(self, theme_mode: str) -> bool:
        if theme_mode == "dark":
            return True
        if theme_mode == "light":
            return False
        return self._system_prefers_dark

    def _apply_theme(self, dark: bool) -> None:
        self.is_dark_theme = dark
        base_css = DARK_CSS if dark else LIGHT_CSS
        scale = self.app_settings.ui_font_scale
        if MIN_FONT_SCALE <= scale <= MAX_FONT_SCALE and scale != 100:
            font_css = f"\nwindow, dialog, messagedialog {{ font-size: {scale}%; }}\n"
        else:
            font_css = ""
        self.css_provider.load_from_data((base_css + font_css).encode("utf-8"))
        gtk_settings = Gtk.Settings.get_default()
        if gtk_settings is not None:
            try:
                if not hasattr(self, "_initial_gtk_theme"):
                    self._initial_gtk_theme = str(gtk_settings.get_property("gtk-theme-name") or "")
                gtk_settings.set_property("gtk-application-prefer-dark-theme", dark)
                init_t = getattr(self, "_initial_gtk_theme", "")
                if not dark and "-Dark" in init_t:
                    light_t = init_t.replace("-Dark", "")
                    if Path(f"/usr/share/themes/{light_t}").exists() or Path.home().joinpath(f".themes/{light_t}").exists():
                        gtk_settings.set_property("gtk-theme-name", light_t)
                elif dark and init_t:
                    gtk_settings.set_property("gtk-theme-name", init_t)
            except Exception:
                pass
        self.btn_theme_toggle.set_label(
            self._t("btn_theme_light") if dark else self._t("btn_theme_dark")
        )

    def _apply_settings_to_ui(self) -> None:
        effective_dark = self._resolve_effective_dark(self.app_settings.theme)
        self._apply_theme(effective_dark)
        self._retranslate_ui()

    def _retranslate_ui(self) -> None:
        """Обновляет все надписи, подсказки и заголовки интерфейса на выбранном языке без перезапуска."""
        self.set_title(self._t("window_title", app_name=__app_name__, version=__version__))
        self.app_title_label.set_markup(self._t("header_subtitle", app_name=__app_name__))

        self.btn_new_vault.set_label(self._t("btn_new_vault"))
        self.btn_new_vault.set_tooltip_text(self._t("tip_new_vault"))
        self.btn_open_vault.set_label(self._t("btn_open_vault"))
        self.btn_open_vault.set_tooltip_text(self._t("tip_open_vault"))
        self.btn_lock_vault.set_label(self._t("btn_lock_vault"))
        self.btn_lock_vault.set_tooltip_text(self._t("tip_lock_vault"))
        self.btn_settings.set_label(self._t("btn_settings"))
        self.btn_settings.set_tooltip_text(self._t("tip_settings"))
        self.btn_theme_toggle.set_label(
            self._t("btn_theme_light") if self.is_dark_theme else self._t("btn_theme_dark")
        )
        self.btn_theme_toggle.set_tooltip_text(self._t("tip_theme_toggle"))

        self.welcome_head_label.set_markup(self._t("welcome_title"))
        self.welcome_desc_label.set_markup(self._t("welcome_desc"))
        self.btn_welcome_create.set_label(self._t("welcome_btn_create"))
        self.btn_welcome_open.set_label(self._t("welcome_btn_open"))

        self.unlock_title_label.set_markup(self._t("unlock_title"))
        self.btn_clean_orphans.set_label(self._t("btn_clean_orphans"))
        self.chk_use_recovery.set_label(self._t("chk_use_recovery"))
        self._on_recovery_mode_toggled(self.chk_use_recovery)
        self.chk_show_secret.set_label(self._t("chk_show_secret"))
        self.btn_unlock_submit.set_label(self._t("btn_unlock_submit"))
        self.btn_cancel_unlock.set_label(self._t("btn_back"))

        if self.vault and not self.vault.is_unlocked:
            self.unlock_file_label.set_markup(
                self._t(
                    "unlock_file_info",
                    path=GLib.markup_escape_text(str(self.vault.vault_path)),
                    size=self._format_size(self._last_unlocked_file_size),
                )
            )
            orphans = self.vault.find_orphaned_temp_files()
            if orphans:
                self.orphan_warning_label.set_text(
                    self._t("orphan_warning_text", count=len(orphans))
                )

        self.btn_add_files.set_label(self._t("btn_add_files"))
        self.btn_add_files.set_tooltip_text(self._t("tip_add_files"))
        self.btn_add_folder.set_label(self._t("btn_add_folder"))
        self.btn_add_folder.set_tooltip_text(self._t("tip_add_folder"))
        self.btn_extract.set_label(self._t("btn_extract"))
        self.btn_extract.set_tooltip_text(self._t("tip_extract"))
        self.btn_delete.set_label(self._t("btn_delete"))
        self.btn_delete.set_tooltip_text(self._t("tip_delete"))
        self.btn_verify.set_label(self._t("btn_verify"))
        self.btn_verify.set_tooltip_text(self._t("tip_verify"))
        self.btn_backup.set_label(self._t("btn_backup"))
        self.btn_backup.set_tooltip_text(self._t("tip_backup"))

        self.lbl_search.set_text(self._t("lbl_search"))
        self.search_entry.set_placeholder_text(self._t("ph_search"))

        for col_key, col_obj in self.tree_columns:
            col_obj.set_title(self._t(col_key))

        self.btn_cancel_op.set_label(self._t("btn_cancel_op"))
        self._update_lock_indicator()
        if self.vault and self.vault.is_unlocked:
            self._refresh_file_list()
        else:
            self.empty_state_label.set_markup(self._t("empty_vault_markup"))
            if not self.is_busy and not self.vault:
                self.status_label.set_text(self._t("status_ready"))

    def _on_toggle_theme_clicked(self, _btn: Gtk.Button) -> None:
        self._record_user_activity()
        new_dark = not self.is_dark_theme
        self.app_settings.theme = "dark" if new_dark else "light"
        try:
            self.settings_manager.save(self.app_settings)
        except OSError:
            pass
        self._apply_theme(new_dark)

    def _update_lock_indicator(self) -> None:
        ctx = self.status_badge.get_style_context()
        ctx.remove_class("status-badge-locked")
        ctx.remove_class("status-badge-unlocked")

        if self.vault and self.vault.is_unlocked:
            self.status_badge.set_text(self._t("status_unlocked"))
            ctx.add_class("status-badge-unlocked")
            self.btn_lock_vault.set_sensitive(not self.is_busy)
            self.vault_path_label.set_text(str(self.vault.vault_path))
        elif self.vault:
            self.status_badge.set_text(self._t("status_locked"))
            ctx.add_class("status-badge-locked")
            self.btn_lock_vault.set_sensitive(False)
            self.vault_path_label.set_text(str(self.vault.vault_path))
        else:
            self.status_badge.set_text(self._t("status_locked"))
            ctx.add_class("status-badge-locked")
            self.btn_lock_vault.set_sensitive(False)
            self.vault_path_label.set_text(self._t("vault_not_selected"))

    def _set_busy_state(self, busy: bool, status_msg: str = "") -> None:
        self.is_busy = busy
        if status_msg:
            self.status_label.set_text(status_msg)

        for widget in (
            self.btn_new_vault,
            self.btn_open_vault,
            self.btn_settings,
            self.btn_add_files,
            self.btn_add_folder,
            self.btn_extract,
            self.btn_delete,
            self.btn_verify,
            self.btn_backup,
            self.btn_unlock_submit,
        ):
            widget.set_sensitive(not busy)

        self.btn_lock_vault.set_sensitive((not busy) and bool(self.vault and self.vault.is_unlocked))

        if busy:
            self.progress_bar.set_fraction(0.0)
            self.progress_bar.set_text(self._t("progress_running"))
            self.progress_bar.show()
            self.btn_cancel_op.show()
        else:
            self.progress_bar.hide()
            self.btn_cancel_op.hide()

    def _on_cancel_operation_clicked(self, _btn: Gtk.Button) -> None:
        self._record_user_activity()
        self._cancel_requested.set()
        self.status_label.set_text(self._t("status_cancel_requested"))

    def _run_background_task(
        self,
        description: str,
        worker_fn: Callable[[Callable[[], bool], Callable[[int, int, str], None]], Any],
        on_success: Callable[[Any], None],
        on_error: Optional[Callable[[Exception], None]] = None,
    ) -> None:
        """Запускает длительную криптографическую или файловую операцию в фоновом потоке."""
        if self.is_busy:
            self._show_message_dialog(
                Gtk.MessageType.WARNING,
                self._t("dlg_busy_title"),
                self._t("dlg_busy_body"),
            )
            return

        self._record_user_activity()
        self._cancel_requested.clear()
        self._set_busy_state(True, description)

        def _cancel_check() -> bool:
            return self._cancel_requested.is_set()

        last_ui_update = [0.0, -1]

        def _progress_cb(current: int, total: int, item_name: str) -> None:
            frac = min(1.0, max(0.0, float(current) / float(max(1, total))))
            pct = int(frac * 100)
            now_mono = time.monotonic()
            if current < total and pct == last_ui_update[1] and (now_mono - last_ui_update[0]) < 0.05:
                return
            last_ui_update[0] = now_mono
            last_ui_update[1] = pct
            short_name = item_name.rsplit("/", 1)[-1] if item_name else ""

            def _ui_prog() -> bool:
                self.progress_bar.set_fraction(frac)
                self.progress_bar.set_text(f"{pct}% ({short_name})")
                return False

            GLib.idle_add(_ui_prog)

        def _thread_target() -> None:
            try:
                result = worker_fn(_cancel_check, _progress_cb)
            except Exception as exc:
                def _ui_err(err: Exception = exc) -> bool:
                    self._active_worker_thread = None
                    self._set_busy_state(False)
                    self._record_user_activity()
                    if isinstance(err, OperationCancelledError):
                        self.status_label.set_text(self._t("status_cancelled"))
                    elif on_error is not None:
                        on_error(err)
                    else:
                        self.status_label.set_text(self._t("status_error_prefix", err=err))
                        self._show_message_dialog(
                            Gtk.MessageType.ERROR,
                            self._t("dlg_op_failed_title"),
                            str(err),
                        )
                    return False

                GLib.idle_add(_ui_err)
                return

            def _ui_done() -> bool:
                self._active_worker_thread = None
                self._set_busy_state(False)
                self._record_user_activity()
                on_success(result)
                return False

            GLib.idle_add(_ui_done)

        t = threading.Thread(target=_thread_target, daemon=True)
        self._active_worker_thread = t
        t.start()

    # ------------------------------------------------------------------
    # Диалоги и окно настроек
    # ------------------------------------------------------------------
    def _show_message_dialog(self, msg_type: Gtk.MessageType, title: str, details: str) -> None:
        dlg = Gtk.MessageDialog(
            transient_for=self,
            flags=0,
            message_type=msg_type,
            buttons=Gtk.ButtonsType.NONE,
            text=title,
        )
        dlg.format_secondary_text(details)
        dlg.add_button(self._t("btn_ok"), Gtk.ResponseType.OK)
        dlg.run()
        dlg.destroy()

    def _ask_confirmation(
        self,
        title: str,
        details: str,
        confirm_label: Optional[str] = None,
        cancel_label: Optional[str] = None,
    ) -> bool:
        dlg = Gtk.MessageDialog(
            transient_for=self,
            flags=0,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.NONE,
            text=title,
        )
        dlg.format_secondary_text(details)
        dlg.add_button(cancel_label or self._t("btn_cancel"), Gtk.ResponseType.CANCEL)
        btn_ok = dlg.add_button(confirm_label or self._t("btn_confirm"), Gtk.ResponseType.OK)
        btn_ok.get_style_context().add_class("danger-button")
        dlg.set_default_response(Gtk.ResponseType.CANCEL)
        resp = dlg.run()
        dlg.destroy()
        return resp == Gtk.ResponseType.OK

    def _on_settings_clicked(self, _btn: Gtk.Button) -> None:
        if self.is_busy:
            return
        self._record_user_activity()
        self.open_settings_dialog()

    def open_settings_dialog(self) -> bool:
        """
        Открывает диалоговое окно настроек MintVault (GTK 3).
        Возвращает True, если настройки были сохранены.
        """
        lang = self.app_settings.language
        dlg = Gtk.Dialog(
            title=tr(lang, "settings_title"),
            transient_for=self,
            flags=Gtk.DialogFlags.MODAL,
        )
        btn_reset = dlg.add_button(tr(lang, "settings_btn_reset_defaults"), Gtk.ResponseType.REJECT)
        dlg.add_button(tr(lang, "btn_cancel"), Gtk.ResponseType.CANCEL)
        btn_save = dlg.add_button(tr(lang, "btn_save"), Gtk.ResponseType.OK)
        btn_save.get_style_context().add_class("primary-button")
        dlg.set_default_size(680, 620)

        content = dlg.get_content_area()
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        content.pack_start(scroll, True, True, 0)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        main_box.set_margin_top(14)
        main_box.set_margin_bottom(14)
        main_box.set_margin_start(16)
        main_box.set_margin_end(16)
        scroll.add(main_box)

        # --- Секция 1: Внешний вид и язык ---
        sec1 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        sec1.get_style_context().add_class("card-panel")
        main_box.pack_start(sec1, False, False, 0)

        lbl_s1 = Gtk.Label(
            label=f"<b>{GLib.markup_escape_text(tr(lang, 'settings_sec_appearance'))}</b>"
        )
        lbl_s1.set_use_markup(True)
        lbl_s1.set_xalign(0.0)
        sec1.pack_start(lbl_s1, False, False, 0)

        grid1 = Gtk.Grid()
        grid1.set_column_spacing(12)
        grid1.set_row_spacing(8)
        sec1.pack_start(grid1, False, False, 0)

        lbl_theme = Gtk.Label(label=tr(lang, "settings_lbl_theme"))
        lbl_theme.set_xalign(0.0)
        lbl_theme.set_hexpand(True)
        combo_theme = Gtk.ComboBoxText()
        combo_theme.append("system", tr(lang, "settings_theme_system"))
        combo_theme.append("light", tr(lang, "settings_theme_light"))
        combo_theme.append("dark", tr(lang, "settings_theme_dark"))
        combo_theme.set_active_id(self.app_settings.theme)
        grid1.attach(lbl_theme, 0, 0, 1, 1)
        grid1.attach(combo_theme, 1, 0, 1, 1)

        lbl_lang = Gtk.Label(label=tr(lang, "settings_lbl_language"))
        lbl_lang.set_xalign(0.0)
        combo_lang = Gtk.ComboBoxText()
        combo_lang.append("ru", tr(lang, "settings_lang_ru"))
        combo_lang.append("en", tr(lang, "settings_lang_en"))
        combo_lang.set_active_id(self.app_settings.language)
        grid1.attach(lbl_lang, 0, 1, 1, 1)
        grid1.attach(combo_lang, 1, 1, 1, 1)

        lbl_font = Gtk.Label(label=tr(lang, "settings_lbl_font_scale"))
        lbl_font.set_xalign(0.0)
        adj_font = Gtk.Adjustment(
            value=self.app_settings.ui_font_scale,
            lower=MIN_FONT_SCALE,
            upper=MAX_FONT_SCALE,
            step_increment=5,
            page_increment=10,
        )
        spin_font = Gtk.SpinButton(adjustment=adj_font, climb_rate=1.0, digits=0)
        grid1.attach(lbl_font, 0, 2, 1, 1)
        grid1.attach(spin_font, 1, 2, 1, 1)

        # --- Секция 2: Поведение при добавлении файлов (работа с оригиналами) ---
        sec2 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        sec2.get_style_context().add_class("card-panel")
        main_box.pack_start(sec2, False, False, 0)

        lbl_s2 = Gtk.Label(
            label=f"<b>{GLib.markup_escape_text(tr(lang, 'settings_sec_originals'))}</b>"
        )
        lbl_s2.set_use_markup(True)
        lbl_s2.set_xalign(0.0)
        sec2.pack_start(lbl_s2, False, False, 0)

        note_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        note_box.get_style_context().add_class("warning-box")
        lbl_note = Gtk.Label(label=tr(lang, "settings_originals_note"))
        lbl_note.set_line_wrap(True)
        lbl_note.set_xalign(0.0)
        note_box.pack_start(lbl_note, False, False, 0)
        sec2.pack_start(note_box, False, False, 0)

        dup_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        lbl_dup = Gtk.Label(label=tr(lang, "settings_lbl_dup_action"))
        lbl_dup.set_xalign(0.0)
        lbl_dup.set_hexpand(True)
        combo_dup = Gtk.ComboBoxText()
        combo_dup.append("ask", tr(lang, "settings_dup_ask"))
        combo_dup.append("replace", tr(lang, "settings_dup_replace"))
        combo_dup.append("keep_both", tr(lang, "settings_dup_keep_both"))
        combo_dup.append("skip", tr(lang, "settings_dup_skip"))
        combo_dup.append("error", tr(lang, "settings_dup_error"))
        combo_dup.set_active_id(self.app_settings.duplicate_file_action)
        dup_row.pack_start(lbl_dup, True, True, 0)
        dup_row.pack_start(combo_dup, False, False, 0)
        sec2.pack_start(dup_row, False, False, 2)

        chk_ask_del_orig = Gtk.CheckButton(
            label=tr(lang, "settings_chk_ask_before_deleting_originals")
        )
        chk_ask_del_orig.set_active(self.app_settings.ask_before_deleting_originals)
        sec2.pack_start(chk_ask_del_orig, False, False, 0)

        chk_offer_del_orig = Gtk.CheckButton(
            label=tr(lang, "settings_chk_offer_delete_originals")
        )
        chk_offer_del_orig.set_active(self.app_settings.offer_delete_originals_after_add)
        sec2.pack_start(chk_offer_del_orig, False, False, 0)

        suppress_toggle_warn = {"active": False}

        def _on_offer_del_toggled(btn: Gtk.CheckButton) -> None:
            if suppress_toggle_warn["active"]:
                return
            if btn.get_active():
                cur_l = combo_lang.get_active_id() or self.app_settings.language
                warn_dlg = Gtk.MessageDialog(
                    transient_for=dlg,
                    flags=Gtk.DialogFlags.MODAL,
                    message_type=Gtk.MessageType.WARNING,
                    buttons=Gtk.ButtonsType.NONE,
                    text=tr(cur_l, "settings_warn_delete_originals_title"),
                )
                warn_dlg.format_secondary_text(tr(cur_l, "settings_warn_delete_originals_body"))
                warn_dlg.add_button(tr(cur_l, "btn_ok"), Gtk.ResponseType.OK)
                warn_dlg.run()
                warn_dlg.destroy()

        chk_offer_del_orig.connect("toggled", _on_offer_del_toggled)

        # --- Секция 3: Безопасность и подтверждения ---
        sec3 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        sec3.get_style_context().add_class("card-panel")
        main_box.pack_start(sec3, False, False, 0)

        lbl_s3 = Gtk.Label(
            label=f"<b>{GLib.markup_escape_text(tr(lang, 'settings_sec_security'))}</b>"
        )
        lbl_s3.set_use_markup(True)
        lbl_s3.set_xalign(0.0)
        sec3.pack_start(lbl_s3, False, False, 0)

        chk_conf_vdel = Gtk.CheckButton(label=tr(lang, "settings_chk_confirm_vault_delete"))
        chk_conf_vdel.set_active(self.app_settings.confirm_before_vault_delete)
        sec3.pack_start(chk_conf_vdel, False, False, 0)

        chk_conf_lext = Gtk.CheckButton(label=tr(lang, "settings_chk_confirm_large_extract"))
        chk_conf_lext.set_active(self.app_settings.confirm_large_extraction)
        sec3.pack_start(chk_conf_lext, False, False, 0)

        grid3 = Gtk.Grid()
        grid3.set_column_spacing(12)
        grid3.set_row_spacing(8)
        sec3.pack_start(grid3, False, False, 0)

        lbl_thresh = Gtk.Label(label=tr(lang, "settings_lbl_large_extract_threshold"))
        lbl_thresh.set_xalign(0.0)
        lbl_thresh.set_hexpand(True)
        adj_thresh = Gtk.Adjustment(
            value=self.app_settings.large_extraction_threshold,
            lower=MIN_LARGE_EXTRACTION_THRESHOLD,
            upper=MAX_LARGE_EXTRACTION_THRESHOLD,
            step_increment=1,
            page_increment=10,
        )
        spin_thresh = Gtk.SpinButton(adjustment=adj_thresh, climb_rate=1.0, digits=0)
        grid3.attach(lbl_thresh, 0, 0, 1, 1)
        grid3.attach(spin_thresh, 1, 0, 1, 1)

        lbl_close = Gtk.Label(label=tr(lang, "settings_lbl_close_action"))
        lbl_close.set_xalign(0.0)
        combo_close = Gtk.ComboBoxText()
        combo_close.append("lock_and_close", tr(lang, "settings_close_lock_immediately"))
        combo_close.append("ask", tr(lang, "settings_close_ask"))
        combo_close.set_active_id(self.app_settings.close_unlocked_action)
        grid3.attach(lbl_close, 0, 1, 1, 1)
        grid3.attach(combo_close, 1, 1, 1, 1)

        lbl_autolock = Gtk.Label(label=tr(lang, "settings_lbl_auto_lock"))
        lbl_autolock.set_xalign(0.0)
        adj_autolock = Gtk.Adjustment(
            value=self.app_settings.auto_lock_minutes,
            lower=MIN_AUTO_LOCK_MINUTES,
            upper=MAX_AUTO_LOCK_MINUTES,
            step_increment=1,
            page_increment=5,
        )
        spin_autolock = Gtk.SpinButton(adjustment=adj_autolock, climb_rate=1.0, digits=0)
        grid3.attach(lbl_autolock, 0, 2, 1, 1)
        grid3.attach(spin_autolock, 1, 2, 1, 1)

        chk_notify_long = Gtk.CheckButton(label=tr(lang, "settings_chk_notify_long_ops"))
        chk_notify_long.set_active(self.app_settings.notify_long_operations)
        sec3.pack_start(chk_notify_long, False, False, 0)

        lbl_bak_dir = Gtk.Label(label=tr(lang, "settings_lbl_backup_dir"))
        lbl_bak_dir.set_xalign(0.0)
        sec3.pack_start(lbl_bak_dir, False, False, 0)

        bak_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        entry_bak_dir = Gtk.Entry()
        entry_bak_dir.set_placeholder_text(tr(lang, "settings_ph_backup_dir"))
        entry_bak_dir.set_text(self.app_settings.default_backup_dir)
        btn_bak_browse = Gtk.Button(label=tr(lang, "btn_browse"))
        btn_bak_clear = Gtk.Button(label=tr(lang, "settings_btn_clear_dir"))

        def _on_browse_bak(_b: Gtk.Button) -> None:
            cur_l = combo_lang.get_active_id() or self.app_settings.language
            fc = Gtk.FileChooserDialog(
                title=tr(cur_l, "settings_lbl_backup_dir"),
                parent=dlg,
                action=Gtk.FileChooserAction.SELECT_FOLDER,
            )
            fc.add_buttons(
                tr(cur_l, "btn_cancel"), Gtk.ResponseType.CANCEL,
                tr(cur_l, "btn_choose"), Gtk.ResponseType.OK,
            )
            if fc.run() == Gtk.ResponseType.OK:
                folder = fc.get_filename()
                if folder:
                    entry_bak_dir.set_text(folder)
            fc.destroy()

        btn_bak_browse.connect("clicked", _on_browse_bak)
        btn_bak_clear.connect("clicked", lambda *_: entry_bak_dir.set_text(""))
        bak_row.pack_start(entry_bak_dir, True, True, 0)
        bak_row.pack_start(btn_bak_browse, False, False, 0)
        bak_row.pack_start(btn_bak_clear, False, False, 0)
        sec3.pack_start(bak_row, False, False, 0)

        def _populate_from_settings(s: AppSettings) -> None:
            suppress_toggle_warn["active"] = True
            try:
                combo_theme.set_active_id(s.theme)
                combo_lang.set_active_id(s.language)
                spin_font.set_value(s.ui_font_scale)
                combo_dup.set_active_id(s.duplicate_file_action)
                chk_ask_del_orig.set_active(s.ask_before_deleting_originals)
                chk_offer_del_orig.set_active(s.offer_delete_originals_after_add)
                chk_conf_vdel.set_active(s.confirm_before_vault_delete)
                chk_conf_lext.set_active(s.confirm_large_extraction)
                spin_thresh.set_value(s.large_extraction_threshold)
                combo_close.set_active_id(s.close_unlocked_action)
                spin_autolock.set_value(s.auto_lock_minutes)
                chk_notify_long.set_active(s.notify_long_operations)
                entry_bak_dir.set_text(s.default_backup_dir)
            finally:
                suppress_toggle_warn["active"] = False

        btn_reset.connect("clicked", lambda *_: _populate_from_settings(AppSettings()))

        content.show_all()
        saved = False
        while True:
            resp = dlg.run()
            if resp == Gtk.ResponseType.REJECT:
                continue
            if resp != Gtk.ResponseType.OK:
                break

            new_cfg = AppSettings(
                theme=combo_theme.get_active_id() or "system",
                ui_font_scale=int(spin_font.get_value_as_int()),
                duplicate_file_action=combo_dup.get_active_id() or "ask",
                ask_before_deleting_originals=chk_ask_del_orig.get_active(),
                offer_delete_originals_after_add=chk_offer_del_orig.get_active(),
                language=combo_lang.get_active_id() or "ru",
                confirm_before_vault_delete=chk_conf_vdel.get_active(),
                confirm_large_extraction=chk_conf_lext.get_active(),
                large_extraction_threshold=int(spin_thresh.get_value_as_int()),
                close_unlocked_action=combo_close.get_active_id() or "lock_and_close",
                auto_lock_minutes=int(spin_autolock.get_value_as_int()),
                notify_long_operations=chk_notify_long.get_active(),
                default_backup_dir=entry_bak_dir.get_text().strip(),
            )
            self.app_settings = self.settings_manager.save(new_cfg)
            self._apply_settings_to_ui()
            self.status_label.set_text(self._t("status_settings_saved"))
            saved = True
            break

        dlg.destroy()
        return saved

    # ------------------------------------------------------------------
    # Создание и открытие хранилища
    # ------------------------------------------------------------------
    def _on_new_vault_clicked(self, _btn: Gtk.Button) -> None:
        if self.is_busy:
            return
        self._record_user_activity()

        dlg = Gtk.Dialog(
            title=self._t("dlg_new_vault_title"),
            transient_for=self,
            flags=Gtk.DialogFlags.MODAL,
        )
        dlg.add_button(self._t("btn_cancel"), Gtk.ResponseType.CANCEL)
        btn_create = dlg.add_button(self._t("btn_new_vault"), Gtk.ResponseType.OK)
        btn_create.get_style_context().add_class("primary-button")
        dlg.set_default_size(560, -1)

        box = dlg.get_content_area()
        box.set_spacing(10)
        box.set_margin_top(14)
        box.set_margin_bottom(14)
        box.set_margin_start(16)
        box.set_margin_end(16)

        warn_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        warn_box.get_style_context().add_class("warning-box")
        warn_lbl = Gtk.Label(label=self._t("dlg_new_vault_warn"))
        warn_lbl.set_use_markup(True)
        warn_lbl.set_line_wrap(True)
        warn_lbl.set_xalign(0.0)
        warn_box.pack_start(warn_lbl, False, False, 0)
        box.pack_start(warn_box, False, False, 0)

        lbl_path = Gtk.Label(label=self._t("lbl_new_vault_path"))
        lbl_path.set_xalign(0.0)
        box.pack_start(lbl_path, False, False, 0)

        path_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        entry_path = Gtk.Entry()
        default_dir = Path.home() / self._t("default_vault_filename")
        entry_path.set_text(str(default_dir))
        btn_browse = Gtk.Button(label=self._t("btn_browse"))

        def _on_browse(_b: Gtk.Button) -> None:
            fc = Gtk.FileChooserDialog(
                title=self._t("fc_save_vault_title"),
                parent=dlg,
                action=Gtk.FileChooserAction.SAVE,
            )
            fc.add_buttons(
                self._t("btn_cancel"), Gtk.ResponseType.CANCEL,
                self._t("btn_choose"), Gtk.ResponseType.OK,
            )
            fc.set_current_name(self._t("default_vault_filename"))
            if fc.run() == Gtk.ResponseType.OK:
                chosen = fc.get_filename()
                if chosen:
                    if not chosen.endswith(".mvault"):
                        chosen += ".mvault"
                    entry_path.set_text(chosen)
            fc.destroy()

        btn_browse.connect("clicked", _on_browse)
        path_row.pack_start(entry_path, True, True, 0)
        path_row.pack_start(btn_browse, False, False, 0)
        box.pack_start(path_row, False, False, 0)

        lbl_p1 = Gtk.Label(label=self._t("lbl_master_pwd1"))
        lbl_p1.set_xalign(0.0)
        box.pack_start(lbl_p1, False, False, 0)
        entry_p1 = Gtk.Entry()
        entry_p1.set_visibility(False)
        box.pack_start(entry_p1, False, False, 0)

        lbl_p2 = Gtk.Label(label=self._t("lbl_master_pwd2"))
        lbl_p2.set_xalign(0.0)
        box.pack_start(lbl_p2, False, False, 0)
        entry_p2 = Gtk.Entry()
        entry_p2.set_visibility(False)
        box.pack_start(entry_p2, False, False, 0)

        chk_show = Gtk.CheckButton(label=self._t("chk_show_pwd"))

        def _toggle_vis(b: Gtk.CheckButton) -> None:
            vis = b.get_active()
            entry_p1.set_visibility(vis)
            entry_p2.set_visibility(vis)

        chk_show.connect("toggled", _toggle_vis)
        box.pack_start(chk_show, False, False, 0)

        chk_recovery = Gtk.CheckButton(label=self._t("chk_gen_recovery"))
        chk_recovery.set_active(True)
        box.pack_start(chk_recovery, False, False, 0)

        lbl_err = Gtk.Label(label="")
        lbl_err.set_use_markup(True)
        lbl_err.set_xalign(0.0)
        box.pack_start(lbl_err, False, False, 0)

        box.show_all()

        while True:
            resp = dlg.run()
            if resp != Gtk.ResponseType.OK:
                entry_p1.set_text("")
                entry_p2.set_text("")
                dlg.destroy()
                return

            vault_file_str = entry_path.get_text().strip()
            p1 = entry_p1.get_text()
            p2 = entry_p2.get_text()
            gen_rec = chk_recovery.get_active()

            if not vault_file_str:
                lbl_err.set_markup(self._t("err_specify_vault_path"))
                continue
            if Path(vault_file_str).exists() or Path(vault_file_str).is_symlink():
                lbl_err.set_markup(self._t("err_vault_already_exists"))
                continue
            if len(p1) < 6:
                lbl_err.set_markup(self._t("err_pwd_too_short"))
                continue
            if p1 != p2:
                lbl_err.set_markup(self._t("err_pwd_mismatch"))
                continue

            break

        entry_p1.set_text("")
        entry_p2.set_text("")
        dlg.destroy()

        self._close_current_vault()

        def _worker(
            _cancel_cb: Callable[[], bool],
            _prog_cb: Callable[[int, int, str], None],
        ) -> Tuple[SecureVault, Optional[str]]:
            return SecureVault.create(
                vault_path=vault_file_str,
                password=p1,
                create_recovery_key=gen_rec,
            )

        def _on_created(res: Tuple[SecureVault, Optional[str]]) -> None:
            new_vault, rec_key = res
            self.vault = new_vault
            self._update_lock_indicator()
            self._refresh_file_list()
            self.stack.set_visible_child_name("workspace")
            self.status_label.set_text(
                self._t("status_vault_created", name=new_vault.vault_path.name)
            )
            if rec_key:
                self._show_recovery_key_dialog(rec_key, new_vault.vault_path)

        self._run_background_task(self._t("task_creating_vault"), _worker, _on_created)

    def _show_recovery_key_dialog(self, recovery_key: str, vault_path: Path) -> None:
        dlg = Gtk.Dialog(
            title=self._t("dlg_rec_key_title"),
            transient_for=self,
            flags=Gtk.DialogFlags.MODAL,
        )
        dlg.add_button(self._t("btn_rec_key_saved"), Gtk.ResponseType.OK)
        dlg.set_default_size(580, -1)

        box = dlg.get_content_area()
        box.set_spacing(12)
        box.set_margin_top(16)
        box.set_margin_bottom(16)
        box.set_margin_start(16)
        box.set_margin_end(16)

        lbl_info = Gtk.Label(label=self._t("dlg_rec_key_info"))
        lbl_info.set_use_markup(True)
        lbl_info.set_line_wrap(True)
        lbl_info.set_xalign(0.0)
        box.pack_start(lbl_info, False, False, 0)

        key_entry = Gtk.Entry()
        key_entry.set_text(recovery_key)
        key_entry.set_editable(False)
        box.pack_start(key_entry, False, False, 0)

        btn_save_file = Gtk.Button(label=self._t("btn_save_rec_file"))

        def _on_save_rec(_b: Gtk.Button) -> None:
            fc = Gtk.FileChooserDialog(
                title=self._t("fc_save_rec_title"),
                parent=dlg,
                action=Gtk.FileChooserAction.SAVE,
            )
            fc.add_buttons(
                self._t("btn_cancel"), Gtk.ResponseType.CANCEL,
                self._t("btn_save"), Gtk.ResponseType.OK,
            )
            fc.set_current_name(f"{vault_path.stem}_RECOVERY_KEY.txt")
            if fc.run() == Gtk.ResponseType.OK:
                out_file = fc.get_filename()
                if out_file:
                    try:
                        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                        fd = os.open(out_file, flags, 0o600)
                        with os.fdopen(fd, "w", encoding="utf-8") as f:
                            f.write(
                                self._t(
                                    "rec_file_content",
                                    vault_name=vault_path.name,
                                    date=datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
                                    recovery_key=recovery_key,
                                )
                            )
                            f.flush()
                            os.fsync(f.fileno())
                        self._show_message_dialog(
                            Gtk.MessageType.INFO,
                            self._t("dlg_rec_saved_title"),
                            self._t("dlg_rec_saved_body", path=out_file),
                        )
                    except OSError as exc:
                        self._show_message_dialog(
                            Gtk.MessageType.ERROR,
                            self._t("dlg_save_err_title"),
                            str(exc),
                        )
            fc.destroy()

        btn_save_file.connect("clicked", _on_save_rec)
        box.pack_start(btn_save_file, False, False, 0)

        box.show_all()
        dlg.run()
        key_entry.set_text("")
        dlg.destroy()

    def _on_open_vault_clicked(self, _btn: Gtk.Button) -> None:
        if self.is_busy:
            return
        self._record_user_activity()
        fc = Gtk.FileChooserDialog(
            title=self._t("fc_open_vault_title"),
            parent=self,
            action=Gtk.FileChooserAction.OPEN,
        )
        fc.add_buttons(
            self._t("btn_cancel"), Gtk.ResponseType.CANCEL,
            self._t("btn_open_vault"), Gtk.ResponseType.OK,
        )

        flt_mvault = Gtk.FileFilter()
        flt_mvault.set_name(self._t("flt_mvault_name"))
        flt_mvault.add_pattern("*.mvault")
        fc.add_filter(flt_mvault)

        flt_all = Gtk.FileFilter()
        flt_all.set_name(self._t("flt_all_name"))
        flt_all.add_pattern("*")
        fc.add_filter(flt_all)

        resp = fc.run()
        chosen = fc.get_filename()
        fc.destroy()

        if resp == Gtk.ResponseType.OK and chosen:
            self._prepare_open_vault(Path(chosen))

    def _prepare_open_vault(self, vault_path: Path) -> None:
        self._close_current_vault()
        try:
            info = SecureVault.inspect_header(vault_path)
        except Exception as exc:
            self._show_message_dialog(
                Gtk.MessageType.ERROR,
                self._t("dlg_open_err_title"),
                str(exc),
            )
            return

        self.vault = SecureVault(vault_path)
        self._last_unlocked_file_size = int(info["file_size"])
        self._update_lock_indicator()

        slot_types = [s.get("slot_type") for s in info["header"].get("key_slots", [])]
        has_rec = "recovery" in slot_types
        self.chk_use_recovery.set_sensitive(has_rec)
        self.chk_use_recovery.set_active(False)

        self.unlock_file_label.set_markup(
            self._t(
                "unlock_file_info",
                path=GLib.markup_escape_text(str(vault_path)),
                size=self._format_size(info["file_size"]),
            )
        )
        self.entry_unlock_secret.set_text("")
        self.unlock_error_label.set_text("")

        orphans = self.vault.find_orphaned_temp_files()
        if orphans:
            self.orphan_warning_label.set_text(
                self._t("orphan_warning_text", count=len(orphans))
            )
            self.orphan_warning_box.show_all()
        else:
            self.orphan_warning_box.hide()

        self.stack.set_visible_child_name("unlock")
        self.entry_unlock_secret.grab_focus()
        self.status_label.set_text(self._t("status_vault_selected", name=vault_path.name))

    def _on_clean_orphans_clicked(self, _btn: Gtk.Button) -> None:
        if not self.vault:
            return
        self._record_user_activity()
        removed = self.vault.cleanup_orphaned_temp_files()
        self.orphan_warning_box.hide()
        self.status_label.set_text(self._t("status_orphans_cleaned", count=removed))

    def _on_recovery_mode_toggled(self, btn: Gtk.CheckButton) -> None:
        if btn.get_active():
            self.lbl_secret_prompt.set_text(self._t("lbl_enter_recovery"))
            self.entry_unlock_secret.set_placeholder_text(self._t("ph_recovery"))
        else:
            self.lbl_secret_prompt.set_text(self._t("lbl_enter_password"))
            self.entry_unlock_secret.set_placeholder_text(self._t("ph_password_or_rec"))

    def _on_unlock_submit_clicked(self, *_args: Any) -> None:
        if not self.vault or self.is_busy:
            return
        self._record_user_activity()
        secret = self.entry_unlock_secret.get_text()
        use_rec = self.chk_use_recovery.get_active()
        if not secret:
            self.unlock_error_label.set_markup(self._t("err_empty_secret"))
            return

        self.entry_unlock_secret.set_text("")
        self.unlock_error_label.set_text("")
        target_vault = self.vault

        def _worker(_cancel_cb: Callable[[], bool], _prog_cb: Callable[[int, int, str], None]) -> None:
            target_vault.unlock(secret, use_recovery_key=use_rec)

        def _on_unlocked(_res: None) -> None:
            self._record_user_activity()
            self._update_lock_indicator()
            self._refresh_file_list()
            self.stack.set_visible_child_name("workspace")
            self.status_label.set_text(
                self._t("status_unlocked_ok", name=target_vault.vault_path.name)
            )

        def _on_unlock_err(err: Exception) -> None:
            escaped = GLib.markup_escape_text(str(err))
            self.unlock_error_label.set_markup(f"<span foreground='#cf222e'>{escaped}</span>")
            self.status_label.set_text(self._t("status_error_prefix", err=err))

        self._run_background_task(
            self._t("task_unlocking"),
            _worker,
            _on_unlocked,
            on_error=_on_unlock_err,
        )

    def _on_lock_vault_clicked(self, _btn: Gtk.Button) -> None:
        if self.is_busy or not self.vault:
            return
        self._record_user_activity()
        v_path = self.vault.vault_path
        self.vault.lock()
        self._prepare_open_vault(v_path)
        self.status_label.set_text(self._t("status_locked_ok"))

    def _close_current_vault(self) -> None:
        if self.vault:
            self.vault.close()
            self.vault = None
        self.list_store.clear()
        self._update_lock_indicator()
        self.stack.set_visible_child_name("welcome")

    # ------------------------------------------------------------------
    # Работа с содержимым хранилища
    # ------------------------------------------------------------------
    def _refresh_file_list(self) -> None:
        self.list_store.clear()
        if not self.vault or not self.vault.is_unlocked:
            return

        query = self.search_entry.get_text()
        entries = self.vault.list_entries(search_query=query)

        total_files = 0
        total_dirs = 0
        total_bytes = 0

        for entry in entries:
            if entry.entry_type == "dir":
                total_dirs += 1
                icon_lbl = self._t("type_dir")
                size_str = "—"
                sha_short = "—"
            else:
                total_files += 1
                total_bytes += entry.size
                icon_lbl = self._t("type_file")
                size_str = self._format_size(entry.size)
                sha_short = entry.sha256[:16] + "…" if entry.sha256 else "—"

            self.list_store.append([
                entry.virtual_path,
                icon_lbl,
                entry.virtual_path.rsplit("/", 1)[-1],
                size_str,
                format_timestamp_localized(entry.mtime),
                sha_short,
                entry.size,
            ])

        if len(entries) == 0:
            if query.strip():
                self.empty_state_label.set_markup(
                    self._t("empty_search_markup", query=GLib.markup_escape_text(query))
                )
            else:
                self.empty_state_label.set_markup(self._t("empty_vault_markup"))
            self.content_stack.set_visible_child_name("empty")
        else:
            self.content_stack.set_visible_child_name("table")

        self.summary_label.set_text(
            self._t(
                "summary_line",
                files=total_files,
                dirs=total_dirs,
                size=self._format_size(total_bytes),
            )
        )

    def _get_selected_virtual_paths(self) -> List[str]:
        selection = self.tree_view.get_selection()
        model, tree_paths = selection.get_selected_rows()
        selected: List[str] = []
        for tp in tree_paths:
            it = model.get_iter(tp)
            vp = model.get_value(it, 0)
            if vp:
                selected.append(str(vp))
        return selected

    def _on_add_files_clicked(self, _btn: Gtk.Button) -> None:
        if not self.vault or not self.vault.is_unlocked or self.is_busy:
            return
        self._record_user_activity()
        fc = Gtk.FileChooserDialog(
            title=self._t("fc_add_files_title"),
            parent=self,
            action=Gtk.FileChooserAction.OPEN,
        )
        fc.set_select_multiple(True)
        fc.add_buttons(
            self._t("btn_cancel"), Gtk.ResponseType.CANCEL,
            self._t("btn_fc_add_files"), Gtk.ResponseType.OK,
        )
        resp = fc.run()
        filenames = fc.get_filenames()
        fc.destroy()

        if resp == Gtk.ResponseType.OK and filenames:
            self._execute_add_paths([Path(f) for f in filenames])

    def _on_add_folder_clicked(self, _btn: Gtk.Button) -> None:
        if not self.vault or not self.vault.is_unlocked or self.is_busy:
            return
        self._record_user_activity()
        fc = Gtk.FileChooserDialog(
            title=self._t("fc_add_folder_title"),
            parent=self,
            action=Gtk.FileChooserAction.SELECT_FOLDER,
        )
        fc.set_select_multiple(True)
        fc.add_buttons(
            self._t("btn_cancel"), Gtk.ResponseType.CANCEL,
            self._t("btn_fc_add_folder"), Gtk.ResponseType.OK,
        )
        resp = fc.run()
        folders = fc.get_filenames()
        fc.destroy()

        if resp == Gtk.ResponseType.OK and folders:
            self._execute_add_paths([Path(f) for f in folders])

    def _on_drag_data_received(
        self,
        _widget: Gtk.Widget,
        drag_context: Gdk.DragContext,
        _x: int,
        _y: int,
        selection_data: Gtk.SelectionData,
        _info: int,
        time_stamp: int,
    ) -> None:
        self._record_user_activity()
        if not self.vault or not self.vault.is_unlocked or self.is_busy:
            Gtk.drag_finish(drag_context, False, False, time_stamp)
            return

        uris = selection_data.get_uris()
        paths: List[Path] = []
        for uri in uris:
            if uri.startswith("file://"):
                parsed = urllib.parse.urlparse(uri)
                if parsed.netloc not in ("", "localhost"):
                    continue
                local_path = urllib.parse.unquote(parsed.path)
                if local_path and "\x00" not in local_path:
                    paths.append(Path(local_path))

        Gtk.drag_finish(drag_context, bool(paths), False, time_stamp)
        if paths:
            self._execute_add_paths(paths)

    def _ask_duplicate_conflict_resolution(self, conflicts: List[str]) -> Optional[str]:
        """
        Показывает диалог выбора действия при совпадении имён файлов в хранилище.
        Возвращает 'replace', 'keep_both', 'skip' или None (если нажата Отмена).
        """
        preview = "\n".join(f"• {vp}" for vp in conflicts[:8])
        if len(conflicts) > 8:
            preview += "\n" + self._t("and_more_items", count=len(conflicts) - 8)

        dlg = Gtk.MessageDialog(
            transient_for=self,
            flags=Gtk.DialogFlags.MODAL,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.NONE,
            text=self._t("dlg_dup_conflict_title"),
        )
        dlg.format_secondary_text(
            self._t("dlg_dup_conflict_body", count=len(conflicts), preview=preview)
        )
        dlg.add_button(self._t("btn_cancel"), Gtk.ResponseType.CANCEL)
        dlg.add_button(self._t("btn_dup_skip"), 101)
        btn_copy = dlg.add_button(self._t("btn_dup_keep_both"), 102)
        btn_copy.get_style_context().add_class("primary-button")
        btn_repl = dlg.add_button(self._t("btn_dup_replace"), 103)
        btn_repl.get_style_context().add_class("danger-button")
        dlg.set_default_response(102)

        resp = dlg.run()
        dlg.destroy()
        if resp == 103:
            return "replace"
        if resp == 102:
            return "keep_both"
        if resp == 101:
            return "skip"
        return None

    def _execute_add_paths(self, paths: List[Path]) -> None:
        if not self.vault or not self.vault.is_unlocked:
            return
        target_vault = self.vault
        # Фиксируем снимок настроек на момент запуска операции (требование 4.2.8)
        op_settings = self.app_settings.copy()
        conflict_policy = op_settings.duplicate_file_action

        if conflict_policy == "ask":
            try:
                conflicts = target_vault.find_conflicts(paths)
            except Exception as exc:
                self._show_message_dialog(
                    Gtk.MessageType.ERROR,
                    self._t("dlg_op_failed_title"),
                    str(exc),
                )
                return
            if conflicts:
                chosen_action = self._ask_duplicate_conflict_resolution(conflicts)
                if chosen_action is None:
                    self.status_label.set_text(self._t("status_cancelled"))
                    return
                conflict_policy = chosen_action
            else:
                conflict_policy = "error"

        def _worker(
            cancel_cb: Callable[[], bool],
            prog_cb: Callable[[int, int, str], None],
        ) -> List[VaultEntry]:
            return target_vault.add_paths(
                paths,
                cancel_check=cancel_cb,
                progress_cb=prog_cb,
                on_conflict=conflict_policy,
            )

        def _on_added(added: List[VaultEntry]) -> None:
            self._refresh_file_list()
            if not added and conflict_policy == "skip":
                self.status_label.set_text(self._t("status_added_skipped"))
                return
            self.status_label.set_text(self._t("status_added_ok", count=len(added)))

            # Проверяем настройку предложения удаления оригиналов:
            # 1) Настройка должна быть включена в снимке операции И в актуальных настройках
            # 2) Удаление всегда является отдельным явно подтверждаемым действием после успешного добавления
            file_entries = [e for e in added if e.entry_type == "file"]
            if (
                file_entries
                and op_settings.offer_delete_originals_after_add
                and self.app_settings.offer_delete_originals_after_add
            ):
                self._offer_verified_originals_deletion(target_vault, paths, added, op_settings)
            elif op_settings.notify_long_operations and len(added) > 0:
                self._show_message_dialog(
                    Gtk.MessageType.INFO,
                    self._t("dlg_added_notify_title"),
                    self._t("dlg_added_notify_body", count=len(added)),
                )

        self._run_background_task(
            self._t("task_adding_files"),
            _worker,
            _on_added,
        )

    def _offer_verified_originals_deletion(
        self,
        target_vault: SecureVault,
        selected_paths: List[Path],
        added_entries: List[VaultEntry],
        op_settings: AppSettings,
    ) -> None:
        """
        Отдельный сценарий предложения удалить оригиналы после успешного добавления в хранилище.
        Никогда не удаляет файлы без явного подтверждения пользователя и предварительной верификации контейнера.
        """
        file_entries = [e for e in added_entries if e.entry_type == "file"]
        if not file_entries:
            return

        preview = "\n".join(f"• {e.virtual_path}" for e in file_entries[:8])
        if len(file_entries) > 8:
            preview += "\n" + self._t("and_more_items", count=len(file_entries) - 8)

        wants_delete = self._ask_confirmation(
            title=self._t("dlg_offer_del_orig_title"),
            details=self._t("dlg_offer_del_orig_body", count=len(file_entries), preview=preview),
            confirm_label=self._t("btn_delete_originals"),
            cancel_label=self._t("btn_keep_originals"),
        )
        if not wants_delete:
            return

        # Если включена настройка «Спрашивать перед удалением оригиналов», запрашиваем финальное подтверждение
        if op_settings.ask_before_deleting_originals or self.app_settings.ask_before_deleting_originals:
            final_confirm = self._ask_confirmation(
                title=self._t("dlg_confirm_del_orig_title"),
                details=self._t(
                    "dlg_confirm_del_orig_body",
                    count=len(file_entries),
                    vault_name=target_vault.vault_path.name,
                ),
                confirm_label=self._t("btn_confirm_del_orig_final"),
                cancel_label=self._t("btn_keep_originals"),
            )
            if not final_confirm:
                return

        def _del_worker(
            cancel_cb: Callable[[], bool],
            _prog_cb: Callable[[int, int, str], None],
        ) -> Tuple[int, List[str]]:
            return target_vault.safe_delete_verified_originals(
                selected_source_paths=selected_paths,
                added_entries=added_entries,
                user_confirmed=True,
                cancel_check=cancel_cb,
            )

        def _on_orig_deleted(res: Tuple[int, List[str]]) -> None:
            deleted_cnt, warnings = res
            self.status_label.set_text(
                self._t("status_originals_deleted", added=len(added_entries), deleted=deleted_cnt)
            )
            if warnings:
                self._show_message_dialog(
                    Gtk.MessageType.WARNING,
                    self._t("dlg_orig_del_warn_title"),
                    self._t(
                        "dlg_orig_del_warn_body",
                        deleted=deleted_cnt,
                        errors="\n".join(f"• {w}" for w in warnings[:10]),
                    ),
                )

        self._run_background_task(
            self._t("task_deleting_originals"),
            _del_worker,
            _on_orig_deleted,
        )

    def _on_extract_clicked(self, _btn: Gtk.Button) -> None:
        if not self.vault or not self.vault.is_unlocked or self.is_busy:
            return
        self._record_user_activity()

        selected_vps = self._get_selected_virtual_paths()
        if not selected_vps:
            all_entries = self.vault.list_entries()
            if not all_entries:
                self._show_message_dialog(
                    Gtk.MessageType.INFO,
                    self._t("dlg_vault_empty_title"),
                    self._t("dlg_vault_empty_body"),
                )
                return
            if not self._ask_confirmation(
                self._t("dlg_extract_all_title"),
                self._t("dlg_extract_all_body", count=len(all_entries)),
                confirm_label=self._t("btn_extract_all"),
            ):
                return
            selected_vps = [e.virtual_path for e in all_entries]
        else:
            if (
                self.app_settings.confirm_large_extraction
                and len(selected_vps) >= self.app_settings.large_extraction_threshold
            ):
                if not self._ask_confirmation(
                    self._t("dlg_extract_large_title"),
                    self._t("dlg_extract_large_body", count=len(selected_vps)),
                    confirm_label=self._t("btn_confirm"),
                ):
                    return

        fc = Gtk.FileChooserDialog(
            title=self._t("fc_extract_title"),
            parent=self,
            action=Gtk.FileChooserAction.SELECT_FOLDER,
        )
        fc.add_buttons(
            self._t("btn_cancel"), Gtk.ResponseType.CANCEL,
            self._t("btn_extract_here"), Gtk.ResponseType.OK,
        )
        resp = fc.run()
        dest_folder = fc.get_filename()
        fc.destroy()

        if resp != Gtk.ResponseType.OK or not dest_folder:
            return

        target_vault = self.vault
        notify_done = self.app_settings.notify_long_operations

        def _worker(cancel_cb: Callable[[], bool], prog_cb: Callable[[int, int, str], None]) -> List[Path]:
            return target_vault.extract_entries(
                virtual_paths=selected_vps,
                destination_dir=dest_folder,
                preserve_structure=True,
                cancel_check=cancel_cb,
                progress_cb=prog_cb,
            )

        def _on_extracted(extracted: List[Path]) -> None:
            self.status_label.set_text(
                self._t("status_extracted_ok", count=len(extracted), dest=dest_folder)
            )
            if notify_done:
                self._show_message_dialog(
                    Gtk.MessageType.INFO,
                    self._t("dlg_extracted_ok_title"),
                    self._t("dlg_extracted_ok_body", count=len(extracted), dest=dest_folder),
                )

        self._run_background_task(
            self._t("task_extracting"),
            _worker,
            _on_extracted,
        )

    def _on_delete_clicked(self, _btn: Gtk.Button) -> None:
        if not self.vault or not self.vault.is_unlocked or self.is_busy:
            return
        self._record_user_activity()

        selected_vps = self._get_selected_virtual_paths()
        if not selected_vps:
            self._show_message_dialog(
                Gtk.MessageType.INFO,
                self._t("dlg_no_selection_title"),
                self._t("dlg_no_selection_body"),
            )
            return

        if self.app_settings.confirm_before_vault_delete:
            preview_list = "\n".join(f"• {p}" for p in selected_vps[:8])
            if len(selected_vps) > 8:
                preview_list += "\n" + self._t("and_more_items", count=len(selected_vps) - 8)

            confirmed = self._ask_confirmation(
                self._t("dlg_delete_vault_title"),
                self._t("dlg_delete_vault_body", count=len(selected_vps), preview=preview_list),
                confirm_label=self._t("btn_confirm_delete_vault"),
            )
            if not confirmed:
                return

        target_vault = self.vault

        def _worker(cancel_cb: Callable[[], bool], _prog_cb: Callable[[int, int, str], None]) -> int:
            return target_vault.delete_entries(selected_vps, cancel_check=cancel_cb)

        def _on_deleted(deleted_count: int) -> None:
            self._refresh_file_list()
            self.status_label.set_text(self._t("status_deleted_vault_ok", count=deleted_count))

        self._run_background_task(self._t("task_deleting_vault"), _worker, _on_deleted)

    def _on_verify_integrity_clicked(self, _btn: Gtk.Button) -> None:
        if not self.vault or not self.vault.is_unlocked or self.is_busy:
            return
        self._record_user_activity()

        target_vault = self.vault

        def _worker(cancel_cb: Callable[[], bool], prog_cb: Callable[[int, int, str], None]) -> IntegrityReport:
            return target_vault.verify_integrity(cancel_check=cancel_cb, progress_cb=prog_cb)

        def _on_verified(rep: IntegrityReport) -> None:
            if rep.is_valid:
                msg = self._t(
                    "dlg_verify_ok_body",
                    path=rep.vault_path,
                    verified=rep.verified_files,
                    total_files=rep.total_files,
                    total_dirs=rep.total_dirs,
                )
                if rep.warnings:
                    msg += f"\n\n{self._t('verify_warnings_header')}\n" + "\n".join(
                        f"- {w}" for w in rep.warnings
                    )
                self.status_label.set_text(self._t("status_verify_ok"))
                self._show_message_dialog(Gtk.MessageType.INFO, self._t("dlg_verify_ok_title"), msg)
            else:
                err_text = "\n".join(f"• {e}" for e in rep.errors[:10])
                msg = self._t(
                    "dlg_verify_bad_body",
                    verified=rep.verified_files,
                    total_files=rep.total_files,
                    corrupted=len(rep.corrupted_entries),
                    errors=err_text,
                )
                self.status_label.set_text(self._t("status_verify_bad"))
                self._show_message_dialog(Gtk.MessageType.ERROR, self._t("dlg_verify_bad_title"), msg)

        self._run_background_task(
            self._t("task_verifying"),
            _worker,
            _on_verified,
        )

    def _on_backup_clicked(self, _btn: Gtk.Button) -> None:
        if not self.vault or self.is_busy:
            return
        self._record_user_activity()

        fc = Gtk.FileChooserDialog(
            title=self._t("fc_backup_title"),
            parent=self,
            action=Gtk.FileChooserAction.SAVE,
        )
        fc.add_buttons(
            self._t("btn_cancel"), Gtk.ResponseType.CANCEL,
            self._t("btn_create_backup"), Gtk.ResponseType.OK,
        )
        pref_dir = self.app_settings.default_backup_dir.strip()
        if pref_dir and Path(pref_dir).is_dir() and not Path(pref_dir).is_symlink():
            fc.set_current_folder(pref_dir)
        else:
            fc.set_current_folder(str(self.vault.vault_path.parent))

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        fc.set_current_name(f"{self.vault.vault_path.stem}_backup_{stamp}.mvault")
        resp = fc.run()
        backup_path = fc.get_filename()
        fc.destroy()

        if resp != Gtk.ResponseType.OK or not backup_path:
            return

        target_vault = self.vault
        notify_done = self.app_settings.notify_long_operations

        def _worker(_cancel_cb: Callable[[], bool], _prog_cb: Callable[[int, int, str], None]) -> Path:
            return target_vault.create_backup(backup_path)

        def _on_backed_up(saved_path: Path) -> None:
            self.status_label.set_text(self._t("status_backup_ok", path=saved_path))
            if notify_done:
                self._show_message_dialog(
                    Gtk.MessageType.INFO,
                    self._t("dlg_backup_ok_title"),
                    self._t("dlg_backup_ok_body", path=saved_path),
                )

        self._run_background_task(self._t("task_backing_up"), _worker, _on_backed_up)

    # ------------------------------------------------------------------
    # Безопасное закрытие окна
    # ------------------------------------------------------------------
    def _on_window_delete_event(self, _widget: Gtk.Widget, _event: Gdk.Event) -> bool:
        if self.is_busy:
            confirm = self._ask_confirmation(
                self._t("dlg_busy_exit_title"),
                self._t("dlg_busy_exit_body"),
                confirm_label=self._t("btn_abort_and_exit"),
            )
            if not confirm:
                return True
            self._cancel_requested.set()
            worker = self._active_worker_thread
            if worker is not None and worker.is_alive():
                worker.join(timeout=3.0)
        elif (
            self.vault
            and self.vault.is_unlocked
            and self.app_settings.close_unlocked_action == "ask"
        ):
            confirm_close = self._ask_confirmation(
                self._t("dlg_close_unlocked_title"),
                self._t("dlg_close_unlocked_body", name=self.vault.vault_path.name),
                confirm_label=self._t("btn_lock_and_exit"),
            )
            if not confirm_close:
                return True

        if self._auto_lock_source_id is not None:
            try:
                GLib.source_remove(self._auto_lock_source_id)
            except Exception:
                pass
            self._auto_lock_source_id = None

        if self.vault:
            self.vault.close()
            self.vault = None
        Gtk.main_quit()
        return False


def run_gui(initial_vault_path: Optional[str] = None) -> int:
    """Точка входа для запуска графического интерфейса GTK 3."""
    win = MintVaultWindow(initial_vault_path=initial_vault_path)
    win.show_all()
    Gtk.main()
    return 0
