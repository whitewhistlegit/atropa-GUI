"""atropa.ui.pages.system_config - System: hostname, timezone/NTP, locale, and keyboard layout."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import system_config
from atropa.ui.pages import BasePage, esc

_MAX_RENDERED_MATCHES = 40


class SystemConfigPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        # ---------------- hostname ----------------
        self.hostname_group = self.add_group("Hostname")
        self.hostname_info_row = Adw.ActionRow(title="Loading…")
        self.hostname_group.add(self.hostname_info_row)
        self.hostname_entry = Adw.EntryRow(title="New hostname")
        set_hostname_btn = Gtk.Button(label="Set", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        set_hostname_btn.connect("clicked", self._on_set_hostname_clicked)
        self.hostname_entry.add_suffix(set_hostname_btn)
        self.hostname_group.add(self.hostname_entry)

        # ---------------- time & date ----------------
        self.time_group = self.add_group("Time & Date")
        self.time_status_row = Adw.ActionRow(title="Loading…")
        self.ntp_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.ntp_switch.connect("state-set", self._on_ntp_toggled)
        self.time_status_row.add_suffix(self.ntp_switch)
        self.time_status_row.add_suffix(Gtk.Label(label="NTP sync", css_classes=["dim-label"]))
        self.time_group.add(self.time_status_row)

        self.tz_filter_group = self.add_group("Change Timezone", "Type to filter, click one to set it.")
        self.tz_filter_row = Adw.EntryRow(title="Filter timezones")
        tz_filter_btn = Gtk.Button(label="Filter", valign=Gtk.Align.CENTER, css_classes=["flat"])
        tz_filter_btn.connect("clicked", lambda _b: self._render_timezone_matches())
        self.tz_filter_row.add_suffix(tz_filter_btn)
        self.tz_filter_group.add(self.tz_filter_row)
        self._tz_result_rows: list = []
        self._all_timezones: list[str] = []

        # ---------------- locale ----------------
        self.locale_group = self.add_group("Locale")
        self.locale_status_row = Adw.ActionRow(title="Loading…")
        self.locale_group.add(self.locale_status_row)

        self.locale_list_group = self.add_group(
            "Locales", "Toggle enables/disables a locale in /etc/locale.gen and regenerates it immediately. "
            "'Use' switches LANG to a locale that's already generated."
        )
        self.locale_filter_row = Adw.EntryRow(title="Filter locales")
        locale_filter_btn = Gtk.Button(label="Filter", valign=Gtk.Align.CENTER, css_classes=["flat"])
        locale_filter_btn.connect("clicked", lambda _b: self._render_locale_matches())
        self.locale_filter_row.add_suffix(locale_filter_btn)
        self.locale_list_group.add(self.locale_filter_row)
        self._locale_result_rows: list = []
        self._all_locale_entries: list = []
        self._generated_locale_names: set[str] = set()

        # ---------------- keyboard ----------------
        self.keyboard_group = self.add_group("Keyboard")
        self.keyboard_status_row = Adw.ActionRow(title="Loading…")
        self.keyboard_group.add(self.keyboard_status_row)

        self.keymap_filter_group = self.add_group("Console Keymap", "Type to filter, click one to set it.")
        self.keymap_filter_row = Adw.EntryRow(title="Filter keymaps")
        keymap_filter_btn = Gtk.Button(label="Filter", valign=Gtk.Align.CENTER, css_classes=["flat"])
        keymap_filter_btn.connect("clicked", lambda _b: self._render_keymap_matches())
        self.keymap_filter_row.add_suffix(keymap_filter_btn)
        self.keymap_filter_group.add(self.keymap_filter_row)
        self._keymap_result_rows: list = []
        self._all_keymaps: list[str] = []

        self.x11_filter_group = self.add_group("X11/Wayland Layout", "Type to filter, click one to set it.")
        self.x11_filter_row = Adw.EntryRow(title="Filter layouts")
        x11_filter_btn = Gtk.Button(label="Filter", valign=Gtk.Align.CENTER, css_classes=["flat"])
        x11_filter_btn.connect("clicked", lambda _b: self._render_x11_matches())
        self.x11_filter_row.add_suffix(x11_filter_btn)
        self.x11_filter_group.add(self.x11_filter_row)
        self._x11_result_rows: list = []
        self._all_x11_layouts: list[str] = []

        self.refresh()

    def refresh(self) -> None:
        self.run_async(system_config.get_hostname_status, self._on_hostname_loaded)
        self.run_async(system_config.get_time_status, self._on_time_loaded)
        self.run_async(system_config.list_timezones, self._on_timezones_loaded)
        self.run_async(system_config.get_locale_status, self._on_locale_loaded)
        self.run_async(system_config.list_locale_gen_entries, self._on_locale_gen_entries_loaded)
        self.run_async(system_config.list_generated_locales, self._on_generated_locales_loaded)
        self.run_async(system_config.get_locale_status, self._on_keyboard_status_loaded)
        self.run_async(system_config.list_keymaps, self._on_keymaps_loaded)
        self.run_async(system_config.list_x11_layouts, self._on_x11_layouts_loaded)

    # --------------------------------------------------------- hostname --

    def _on_hostname_loaded(self, result, error) -> bool:
        if error:
            self.hostname_info_row.set_title("Couldn't read hostname")
            self.hostname_info_row.set_subtitle(esc(error))
            return False
        self.hostname_info_row.set_title(esc(result.static_hostname or "(unset)"))
        self.hostname_info_row.set_subtitle(
            esc(f"{result.os_name} · {result.kernel} · {result.chassis}".strip(" ·"))
        )
        return False

    def _on_set_hostname_clicked(self, _widget) -> None:
        name = self.hostname_entry.get_text().strip()
        if not name:
            self.notify("Enter a hostname first", is_error=True)
            return
        self.confirm(
            f"Set hostname to '{name}'?",
            "Runs hostnamectl set-hostname. Some services may need a restart to pick up the change.",
            "Set",
            lambda: self.run_async(lambda: system_config.set_hostname(name), self.handle_command_result),
        )

    # --------------------------------------------------------- time & date --

    def _on_time_loaded(self, result, error) -> bool:
        if error:
            self.time_status_row.set_title("Couldn't read time status")
            self.time_status_row.set_subtitle(esc(error))
            return False
        self.time_status_row.set_title(esc(result.local_time or "Unknown time"))
        self.time_status_row.set_subtitle(esc(result.timezone))
        self.ntp_switch.set_active(result.ntp_service_active)
        return False

    def _on_ntp_toggled(self, _switch: Gtk.Switch, state: bool) -> bool:
        self.run_async(lambda: system_config.set_ntp(state), self.handle_command_result)
        return False

    def _on_timezones_loaded(self, result, error) -> bool:
        if error:
            self.notify(f"Couldn't list timezones: {error}", is_error=True)
            return False
        self._all_timezones = result
        self._render_timezone_matches()
        return False

    def _render_timezone_matches(self) -> None:
        self.clear_rows(self.tz_filter_group, self._tz_result_rows)
        self._tz_result_rows = []
        query = self.tz_filter_row.get_text().strip().lower()
        matches = [tz for tz in self._all_timezones if query in tz.lower()] if self._all_timezones else []

        for tz in matches[:_MAX_RENDERED_MATCHES]:
            row = Adw.ActionRow(title=esc(tz))
            btn = Gtk.Button(label="Set", valign=Gtk.Align.CENTER)
            btn.connect("clicked", self._on_set_timezone_clicked, tz)
            row.add_suffix(btn)
            self.tz_filter_group.add(row)
            self._tz_result_rows.append(row)

        if len(matches) > _MAX_RENDERED_MATCHES:
            note = Adw.ActionRow(title=f"Showing {_MAX_RENDERED_MATCHES} of {len(matches)} matches - refine your search")
            self.tz_filter_group.add(note)
            self._tz_result_rows.append(note)
        elif not matches and self._all_timezones:
            note = Adw.ActionRow(title="No matches")
            self.tz_filter_group.add(note)
            self._tz_result_rows.append(note)

    def _on_set_timezone_clicked(self, _btn: Gtk.Button, tz: str) -> None:
        self.confirm(
            f"Set timezone to {tz}?",
            "Runs timedatectl set-timezone.",
            "Set",
            lambda: self.run_async(lambda: system_config.set_timezone(tz), self.handle_command_result),
        )

    # --------------------------------------------------------- locale --

    def _on_locale_loaded(self, result, error) -> bool:
        if error:
            self.locale_status_row.set_title("Couldn't read locale status")
            self.locale_status_row.set_subtitle(esc(error))
            return False
        self.locale_status_row.set_title(esc(result.lang or "(unset)"))
        self.locale_status_row.set_subtitle("Current LANG")
        return False

    def _on_locale_gen_entries_loaded(self, result, error) -> bool:
        if error:
            self.notify(f"Couldn't read /etc/locale.gen: {error}", is_error=True)
            return False
        self._all_locale_entries = result
        self._render_locale_matches()
        return False

    def _on_generated_locales_loaded(self, result, error) -> bool:
        if error:
            return False
        self._generated_locale_names = set(result)
        self._render_locale_matches()
        return False

    def _render_locale_matches(self) -> None:
        self.clear_rows(self.locale_list_group, self._locale_result_rows)
        self._locale_result_rows = []
        query = self.locale_filter_row.get_text().strip().lower()
        matches = [e for e in self._all_locale_entries if query in e.locale.lower()]

        for entry in matches[:_MAX_RENDERED_MATCHES]:
            row = Adw.ActionRow(title=esc(entry.locale), subtitle=esc(entry.charmap))

            switch = Gtk.Switch(valign=Gtk.Align.CENTER, active=entry.enabled)
            switch.connect("state-set", self._on_locale_gen_toggled, entry)
            row.add_suffix(switch)

            if entry.locale in self._generated_locale_names:
                use_btn = Gtk.Button(label="Use", valign=Gtk.Align.CENTER)
                use_btn.connect("clicked", self._on_use_locale_clicked, entry.locale)
                row.add_suffix(use_btn)

            self.locale_list_group.add(row)
            self._locale_result_rows.append(row)

        if len(matches) > _MAX_RENDERED_MATCHES:
            note = Adw.ActionRow(title=f"Showing {_MAX_RENDERED_MATCHES} of {len(matches)} matches - refine your search")
            self.locale_list_group.add(note)
            self._locale_result_rows.append(note)
        elif not matches and self._all_locale_entries:
            note = Adw.ActionRow(title="No matches")
            self.locale_list_group.add(note)
            self._locale_result_rows.append(note)

    def _on_locale_gen_toggled(self, _switch: Gtk.Switch, state: bool, entry) -> bool:
        self.run_async(
            lambda: system_config.set_locale_gen_enabled(entry.locale, entry.charmap, state),
            self.handle_command_result,
        )
        return False

    def _on_use_locale_clicked(self, _btn: Gtk.Button, locale: str) -> None:
        self.confirm(
            f"Switch LANG to {locale}?",
            "Runs localectl set-locale. Some applications may need to be restarted to reflect the change.",
            "Switch",
            lambda: self.run_async(lambda: system_config.set_locale(locale), self.handle_command_result),
        )

    # --------------------------------------------------------- keyboard --

    def _on_keyboard_status_loaded(self, result, error) -> bool:
        if error:
            self.keyboard_status_row.set_title("Couldn't read keyboard status")
            self.keyboard_status_row.set_subtitle(esc(error))
            return False
        self.keyboard_status_row.set_title(esc(result.vc_keymap or "(unset)"))
        self.keyboard_status_row.set_subtitle(esc(f"Console keymap · X11 layout: {result.x11_layout or '(unset)'}"))
        return False

    def _on_keymaps_loaded(self, result, error) -> bool:
        if error:
            self.notify(f"Couldn't list keymaps: {error}", is_error=True)
            return False
        self._all_keymaps = result
        self._render_keymap_matches()
        return False

    def _render_keymap_matches(self) -> None:
        self.clear_rows(self.keymap_filter_group, self._keymap_result_rows)
        self._keymap_result_rows = []
        query = self.keymap_filter_row.get_text().strip().lower()
        matches = [k for k in self._all_keymaps if query in k.lower()] if self._all_keymaps else []

        for keymap in matches[:_MAX_RENDERED_MATCHES]:
            row = Adw.ActionRow(title=esc(keymap))
            btn = Gtk.Button(label="Set", valign=Gtk.Align.CENTER)
            btn.connect("clicked", self._on_set_keymap_clicked, keymap)
            row.add_suffix(btn)
            self.keymap_filter_group.add(row)
            self._keymap_result_rows.append(row)

        if len(matches) > _MAX_RENDERED_MATCHES:
            note = Adw.ActionRow(title=f"Showing {_MAX_RENDERED_MATCHES} of {len(matches)} matches - refine your search")
            self.keymap_filter_group.add(note)
            self._keymap_result_rows.append(note)
        elif not matches and self._all_keymaps:
            note = Adw.ActionRow(title="No matches")
            self.keymap_filter_group.add(note)
            self._keymap_result_rows.append(note)

    def _on_set_keymap_clicked(self, _btn: Gtk.Button, keymap: str) -> None:
        self.confirm(
            f"Set console keymap to {keymap}?",
            "Runs localectl set-keymap.",
            "Set",
            lambda: self.run_async(lambda: system_config.set_keymap(keymap), self.handle_command_result),
        )

    def _on_x11_layouts_loaded(self, result, error) -> bool:
        if error:
            self.notify(f"Couldn't list X11 layouts: {error}", is_error=True)
            return False
        self._all_x11_layouts = result
        self.x11_filter_group.set_visible(bool(result))
        self._render_x11_matches()
        return False

    def _render_x11_matches(self) -> None:
        self.clear_rows(self.x11_filter_group, self._x11_result_rows)
        self._x11_result_rows = []
        query = self.x11_filter_row.get_text().strip().lower()
        matches = [layout for layout in self._all_x11_layouts if query in layout.lower()] if self._all_x11_layouts else []

        for layout in matches[:_MAX_RENDERED_MATCHES]:
            row = Adw.ActionRow(title=esc(layout))
            btn = Gtk.Button(label="Set", valign=Gtk.Align.CENTER)
            btn.connect("clicked", self._on_set_x11_layout_clicked, layout)
            row.add_suffix(btn)
            self.x11_filter_group.add(row)
            self._x11_result_rows.append(row)

        if len(matches) > _MAX_RENDERED_MATCHES:
            note = Adw.ActionRow(title=f"Showing {_MAX_RENDERED_MATCHES} of {len(matches)} matches - refine your search")
            self.x11_filter_group.add(note)
            self._x11_result_rows.append(note)
        elif not matches and self._all_x11_layouts:
            note = Adw.ActionRow(title="No matches")
            self.x11_filter_group.add(note)
            self._x11_result_rows.append(note)

    def _on_set_x11_layout_clicked(self, _btn: Gtk.Button, layout: str) -> None:
        self.confirm(
            f"Set X11/Wayland layout to {layout}?",
            "Runs localectl set-x11-keymap.",
            "Set",
            lambda: self.run_async(lambda: system_config.set_x11_layout(layout), self.handle_command_result),
        )
