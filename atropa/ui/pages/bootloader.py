"""atropa.ui.pages.bootloader - Bootloader module (GRUB / systemd-boot)."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import bootloader
from atropa.ui.pages import BasePage, esc


class BootloaderPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self.status_group = self.add_group("Bootloader")
        self.status_row = Adw.ActionRow(title="Detecting bootloader…")
        self.status_group.add(self.status_row)

        self.timeout_row = Adw.SpinRow.new_with_range(0, 60, 1)
        self.timeout_row.set_title("Boot menu timeout (seconds)")
        apply_timeout_btn = Gtk.Button(label="Apply", valign=Gtk.Align.CENTER)
        apply_timeout_btn.connect("clicked", self._on_apply_timeout)
        self.timeout_row.add_suffix(apply_timeout_btn)
        self.status_group.add(self.timeout_row)

        regen_row = Adw.ActionRow(title="Regenerate boot configuration", subtitle="Run after kernel/initramfs changes")
        regen_btn = Gtk.Button(label="Regenerate")
        regen_btn.set_valign(Gtk.Align.CENTER)
        regen_btn.connect("clicked", self._on_regenerate)
        regen_row.add_suffix(regen_btn)
        self.status_group.add(regen_row)

        self.entries_group = self.add_group("Boot Entries")

        self.refresh()

    def refresh(self) -> None:
        self.clear_rows(self.entries_group, getattr(self, "_entry_rows", []))
        self._entry_rows = [self.start_loading(self.entries_group, "Loading boot entries…")]
        self.run_async(bootloader.get_info, self._on_loaded)

    def _on_loaded(self, result, error) -> bool:
        if error:
            self.status_row.set_title("Could not read bootloader configuration")
            self.status_row.set_subtitle(esc(error))
            return False

        info = result
        if info.kind == "unknown":
            self.status_row.set_title("No supported bootloader detected")
            self.status_row.set_subtitle("Looked for GRUB and systemd-boot")
        else:
            self.status_row.set_title(f"Using {info.kind}")

        if info.default_timeout.isdigit():
            self.timeout_row.set_value(int(info.default_timeout))

        for row in list(getattr(self, "_entry_rows", [])):
            self.entries_group.remove(row)
        self._entry_rows = []

        for entry in info.entries:
            row = Adw.ActionRow(title=esc(entry.title), subtitle=esc(entry.identifier))
            self.entries_group.add(row)
            self._entry_rows.append(row)

        return False

    def _on_apply_timeout(self, _btn: Gtk.Button) -> None:
        seconds = int(self.timeout_row.get_value())
        self.notify("Applying timeout and regenerating config…")
        self.run_async(lambda: bootloader.set_timeout(seconds), self.handle_command_result)

    def _on_regenerate(self, _btn: Gtk.Button) -> None:
        self.notify("Regenerating boot configuration…")
        self.run_async(bootloader.regenerate_config, self.handle_command_result)
