"""atropa.ui.pages.firmware - Firmware module (devices and LVFS updates through fwupd)."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import firmware
from atropa.ui.pages import BasePage, esc


class FirmwarePage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self.devices_group = self.add_group("Devices", "Hardware fwupd can update on this machine")

        self.updates_group = self.add_group("Updates")
        self.updates_row = Adw.ActionRow(title="Not checked")
        self.check_btn = Gtk.Button(label="Check for updates", valign=Gtk.Align.CENTER)
        self.check_btn.connect("clicked", self._on_check_clicked)
        self.updates_row.add_suffix(self.check_btn)

        # The one button that can change hardware: keep it visually primary,
        # but never run it without the confirmation below.
        self.install_btn = Gtk.Button(
            label="Install all updates", valign=Gtk.Align.CENTER, css_classes=["suggested-action"]
        )
        self.install_btn.connect("clicked", self._on_install_clicked)
        self.updates_row.add_suffix(self.install_btn)
        self.updates_group.add(self.updates_row)

        self.refresh()

    # -- data loading -----------------------------------------------------------

    def refresh(self) -> None:
        self._load_devices()
        self._load_updates()

    def _load_devices(self) -> None:
        self.clear_rows(self.devices_group, getattr(self, "_device_rows", []))
        self._device_rows = [self.start_loading(self.devices_group, "Looking for firmware devices…")]
        self.run_async(firmware.devices, self._on_devices_loaded)

    def _load_updates(self) -> None:
        installed = firmware.fwupd_installed()
        self.check_btn.set_sensitive(installed)
        self.install_btn.set_sensitive(installed)
        if not installed:
            # fwupdmgr can't run at all; say so once here instead of
            # firing a privileged call that could only fail.
            self.updates_row.set_title("Not checked")
            self.updates_row.set_subtitle("fwupd isn't installed - install it with: pacman -S fwupd")
            return
        self.run_async(firmware.updates, self._on_updates_loaded)

    def _on_devices_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_device_rows", [])):
            self.devices_group.remove(row)
        self._device_rows = []

        if error:
            self._add_device_row("Couldn't list firmware devices", str(error))
            return False

        if not result:
            self._add_device_row("No firmware devices found", "fwupd didn't report any updatable hardware")
            return False

        for device in result:
            name = device.name or device.device_id
            parts = []
            if device.version:
                parts.append(f"version {device.version}")
            if device.vendor:
                parts.append(device.vendor)
            self._add_device_row(name, " · ".join(parts))
        return False

    def _add_device_row(self, title: str, subtitle: str = "") -> None:
        row = Adw.ActionRow(title=esc(title))
        if subtitle:
            row.set_subtitle(esc(subtitle))
        self.devices_group.add(row)
        self._device_rows.append(row)

    def _on_updates_loaded(self, result, error) -> bool:
        if error:
            self.updates_row.set_title("Couldn't check for updates")
            self.updates_row.set_subtitle(esc(error))
            return False

        count = len(result)
        if count == 0:
            self.updates_row.set_title("Up to date")
            self.updates_row.set_subtitle("")
        else:
            self.updates_row.set_title(f"{count} update{'s' if count != 1 else ''} available")
            self.updates_row.set_subtitle("")
        return False

    # -- actions ----------------------------------------------------------------

    def _on_check_clicked(self, _btn: Gtk.Button) -> None:
        self.updates_row.set_title("Checking for updates…")
        self.updates_row.set_subtitle("")

        def done(result, error) -> bool:
            self.handle_command_result(result, error, "Firmware metadata refreshed", refresh=False)
            # Re-read either way: after a failure the summary would otherwise
            # stay on "Checking for updates…" for good.
            self.refresh()
            return False

        self.run_action(firmware.refresh, done)

    def _on_install_clicked(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Install firmware updates?",
            "Firmware updates can require a reboot and a stable power source. fwupd applies them now; "
            "the machine may reboot on its own if the firmware requires it.",
            "Install",
            lambda: self.run_streaming_operation("Installing firmware updates", firmware.install_updates),
        )
