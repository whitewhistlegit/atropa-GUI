"""atropa.ui.pages.power - Power module (profiles, battery limits, and zram swap)."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import power
from atropa.backend.privilege import path_exists
from atropa.ui.pages import BasePage, esc

# The daemon's names are for scripts; the GUI shows what they mean.
PROFILE_LABELS = {
    "power-saver": "Power saver",
    "balanced": "Balanced",
    "performance": "Performance",
}


def _humanise(name: str) -> str:
    """A profile label, falling back to a readable form for unknown names."""
    if name in PROFILE_LABELS:
        return PROFILE_LABELS[name]
    return name.replace("-", " ").replace("_", " ").capitalize()


class PowerPage(BasePage):
    def __init__(self) -> None:
        super().__init__()
        self._suppress_signals = False
        self._profiles: list[str] = []
        self._battery_rows: list = []
        self._swap_rows: list = []
        self._zram_rows: list = []

        profile_group = self.add_group("Power profile")
        self.profile_row = Adw.ComboRow(title="Power profile", subtitle="Reading…")
        # Plain text: the combo row showed esc()'d subtitles literally
        # ("isn&apos;t installed"), and an error message needs no markup.
        self.profile_row.set_use_markup(False)
        self.profile_row.connect("notify::selected", self._on_profile_selected)
        profile_group.add(self.profile_row)

        # Not every laptop's firmware exposes a charge threshold; saying so
        # once here is better than every row repeating it.
        self.battery_group = self.add_group(
            "Battery",
            "Charge limits are only available on hardware that exposes one - many laptops don't.",
        )

        self.swap_group = self.add_group("Swap", "zram devices, total swap, and whether hibernation can work.")

        self.zram_group = self.add_group("zram swap", "Compressed swap in RAM, set up by zram-generator.")
        self.zram_spin = Adw.SpinRow.new_with_range(512, 65536, 256)
        self.zram_spin.set_title("Size in MB")
        self.zram_spin.set_value(4096)
        self.zram_enable_btn = Gtk.Button(label="Enable zram", valign=Gtk.Align.CENTER)
        self.zram_enable_btn.connect("clicked", self._on_enable_zram_clicked)
        self.zram_spin.add_suffix(self.zram_enable_btn)
        self.zram_group.add(self.zram_spin)

        self.refresh()

    # -- loading ------------------------------------------------------------

    def refresh(self) -> None:
        self.run_async(self._read_profile_state, self._on_profile_loaded)

        self._drop_rows(self.battery_group, "_battery_rows")
        self._battery_rows = [self.start_loading(self.battery_group, "Reading battery…")]
        self.run_async(power.batteries, self._on_batteries_loaded)

        self._drop_rows(self.swap_group, "_swap_rows")
        self._swap_rows = [self.start_loading(self.swap_group, "Reading swap…")]
        self.run_async(self._read_swap_state, self._on_swap_loaded)

        self._drop_rows(self.zram_group, "_zram_rows")
        self._zram_rows = [self.start_loading(self.zram_group, "Reading zram configuration…")]
        self.run_async(power.zram_config, self._on_zram_config_loaded)

    def _drop_rows(self, group: Adw.PreferencesGroup, attr: str) -> None:
        rows = getattr(self, attr, [])
        self.clear_rows(group, rows)
        setattr(self, attr, [])

    def _add_row(self, group: Adw.PreferencesGroup, attr: str, title: str, subtitle: str = "") -> Adw.ActionRow:
        row = Adw.ActionRow(title=esc(title))
        if subtitle:
            row.set_subtitle(esc(subtitle))
        group.add(row)
        getattr(self, attr).append(row)
        return row

    # -- power profile ------------------------------------------------------

    def _read_profile_state(self) -> tuple[list[str], str | None]:
        profiles = power.profiles()
        # Asking for the current profile is pointless when the tool is
        # missing; profiles() has already answered that cheaply.
        return profiles, power.current_profile() if profiles else None

    def _on_profile_loaded(self, result, error) -> bool:
        if error:
            self.profile_row.set_sensitive(False)
            self.profile_row.set_subtitle(f"Couldn't read power profiles: {error}")
            return False

        profiles, current = result
        self._profiles = profiles
        labels = [PROFILE_LABELS.get(name, _humanise(name)) for name in profiles]

        # Replacing the model re-selects row 0 and emits notify::selected;
        # without the guard that looks like the user picked a profile.
        self._suppress_signals = True
        try:
            self.profile_row.set_model(Gtk.StringList.new(labels))
            if current in profiles:
                self.profile_row.set_selected(profiles.index(current))
            self.profile_row.set_sensitive(bool(profiles))
            if profiles:
                self.profile_row.set_subtitle("provided by power-profiles-daemon")
            else:
                self.profile_row.set_subtitle("power-profiles-daemon isn't installed")
        finally:
            self._suppress_signals = False
        return False

    def _resync_profile(self) -> None:
        self.run_async(self._read_profile_state, self._on_profile_loaded)

    def _on_profile_selected(self, row: Adw.ComboRow, _pspec) -> None:
        if self._suppress_signals:
            return
        index = row.get_selected()
        if index < 0 or index >= len(self._profiles):
            return
        name = self._profiles[index]

        def done(result, error) -> bool:
            self.handle_command_result(result, error, f"Power profile set to {_humanise(name)}", refresh=False)
            # Re-read whatever happened: a dismissed polkit prompt would
            # otherwise leave the combo showing a profile never applied.
            self._resync_profile()
            return False

        if not self.run_action(lambda: power.set_profile(name), done):
            self._resync_profile()

    # -- battery ------------------------------------------------------------

    def _on_batteries_loaded(self, result, error) -> bool:
        self._drop_rows(self.battery_group, "_battery_rows")

        if error:
            self._add_row(self.battery_group, "_battery_rows", "Couldn't read battery status", str(error))
            return False
        if not result:
            self._add_row(
                self.battery_group,
                "_battery_rows",
                "No battery",
                "Desktops and virtual machines don't have one",
            )
            return False

        for index, battery in enumerate(result):
            capacity = f"{battery.capacity}%" if battery.capacity is not None else "capacity unknown"
            status = battery.status or "status unknown"
            self._add_row(
                self.battery_group,
                "_battery_rows",
                f"Battery {index} — {capacity}, {status}",
            )
            self._add_charge_limit_row(battery, index)
        return False

    def _add_charge_limit_row(self, battery: power.Battery, index: int) -> None:
        # path_exists() rather than .exists(): a root-only sysfs directory
        # must not crash the page.
        if not path_exists(battery.charge_limit_path):
            return

        spin = Adw.SpinRow.new_with_range(0, 100, 1)
        spin.set_title(f"Battery {index} charge limit")
        spin.set_subtitle("Stop charging at this percentage - ignored by laptops without a limit")
        spin.set_value(battery.charge_limit if battery.charge_limit is not None else 100)
        apply_btn = Gtk.Button(label="Apply", valign=Gtk.Align.CENTER)
        apply_btn.connect("clicked", lambda _btn, name=battery.name, row=spin: self._on_apply_charge_limit(name, row))
        spin.add_suffix(apply_btn)
        self.battery_group.add(spin)
        self._battery_rows.append(spin)

    def _on_apply_charge_limit(self, name: str, spin: Adw.SpinRow) -> None:
        limit = int(spin.get_value())
        self.run_action(lambda: power.set_charge_limit(name, limit), self.handle_command_result)

    # -- swap and zram state ------------------------------------------------

    def _read_swap_state(self):
        return power.zram_devices(), power.swap_total_mb(), power.hibernate_status()

    def _on_swap_loaded(self, result, error) -> bool:
        self._drop_rows(self.swap_group, "_swap_rows")

        if error:
            self._add_row(self.swap_group, "_swap_rows", "Couldn't read swap status", str(error))
            return False

        devices, total_mb, hibernate = result
        for device in devices:
            used = f", {device.data} used" if device.data else ""
            self._add_row(self.swap_group, "_swap_rows", f"{device.name} — {device.size}{used}", "zram device")

        self._add_row(
            self.swap_group,
            "_swap_rows",
            "Swap total",
            f"{total_mb} MB" if total_mb else "No swap configured",
        )
        self._add_row(
            self.swap_group,
            "_swap_rows",
            "Hibernation supported" if hibernate.supported else "Hibernation isn't supported",
            hibernate.detail,
        )
        return False

    def _on_zram_config_loaded(self, config, error) -> bool:
        self._drop_rows(self.zram_group, "_zram_rows")

        if error:
            self.zram_spin.set_visible(True)
            self._add_row(self.zram_group, "_zram_rows", "Couldn't read zram configuration", str(error))
            return False

        if config.exists:
            # Already configured: changing it from a spin row would overwrite
            # a hand-edited file without showing what's there first.
            self.zram_spin.set_visible(False)
            content = (config.content or "").strip() or "(empty configuration file)"
            self._add_row(
                self.zram_group,
                "_zram_rows",
                "zram is already configured",
                f"{config.path}: {content}",
            )
        else:
            self.zram_spin.set_visible(True)
            self._add_row(
                self.zram_group,
                "_zram_rows",
                "No zram swap configured",
                "zram-generator's configuration file doesn't exist yet",
            )
        return False

    def _on_enable_zram_clicked(self, _btn: Gtk.Button) -> None:
        size_mb = int(self.zram_spin.get_value())
        self.confirm(
            "Enable zram swap?",
            "Writes /etc/systemd/zram-generator.conf, backs up any existing file, and starts "
            "systemd-zram-setup@zram0.service. Kernel swap-on-zram must be available (CONFIG_ZRAM).",
            "Enable",
            lambda: self.run_action(lambda: power.enable_zram(size_mb), self.handle_command_result),
            destructive=False,
        )
