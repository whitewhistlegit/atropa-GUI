"""atropa.ui.pages.disk_health - Disk health, filesystem space, and routine cleanup."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import disk_health
from atropa.ui.pages import BasePage, esc

# Decimal units, matching what disk vendors and most desktop disks tools
# report ("100.0 GB"), rather than df's raw bytes.
_SIZE_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def _human_bytes(count: int) -> str:
    value = float(count)
    for unit in _SIZE_UNITS:
        if value < 1000 or unit == _SIZE_UNITS[-1]:
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1000
    return f"{count} B"


class DiskHealthPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self.smart_group = self.add_group(
            "SMART Health",
            "Read through smartctl -H. Most drives only answer as root, so if the rows say UNKNOWN, "
            "use 'Read SMART as administrator' below - one password covers the whole read.",
        )

        self.space_group = self.add_group("Space", "Mounted filesystems, excluding virtual ones (tmpfs, efivarfs)")

        self.maintenance_group = self.add_group("Maintenance")

        self.fstrim_row = Adw.ActionRow(title="fstrim.timer", subtitle="Checking…")
        self.fstrim_btn = Gtk.Button(label="Enable", valign=Gtk.Align.CENTER)
        self.fstrim_btn.connect("clicked", self._on_enable_fstrim)
        self.fstrim_row.add_suffix(self.fstrim_btn)
        self.maintenance_group.add(self.fstrim_row)

        self.journal_row = Adw.ActionRow(title="Journal", subtitle="Checking…")
        vacuum_btn = Gtk.Button(label="Vacuum to 200 MB", valign=Gtk.Align.CENTER)
        vacuum_btn.connect("clicked", self._on_vacuum_journal)
        self.journal_row.add_suffix(vacuum_btn)
        self.maintenance_group.add(self.journal_row)

        self.cache_row = Adw.ActionRow(title="~/.cache", subtitle="Checking…")
        clear_cache_btn = Gtk.Button(label="Clear cache", valign=Gtk.Align.CENTER)
        clear_cache_btn.connect("clicked", self._on_clear_cache)
        self.cache_row.add_suffix(clear_cache_btn)
        self.maintenance_group.add(self.cache_row)

        self.coredumps_row = Adw.ActionRow(
            title="Coredumps", subtitle="Crash dumps systemd keeps past their age limit"
        )
        clean_coredumps_btn = Gtk.Button(label="Clean old coredumps", valign=Gtk.Align.CENTER)
        clean_coredumps_btn.connect("clicked", self._on_clean_coredumps)
        self.coredumps_row.add_suffix(clean_coredumps_btn)
        self.maintenance_group.add(self.coredumps_row)

        self.refresh()

    # -- data loading -----------------------------------------------------------

    def refresh(self) -> None:
        self._load_smart()
        self._load_space()
        self._load_maintenance()

    def _load_smart(self) -> None:
        self.clear_rows(self.smart_group, getattr(self, "_smart_rows", []))
        self._smart_rows = [self.start_loading(self.smart_group, "Checking disk health…")]
        self.run_async(self._collect_smart, self._on_smart_loaded)

    @staticmethod
    def _collect_smart() -> list:
        """
        Reads every disk on the worker thread.

        One disk smartctl cannot open becomes that disk's own error string
        instead of failing the whole group - the other disks still have
        useful health to show.
        """
        results = []
        for device in disk_health.list_disks():
            try:
                results.append(disk_health.smart_status(device))
            except Exception as exc:  # noqa: BLE001 - shown as this disk's subtitle
                results.append((device, str(exc)))
        return results

    def _on_smart_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_smart_rows", [])):
            self.smart_group.remove(row)
        self._smart_rows = []

        if error:
            self._add_smart_row("Couldn't read disk health", str(error), "UNKNOWN")
            return False
        if not result:
            self._add_smart_row("No disks found", "lsblk didn't report any whole disks", "")
            return False

        self._render_smart(result)
        return False

    def _render_smart(self, items: list) -> None:
        for item in items:
            if isinstance(item, tuple):
                device, message = item
                self._add_smart_row(device, message, "UNKNOWN")
                continue
            verdict = "PASSED" if item.passed is True else "FAILED" if item.passed is False else "UNKNOWN"
            self._add_smart_row(item.device, item.detail, verdict)
        if any(not isinstance(item, tuple) and item.passed is None for item in items):
            self._add_privileged_smart_row()

    def _add_privileged_smart_row(self) -> None:
        """
        Offered instead of prompting on page open: a status page must not ask
        for a password just to draw itself, and smartctl needs root on most
        machines. One explicit click, one prompt, every disk read.
        """
        row = Adw.ActionRow(
            title="Read SMART as administrator",
            subtitle="smartctl needs root for most NVMe/ATA drives; the password is remembered for a few minutes",
        )
        read_btn = Gtk.Button(label="Read SMART", valign=Gtk.Align.CENTER)
        read_btn.add_css_class("suggested-action")
        read_btn.connect("clicked", self._on_read_smart_privileged)
        row.add_suffix(read_btn)
        self.smart_group.add(row)
        self._smart_rows.append(row)

    def _on_read_smart_privileged(self, _btn: Gtk.Button) -> None:
        self.run_action(self._collect_privileged_smart, self._on_privileged_smart_loaded)

    @staticmethod
    def _collect_privileged_smart() -> list:
        results = []
        for device in disk_health.list_disks():
            try:
                results.append(disk_health.smart_status_privileged(device))
            except Exception as exc:  # noqa: BLE001 - shown as that disk's row
                results.append((device, str(exc)))
        return results

    def _on_privileged_smart_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_smart_rows", [])):
            self.smart_group.remove(row)
        self._smart_rows = []
        if error:
            self._add_smart_row("Couldn't read SMART as administrator", str(error), "UNKNOWN")
            return False
        self._render_smart(result)
        return False

    def _add_smart_row(self, title: str, subtitle: str, verdict: str) -> None:
        row = Adw.ActionRow(title=esc(title))
        if subtitle:
            row.set_subtitle(esc(subtitle))
        if verdict:
            row.add_suffix(Gtk.Label(label=esc(verdict), css_classes=["dim-label"]))
        self.smart_group.add(row)
        self._smart_rows.append(row)

    def _load_space(self) -> None:
        self.clear_rows(self.space_group, getattr(self, "_space_rows", []))
        self._space_rows = [self.start_loading(self.space_group, "Reading filesystem usage…")]
        self.run_async(disk_health.filesystems, self._on_space_loaded)

    def _on_space_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_space_rows", [])):
            self.space_group.remove(row)
        self._space_rows = []

        if error:
            row = Adw.ActionRow(title="Couldn't read filesystem usage", subtitle=esc(error))
        elif not result:
            row = Adw.ActionRow(title="No mounted filesystems found")
        else:
            row = None
        if row is not None:
            self.space_group.add(row)
            self._space_rows.append(row)
            return False

        for usage in result:
            row = Adw.ActionRow(title=esc(usage.target))
            row.set_subtitle(
                esc(
                    f"{_human_bytes(usage.used)} used of {_human_bytes(usage.size)} "
                    f"({usage.percent}%)"
                )
            )
            row.add_suffix(Gtk.Label(label=esc(f"{usage.percent}%"), css_classes=["dim-label"]))
            self.space_group.add(row)
            self._space_rows.append(row)
        return False

    def _load_maintenance(self) -> None:
        self.fstrim_row.set_subtitle("Checking…")
        self.fstrim_btn.set_sensitive(False)
        self.run_async(disk_health.fstrim_status, self._on_fstrim_loaded)

        self.journal_row.set_subtitle("Checking…")
        self.run_async(disk_health.journal_usage, self._on_journal_loaded)

        self.cache_row.set_subtitle("Checking…")
        self.run_async(disk_health.cache_size, self._on_cache_loaded)

    def _on_fstrim_loaded(self, status, error) -> bool:
        if error:
            self.fstrim_row.set_subtitle(esc(error))
            self.fstrim_btn.set_sensitive(False)
            return False
        if not status.installed:
            self.fstrim_row.set_subtitle("fstrim isn't installed (it comes from util-linux)")
            self.fstrim_btn.set_sensitive(False)
            return False
        self.fstrim_row.set_subtitle(
            esc(
                f"fstrim.timer {'enabled' if status.enabled else 'disabled'} / "
                f"{'active' if status.active else 'inactive'}"
            )
        )
        self.fstrim_btn.set_sensitive(not status.enabled)
        return False

    def _on_journal_loaded(self, size, error) -> bool:
        if error:
            self.journal_row.set_subtitle(esc(error))
        else:
            self.journal_row.set_subtitle(esc(_human_bytes(size)))
        return False

    def _on_cache_loaded(self, size, error) -> bool:
        if error:
            self.cache_row.set_subtitle(esc(error))
        elif size is None:
            self.cache_row.set_subtitle("Couldn't measure ~/.cache")
        else:
            self.cache_row.set_subtitle(esc(_human_bytes(size)))
        return False

    # -- actions ----------------------------------------------------------------

    def _on_enable_fstrim(self, _btn: Gtk.Button) -> None:
        self.run_action(
            disk_health.enable_fstrim,
            lambda result, error: self.handle_command_result(result, error, "fstrim.timer enabled"),
        )

    def _on_vacuum_journal(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Vacuum the journal to 200 MB?",
            "journalctl --vacuum-size=200M deletes the oldest archived journal entries until the journal "
            "fits in 200 MB. This can't be undone.",
            "Vacuum",
            lambda: self.run_action(
                lambda: disk_health.vacuum_journal("200M"),
                lambda result, error: self.handle_command_result(result, error, "Journal vacuumed"),
            ),
        )

    def _on_clear_cache(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Delete everything in ~/.cache?",
            "Applications rebuild their caches; a running app may briefly slow down. Nothing outside "
            "~/.cache is touched.",
            "Delete",
            self._clear_cache,
        )

    def _clear_cache(self) -> None:
        def done(count, error) -> bool:
            if error:
                self.notify(f"Error: {error}", is_error=True)
                return False
            self.notify(f"Removed {count} item{'s' if count != 1 else ''} from ~/.cache")
            self.refresh()
            return False

        self.run_action(disk_health.clear_user_cache, done)

    def _on_clean_coredumps(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Clean old coredumps?",
            "systemd-tmpfiles --clean removes coredumps older than the age systemd keeps. Recent ones stay.",
            "Clean",
            lambda: self.run_action(
                disk_health.clean_coredumps,
                lambda result, error: self.handle_command_result(result, error, "Old coredumps cleaned"),
            ),
        )
