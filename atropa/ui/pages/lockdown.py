"""atropa.ui.pages.lockdown - reversible radio lockdown plus on-demand scans."""

from __future__ import annotations

from datetime import datetime

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import aide, hardening, lockdown, rootkit
from atropa.ui.pages import BasePage, esc

_LOCKDOWN_BODY = (
    "Turns off NetworkManager networking (wired and Wi-Fi) and the Wi-Fi radio, and stops the Bluetooth "
    "service. If you're connected over SSH the session will drop; if your keyboard or mouse is Bluetooth "
    "it will disconnect. The state from before is saved, and 'Exit lockdown' restores exactly that - "
    "a radio that was already off stays off."
)


def _format_when(value: str) -> str:
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return value


def _on_off(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return "on" if value else "off"


class LockdownPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self.lockdown_group = self.add_group(
            "Lockdown",
            "A reversible radio-silence mode: no wired or wireless networking, no Wi-Fi radio, no Bluetooth. "
            "Nothing about the firewall or SSH configuration is changed - with networking off there is no "
            "remote surface left to reach.",
        )
        self.lockdown_row = Adw.ActionRow(title="Checking lockdown status…")
        self.lock_btn = Gtk.Button(
            label="Turn on lockdown", valign=Gtk.Align.CENTER, css_classes=["destructive-action"]
        )
        self.lock_btn.connect("clicked", self._on_lockdown)
        self.restore_btn = Gtk.Button(label="Exit lockdown", valign=Gtk.Align.CENTER, visible=False)
        self.restore_btn.connect("clicked", self._on_restore)
        self.lockdown_row.add_suffix(self.lock_btn)
        self.lockdown_row.add_suffix(self.restore_btn)
        self.lockdown_group.add(self.lockdown_row)

        self.scan_group = self.add_group(
            "Scans",
            "On demand and read-only (the scanners themselves run as root through pkexec). None of these "
            "removes or fixes anything: a scanner's warnings are a starting point for review, not a verdict.",
        )

        self.aide_row = Adw.ActionRow(title="File integrity (AIDE)", subtitle="Checking…")
        self.aide_btn = Gtk.Button(label="Run check", valign=Gtk.Align.CENTER)
        self.aide_btn.connect("clicked", self._on_aide_check)
        self.aide_row.add_suffix(self.aide_btn)
        self.scan_group.add(self.aide_row)

        self.rootkit_row = Adw.ActionRow(title="Rootkit scan (rkhunter)", subtitle="Checking…")
        self.rootkit_btn = Gtk.Button(label="Scan", valign=Gtk.Align.CENTER)
        self.rootkit_btn.connect("clicked", self._on_rootkit_scan)
        self.update_btn = Gtk.Button(label="Update signatures", valign=Gtk.Align.CENTER)
        self.update_btn.connect("clicked", self._on_rootkit_update)
        self.rootkit_row.add_suffix(self.rootkit_btn)
        self.rootkit_row.add_suffix(self.update_btn)
        self.scan_group.add(self.rootkit_row)

        self.baseline_row = Adw.ActionRow(
            title="Rootkit baseline",
            subtitle="Records current file properties as trusted after a clean scan or a trusted update",
        )
        self.baseline_btn = Gtk.Button(
            label="Rebaseline", valign=Gtk.Align.CENTER, css_classes=["destructive-action"]
        )
        self.baseline_btn.connect("clicked", self._on_rootkit_baseline)
        self.baseline_row.add_suffix(self.baseline_btn)
        self.scan_group.add(self.baseline_row)

        self.cve_row = Adw.ActionRow(title="Known CVEs (arch-audit)", subtitle="Not checked this session")
        self.cve_btn = Gtk.Button(label="Scan", valign=Gtk.Align.CENTER)
        self.cve_btn.connect("clicked", self._on_cve_scan)
        self.cve_row.add_suffix(self.cve_btn)
        self.scan_group.add(self.cve_row)

        self.refresh()

    # -- status -----------------------------------------------------------------

    def refresh(self) -> None:
        self.run_async(lockdown.status, self._on_lockdown_status)
        self.run_async(self._scan_status, self._on_scan_status)

    def _on_lockdown_status(self, status, error) -> bool:
        if error:
            self.lockdown_row.set_title("Couldn't read lockdown status")
            self.lockdown_row.set_subtitle(esc(error))
            return False

        if status.active:
            saved = _format_when(status.snapshot.saved_at) if status.snapshot and status.snapshot.saved_at else "earlier"
            self.lockdown_row.set_title("Lockdown is on")
            self.lockdown_row.set_subtitle(
                esc(
                    f"Networking and the Wi-Fi radio are off, Bluetooth is stopped. The state saved {saved} "
                    "is restored by 'Exit lockdown'."
                )
            )
            self.lock_btn.set_visible(False)
            self.restore_btn.set_visible(True)
            self.restore_btn.set_sensitive(True)
            return False

        self.lockdown_row.set_title("Lockdown is off")
        self.lockdown_row.set_subtitle(
            esc(
                f"Networking {_on_off(status.networking)} · Wi-Fi radio {_on_off(status.wifi)} · "
                f"Bluetooth {'active' if status.bluetooth_active else 'inactive' if status.bluetooth_active is False else 'unknown'}"
            )
        )
        self.lock_btn.set_visible(True)
        self.lock_btn.set_sensitive(True)
        self.restore_btn.set_visible(False)
        return False

    @staticmethod
    def _scan_status() -> dict:
        state: dict = {}
        try:
            state["aide"] = aide.get_status()
        except Exception as exc:  # noqa: BLE001 - shown in that row
            state["aide_error"] = str(exc)
        try:
            state["aide_record"] = aide.load_check_record()
        except Exception:  # noqa: BLE001
            state["aide_record"] = None
        try:
            state["rootkit"] = rootkit.status()
        except Exception as exc:  # noqa: BLE001
            state["rootkit_error"] = str(exc)
        try:
            state["rootkit_record"] = rootkit.load_scan_record()
        except Exception:  # noqa: BLE001
            state["rootkit_record"] = None
        return state

    def _on_scan_status(self, state, error) -> bool:
        if error:
            self.aide_row.set_subtitle(esc(f"Couldn't check AIDE: {error}"))
            self.rootkit_row.set_subtitle(esc(f"Couldn't check rkhunter: {error}"))
            return False

        aide_status = state.get("aide")
        if state.get("aide_error") or aide_status is None or not aide_status.installed:
            self.aide_row.set_subtitle(
                "AIDE isn't installed - install it with your AUR helper (e.g. `paru -S aide`), then return here."
            )
            self.aide_btn.set_sensitive(False)
        elif aide_status.baseline_initialized is False:
            self.aide_row.set_subtitle(
                "AIDE is installed but has no baseline yet - initialize it on the File Integrity page first."
            )
            self.aide_btn.set_sensitive(False)
        else:
            self.aide_btn.set_sensitive(True)
            record = state.get("aide_record")
            if record is None:
                self.aide_row.set_subtitle("AIDE is installed; no check recorded yet")
            elif record.summary is None:
                self.aide_row.set_subtitle(esc(f"Last check {_format_when(record.checked_at)} produced no summary"))
            elif record.summary.clean:
                self.aide_row.set_subtitle(esc(f"Last check {_format_when(record.checked_at)}: no changes"))
            else:
                summary = record.summary
                self.aide_row.set_subtitle(
                    esc(
                        f"Last check {_format_when(record.checked_at)}: {summary.added} added, "
                        f"{summary.removed} removed, {summary.changed} changed"
                    )
                )

        rootkit_status = state.get("rootkit")
        if state.get("rootkit_error") or rootkit_status is None or not rootkit_status.installed:
            self.rootkit_row.set_subtitle(
                "rkhunter isn't installed - install it with: pacman -S rkhunter"
            )
            self.rootkit_btn.set_sensitive(False)
            self.update_btn.set_sensitive(False)
            self.baseline_btn.set_sensitive(False)
        else:
            self.rootkit_btn.set_sensitive(True)
            self.update_btn.set_sensitive(True)
            self.baseline_btn.set_sensitive(True)
            updated = (
                f"signatures updated {_format_when(rootkit_status.database_updated)}"
                if rootkit_status.database_updated
                else "signature date unknown"
            )
            record = state.get("rootkit_record")
            if record is None:
                self.rootkit_row.set_subtitle(esc(f"rkhunter installed; {updated}; no scan recorded yet"))
            elif record.has_warnings:
                self.rootkit_row.set_subtitle(
                    esc(f"Last scan {_format_when(record.checked_at)}: {len(record.warnings)} warning(s)")
                )
            else:
                self.rootkit_row.set_subtitle(
                    esc(f"Last scan {_format_when(record.checked_at)}: no warnings reported")
                )
        return False

    # -- lockdown actions -------------------------------------------------------

    def _on_lockdown(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Turn on lockdown?",
            _LOCKDOWN_BODY,
            "Turn on lockdown",
            lambda: self.run_action(
                lockdown.enable,
                lambda result, error: self.handle_command_result(result, error, "Lockdown is on"),
            ),
        )

    def _on_restore(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Exit lockdown?",
            "Restores the networking, Wi-Fi radio and Bluetooth state saved when lockdown was turned on. "
            "Radios that were already off stay off.",
            "Restore",
            lambda: self.run_action(
                lockdown.disable,
                lambda result, error: self.handle_command_result(result, error, "Lockdown is off"),
            ),
        )

    # -- scans -------------------------------------------------------------------

    def _on_aide_check(self, _btn: Gtk.Button) -> None:
        self.aide_row.set_subtitle("Running AIDE check…")
        # AIDE's exit status is a bitmask: 1 new, 2 removed, 4 changed (1-7).
        self.run_streaming_operation(
            "Running AIDE check", aide.run_check, self._on_aide_done, success_codes=set(range(8))
        )

    def _on_aide_done(self, result, error) -> bool:
        if error:
            self.notify(f"AIDE check failed: {error}", is_error=True)
            self.aide_row.set_subtitle(esc(f"AIDE check failed: {error}"))
            return False

        output = result.stdout if result is not None else ""
        record = aide.build_check_record(output, result.returncode if result is not None else None)
        try:
            aide.save_check_record(record)
        except OSError as exc:
            self.notify(f"AIDE finished, but the result couldn't be saved: {exc}", is_error=True)

        summary = record.summary
        when = _format_when(record.checked_at)
        if summary is None:
            message = "AIDE finished without a parsable summary"
        elif summary.clean:
            message = f"AIDE: no changes ({when})"
        else:
            message = (
                f"AIDE: {summary.added} added, {summary.removed} removed, "
                f"{summary.changed} changed ({when})"
            )
        self.aide_row.set_subtitle(esc(message))
        self.notify(message, is_error=summary is not None and not summary.clean)
        return False

    def _on_rootkit_scan(self, _btn: Gtk.Button) -> None:
        self.rootkit_row.set_subtitle("Running rkhunter…")
        self.run_streaming_operation(
            "Running rootkit scan", rootkit.scan, self._on_rootkit_done, success_codes={0, 1}
        )

    def _on_rootkit_done(self, result, error) -> bool:
        if error:
            self.notify(f"Rootkit scan failed: {error}", is_error=True)
            self.rootkit_row.set_subtitle(esc(f"Rootkit scan failed: {error}"))
            return False

        output = result.stdout if result is not None else ""
        record = rootkit.build_scan_record(output, result.returncode if result is not None else 0)
        try:
            rootkit.save_scan_record(record)
        except OSError as exc:
            self.notify(f"Scan finished, but the result couldn't be saved: {exc}", is_error=True)

        when = _format_when(record.checked_at)
        if record.has_warnings:
            message = f"{len(record.warnings)} warning(s) found ({when}) - review the scan log"
            self.rootkit_row.set_subtitle(esc(message))
            self.notify(message, is_error=True)
        else:
            message = f"No warnings reported ({when})"
            self.rootkit_row.set_subtitle(esc(message))
            self.notify(message)
        return False

    def _on_rootkit_update(self, _btn: Gtk.Button) -> None:
        self.run_action(rootkit.update_signatures, self.handle_command_result)

    def _on_rootkit_baseline(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Accept the current filesystem state as the rootkit baseline?",
            "rkhunter records the current file properties as trusted. If this machine is already "
            "compromised, that makes the compromise the baseline - only do this after a clean scan or "
            "a trusted package update.",
            "Rebaseline",
            lambda: self.run_action(rootkit.update_baseline, self.handle_command_result),
        )

    def _on_cve_scan(self, _btn: Gtk.Button) -> None:
        self.cve_row.set_subtitle("Scanning installed packages…")
        self.run_async(hardening.vulnerability_scan, self._on_cve_done)

    def _on_cve_done(self, advisories, error) -> bool:
        if error:
            self.cve_row.set_subtitle(esc(f"Couldn't scan: {error}"))
            self.notify(f"Vulnerability scan failed: {error}", is_error=True)
            return False
        if not advisories:
            self.cve_row.set_subtitle("No known vulnerabilities in the installed packages")
            return False
        self.cve_row.set_subtitle(
            esc(f"{len(advisories)} advisory line(s) - see the Hardening page for the details")
        )
        self.notify(f"{len(advisories)} vulnerable package(s) found", is_error=True)
        return False
