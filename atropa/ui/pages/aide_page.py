"""
atropa.ui.pages.aide_page
--------------------------
CIS DIL Phase 3: File Integrity (AIDE). See backend/aide.py's docstring
for why installation isn't handled here (AUR-only, matches the existing
paru/yay posture) and why scheduling detects the package's own timer
rather than Atropa shipping a duplicate one.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import aide
from atropa.ui.pages import BasePage, esc


class AidePage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self.status_group = self.add_group(
            "File Integrity (AIDE)",
            "CIS 1.3-style filesystem integrity monitoring: a baseline database of file checksums/permissions, "
            "checked against the live filesystem to catch unexpected changes. AIDE is AUR-only on Arch (dropped "
            "from the official repos) - install it with your AUR helper first; Atropa manages it from there.",
        )
        self.not_installed_row: Adw.ActionRow | None = None
        self.installed_row = Adw.ActionRow(title="AIDE")
        self.baseline_row = Adw.ActionRow(title="Baseline database")
        self.init_btn = Gtk.Button(label="Initialize baseline", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        self.init_btn.connect("clicked", lambda _b: self._on_initialize_clicked())
        self.baseline_row.add_suffix(self.init_btn)

        self.timer_row = Adw.ActionRow(title="Scheduled checks")
        self.timer_btn = Gtk.Button(label="Enable", valign=Gtk.Align.CENTER)
        self.timer_btn.connect("clicked", lambda _b: self._on_timer_toggle_clicked())
        self.timer_row.add_suffix(self.timer_btn)

        # Rows currently added to status_group - tracked explicitly (same
        # pattern as inventory_hygiene.py's _inventory_rows) rather than
        # remove()-with-a-swallowed-exception, so refresh() never risks
        # stacking duplicate rows or silently masking a real removal bug.
        self._status_rows: list[Adw.ActionRow] = []

        self.check_group = self.add_group(
            "Run a check",
            "Compares the live filesystem against the baseline database and reports what's added, removed, or "
            "changed. Can take a few minutes on a full disk.",
        )
        self.check_btn = Gtk.Button(label="Run check now", valign=Gtk.Align.CENTER)
        self.check_btn.connect("clicked", lambda _b: self._on_check_clicked())
        self.check_summary_row = Adw.ActionRow(title="No check run yet this session")
        self.check_summary_row.add_suffix(self.check_btn)
        self.check_group.add(self.check_summary_row)
        self.update_baseline_row: Adw.ActionRow | None = None

        self._last_check_output = ""

        self.refresh()

    # -- status ---------------------------------------------------------------

    def refresh(self) -> None:
        self.run_async(aide.get_status, self._on_status)

    def _on_status(self, status, error) -> bool:
        self.clear_rows(self.status_group, self._status_rows)
        self._status_rows = []

        if error:
            self.notify(f"Error: {error}", is_error=True)
            return False

        if not status.installed:
            row = Adw.ActionRow(
                title="AIDE isn't installed",
                subtitle="AUR-only - install it with your AUR helper (e.g. `paru -S aide`), then come back here.",
            )
            self.status_group.add(row)
            self._status_rows.append(row)
            self.check_btn.set_sensitive(False)
            return False

        self.installed_row.set_subtitle(esc(f"Config file: {'present' if status.config_exists else 'missing'} at {aide.CONFIG_FILE}"))
        self.status_group.add(self.installed_row)
        self._status_rows.append(self.installed_row)

        if status.baseline_initialized:
            self.baseline_row.set_subtitle("Initialized")
            self.init_btn.set_label("Re-initialize")
            self.check_btn.set_sensitive(True)
        else:
            self.baseline_row.set_subtitle("Not yet initialized - run this before checks mean anything")
            self.init_btn.set_label("Initialize baseline")
            self.check_btn.set_sensitive(False)
        self.status_group.add(self.baseline_row)
        self._status_rows.append(self.baseline_row)

        if status.timer_unit:
            state = "active" if status.timer_active else "inactive"
            enabled = "enabled at boot" if status.timer_enabled else "not enabled at boot"
            self.timer_row.set_subtitle(esc(f"{status.timer_unit} - {state}, {enabled}"))
            self.timer_btn.set_label("Disable" if status.timer_active or status.timer_enabled else "Enable")
            self.timer_btn.set_sensitive(True)
        else:
            self.timer_row.set_subtitle(
                "No AIDE timer unit found - the AUR package usually ships one; check its post-install message"
            )
            self.timer_btn.set_sensitive(False)
        self.status_group.add(self.timer_row)
        self._status_rows.append(self.timer_row)

        return False

    # -- initialize / re-initialize baseline -----------------------------------

    def _on_initialize_clicked(self) -> None:
        self.run_streaming_operation("Initializing AIDE baseline", aide.initialize_baseline, self._on_init_done)

    def _on_init_done(self, result, error) -> bool:
        return self.handle_command_result(result, error, success_message="Baseline initialized")

    # -- run check --------------------------------------------------------------

    def _on_check_clicked(self) -> None:
        self.run_streaming_operation("Running AIDE check", aide.run_check, self._on_check_done)

    def _on_check_done(self, result, error) -> bool:
        if error:
            self.notify(f"Error: {error}", is_error=True)
            return False

        self._last_check_output = result.stdout if result is not None else ""
        summary = aide.parse_check_summary(self._last_check_output)

        if self.update_baseline_row is not None:
            self.check_group.remove(self.update_baseline_row)
            self.update_baseline_row = None

        if summary is None:
            self.check_summary_row.set_title("Check finished, but no summary could be parsed")
            self.check_summary_row.set_subtitle("See the log above for AIDE's raw output")
        elif summary.clean:
            self.check_summary_row.set_title("Clean - no changes detected")
            self.check_summary_row.set_subtitle("")
        else:
            self.check_summary_row.set_title(
                f"{summary.added} added, {summary.removed} removed, {summary.changed} changed"
            )
            self.check_summary_row.set_subtitle("Review the changes below before updating the baseline")
            self.update_baseline_row = Adw.ActionRow(
                title="Update baseline",
                subtitle="Only do this after you've confirmed the changes above are legitimate - "
                "re-baselining accepts everything currently reported as the new normal.",
            )
            update_btn = Gtk.Button(label="Update baseline", valign=Gtk.Align.CENTER, css_classes=["destructive-action"])
            update_btn.connect("clicked", lambda _b: self._on_update_baseline_clicked())
            self.update_baseline_row.add_suffix(update_btn)
            self.check_group.add(self.update_baseline_row)

        return False

    def _on_update_baseline_clicked(self) -> None:
        self.confirm(
            "Update the AIDE baseline?",
            "This accepts everything the last check reported (additions, removals, changes) as the new "
            "trusted state. Only do this if you've reviewed the changes and they're legitimate.",
            "Update baseline",
            self._run_update_baseline,
        )

    def _run_update_baseline(self) -> None:
        self.run_streaming_operation("Updating AIDE baseline", aide.update_baseline, self._on_init_done)

    # -- timer --------------------------------------------------------------

    def _on_timer_toggle_clicked(self) -> None:
        self.run_async(self._toggle_timer, self._on_timer_toggled)

    def _toggle_timer(self):
        status = aide.get_status()
        if not status.timer_unit:
            return None
        if status.timer_active or status.timer_enabled:
            return aide.disable_timer(status.timer_unit)
        return aide.enable_timer(status.timer_unit)

    def _on_timer_toggled(self, result, error) -> bool:
        return self.handle_command_result(result, error)
