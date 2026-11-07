"""
atropa.ui.pages.aide_page
--------------------------
CIS DIL Phase 3: File Integrity (AIDE). See backend/aide.py's docstring
for why installation isn't handled here (AUR-only, matches the existing
paru/yay posture) and why scheduling detects the package's own timer
rather than Atropa shipping a duplicate one.
"""

from __future__ import annotations

from datetime import datetime

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import aide
from atropa.ui.pages import BasePage, esc

# Showing every changed path of a big diff would turn the page into a wall
# of rows; the counts already say how much there is. The full list stays in
# the check log.
_CHANGE_LIMIT = 60

_KIND_LABELS = {"added": "ADDED", "removed": "REMOVED", "changed": "CHANGED"}


def _format_when(value: str) -> str:
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return value


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
        self._timer_subtitle = ""

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

        # The list of changed paths used to exist only inside the streaming
        # dialog, which is gone as soon as the check finishes. Keeping the
        # parsed result on disk makes the page answer "what changed?" the
        # next time it's opened, not just "how many".
        self.last_check_group = self.add_group(
            "Last check",
            "The saved result of the most recent check - it survives closing Atropa. Re-baselining clears it, "
            "because those changes become the new normal.",
        )
        self.last_check_row = Adw.ActionRow(title="No check recorded yet")
        self.last_check_group.add(self.last_check_row)
        self._change_rows: list[Adw.ActionRow] = []

        self.config_group = self.add_group(
            "Configuration",
            "Validates /etc/aide.conf and everything it includes, without walking the filesystem.",
        )
        self.config_row = Adw.ActionRow(title="aide.conf", subtitle="Not validated this session")
        self.validate_btn = Gtk.Button(label="Validate", valign=Gtk.Align.CENTER)
        self.validate_btn.connect("clicked", self._on_validate_config)
        self.config_row.add_suffix(self.validate_btn)
        self.config_group.add(self.config_row)

        self._last_check_output = ""

        self.refresh()

    # -- status ---------------------------------------------------------------

    def refresh(self) -> None:
        self.run_async(aide.get_status, self._on_status)
        self.run_async(aide.load_check_record, self._on_record_loaded)

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
            self.validate_btn.set_sensitive(False)
            self.init_btn.set_sensitive(False)
            return False

        self.installed_row.set_subtitle(
            esc(f"Config file: {'present' if status.config_exists else 'missing'} at {aide.CONFIG_FILE}")
        )
        self.status_group.add(self.installed_row)
        self._status_rows.append(self.installed_row)

        if status.baseline_initialized is None:
            # /var/lib/aide is root-only: a check (which runs as root) will say.
            self.baseline_row.set_subtitle(
                "Can't tell without root - the database directory isn't readable. Run a check to find out"
            )
            self.init_btn.set_label("Initialize baseline")
            self.check_btn.set_sensitive(True)
        elif status.baseline_initialized:
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
            self._timer_subtitle = f"{status.timer_unit} - {state}, {enabled}"
            self.timer_row.set_subtitle(esc(self._timer_subtitle))
            self.timer_btn.set_label("Disable" if status.timer_active or status.timer_enabled else "Enable")
            self.timer_btn.set_sensitive(True)
            self.run_async(lambda: aide.timer_details(status.timer_unit), self._on_timer_details)
        else:
            self._timer_subtitle = ""
            self.timer_row.set_subtitle(
                "No AIDE timer unit found - the AUR package usually ships one; check its post-install message"
            )
            self.timer_btn.set_sensitive(False)
        self.status_group.add(self.timer_row)
        self._status_rows.append(self.timer_row)

        return False

    def _on_timer_details(self, details, error) -> bool:
        if error or details is None or not self._timer_subtitle:
            return False
        if details.next_run:
            self.timer_row.set_subtitle(esc(f"{self._timer_subtitle} · next run {details.next_run}"))
        elif details.last_run:
            self.timer_row.set_subtitle(esc(f"{self._timer_subtitle} · last run {details.last_run}"))
        else:
            self.timer_row.set_subtitle(esc(f"{self._timer_subtitle} · no next run scheduled"))
        return False

    # -- last check -------------------------------------------------------------

    def _on_record_loaded(self, record, error) -> bool:
        if error:
            return False
        self._render_record(record)
        return False

    def _render_record(self, record: aide.CheckRecord | None) -> None:
        self.clear_rows(self.last_check_group, self._change_rows)
        self._change_rows = []

        if record is None:
            self.last_check_row.set_title("No check recorded yet")
            self.last_check_row.set_subtitle("Run a check to see what changed")
            return

        when = _format_when(record.checked_at)
        summary = record.summary
        if summary is None:
            self.last_check_row.set_title("Last check didn't produce a summary")
            self.last_check_row.set_subtitle(esc(f"{when} - see the check log for AIDE's raw output"))
            return
        if summary.clean:
            self.last_check_row.set_title("Clean - no changes detected")
            self.last_check_row.set_subtitle(esc(when))
            return

        self.last_check_row.set_title(
            f"{summary.added} added, {summary.removed} removed, {summary.changed} changed"
        )
        self.last_check_row.set_subtitle(esc(f"Checked {when}"))

        for entry in record.entries[:_CHANGE_LIMIT]:
            row = Adw.ActionRow(title=esc(entry.path))
            if entry.detail:
                row.set_subtitle(esc(entry.detail))
            row.add_suffix(Gtk.Label(label=_KIND_LABELS[entry.kind], css_classes=["dim-label"]))
            self.last_check_group.add(row)
            self._change_rows.append(row)

        remaining = len(record.entries) - _CHANGE_LIMIT
        if remaining > 0:
            row = Adw.ActionRow(
                title=esc(f"… and {remaining} more changed path{'s' if remaining != 1 else ''}"),
                subtitle="The full list is in the check log",
            )
            self.last_check_group.add(row)
            self._change_rows.append(row)

    # -- initialize / re-initialize baseline -----------------------------------

    def _on_initialize_clicked(self) -> None:
        self.run_streaming_operation("Initializing AIDE baseline", aide.initialize_baseline, self._on_baseline_done)

    def _on_baseline_done(self, result, error) -> bool:
        # A fresh baseline makes the saved check stale by definition - its
        # "changes" are exactly what was just accepted as the new normal.
        succeeded = error is None and getattr(result, "ok", False)
        if succeeded:
            aide.clear_check_record()
        handled = self.handle_command_result(result, error, success_message="Baseline updated")
        if succeeded:
            self._render_record(None)
        return handled

    # -- run check --------------------------------------------------------------

    def _on_check_clicked(self) -> None:
        # AIDE's exit status is a bitmask: 1 new, 2 removed, 4 changed (1-7).
        self.run_streaming_operation(
            "Running AIDE check", aide.run_check, self._on_check_done, success_codes=set(range(8))
        )

    def _on_check_done(self, result, error) -> bool:
        if error:
            self.notify(f"Error: {error}", is_error=True)
            return False

        self._last_check_output = result.stdout if result is not None else ""
        record = aide.build_check_record(
            self._last_check_output, result.returncode if result is not None else None
        )
        try:
            aide.save_check_record(record)
        except OSError as exc:
            self.notify(f"Check finished, but the result couldn't be saved: {exc}", is_error=True)

        if self.update_baseline_row is not None:
            self.check_group.remove(self.update_baseline_row)
            self.update_baseline_row = None

        self._render_record(record)
        summary = record.summary
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
        self.run_streaming_operation("Updating AIDE baseline", aide.update_baseline, self._on_baseline_done)

    # -- config validation ------------------------------------------------------

    def _on_validate_config(self, _btn: Gtk.Button) -> None:
        self.config_row.set_subtitle("Validating…")
        self.run_action(aide.check_config, self._on_config_validated)

    def _on_config_validated(self, result, error) -> bool:
        if error:
            self.config_row.set_subtitle(esc(f"Couldn't validate: {error}"))
            self.notify(f"Couldn't validate aide.conf: {error}", is_error=True)
            return False
        output = (result.stdout or result.stderr).strip()
        if result.ok:
            self.config_row.set_subtitle(esc(output or "Parses cleanly, including its includes"))
            self.notify("AIDE configuration is valid")
        else:
            self.config_row.set_subtitle(esc(f"Invalid: {output[:300]}"))
            self.notify("AIDE configuration has errors", is_error=True)
        return False

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
