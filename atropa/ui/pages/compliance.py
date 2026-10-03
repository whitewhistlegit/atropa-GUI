"""atropa.ui.pages.compliance - Compliance Report: a categorized, scored security posture summary."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, Gtk  # noqa: E402

from atropa.backend import compliance
from atropa.ui.pages import BasePage, esc

_STATUS_ICON = {
    "pass": "emblem-ok-symbolic",
    "warn": "dialog-warning-symbolic",
    "fail": "dialog-error-symbolic",
    "info": "dialog-information-symbolic",
}


class CompliancePage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        intro_group = self.add_group(
            "Compliance Report",
            f"{compliance.DISCLAIMER}",
        )
        self.summary_row = Adw.ActionRow(title="Generating report…")
        export_btn = Gtk.Button(label="Export Report (Markdown)", valign=Gtk.Align.CENTER)
        export_btn.connect("clicked", self._on_export_clicked)
        self.summary_row.add_suffix(export_btn)
        refresh_btn = Gtk.Button(label="Re-run", valign=Gtk.Align.CENTER)
        refresh_btn.connect("clicked", lambda _b: self.refresh())
        self.summary_row.add_suffix(refresh_btn)
        intro_group.add(self.summary_row)

        self._category_groups: list[Adw.PreferencesGroup] = []
        self._report = None
        self.refresh()

    def refresh(self) -> None:
        self.summary_row.set_title("Generating report…")
        self.summary_row.set_subtitle("")
        self.run_async(compliance.generate_report, self._on_report_loaded)

    def _on_report_loaded(self, result, error) -> bool:
        if error:
            self.summary_row.set_title("Couldn't generate report")
            self.summary_row.set_subtitle(esc(error))
            return False

        self._report = result

        # Rebuild the category groups from scratch each run - the set of
        # categories can change (e.g. a category disappears if nothing
        # scorable ever lands in it), so a fixed pre-built layout like the
        # Dependencies page uses doesn't fit here as cleanly.
        for group in self._category_groups:
            self.preferences_page.remove(group)
        self._category_groups = []

        pct = round(result.overall_score * 100)
        self.summary_row.set_title(f"Overall score: {pct}% ({result.scored_check_count} scored checks)")
        self.summary_row.set_subtitle(f"Host: {result.hostname} · Generated {result.generated_at}")

        for category in result.categories:
            score_text = f"{round(category.score * 100)}%" if category.score is not None else "N/A"
            group = self.add_group(f"{category.name} — {score_text}")
            for check in category.checks:
                row = Adw.ActionRow(title=esc(check.name), subtitle=esc(check.detail))
                row.add_prefix(Gtk.Image.new_from_icon_name(_STATUS_ICON.get(check.status, "dialog-question-symbolic")))
                row.add_suffix(Gtk.Label(label=check.status.upper(), css_classes=["dim-label"]))
                group.add(row)
            self._category_groups.append(group)

        return False

    def _on_export_clicked(self, _btn: Gtk.Button) -> None:
        if self._report is None:
            self.notify("Report isn't ready yet", is_error=True)
            return

        dialog = Gtk.FileDialog()
        dialog.set_initial_name("atropa-compliance-report.md")
        dialog.save(self.get_root(), None, self._on_save_location_chosen)

    def _on_save_location_chosen(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            gfile = dialog.save_finish(result)
        except Exception:  # noqa: BLE001 - user cancelled or dialog error, nothing to do
            return
        if not gfile:
            return
        path = gfile.get_path()
        if not path:
            return
        try:
            compliance.save_report_to_file(self._report, path)
        except OSError as exc:
            self.notify(f"Couldn't save report: {exc}", is_error=True)
            return
        self.notify(f"Report saved to {path}")
