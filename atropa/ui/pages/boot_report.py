"""atropa.ui.pages.boot_report - What went wrong since the last boot."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import boot_report
from atropa.ui.pages import BasePage, esc


def _format_uptime(seconds: float | None) -> str:
    if seconds is None:
        return "Uptime unavailable"
    total_minutes = int(seconds) // 60
    days, remainder = divmod(total_minutes, 24 * 60)
    hours, minutes = divmod(remainder, 60)
    if days:
        return f"up {days} d {hours} h {minutes} min"
    if hours:
        return f"up {hours} h {minutes} min"
    return f"up {minutes} min"


def _count(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _summary(report: boot_report.BootReport) -> str:
    return " · ".join(
        (
            _count(len(report.journal), "journal error"),
            _count(len(report.units), "failed unit"),
            _count(len(report.crashes), "recent crash"),
        )
    )


class BootReportPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self.boot_group = self.add_group("This boot")
        self.uptime_row = Adw.ActionRow(title="Reading boot status…")
        refresh_btn = Gtk.Button(label="Refresh", valign=Gtk.Align.CENTER)
        refresh_btn.connect("clicked", lambda _b: self.refresh())
        self.uptime_row.add_suffix(refresh_btn)
        self.boot_group.add(self.uptime_row)

        self.journal_group = self.add_group("Errors in this boot's journal")
        self.units_group = self.add_group("Failed units")
        self.crashes_group = self.add_group("Recent crashes")

        # key, group, row-list attribute, loading text, error-row title
        self._groups = (
            (
                "journal",
                self.journal_group,
                "_journal_rows",
                "Reading this boot's journal…",
                "Couldn't read this boot's journal",
            ),
            ("units", self.units_group, "_units_rows", "Reading failed units…", "Couldn't read failed units"),
            ("crashes", self.crashes_group, "_crashes_rows", "Reading recent crashes…", "Couldn't read recent crashes"),
        )
        self._journal_rows: list = []
        self._units_rows: list = []
        self._crashes_rows: list = []
        self.refresh()

    def refresh(self) -> None:
        self.uptime_row.set_title("Reading boot status…")
        self.uptime_row.set_subtitle("")
        for _key, group, attr, loading, _error_title in self._groups:
            self.clear_rows(group, getattr(self, attr))
            setattr(self, attr, [self.start_loading(group, loading)])
        self.run_async(boot_report.collect, self._on_loaded)

    def _on_loaded(self, result, error) -> bool:
        for _key, group, attr, _loading, _error_title in self._groups:
            self.clear_rows(group, getattr(self, attr))
            setattr(self, attr, [])

        if error:
            self.uptime_row.set_title("Couldn't read boot status")
            self.uptime_row.set_subtitle(esc(error))
            for _key, group, attr, _loading, error_title in self._groups:
                self._add_row(group, attr, error_title, str(error))
            return False

        report = result
        self.uptime_row.set_title(esc(_format_uptime(report.uptime)))
        self.uptime_row.set_subtitle(esc(_summary(report)))

        for key, group, attr, _loading, error_title in self._groups:
            self._fill_group(group, attr, getattr(report, key), report.errors.get(key, ""), error_title)
        return False

    def _fill_group(self, group, attr: str, problems: list, error: str, error_title: str) -> None:
        if error:
            self._add_row(group, attr, error_title, error)
            return
        if not problems:
            self._add_row(group, attr, "Nothing here", dim=True)
            return
        for problem in problems:
            self._add_row(group, attr, problem.title, problem.detail)

    def _add_row(self, group, attr: str, title: str, detail: str = "", dim: bool = False) -> None:
        row = Adw.ActionRow(title=esc(title), subtitle=esc(detail))
        if dim:
            row.add_css_class("dim-label")
        group.add(row)
        getattr(self, attr).append(row)
