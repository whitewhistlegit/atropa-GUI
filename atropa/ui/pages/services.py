"""atropa.ui.pages.services - Systemd Services module."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import services
from atropa.ui.pages import BasePage, esc

MAX_ROWS = 150
JOURNAL_LINES = 100


class ServicesPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        filter_group = self.add_group("Filter")
        self.filter_row = Adw.EntryRow(title="Filter by name (e.g. 'sshd', leave empty for all)")
        filter_btn = Gtk.Button(label="Apply", valign=Gtk.Align.CENTER, css_classes=["flat"])
        filter_btn.connect("clicked", lambda _b: self.refresh())
        self.filter_row.add_suffix(filter_btn)
        filter_group.add(self.filter_row)

        self.services_group = self.add_group("Services")
        self.refresh()

    def refresh(self) -> None:
        term = self.filter_row.get_text().strip()
        pattern = f"*{term}*.service" if term else "*.service"
        self.clear_rows(self.services_group, getattr(self, "_service_rows", []))
        self._service_rows = [self.start_loading(self.services_group, "Loading services…")]
        self.run_async(lambda: services.list_services(pattern), self._on_loaded)

    def _on_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_service_rows", [])):
            self.services_group.remove(row)
        self._service_rows = []

        if error:
            self.notify(f"Failed to list services: {error}", is_error=True)
            return False

        if len(result) > MAX_ROWS:
            row = Adw.ActionRow(
                title=f"Showing the first {MAX_ROWS} of {len(result)} services",
                subtitle="Type part of a name in the filter above to find the rest",
            )
            self.services_group.add(row)
            self._service_rows.append(row)

        for svc in result[:MAX_ROWS]:
            subtitle = f"{svc.active}/{svc.sub} · {svc.enabled}"
            row = Adw.ActionRow(title=esc(svc.unit), subtitle=esc(subtitle))

            journal_btn = Gtk.Button(
                icon_name="text-x-generic-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"]
            )
            journal_btn.set_tooltip_text("Show its journal")
            journal_btn.connect("clicked", self._on_journal_clicked, svc.unit)
            row.add_suffix(journal_btn)

            if svc.active == "active":
                restart_btn = Gtk.Button(label="Restart", valign=Gtk.Align.CENTER, css_classes=["flat"])
                restart_btn.connect("clicked", self._on_restart_clicked, svc.unit)
                row.add_suffix(restart_btn)
                toggle_btn = Gtk.Button(label="Stop", valign=Gtk.Align.CENTER)
                toggle_btn.connect("clicked", self._on_stop_clicked, svc.unit)
            else:
                toggle_btn = Gtk.Button(label="Start", valign=Gtk.Align.CENTER)
                toggle_btn.connect("clicked", self._on_start_clicked, svc.unit)
            row.add_suffix(toggle_btn)

            if svc.enabled == "enabled":
                enable_btn = Gtk.Button(label="Disable", valign=Gtk.Align.CENTER, css_classes=["flat"])
                enable_btn.connect("clicked", self._on_disable_clicked, svc.unit)
            else:
                enable_btn = Gtk.Button(label="Enable", valign=Gtk.Align.CENTER, css_classes=["flat"])
                enable_btn.connect("clicked", self._on_enable_clicked, svc.unit)
            row.add_suffix(enable_btn)

            self.services_group.add(row)
            self._service_rows.append(row)
        return False

    def _on_start_clicked(self, _btn: Gtk.Button, unit: str) -> None:
        self.run_action(lambda: services.start(unit), self.handle_command_result)

    def _on_stop_clicked(self, _btn: Gtk.Button, unit: str) -> None:
        self._confirm_unit_change(unit, "Stop", f"{unit} stops right away.", services.stop)

    def _on_restart_clicked(self, _btn: Gtk.Button, unit: str) -> None:
        # stop_impact() describes the unit being gone. A restart is that for a
        # moment - and for good if the unit doesn't come back up, as sshd
        # won't with a broken config.
        impact = services.stop_impact(unit)
        body = f"{unit} stops and starts again."
        if impact:
            body += f"\n\nUntil it is back - or for good, if it fails to start: {impact}"
        self.confirm(
            f"Restart {unit}?",
            body,
            "Restart",
            lambda: self.run_action(
                lambda: services.restart(unit),
                lambda result, error: self.handle_command_result(result, error, f"Restarted {unit}"),
            ),
        )

    def _on_journal_clicked(self, _btn: Gtk.Button, unit: str) -> None:
        buffer = Gtk.TextBuffer()
        buffer.set_text("Loading…")
        text_view = Gtk.TextView(buffer=buffer, editable=False, monospace=True, cursor_visible=False)
        text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        scroller = Gtk.ScrolledWindow(min_content_height=360, min_content_width=560)
        scroller.set_child(text_view)

        dialog = Adw.AlertDialog(
            heading=f"Journal: {unit}", body=f"The last {JOURNAL_LINES} lines, newest at the bottom."
        )
        dialog.set_heading_use_markup(False)
        dialog.set_extra_child(scroller)
        dialog.add_response("close", "Close")

        def on_loaded(result, error) -> bool:
            if error:
                buffer.set_text(f"Couldn't read the journal: {error}")
            else:
                buffer.set_text(result.strip() or "No journal entries for this unit.")
            buffer.place_cursor(buffer.get_end_iter())
            text_view.scroll_to_mark(buffer.get_insert(), 0.0, True, 0.0, 1.0)
            return False

        self.run_async(lambda: services.journal_tail(unit, JOURNAL_LINES), on_loaded)
        dialog.present(self.get_root())

    def _on_enable_clicked(self, _btn: Gtk.Button, unit: str) -> None:
        self.run_action(lambda: services.enable(unit), self.handle_command_result)

    def _on_disable_clicked(self, _btn: Gtk.Button, unit: str) -> None:
        self._confirm_unit_change(
            unit, "Disable", f"{unit} keeps running for now but won't start at the next boot.", services.disable
        )

    def _confirm_unit_change(self, unit: str, verb: str, effect: str, action) -> None:
        self.confirm(
            f"{verb} {unit}?",
            f"{effect} {services.stop_impact(unit)}".strip(),
            verb,
            lambda: self.run_action(lambda: action(unit), self.handle_command_result),
        )
