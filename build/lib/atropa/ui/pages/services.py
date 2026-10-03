"""atropa.ui.pages.services - Systemd Services module."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import services
from atropa.ui.pages import BasePage, esc


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

        for svc in result[:150]:
            subtitle = f"{svc.active}/{svc.sub} · {svc.enabled}"
            row = Adw.ActionRow(title=esc(svc.unit), subtitle=esc(subtitle))

            if svc.active == "active":
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
        self.run_async(lambda: services.start(unit), self.handle_command_result)

    def _on_stop_clicked(self, _btn: Gtk.Button, unit: str) -> None:
        self.run_async(lambda: services.stop(unit), self.handle_command_result)

    def _on_enable_clicked(self, _btn: Gtk.Button, unit: str) -> None:
        self.run_async(lambda: services.enable(unit), self.handle_command_result)

    def _on_disable_clicked(self, _btn: Gtk.Button, unit: str) -> None:
        self.run_async(lambda: services.disable(unit), self.handle_command_result)
