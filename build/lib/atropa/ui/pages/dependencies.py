"""atropa.ui.pages.dependencies - Dependency overview: what's installed, what's missing, install from here."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import dependencies, pacman
from atropa.ui.pages import BasePage, esc


class DependenciesPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        intro_group = self.add_group(
            "Dependencies",
            "Every external tool Atropa's modules shell out to, in one place, instead of "
            "discovering a gap only when you click into that module. Nothing here is required "
            "just to run Atropa itself - only pkexec and pacman are core; everything else "
            "enables a specific module.",
        )
        self.summary_row = Adw.ActionRow(title="Checking installed tools…")
        refresh_btn = Gtk.Button(label="Re-check", valign=Gtk.Align.CENTER)
        refresh_btn.connect("clicked", lambda _b: self.refresh())
        self.summary_row.add_suffix(refresh_btn)
        intro_group.add(self.summary_row)

        self._module_groups: dict[str, Adw.PreferencesGroup] = {}
        self._group_rows: dict[str, list] = {}
        # Pre-create one group per module, in catalog order, so layout is stable
        # across refreshes instead of groups appearing/disappearing/reordering.
        seen_modules: list[str] = []
        for dep in dependencies.CATALOG:
            if dep.module not in seen_modules:
                seen_modules.append(dep.module)
        for module_name in seen_modules:
            group = self.add_group(module_name)
            self._module_groups[module_name] = group
            self._group_rows[module_name] = []

        self.refresh()

    def refresh(self) -> None:
        self.summary_row.set_title("Checking installed tools…")
        self.summary_row.set_subtitle("")
        for module_name, group in self._module_groups.items():
            self.clear_rows(group, self._group_rows[module_name])
            self._group_rows[module_name] = [self.start_loading(group, "Checking…")]
        self.run_async(dependencies.check_all, self._on_loaded)

    def _on_loaded(self, result, error) -> bool:
        if error:
            self.summary_row.set_title("Couldn't check dependencies")
            self.summary_row.set_subtitle(esc(error))
            return False

        installed = sum(1 for s in result if s.installed)
        total = len(result)
        missing_required = [s for s in result if s.dependency.required and not s.installed]
        if missing_required:
            names = ", ".join(s.dependency.name for s in missing_required)
            self.summary_row.set_title(f"{installed}/{total} installed - missing required: {names}")
        else:
            self.summary_row.set_title(f"{installed}/{total} tools installed")

        # Group statuses by module, preserving catalog order within each group.
        by_module: dict[str, list] = {name: [] for name in self._module_groups}
        for status in result:
            by_module.setdefault(status.dependency.module, []).append(status)

        for module_name, group in self._module_groups.items():
            self.clear_rows(group, self._group_rows[module_name])
            rows = []
            for status in by_module.get(module_name, []):
                row = self._build_row(status)
                group.add(row)
                rows.append(row)
            self._group_rows[module_name] = rows

        return False

    def _build_row(self, status) -> Adw.ActionRow:
        dep = status.dependency
        subtitle = f"{dep.description} · required" if dep.required else dep.description
        row = Adw.ActionRow(title=esc(dep.name), subtitle=esc(subtitle))

        if status.installed:
            row.add_prefix(Gtk.Image.new_from_icon_name("emblem-ok-symbolic"))
            row.add_suffix(Gtk.Label(label="installed", css_classes=["dim-label"]))
            return row

        icon_name = "dialog-error-symbolic" if dep.required else "dialog-warning-symbolic"
        row.add_prefix(Gtk.Image.new_from_icon_name(icon_name))

        if dep.package:
            install_btn = Gtk.Button(label=f"Install {dep.package}", valign=Gtk.Align.CENTER)
            if dep.required:
                install_btn.add_css_class("suggested-action")
            install_btn.connect("clicked", self._on_install_clicked, dep.package)
            row.add_suffix(install_btn)
        elif dep.note:
            row.set_subtitle(esc(f"{subtitle} · {dep.note}"))

        return row

    def _on_install_clicked(self, _btn: Gtk.Button, package: str) -> None:
        self.confirm(
            f"Install {package}?",
            f"Runs 'pacman -S {package}'.",
            "Install",
            lambda: self.run_async(lambda: pacman.install([package]), self.handle_command_result),
        )
