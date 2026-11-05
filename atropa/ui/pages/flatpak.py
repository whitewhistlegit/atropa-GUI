"""atropa.ui.pages.flatpak - Flatpak module (apps, updates, and unused runtimes)."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import flatpak
from atropa.ui.pages import BasePage, esc


class FlatpakPage(BasePage):
    def __init__(self) -> None:
        super().__init__()
        self._installed = flatpak.flatpak_installed()
        self._app_rows: list = []
        self._update_rows: list = []

        self.apps_group = self.add_group("Installed applications")

        self.updates_group = self.add_group("Updates", "Updates come from each app's configured remote")
        self.updates_row = Adw.ActionRow(title="Not checked")
        self.check_btn = Gtk.Button(label="Check", valign=Gtk.Align.CENTER)
        self.check_btn.connect("clicked", lambda _b: self._load_updates())
        self.updates_row.add_suffix(self.check_btn)
        self.update_all_btn = Gtk.Button(label="Update all")
        self.update_all_btn.add_css_class("suggested-action")
        self.update_all_btn.set_valign(Gtk.Align.CENTER)
        self.update_all_btn.connect("clicked", self._on_update_all_clicked)
        self.updates_row.add_suffix(self.update_all_btn)
        self.updates_group.add(self.updates_row)

        self.cleanup_group = self.add_group("Cleanup")
        self.cleanup_row = Adw.ActionRow(
            title="Remove unused runtimes",
            subtitle="Runtimes no installed app depends on",
        )
        self.remove_btn = Gtk.Button(label="Remove", valign=Gtk.Align.CENTER)
        self.remove_btn.connect("clicked", self._on_remove_unused_clicked)
        self.cleanup_row.add_suffix(self.remove_btn)
        self.cleanup_group.add(self.cleanup_row)

        self.refresh()

    # -- loading ------------------------------------------------------------

    def refresh(self) -> None:
        # Re-check rather than trust __init__: Flatpak may have been installed
        # while the window stayed open.
        self._installed = flatpak.flatpak_installed()
        if not self._installed:
            self._show_missing()
            return

        self._load_apps()
        self._load_updates()

    def _show_missing(self) -> None:
        self._drop_rows(self.apps_group, "_app_rows")
        self._drop_rows(self.updates_group, "_update_rows")

        row = Adw.ActionRow(title="Flatpak isn't installed (pacman -S flatpak)")
        row.add_css_class("dim-label")
        self.apps_group.add(row)
        self._app_rows.append(row)

        self.updates_row.set_title("Not checked")
        self.updates_row.set_subtitle(esc("Flatpak isn't installed - nothing to check"))
        self.check_btn.set_sensitive(False)
        self.update_all_btn.set_sensitive(False)
        self.remove_btn.set_sensitive(False)
        self.cleanup_row.set_subtitle(esc("Flatpak isn't installed"))

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

    def _load_apps(self) -> None:
        self.check_btn.set_sensitive(True)
        self.update_all_btn.set_sensitive(True)
        self.remove_btn.set_sensitive(True)

        self._drop_rows(self.apps_group, "_app_rows")
        self._app_rows = [self.start_loading(self.apps_group, "Listing Flatpak apps…")]
        self.run_async(flatpak.installed_apps, self._on_apps_loaded)

    def _on_apps_loaded(self, result, error) -> bool:
        self._drop_rows(self.apps_group, "_app_rows")

        if error:
            self._add_row(self.apps_group, "_app_rows", "Couldn't list Flatpak apps", str(error))
            return False
        if not result:
            self._add_row(
                self.apps_group,
                "_app_rows",
                "No Flatpak apps installed",
                "Install one with: flatpak install <remote> <app-id>",
            )
            return False

        for app in result:
            subtitle = f"version {app.version or 'unknown'} · {app.origin or 'unknown'}"
            self._add_row(self.apps_group, "_app_rows", app.app_id, subtitle)
        return False

    def _load_updates(self) -> None:
        if not self._installed:
            return
        self._drop_rows(self.updates_group, "_update_rows")
        self.updates_row.set_title("Checking for updates…")
        self.updates_row.set_subtitle("")
        self._update_rows = [self.start_loading(self.updates_group, "Checking for updates…")]
        self.run_async(flatpak.available_updates, self._on_updates_loaded)

    def _on_updates_loaded(self, result, error) -> bool:
        self._drop_rows(self.updates_group, "_update_rows")

        if error:
            self.updates_row.set_title("Not checked")
            self.updates_row.set_subtitle(esc(f"Couldn't check: {error}"))
            return False
        if not result:
            self.updates_row.set_title("Up to date")
            self.updates_row.set_subtitle("")
            return False

        count = len(result)
        self.updates_row.set_title(f"{count} update{'s' if count != 1 else ''}")
        self.updates_row.set_subtitle("")
        for update in result:
            subtitle = f"version {update.version or 'unknown'} · {update.origin or 'unknown'}"
            self._add_row(self.updates_group, "_update_rows", update.app_id, subtitle)
        return False

    # -- actions ------------------------------------------------------------

    def _on_update_all_clicked(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Update all Flatpak apps?",
            "Runs flatpak update -y, including runtimes. System-wide installs prompt for the administrator password.",
            "Update",
            lambda: self.run_streaming_operation("Updating Flatpak apps", flatpak.update_all),
        )

    def _on_remove_unused_clicked(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Remove unused Flatpak runtimes?",
            "Deletes runtimes no installed app depends on. Freed space can be large; reinstalling an app "
            "re-downloads them.",
            "Remove",
            lambda: self.run_streaming_operation("Removing unused runtimes", flatpak.remove_unused),
        )
