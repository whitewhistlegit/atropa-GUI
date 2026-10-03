"""atropa.ui.pages.packages - Package Management module (pacman + AUR)."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import pacman
from atropa.ui.pages import BasePage, esc


class PackagesPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        # --- System-wide actions -------------------------------------------------
        actions_group = self.add_group("System", "Keep your package database and installed software current")

        self.updates_row = Adw.ActionRow(title="Checking for updates…")
        sync_btn = Gtk.Button(label="Refresh database")
        sync_btn.set_valign(Gtk.Align.CENTER)
        sync_btn.connect("clicked", self._on_sync_clicked)
        self.updates_row.add_suffix(sync_btn)

        upgrade_btn = Gtk.Button(label="Upgrade system")
        upgrade_btn.add_css_class("suggested-action")
        upgrade_btn.set_valign(Gtk.Align.CENTER)
        upgrade_btn.connect("clicked", self._on_upgrade_clicked)
        self.updates_row.add_suffix(upgrade_btn)
        actions_group.add(self.updates_row)

        clean_row = Adw.ActionRow(title="Clean package cache", subtitle="Remove old/uninstalled packages from /var/cache/pacman")
        clean_btn = Gtk.Button(label="Clean")
        clean_btn.set_valign(Gtk.Align.CENTER)
        clean_btn.connect("clicked", self._on_clean_clicked)
        clean_row.add_suffix(clean_btn)
        actions_group.add(clean_row)

        # --- pending updates (visible list, not just a count) -----------------------
        self.updates_list_group = self.add_group(
            "Pending Updates",
            "Updating a single package here instead of the full system is a partial "
            "upgrade - Arch explicitly discourages this since other still-outdated "
            "packages may depend on the old library versions. Prefer 'Upgrade system' above.",
        )

        # --- Search / install ------------------------------------------------------
        search_group = self.add_group("Find and Install", "Searches official repos plus AUR (if paru/yay is installed)")
        self.search_entry = Adw.EntryRow(title="Package name")
        search_btn = Gtk.Button(label="Search", valign=Gtk.Align.CENTER)
        search_btn.add_css_class("flat")
        search_btn.connect("clicked", self._on_search_clicked)
        self.search_entry.add_suffix(search_btn)
        search_group.add(self.search_entry)

        self.search_results_group = self.add_group("Search Results")
        self.search_results_group.set_visible(False)

        # --- Installed packages ------------------------------------------------------
        self.installed_group = self.add_group("Explicitly Installed Packages")

        self.refresh()

    # -- data loading -----------------------------------------------------------

    def refresh(self) -> None:
        self.updates_row.set_title("Checking for updates…")
        self.clear_rows(self.updates_list_group, getattr(self, "_update_rows", []))
        self._update_rows = [self.start_loading(self.updates_list_group, "Checking for updates…")]
        self.run_async(pacman.check_updates, self._on_updates_loaded)
        self.clear_rows(self.installed_group, getattr(self, "_installed_rows", []))
        self._installed_rows = [self.start_loading(self.installed_group, "Loading installed packages…")]
        self.run_async(pacman.list_explicit, self._on_installed_loaded)

    def _on_updates_loaded(self, result, error) -> None:
        for row in list(getattr(self, "_update_rows", [])):
            self.updates_list_group.remove(row)
        self._update_rows = []

        if error:
            self.updates_row.set_title("Couldn't check for updates")
            self.updates_row.set_subtitle(esc(error))
            return

        count = len(result)
        if count == 0:
            self.updates_row.set_title("System is up to date")
            row = Adw.ActionRow(title="Nothing pending")
            self.updates_list_group.add(row)
            self._update_rows.append(row)
            return

        self.updates_row.set_title(f"{count} update{'s' if count != 1 else ''} available")
        for update in result:
            subtitle = f"{update.old_version} → {update.new_version}" if update.old_version else "version info unavailable"
            row = Adw.ActionRow(title=esc(update.name), subtitle=esc(subtitle))
            update_btn = Gtk.Button(label="Update only this", valign=Gtk.Align.CENTER)
            update_btn.connect("clicked", self._on_update_single_clicked, update.name)
            row.add_suffix(update_btn)
            self.updates_list_group.add(row)
            self._update_rows.append(row)

    def _on_installed_loaded(self, result, error) -> None:
        # Clear previously listed rows (skip the group's own header widgets by rebuilding)
        for row in list(getattr(self, "_installed_rows", [])):
            self.installed_group.remove(row)
        self._installed_rows = []

        if error:
            self.notify(f"Failed to list packages: {error}", is_error=True)
            return

        for pkg in result[:200]:  # cap for UI responsiveness; use search for the rest
            row = Adw.ActionRow(title=esc(pkg.name), subtitle=esc(pkg.version))
            remove_btn = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER)
            remove_btn.add_css_class("flat")
            remove_btn.connect("clicked", self._on_remove_clicked, pkg.name)
            row.add_suffix(remove_btn)
            self.installed_group.add(row)
            self._installed_rows.append(row)

    # -- actions -----------------------------------------------------------

    def _on_sync_clicked(self, _btn: Gtk.Button) -> None:
        self.notify("Refreshing package database…")
        self.run_async(pacman.sync_database, self.handle_command_result)

    def _on_upgrade_clicked(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Upgrade entire system?",
            "This runs 'pacman -Syu' and may take a while. Continue?",
            "Upgrade",
            lambda: self.run_streaming_operation("Upgrading System", pacman.upgrade_system_streaming),
        )

    def _on_clean_clicked(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Clean package cache?",
            "This removes cached package files that are no longer installed.",
            "Clean",
            lambda: self.run_async(pacman.clean_cache, self.handle_command_result),
        )

    def _on_remove_clicked(self, _btn: Gtk.Button, package_name: str) -> None:
        self.confirm(
            f"Remove {package_name}?",
            "This uninstalls the package and any dependencies no longer needed by anything else.",
            "Remove",
            lambda: self.run_async(lambda: pacman.remove([package_name]), self.handle_command_result),
        )

    def _on_search_clicked(self, _btn: Gtk.Button) -> None:
        query = self.search_entry.get_text().strip()
        if not query:
            return
        self.search_results_group.set_visible(True)
        self.clear_rows(self.search_results_group, getattr(self, "_search_rows", []))
        self._search_rows = [self.start_loading(self.search_results_group, f"Searching for '{query}'…")]
        self.run_async(lambda: pacman.search(query), self._on_search_done)

    def _on_search_done(self, result, error) -> None:
        for row in list(getattr(self, "_search_rows", [])):
            self.search_results_group.remove(row)
        self._search_rows = []

        if error:
            self.notify(f"Search failed: {error}", is_error=True)
            return

        for pkg in result[:50]:
            row = Adw.ActionRow(title=esc(pkg.name), subtitle=esc(pkg.description or pkg.version))
            if pkg.installed:
                row.add_suffix(Gtk.Label(label="installed", css_classes=["dim-label"]))
            else:
                install_btn = Gtk.Button(label="Install", valign=Gtk.Align.CENTER)
                install_btn.connect("clicked", self._on_install_clicked, pkg.name)
                row.add_suffix(install_btn)
            self.search_results_group.add(row)
            self._search_rows.append(row)

    def _on_install_clicked(self, _btn: Gtk.Button, package_name: str) -> None:
        self.notify(f"Installing {package_name}…")
        self.run_async(lambda: pacman.install([package_name]), self.handle_command_result)

    def _on_update_single_clicked(self, _btn: Gtk.Button, package_name: str) -> None:
        self.confirm(
            f"Update only {package_name}?",
            "This is a partial upgrade. Arch's own guidance is to avoid updating "
            "individual packages while others stay behind - if this package now "
            "expects a newer shared library than what's still installed for other "
            "packages, something else could break. A full 'Upgrade system' is the "
            "supported way to update. Continue anyway?",
            "Update anyway",
            lambda: self.run_async(lambda: pacman.update_single_package(package_name), self.handle_command_result),
        )
