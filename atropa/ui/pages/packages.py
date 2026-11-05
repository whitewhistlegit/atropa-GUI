"""atropa.ui.pages.packages - Package Management module (pacman + AUR)."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import news as news_backend, pacman, system_health
from atropa.ui.pages import BasePage, esc


class PackagesPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        # --- System-wide actions -------------------------------------------------
        actions_group = self.add_group("System", "Keep your package database and installed software current")

        self.updates_row = Adw.ActionRow(title="Checking for updates…")
        # Not "Refresh database": that was `pacman -Sy`, after which any
        # install is a partial upgrade. check_updates() leaves it alone.
        check_btn = Gtk.Button(label="Check for updates")
        check_btn.set_valign(Gtk.Align.CENTER)
        check_btn.connect("clicked", lambda _b: self._load_updates())
        self.updates_row.add_suffix(check_btn)

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

        # --- Arch news before an upgrade --------------------------------------------
        # Only fetched when the user asks: the Packages page already reads the
        # local package database on open and shouldn't also hit the network.
        self.news_group = self.add_group(
            "Before Upgrading",
            "Arch news announces manual steps that a plain -Syu won't do for you: config migrations, "
            "packages that need removing first, reboots. Items newer than your last full upgrade are the "
            "ones that matter.",
        )
        self.news_status_row = Adw.ActionRow(title="Arch news not checked yet")
        self.news_btn = Gtk.Button(label="Check news", valign=Gtk.Align.CENTER)
        self.news_btn.connect("clicked", self._on_check_news)
        self.news_status_row.add_suffix(self.news_btn)
        self.news_group.add(self.news_status_row)
        self._news_rows: list[Adw.ActionRow] = []

        # --- post-upgrade health (read-only) -----------------------------------------
        self.health_group = self.add_group(
            "System Health",
            "Read-only checks worth running after an upgrade: failed units, reboot status, and CPU microcode.",
        )
        self.health_recheck_btn = Gtk.Button(label="Re-check", valign=Gtk.Align.CENTER)
        self.health_recheck_btn.connect("clicked", lambda _b: self._load_health())
        self.health_group.set_header_suffix(self.health_recheck_btn)

        # --- pacman.conf options (privileged edits, backed up + validated) ------------
        self._suppress_config = False
        self.config_group = self.add_group(
            "pacman Configuration",
            "Edits /etc/pacman.conf. Every change is backed up first and checked with pacman-conf before it's kept.",
        )
        self.config_reload_btn = Gtk.Button(label="Reload", valign=Gtk.Align.CENTER)
        self.config_reload_btn.connect("clicked", lambda _b: self._load_config())
        self.config_group.set_header_suffix(self.config_reload_btn)

        self.color_row = Adw.SwitchRow(title="Color output", subtitle="Colorize pacman's terminal output")
        self.color_row.connect("notify::active", self._on_color_toggled)
        self.config_group.add(self.color_row)

        parallel_adjustment = Gtk.Adjustment(lower=1, upper=20, step_increment=1, page_increment=5, value=1)
        self.parallel_row = Adw.SpinRow(
            title="Parallel downloads",
            subtitle="How many packages pacman downloads at once (1–20)",
            adjustment=parallel_adjustment,
            digits=0,
        )
        self.parallel_apply_btn = Gtk.Button(label="Apply", valign=Gtk.Align.CENTER)
        self.parallel_apply_btn.connect("clicked", self._on_parallel_apply)
        self.parallel_row.add_suffix(self.parallel_apply_btn)
        self.config_group.add(self.parallel_row)

        self.multilib_row = Adw.SwitchRow(
            title="Multilib repository",
            subtitle="32-bit packages and libraries from [multilib]",
        )
        self.multilib_row.connect("notify::active", self._on_multilib_toggled)
        self.config_group.add(self.multilib_row)
        self._set_config_sensitive(False)

        # --- pending updates (visible list, not just a count) -----------------------
        self.updates_list_group = self.add_group(
            "Pending Updates",
            "Arch only supports upgrading everything together - 'Upgrade system' above installs these.",
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

        # --- Orphans -----------------------------------------------------------------
        self.orphans_group = self.add_group(
            "Orphaned Packages",
            "Installed as a dependency of something that has since been removed. Nothing installed needs them.",
        )
        self.remove_orphans_btn = Gtk.Button(label="Remove all", valign=Gtk.Align.CENTER, visible=False)
        self.remove_orphans_btn.connect("clicked", self._on_remove_orphans_clicked)
        self.orphans_group.set_header_suffix(self.remove_orphans_btn)
        self._orphan_names: list[str] = []

        # --- Installed packages ------------------------------------------------------
        self.installed_group = self.add_group("Explicitly Installed Packages")

        self.refresh()

    # -- data loading -----------------------------------------------------------

    def refresh(self) -> None:
        self._load_updates()
        self._load_health()
        self._load_config()
        self.clear_rows(self.installed_group, getattr(self, "_installed_rows", []))
        self._installed_rows = [self.start_loading(self.installed_group, "Loading installed packages…")]
        self.run_async(pacman.list_explicit, self._on_installed_loaded)
        self.clear_rows(self.orphans_group, getattr(self, "_orphan_rows", []))
        self._orphan_rows = [self.start_loading(self.orphans_group, "Looking for orphaned packages…")]
        self.remove_orphans_btn.set_visible(False)
        self.run_async(pacman.list_orphans, self._on_orphans_loaded)

    def _on_check_news(self, _btn: Gtk.Button) -> None:
        self.news_btn.set_sensitive(False)
        self.news_status_row.set_title("Checking Arch news…")
        self.news_status_row.set_subtitle("Fetching the news feed")
        self.run_async(news_backend.check, self._on_news_checked)

    def _on_news_checked(self, report, error) -> bool:
        self.news_btn.set_sensitive(True)
        self.clear_rows(self.news_group, self._news_rows)
        self._news_rows = []

        if error or report.error:
            self.news_status_row.set_title("Couldn't check Arch news")
            self.news_status_row.set_subtitle(esc(error or report.error))
            return False

        checked = report.checked_at.astimezone().strftime("%Y-%m-%d %H:%M")
        since = report.since.astimezone().strftime("%Y-%m-%d") if report.since else ""
        if not report.items:
            self.news_status_row.set_title(
                "No news since the last full upgrade" if since else "No news items were returned"
            )
            self.news_status_row.set_subtitle(esc(f"Checked {checked}"))
            return False

        if since:
            self.news_status_row.set_title(f"{len(report.items)} news item(s) since {since}")
        else:
            self.news_status_row.set_title(f"{len(report.items)} recent news item(s)")
        self.news_status_row.set_subtitle("Read anything that applies to this machine before upgrading")

        for item in report.items:
            row = Adw.ActionRow(title=esc(item.title))
            when = item.published.astimezone().strftime("%Y-%m-%d")
            summary = item.summary[:160] + ("…" if len(item.summary) > 160 else "")
            row.set_subtitle(esc(f"{when} · {summary}" if summary else when))
            open_btn = Gtk.Button(label="Open", valign=Gtk.Align.CENTER)
            open_btn.connect("clicked", self._on_open_news_link, item.link)
            row.add_suffix(open_btn)
            self.news_group.add(row)
            self._news_rows.append(row)
        return False

    def _on_open_news_link(self, _btn: Gtk.Button, link: str) -> None:
        Gtk.show_uri(self.get_root(), link, 0)

    def _load_health(self) -> None:
        self.clear_rows(self.health_group, getattr(self, "_health_rows", []))
        self._health_rows = [self.start_loading(self.health_group, "Checking system health…")]
        self.run_async(system_health.check_all, self._on_health_loaded)

    def _add_health_row(self, title: str, subtitle: str = "") -> None:
        row = Adw.ActionRow(title=esc(title))
        if subtitle:
            row.set_subtitle(esc(subtitle))
        self.health_group.add(row)
        self._health_rows.append(row)

    def _on_health_loaded(self, report, error) -> bool:
        for row in list(getattr(self, "_health_rows", [])):
            self.health_group.remove(row)
        self._health_rows = []

        if error:
            self._add_health_row("Couldn't check system health", str(error))
            return False

        if report.failed_units_error:
            self._add_health_row("Couldn't list failed units", report.failed_units_error)
        elif not report.failed_units:
            self._add_health_row("No failed units", "Everything systemd tried to start is running")
        else:
            count = len(report.failed_units)
            self._add_health_row(
                f"{count} failed unit{'s' if count != 1 else ''}",
                "Shown by systemctl --failed",
            )
            for unit in report.failed_units[:8]:
                self._add_health_row(unit.name, unit.description)
            if count > 8:
                self._add_health_row(f"…and {count - 8} more", "See systemctl --failed for the full list")

        if report.kernel_error:
            self._add_health_row("Couldn't determine kernel status", report.kernel_error)
        elif report.kernel is None:
            self._add_health_row("Kernel status unavailable")
        elif report.kernel.reboot_required is True:
            self._add_health_row(
                "Reboot recommended",
                f"Running {report.kernel.running}; {report.kernel.package} now installs {report.kernel.package_release}",
            )
        elif report.kernel.reboot_required is False:
            self._add_health_row("Kernel is current", f"Running {report.kernel.running}")
        else:
            self._add_health_row("Kernel status unknown", "Couldn't match the running kernel to an installed package")

        if report.microcode_error:
            self._add_health_row("Couldn't check CPU microcode", report.microcode_error)
        elif report.microcode is None or report.microcode.package is None:
            self._add_health_row("Microcode check unavailable", "Couldn't identify the CPU vendor")
        elif report.microcode.installed:
            self._add_health_row("CPU microcode installed", f"{report.microcode.package} is present")
        else:
            self._add_health_row(
                "CPU microcode package missing",
                f"Install {report.microcode.package} to receive microcode updates",
            )
        return False

    # -- pacman.conf options -----------------------------------------------------

    def _set_config_sensitive(self, sensitive: bool) -> None:
        for row in (self.color_row, self.parallel_row, self.multilib_row):
            row.set_sensitive(sensitive)

    def _load_config(self) -> None:
        self.run_async(pacman.read_config, self._on_config_loaded)

    def _on_config_loaded(self, settings, error) -> bool:
        if error:
            self._set_config_sensitive(False)
            self.notify(f"Couldn't read pacman.conf: {error}", is_error=True)
            return False

        self._suppress_config = True
        self.color_row.set_active(settings.color)
        self.parallel_row.set_value(settings.parallel_downloads if settings.parallel_downloads is not None else 1)
        self.multilib_row.set_active(settings.multilib)
        self._suppress_config = False

        if settings.parallel_downloads is None:
            self.parallel_row.set_subtitle(
                "How many packages pacman downloads at once (1–20). Pacman's default is 1."
            )
        else:
            self.parallel_row.set_subtitle(
                f"How many packages pacman downloads at once (1–20). Currently {settings.parallel_downloads}."
            )
        self._set_config_sensitive(True)
        return False

    def _apply_config_change(self, work_fn, success_message: str) -> None:
        def done(result, error) -> bool:
            self.handle_command_result(result, error, success_message, refresh=False)
            self._load_config()
            return False

        if not self.run_action(work_fn, done):
            self._load_config()

    def _on_color_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_config:
            return
        enabled = switch.get_active()
        self._apply_config_change(lambda: pacman.set_color(enabled), "Color updated")

    def _on_parallel_apply(self, _button: Gtk.Button) -> None:
        count = int(self.parallel_row.get_value())
        self._apply_config_change(
            lambda: pacman.set_parallel_downloads(count),
            "Parallel downloads updated",
        )

    def _on_multilib_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_config:
            return
        enabled = switch.get_active()
        if enabled:
            heading = "Enable the multilib repository?"
            body = (
                "Adds [multilib] to /etc/pacman.conf so pacman can install 32-bit packages. "
                "Nothing is downloaded or installed now."
            )
            label = "Enable"
        else:
            heading = "Disable the multilib repository?"
            body = (
                "Removes [multilib] from /etc/pacman.conf. Packages already installed from it "
                "stay installed."
            )
            label = "Disable"
        self.confirm(
            heading,
            body,
            label,
            lambda: self._apply_config_change(lambda: pacman.set_multilib(enabled), "Multilib updated"),
            on_cancel=self._load_config,
            destructive=not enabled,
        )

    def _on_orphans_loaded(self, result, error) -> None:
        for row in list(getattr(self, "_orphan_rows", [])):
            self.orphans_group.remove(row)
        self._orphan_rows = []
        self._orphan_names = [] if error else [pkg.name for pkg in result]
        self.remove_orphans_btn.set_visible(bool(self._orphan_names))

        if error:
            row = Adw.ActionRow(title="Couldn't look for orphaned packages", subtitle=esc(error))
        elif not result:
            row = Adw.ActionRow(title="No orphaned packages")
        else:
            row = None
        if row is not None:
            self.orphans_group.add(row)
            self._orphan_rows.append(row)
            return

        for pkg in result:
            row = Adw.ActionRow(title=esc(pkg.name), subtitle=esc(pkg.version))
            remove_btn = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER)
            remove_btn.add_css_class("flat")
            remove_btn.connect("clicked", self._on_remove_clicked, pkg.name)
            row.add_suffix(remove_btn)
            self.orphans_group.add(row)
            self._orphan_rows.append(row)

    def _load_updates(self) -> None:
        self.updates_row.set_title("Checking for updates…")
        if pacman.live_update_check_available():
            self.updates_row.set_subtitle("")
        else:
            self.updates_row.set_subtitle(
                "As of the last full upgrade - install pacman-contrib and fakeroot to check the mirrors"
            )
        self.clear_rows(self.updates_list_group, getattr(self, "_update_rows", []))
        self._update_rows = [self.start_loading(self.updates_list_group, "Checking for updates…")]
        self.run_async(pacman.check_updates, self._on_updates_loaded)

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
            lambda: self.run_action(pacman.clean_cache, self.handle_command_result),
        )

    def _on_remove_clicked(self, _btn: Gtk.Button, package_name: str) -> None:
        self.confirm(
            f"Remove {package_name}?",
            "This uninstalls the package and any dependencies no longer needed by anything else.",
            "Remove",
            lambda: self.run_action(lambda: pacman.remove([package_name]), self.handle_command_result),
        )

    def _on_remove_orphans_clicked(self, _btn: Gtk.Button) -> None:
        # The names shown are the names removed. If one of them has become
        # needed since the list was loaded, pacman refuses the whole removal.
        names = list(self._orphan_names)
        if not names:
            return
        shown = ", ".join(names[:30]) + (f" and {len(names) - 30} more" if len(names) > 30 else "")
        self.confirm(
            f"Remove {len(names)} orphaned package{'s' if len(names) != 1 else ''}?",
            f"This uninstalls {shown}, along with anything that only {'it' if len(names) == 1 else 'they'} needed.",
            "Remove",
            lambda: self.run_action(
                lambda: pacman.remove(names),
                lambda result, error: self.handle_command_result(result, error, "Orphaned packages removed"),
            ),
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
            elif pkg.repo == "aur":
                # pacman can't install AUR packages - the old Install button
                # here just failed with "target not found".
                aur_label = Gtk.Label(label="AUR", css_classes=["dim-label"])
                aur_label.set_tooltip_text(
                    f"Built from a user-submitted PKGBUILD - read it first, then install from a terminal "
                    f"with your AUR helper (e.g. paru -S {pkg.name})"
                )
                row.add_suffix(aur_label)
            else:
                install_btn = Gtk.Button(label="Install", valign=Gtk.Align.CENTER)
                install_btn.connect("clicked", self._on_install_clicked, pkg.name)
                row.add_suffix(install_btn)
            self.search_results_group.add(row)
            self._search_rows.append(row)

    def _on_install_clicked(self, _btn: Gtk.Button, package_name: str) -> None:
        if self.run_action(
            lambda: pacman.install([package_name]), lambda r, e: self._on_install_done(r, e, package_name)
        ):
            self.notify(f"Installing {package_name}…")

    def _on_install_done(self, result, error, package_name: str) -> bool:
        if isinstance(error, pacman.PartialUpgradeError):
            self.confirm(
                "Upgrade the system first?",
                f"{error}\n\n'Upgrade and install' runs pacman -Syu --needed {package_name}: a full system "
                "upgrade that installs it as well.",
                "Upgrade and install",
                lambda: self.run_streaming_operation(
                    f"Upgrading and installing {package_name}",
                    lambda on_line: pacman.upgrade_and_install_streaming([package_name], on_line),
                ),
            )
            return False
        return self.handle_command_result(result, error, f"Installed {package_name}")
