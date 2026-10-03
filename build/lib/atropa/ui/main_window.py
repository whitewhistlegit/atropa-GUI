"""
atropa.ui.main_window
--------------------------
The top-level window: a YaST-style split view with a module sidebar on the
left and the active module's page on the right.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from atropa.backend import plugins as plugins_backend
from atropa.ui.pages.activity import ActivityPage
from atropa.ui.pages.addons import AddonsPage
from atropa.ui.pages.apparmor import ApparmorPage
from atropa.ui.pages.bootloader import BootloaderPage
from atropa.ui.pages.compliance import CompliancePage
from atropa.ui.pages.dependencies import DependenciesPage
from atropa.ui.pages.aide_page import AidePage
from atropa.ui.pages.hardening import HardeningPage
from atropa.ui.pages.inventory_hygiene import InventoryHygienePage
from atropa.ui.pages.network import NetworkPage
from atropa.ui.pages.packages import PackagesPage
from atropa.ui.pages.plugin_page import PluginPage
from atropa.ui.pages.profiles import ProfilesPage
from atropa.ui.pages.quicksetup import QuickSetupPage
from atropa.ui.pages.security import SecurityPage
from atropa.ui.pages.selinux import SelinuxPage
from atropa.ui.pages.refpolicy_build import RefpolicyBuildPage
from atropa.ui.pages.selinux_load import SelinuxLoadPage
from atropa.ui.pages.selinux_review import SelinuxReviewPage
from atropa.ui.pages.services import ServicesPage
from atropa.ui.pages.system_config import SystemConfigPage
from atropa.ui.pages.users import UsersPage

MODULES = [
    ("packages", "Package Management", "system-software-install-symbolic", PackagesPage),
    ("system_config", "System", "computer-symbolic", SystemConfigPage),
    ("network", "Network", "network-wired-symbolic", NetworkPage),
    ("users", "Users & Groups", "system-users-symbolic", UsersPage),
    ("services", "Services", "applications-system-symbolic", ServicesPage),
    ("bootloader", "Bootloader", "drive-harddisk-symbolic", BootloaderPage),
    ("quicksetup", "Security Quick Setup", "starred-symbolic", QuickSetupPage),
    ("profiles", "Security Profiles", "send-to-symbolic", ProfilesPage),
    ("security", "Security", "security-high-symbolic", SecurityPage),
    ("hardening", "Hardening", "security-medium-symbolic", HardeningPage),
    ("compliance", "Compliance Report", "text-x-generic-symbolic", CompliancePage),
    ("inventory_hygiene", "Inventory & Hygiene", "view-list-symbolic", InventoryHygienePage),
    ("aide", "File Integrity", "drive-harddisk-symbolic", AidePage),
    ("apparmor", "AppArmor", "shield-symbolic", ApparmorPage),
    ("selinux", "SELinux", "changes-prevent-symbolic", SelinuxPage),
    ("selinux_load", "SELinux: Load Policy", "document-open-symbolic", SelinuxLoadPage),
    ("selinux_review", "SELinux: Denial Review", "edit-find-symbolic", SelinuxReviewPage),
    ("refpolicy_build", "SELinux: Build Policy", "system-run-symbolic", RefpolicyBuildPage),
    ("dependencies", "Dependencies", "system-search-symbolic", DependenciesPage),
    ("addons", "Add-ons", "application-x-addon-symbolic", AddonsPage),
    ("activity", "Activity & Backups", "document-properties-symbolic", ActivityPage),
]


def _discover_plugin_modules() -> list[tuple[str, str, str, object]]:
    """
    Turns every enabled, valid plugin into a MODULES-shaped entry, so it
    renders through the exact same sidebar/stack machinery as a built-in
    page. Only plugins.enabled_plugins() (valid AND enabled - see that
    module) ever reaches here; disabled or invalid plugins only ever show
    up in the Add-ons page's listing, never as a live sidebar entry.
    """
    entries = []
    for discovered in plugins_backend.enabled_plugins():
        manifest = discovered.manifest
        key = f"plugin_{manifest.id}"
        entries.append((key, manifest.title, manifest.icon, lambda m=manifest: PluginPage(m)))
    return entries


class AtropaWindow(Adw.ApplicationWindow):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.set_title("Atropa")
        self.set_default_size(1100, 700)

        # Plugin discovery/loading happens once, here, at startup - not
        # live-reloaded while running. Enabling/disabling a plugin (Add-ons
        # page) takes effect on the next launch, not immediately; simpler
        # and safer than mutating the sidebar/stack at runtime.
        self.modules = MODULES + _discover_plugin_modules()
        self._module_classes = {key: page_cls for key, _title, _icon, page_cls in self.modules}
        self._titles = {key: title for key, title, _icon, _cls in self.modules}

        self.split_view = Adw.NavigationSplitView()
        self.set_content(self.split_view)

        self.split_view.set_sidebar(self._build_sidebar())
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)

        self.content_page = Adw.NavigationPage()
        self.content_page.set_title("Atropa")
        content_toolbar = Adw.ToolbarView()
        content_header = Adw.HeaderBar()
        content_toolbar.add_top_bar(content_header)
        content_toolbar.set_content(self.stack)
        self.content_page.set_child(content_toolbar)
        self.split_view.set_content(self.content_page)

        # Pages are constructed lazily, the first time they're actually
        # navigated to - see _ensure_page_materialized(). Nearly every
        # page's own __init__() ends with self.refresh(), and for several
        # pages (AppArmor's aa-status, Inventory & Hygiene's account
        # scan, Compliance Report, ...) that means a pkexec authentication
        # prompt. Constructing all ~20 pages eagerly at startup used to
        # fire every one of those prompts at once on every single launch -
        # bad on its own, and a genuine pam_faillock lockout risk stacked
        # on top of a normal login lockout policy, from nothing more than
        # opening the app. Materializing only the page currently being
        # viewed means exactly one page's worth of prompts, only when the
        # user actually asked to see that page.
        self._pages: dict[str, Gtk.Widget] = {}

        first_key = self.modules[0][0]
        self._ensure_page_materialized(first_key)
        self.stack.set_visible_child_name(first_key)
        self.content_page.set_title(self._titles.get(first_key, first_key))

    def _ensure_page_materialized(self, key: str) -> Gtk.Widget:
        """
        Constructs the page for `key` - running its __init__(), and
        whatever initial refresh() that triggers - the first time it's
        actually needed, and returns the same instance on every later
        call. Also re-checks the SELinux page cross-wiring on each call,
        since which of the two/three pages exists first now depends on
        navigation order instead of all of them always existing at
        startup together.
        """
        page_widget = self._pages.get(key)
        if page_widget is not None:
            return page_widget

        page_cls = self._module_classes[key]
        page_widget = page_cls()
        self.stack.add_titled(page_widget, key, self._titles.get(key, key))
        self._pages[key] = page_widget

        # Let 'Generate .te' on the SELinux page(s) hand results to the Load
        # Policy page - wire in whichever order the pages get materialized.
        if key in ("selinux", "selinux_review") and "selinux_load" in self._pages:
            page_widget.set_load_page(self._pages["selinux_load"])
        if key == "selinux_load":
            if "selinux" in self._pages:
                self._pages["selinux"].set_load_page(page_widget)
            if "selinux_review" in self._pages:
                self._pages["selinux_review"].set_load_page(page_widget)

        return page_widget

    def _build_sidebar(self) -> Adw.NavigationPage:
        sidebar_page = Adw.NavigationPage()
        sidebar_page.set_title("Atropa")

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(False)
        toolbar.add_top_bar(header)

        listbox = Gtk.ListBox()
        listbox.add_css_class("navigation-sidebar")
        listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)

        for key, title, icon_name, _cls in self.modules:
            row = Adw.ActionRow()
            row.set_title(GLib.markup_escape_text(title))
            row.set_activatable(True)
            icon = Gtk.Image.new_from_icon_name(icon_name)
            row.add_prefix(icon)
            row.set_name(key)
            listbox.append(row)

        listbox.connect("row-activated", self._on_row_activated)
        listbox.select_row(listbox.get_row_at_index(0))

        scroller = Gtk.ScrolledWindow()
        scroller.set_child(listbox)
        toolbar.set_content(scroller)

        sidebar_page.set_child(toolbar)
        return sidebar_page

    def _on_row_activated(self, _listbox: Gtk.ListBox, row: Adw.ActionRow) -> None:
        key = row.get_name()
        self._ensure_page_materialized(key)
        self.stack.set_visible_child_name(key)
        self.content_page.set_title(self._titles.get(key, key))
        # Deliberately NOT calling page_widget.refresh() here. The page
        # already refreshed itself once, the moment it was first
        # materialized (see _ensure_page_materialized). Re-running
        # refresh() on every single navigation click used to mean
        # re-authenticating for every privileged read (aa-status, the
        # shadow file, ...) on every single visit to a page like AppArmor
        # or Inventory & Hygiene - not just once per session, every click.
        # Pages that want intentionally fresh data have their own explicit
        # "Re-scan"/refresh button for exactly that purpose.
        # On narrow/mobile-style layouts, collapse to content after picking a module
        self.split_view.set_show_content(True)
