"""
atropa.ui.main_window
--------------------------
The top-level window: a split view with a grouped, searchable module sidebar
on the left and the active module's page on the right.

Visual structure (the functional contract is unchanged - pages are still
constructed lazily and still own their refresh()):

  sidebar: brand header -> module search -> sectioned navigation list -> footer
  content: header (module icon, title, tagline, menu) -> page stack

All of the styling that makes this feel like a finished product lives in
atropa/resources/style.css; the widget code below only adds the class names
and structure that stylesheet hooks into.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from atropa import __version__  # noqa: E402
from atropa.backend import plugins as plugins_backend  # noqa: E402
from atropa.ui.pages.activity import ActivityPage  # noqa: E402
from atropa.ui.pages.addons import AddonsPage  # noqa: E402
from atropa.ui.pages.apparmor import ApparmorPage  # noqa: E402
from atropa.ui.pages.boot_report import BootReportPage  # noqa: E402
from atropa.ui.pages.boot_security import BootSecurityPage  # noqa: E402
from atropa.ui.pages.bootloader import BootloaderPage  # noqa: E402
from atropa.ui.pages.compliance import CompliancePage  # noqa: E402
from atropa.ui.pages.dependencies import DependenciesPage  # noqa: E402
from atropa.ui.pages.aide_page import AidePage  # noqa: E402
from atropa.ui.pages.disk_health import DiskHealthPage  # noqa: E402
from atropa.ui.pages.firmware import FirmwarePage  # noqa: E402
from atropa.ui.pages.flatpak import FlatpakPage  # noqa: E402
from atropa.ui.pages.hardening import HardeningPage  # noqa: E402
from atropa.ui.pages.inventory_hygiene import InventoryHygienePage  # noqa: E402
from atropa.ui.pages.lockdown import LockdownPage  # noqa: E402
from atropa.ui.pages.mirrors import MirrorsPage  # noqa: E402
from atropa.ui.pages.network import NetworkPage  # noqa: E402
from atropa.ui.pages.packages import PackagesPage  # noqa: E402
from atropa.ui.pages.pacnew import PacnewPage  # noqa: E402
from atropa.ui.pages.plugin_page import PluginPage  # noqa: E402
from atropa.ui.pages.power import PowerPage  # noqa: E402
from atropa.ui.pages.profiles import ProfilesPage  # noqa: E402
from atropa.ui.pages.quicksetup import QuickSetupPage  # noqa: E402
from atropa.ui.pages.security import SecurityPage  # noqa: E402
from atropa.ui.pages.selinux import SelinuxPage  # noqa: E402
from atropa.ui.pages.refpolicy_build import RefpolicyBuildPage  # noqa: E402
from atropa.ui.pages.selinux_load import SelinuxLoadPage  # noqa: E402
from atropa.ui.pages.selinux_review import SelinuxReviewPage  # noqa: E402
from atropa.ui.pages.services import ServicesPage  # noqa: E402
from atropa.ui.pages.system_config import SystemConfigPage  # noqa: E402
from atropa.ui.pages.users import UsersPage  # noqa: E402

# Order here is the sidebar order. `section` picks which group the module is
# listed under; tags are short one-liners shown in the content header, so the
# window always says what the page in front of you is for.
SECTIONS = {
    "core": "CORE",
    "security": "SECURITY",
    "maintenance": "MAINTENANCE",
    "extensions": "EXTENSIONS",
}


@dataclass(frozen=True)
class Module:
    key: str
    title: str
    icon: str
    page: Callable[[], Gtk.Widget]
    tagline: str = ""
    section: str = "core"


MODULES = [
    Module(
        "packages", "Package Management", "system-software-install-symbolic", PackagesPage,
        "Install, update, and clean up software", "core",
    ),
    Module(
        "system_config", "System", "computer-symbolic", SystemConfigPage,
        "Hostname, time, locale, and keyboard", "core",
    ),
    Module(
        "network", "Network", "network-wired-symbolic", NetworkPage,
        "Connections, Wi-Fi, and addressing", "core",
    ),
    Module(
        "services", "Services", "applications-system-symbolic", ServicesPage,
        "Start, stop, and enable systemd units", "core",
    ),
    Module(
        "bootloader", "Bootloader", "drive-harddisk-symbolic", BootloaderPage,
        "Boot entries and the default timeout", "core",
    ),
    Module(
        "users", "Users & Groups", "system-users-symbolic", UsersPage,
        "Accounts, groups, and passwords", "core",
    ),
    Module(
        "quicksetup", "Security Quick Setup", "starred-symbolic", QuickSetupPage,
        "A guided security baseline in one pass", "security",
    ),
    Module(
        "profiles", "Security Profiles", "send-to-symbolic", ProfilesPage,
        "Move this machine's security posture to another", "security",
    ),
    Module(
        "security", "Security", "security-high-symbolic", SecurityPage,
        "Firewall, SSH, and sudoers safeguards", "security",
    ),
    Module(
        "hardening", "Hardening", "security-medium-symbolic", HardeningPage,
        "Kernel, login, and audit hardening", "security",
    ),
    Module(
        "boot_security", "Encryption & Secure Boot", "channel-secure-symbolic", BootSecurityPage,
        "LUKS root, Secure Boot, and sbctl signing", "security",
    ),
    Module(
        "compliance", "Compliance Report", "text-x-generic-symbolic", CompliancePage,
        "How exposed this machine is, and why", "security",
    ),
    Module(
        "inventory_hygiene", "Inventory & Hygiene", "view-list-symbolic", InventoryHygienePage,
        "Read-only scans for drift and leftovers", "security",
    ),
    Module(
        "aide", "File Integrity", "drive-harddisk-symbolic", AidePage,
        "Baselines and checks for changed files", "security",
    ),
    Module(
        "lockdown", "Lockdown & Scans", "system-lock-screen-symbolic", LockdownPage,
        "Cut the radios, check integrity and look for rootkits", "security",
    ),
    Module(
        "apparmor", "AppArmor", "security-high-symbolic", ApparmorPage,
        "Profile modes, rules, and denials", "security",
    ),
    Module(
        "selinux", "SELinux", "changes-prevent-symbolic", SelinuxPage,
        "Modes, booleans, and denial review", "security",
    ),
    Module(
        "selinux_load", "SELinux: Load Policy", "document-open-symbolic", SelinuxLoadPage,
        "Compile and load policy modules", "security",
    ),
    Module(
        "selinux_review", "SELinux: Denial Review", "edit-find-symbolic", SelinuxReviewPage,
        "Triage denials and draft policy", "security",
    ),
    Module(
        "refpolicy_build", "SELinux: Build Policy", "system-run-symbolic", RefpolicyBuildPage,
        "Build and install a policy tree", "security",
    ),
    Module(
        "pacnew", "Config Changes", "document-revert-symbolic", PacnewPage,
        "Review .pacnew and .pacsave files after upgrades", "maintenance",
    ),
    Module(
        "boot_report", "Boot Report", "dialog-warning-symbolic", BootReportPage,
        "What went wrong since this boot", "maintenance",
    ),
    Module(
        "disk_health", "Disk Health", "drive-harddisk-symbolic", DiskHealthPage,
        "SMART health, filesystem space, and cleanup", "maintenance",
    ),
    Module(
        "firmware", "Firmware", "application-x-firmware-symbolic", FirmwarePage,
        "Firmware devices and updates through fwupd", "maintenance",
    ),
    Module(
        "mirrors", "Mirrors", "network-server-symbolic", MirrorsPage,
        "Rank and apply pacman mirrors with reflector", "maintenance",
    ),
    Module(
        "power", "Power", "battery-good-symbolic", PowerPage,
        "Power profiles, battery limits, and zram swap", "maintenance",
    ),
    Module(
        "flatpak", "Flatpak", "package-x-generic-symbolic", FlatpakPage,
        "Flatpak apps, updates, and unused runtimes", "maintenance",
    ),
    Module(
        "dependencies", "Dependencies", "system-search-symbolic", DependenciesPage,
        "The external tools each module needs", "maintenance",
    ),
    Module(
        "addons", "Add-ons", "application-x-addon-symbolic", AddonsPage,
        "Declarative extensions you enable", "maintenance",
    ),
    Module(
        "activity", "Activity & Backups", "document-properties-symbolic", ActivityPage,
        "Every privileged command and backup", "maintenance",
    ),
]


def _one_line(text: str, limit: int = 84) -> str:
    """Collapse a plugin description to a single, short header tagline."""
    text = " ".join((text or "").split())
    if not text:
        return ""
    for stop in (". ", "! ", "? "):
        end = text.find(stop)
        if 0 <= end < limit:
            return text[: end + 1]
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip(" ,;:-") + "…"


def _discover_plugin_modules() -> list[Module]:
    """
    Turns every enabled, valid plugin into a Module, so it renders through
    the exact same sidebar/stack machinery as a built-in page. Only
    plugins.enabled_plugins() (valid AND enabled - see that module) ever
    reaches here; disabled or invalid plugins only ever show up in the
    Add-ons page's listing, never as a live sidebar entry.
    """
    entries = []
    for discovered in plugins_backend.enabled_plugins():
        manifest = discovered.manifest
        entries.append(
            Module(
                key=f"plugin_{manifest.id}",
                title=manifest.title,
                icon=manifest.icon or "application-x-addon-symbolic",
                page=lambda m=manifest: PluginPage(m),
                tagline=_one_line(manifest.description) or "Extension",
                section="extensions",
            )
        )
    return entries


class AtropaWindow(Adw.ApplicationWindow):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.set_title("Atropa")
        # Big enough for the sidebar plus a readable 600px preferences column,
        # small enough to still fit a 1366x768 laptop screen with decorations.
        self.set_default_size(1160, 740)
        self.set_size_request(940, 560)

        app = self.get_application()
        self._app_id = (app.get_application_id() if app is not None else None) or "org.atropa.Atropa"

        # Plugin discovery/loading happens once, here, at startup - not
        # live-reloaded while running. Enabling/disabling a plugin (Add-ons
        # page) takes effect on the next launch, not immediately; simpler
        # and safer than mutating the sidebar/stack at runtime.
        self.modules = MODULES + _discover_plugin_modules()
        self._modules_by_key = {module.key: module for module in self.modules}
        self._titles = {module.key: module.title for module in self.modules}
        self._search_text = {
            module.key: " ".join((module.title, module.tagline, module.section)).lower()
            for module in self.modules
        }
        self._module_rows: dict[str, Adw.ActionRow] = {}
        self._section_rows: dict[str, Gtk.ListBoxRow] = {}

        self.split_view = Adw.NavigationSplitView()
        self.split_view.set_min_sidebar_width(280)
        self.split_view.set_max_sidebar_width(340)
        self.split_view.set_sidebar_width_fraction(0.27)
        self.set_content(self.split_view)

        self.split_view.set_sidebar(self._build_sidebar())
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_transition_duration(140)

        self.content_page = Adw.NavigationPage()
        self.content_page.set_title("Atropa")
        content_toolbar = Adw.ToolbarView()
        content_header = self._build_content_header()
        content_toolbar.add_top_bar(content_header)
        content_toolbar.set_content(self.stack)
        self.content_page.set_child(content_toolbar)
        self.split_view.set_content(self.content_page)

        # In the two-pane layout the content header owns the window controls.
        # When the split view collapses to one pane, the sidebar header needs
        # them back or a sidebar-only window would have no close/minimise.
        self.split_view.connect("notify::collapsed", self._sync_sidebar_window_controls)
        self._sync_sidebar_window_controls()

        self._add_actions()

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

        first_key = self.modules[0].key
        self._activate_module(first_key, collapse=False)
        # Start keyboard focus on the navigation list, not in the search
        # entry - an empty search field that already has focus reads as if
        # the user had started typing a query.
        self.nav_list.grab_focus()

    # -- chrome -------------------------------------------------------------

    def _brand_widget(self) -> Gtk.Widget:
        tile = Gtk.Box(css_classes=["brand-tile"], valign=Gtk.Align.CENTER)
        logo = Gtk.Image.new_from_icon_name(self._app_id)
        logo.set_pixel_size(22)
        tile.append(logo)

        title = Adw.WindowTitle(title="Atropa", subtitle="System control center")
        title.add_css_class("atropa-brand")

        brand = Gtk.Box(spacing=10, valign=Gtk.Align.CENTER)
        brand.append(tile)
        brand.append(title)
        return brand

    def _build_sidebar(self) -> Adw.NavigationPage:
        sidebar_page = Adw.NavigationPage()
        sidebar_page.set_title("Atropa")

        toolbar = Adw.ToolbarView()
        toolbar.add_css_class("atropa-sidebar")
        header = Adw.HeaderBar()
        self.sidebar_header = header
        header.set_show_start_title_buttons(False)
        header.set_show_end_title_buttons(False)
        header.set_title_widget(Gtk.Box())
        header.pack_start(self._brand_widget())
        toolbar.add_top_bar(header)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content.append(self._build_search())

        self.nav_list = Gtk.ListBox()
        self.nav_list.add_css_class("navigation-sidebar")
        self.nav_list.add_css_class("atropa-nav")
        self.nav_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.nav_list.set_activate_on_single_click(True)
        self.nav_list.connect("row-activated", self._on_row_activated)

        for section, section_title in SECTIONS.items():
            section_modules = [module for module in self.modules if module.section == section]
            if not section_modules:
                continue

            section_row = Gtk.ListBoxRow(selectable=False, activatable=False, focusable=False)
            section_row.add_css_class("nav-section-row")
            label = Gtk.Label(label=section_title, xalign=0, css_classes=["nav-section-label"])
            section_row.set_child(label)
            self.nav_list.append(section_row)
            self._section_rows[section] = section_row

            for module in section_modules:
                row = Adw.ActionRow()
                row.set_title(GLib.markup_escape_text(module.title))
                row.set_activatable(True)
                icon = Gtk.Image.new_from_icon_name(module.icon)
                icon.set_pixel_size(18)
                row.add_prefix(icon)
                row.set_name(module.key)
                row.add_css_class("nav-row")
                self.nav_list.append(row)
                self._module_rows[module.key] = row

        # Shown instead of an empty list when the search matches nothing.
        self._empty_row = Gtk.ListBoxRow(selectable=False, activatable=False, focusable=False)
        self._empty_row.add_css_class("nav-empty-row")
        empty_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=4,
            margin_top=22,
            margin_bottom=10,
            margin_start=18,
            margin_end=18,
        )
        empty_icon = Gtk.Image.new_from_icon_name("edit-find-symbolic")
        empty_icon.set_pixel_size(26)
        empty_icon.add_css_class("nav-empty-icon")
        empty_icon.set_halign(Gtk.Align.CENTER)
        empty_title = Gtk.Label(label="No matches", css_classes=["nav-empty-title"])
        empty_title.set_halign(Gtk.Align.CENTER)
        empty_hint = Gtk.Label(
            label="Try a module name or a feature, like firewall",
            wrap=True,
            justify=Gtk.Justification.CENTER,
            css_classes=["nav-empty-label"],
        )
        empty_hint.set_halign(Gtk.Align.CENTER)
        clear_button = Gtk.Button(label="Clear search", valign=Gtk.Align.CENTER, css_classes=["flat"])
        clear_button.set_halign(Gtk.Align.CENTER)
        clear_button.connect("clicked", self._on_clear_search_clicked)
        empty_box.append(empty_icon)
        empty_box.append(empty_title)
        empty_box.append(empty_hint)
        empty_box.append(clear_button)
        self._empty_row.set_child(empty_box)
        self._empty_row.set_visible(False)
        self.nav_list.append(self._empty_row)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_child(self.nav_list)
        scroller.set_vexpand(True)
        content.append(scroller)

        toolbar.set_content(content)
        toolbar.add_bottom_bar(self._build_footer())

        sidebar_page.set_child(toolbar)
        return sidebar_page

    def _build_search(self) -> Gtk.Widget:
        wrapper = Gtk.Box(margin_top=2, margin_bottom=8, margin_start=12, margin_end=12)
        wrapper.set_hexpand(True)

        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Search modules")
        self.search_entry.set_hexpand(True)
        self.search_entry.add_css_class("atropa-search")
        self.search_entry.connect("search-changed", self._on_search_changed)
        self.search_entry.connect("activate", self._on_search_activate)
        self.search_entry.connect("stop-search", self._on_search_stopped)
        wrapper.append(self.search_entry)
        return wrapper

    def _build_footer(self) -> Gtk.Widget:
        footer = Gtk.Box(spacing=10, css_classes=["sidebar-footer"])

        shield = Gtk.Image.new_from_icon_name("security-high-symbolic")
        shield.set_pixel_size(16)
        shield.set_valign(Gtk.Align.CENTER)
        footer.append(shield)

        labels = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1, hexpand=True)

        # Title and version share a line so the footer keeps fitting at the
        # sidebar's narrowest width; the explanatory line runs underneath.
        top_line = Gtk.Box(spacing=8)
        title = Gtk.Label(label="Asks before privileged changes", xalign=0, hexpand=True, css_classes=["footer-title"])
        version = Gtk.Label(label=f"v{__version__}", css_classes=["version-chip"], valign=Gtk.Align.CENTER)
        top_line.append(title)
        top_line.append(version)

        subtitle = Gtk.Label(label="Polkit · no stored passwords", xalign=0, css_classes=["footer-subtitle"])
        labels.append(top_line)
        labels.append(subtitle)
        footer.append(labels)
        return footer

    def _build_content_header(self) -> Adw.HeaderBar:
        header = Adw.HeaderBar()
        header.add_css_class("atropa-content-header")

        self.content_icon = Gtk.Image.new_from_icon_name("system-software-install-symbolic")
        self.content_icon.set_pixel_size(18)

        icon_tile = Gtk.Box(css_classes=["page-icon-tile"], valign=Gtk.Align.CENTER)
        icon_tile.append(self.content_icon)

        self.content_title = Adw.WindowTitle(title="Atropa", subtitle="")
        self.content_title.add_css_class("atropa-content-title")

        title_box = Gtk.Box(spacing=10, valign=Gtk.Align.CENTER)
        title_box.append(icon_tile)
        title_box.append(self.content_title)
        header.set_title_widget(title_box)

        self.menu_button = Gtk.MenuButton(icon_name="open-menu-symbolic", tooltip_text="Main menu")
        self.menu_button.set_valign(Gtk.Align.CENTER)
        self.menu_button.set_menu_model(self._build_menu())
        header.pack_end(self.menu_button)
        return header

    def _build_menu(self) -> Gio.Menu:
        menu = Gio.Menu()
        menu.append("Refresh Page", "win.refresh-page")
        menu.append("Search Modules", "win.focus-search")
        about = Gio.Menu()
        about.append("About Atropa", "win.about")
        menu.append_section(None, about)
        return menu

    def _add_actions(self) -> None:
        for name, handler in (
            ("refresh-page", self._on_refresh_page),
            ("focus-search", self._on_focus_search),
            ("about", self._on_about),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", handler)
            self.add_action(action)

        app = self.get_application()
        if app is not None:
            app.set_accels_for_action("win.refresh-page", ["F5"])
            app.set_accels_for_action("win.focus-search", ["<Control>k", "<Control>f"])

    # -- navigation ---------------------------------------------------------

    def _activate_module(self, key: str, collapse: bool = True) -> None:
        self._ensure_page_materialized(key)
        self.stack.set_visible_child_name(key)
        self._set_content_header(key)

        row = self._module_rows.get(key)
        if row is not None:
            self.nav_list.select_row(row)

        # On narrow/mobile-style layouts, collapse to content after picking a
        # module. Not on the very first activation, so a narrow window still
        # opens on the sidebar where the choice is.
        if collapse:
            self.split_view.set_show_content(True)

    def _sync_sidebar_window_controls(self, *_args) -> None:
        self.sidebar_header.set_show_end_title_buttons(self.split_view.get_collapsed())

    def _set_content_header(self, key: str) -> None:
        module = self._modules_by_key.get(key)
        if module is None:
            return
        self.content_title.set_title(module.title)
        self.content_title.set_subtitle(module.tagline)
        self.content_icon.set_from_icon_name(module.icon)
        self.content_page.set_title(module.title)
        self.set_title(f"{module.title} · Atropa")

    def _on_row_activated(self, _listbox: Gtk.ListBox, row: Adw.ActionRow) -> None:
        key = row.get_name()
        self._activate_module(key)
        # Deliberately NOT calling page_widget.refresh() here. The page
        # already refreshed itself once, the moment it was first
        # materialized (see _ensure_page_materialized). Re-running
        # refresh() on every single navigation click used to mean
        # re-authenticating for every privileged read (aa-status, the
        # shadow file, ...) on every single visit to a page like AppArmor
        # or Inventory & Hygiene - not just once per session, every click.
        # Pages that want intentionally fresh data have their own explicit
        # "Re-scan"/refresh button for exactly that purpose, and the main
        # menu's "Refresh Page" is the explicit version of the same idea.

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

        page_widget = self._modules_by_key[key].page()
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

    # -- search -------------------------------------------------------------

    def _on_search_changed(self, entry: Gtk.SearchEntry) -> None:
        query = entry.get_text().strip().lower()
        visible_per_section = dict.fromkeys(SECTIONS, 0)

        for module in self.modules:
            row = self._module_rows.get(module.key)
            if row is None:
                continue
            matches = not query or query in self._search_text[module.key]
            row.set_visible(matches)
            if matches:
                visible_per_section[module.section] += 1

        for section, section_row in self._section_rows.items():
            section_row.set_visible(visible_per_section.get(section, 0) > 0)

        self._empty_row.set_visible(not any(row.get_visible() for row in self._module_rows.values()))

    def _on_search_activate(self, _entry: Gtk.SearchEntry) -> None:
        # Apply the current text immediately: "search-changed" is delayed by
        # Gtk.SearchEntry, and Enter can arrive before it has run.
        self._on_search_changed(_entry)
        for module in self.modules:
            row = self._module_rows.get(module.key)
            if row is not None and row.get_visible():
                row.grab_focus()
                self._activate_module(module.key)
                break

    def _on_search_stopped(self, entry: Gtk.SearchEntry) -> None:
        entry.set_text("")

    def _on_clear_search_clicked(self, _button: Gtk.Button) -> None:
        self.search_entry.set_text("")
        self.search_entry.grab_focus()

    # -- window actions -----------------------------------------------------

    def _on_focus_search(self, *_args) -> None:
        # On narrow layouts the sidebar may be hidden behind the content;
        # bring it back before focusing the entry.
        self.split_view.set_show_content(False)
        self.search_entry.grab_focus()

    def _on_refresh_page(self, *_args) -> None:
        key = self.stack.get_visible_child_name()
        page = self._pages.get(key) if key is not None else None
        if page is not None and hasattr(page, "refresh"):
            page.refresh()

    def _on_about(self, *_args) -> None:
        about = Adw.AboutDialog(
            application_name="Atropa",
            application_icon=self._app_id,
            version=__version__,
            developer_name="The Atropa contributors",
            comments=(
                "A YaST-inspired system control center for Arch Linux.\n\n"
                "Runs as your normal user and authenticates through polkit only for "
                "the individual actions that need root."
            ),
            website="https://github.com/whitewhistlegit/atropa-GUI",
            issue_url="https://github.com/whitewhistlegit/atropa-GUI/issues",
            license_type=Gtk.License.GPL_3_0,
            developers=["whitewhistlegit"],
            copyright="© 2025–2026 The Atropa contributors",
        )
        about.present(self)
