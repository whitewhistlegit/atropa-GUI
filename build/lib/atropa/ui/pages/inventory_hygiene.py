"""
atropa.ui.pages.inventory_hygiene
----------------------------------
CIS DIL Phase 2: Service Inventory (2.2/2.3-style) + Account & File Hygiene
(6.1/6.2-style). Both are read-only scans, same rationale as
DOCUMENTATION.md gives for account_hygiene.py: several of these findings
(a stray UID-0 account, an unexpected server actually listening) need a
human to decide *why* before anything changes, so this page only ever
reports - there's no "Apply"/"Fix" button anywhere on it.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import account_hygiene, inventory
from atropa.ui.pages import BasePage, esc

STATUS_ICON = {
    "pass": "emblem-ok-symbolic",
    "warn": "dialog-warning-symbolic",
    "fail": "dialog-error-symbolic",
    "info": "dialog-information-symbolic",
}


class InventoryHygienePage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self.inventory_group = self.add_group(
            "Service Inventory",
            "Special-purpose services (CIS 2.2/2.3-style) - installed-but-inactive is a much smaller finding "
            "than installed-and-active. Arch often bundles client and server tooling in one package (inetutils, "
            "openldap, nfs-utils), so each row reports both facts directly rather than forcing a client/server "
            "label that wouldn't be accurate here.",
        )
        self._inventory_rows: list[Adw.ActionRow] = []
        rescan_inv_btn = Gtk.Button(label="Re-scan", valign=Gtk.Align.CENTER)
        rescan_inv_btn.connect("clicked", lambda _b: self._scan_inventory())
        self.inventory_summary_row = Adw.ActionRow(title="Scanning…")
        self.inventory_summary_row.add_suffix(rescan_inv_btn)
        self.inventory_group.add(self.inventory_summary_row)

        self.hygiene_group = self.add_group(
            "Account & File Hygiene",
            "File permissions on passwd/shadow/group/gshadow, duplicate UIDs/GIDs, stray UID-0 accounts, "
            "system accounts with a login shell, home directory ownership, empty password fields, and root "
            "PATH integrity (CIS 6.1/6.2-style). Read-only - nothing here is auto-fixed.",
        )
        self._hygiene_rows: list[Adw.ActionRow] = []
        rescan_hyg_btn = Gtk.Button(label="Re-scan", valign=Gtk.Align.CENTER)
        rescan_hyg_btn.connect("clicked", lambda _b: self._scan_hygiene())
        self.hygiene_summary_row = Adw.ActionRow(title="Scanning…")
        self.hygiene_summary_row.add_suffix(rescan_hyg_btn)
        self.hygiene_group.add(self.hygiene_summary_row)

        self.refresh()

    def refresh(self) -> None:
        self._scan_inventory()
        self._scan_hygiene()

    # -- Service Inventory ---------------------------------------------------

    def _scan_inventory(self) -> None:
        self.inventory_summary_row.set_title("Scanning installed services…")
        self.clear_rows(self.inventory_group, self._inventory_rows)
        self._inventory_rows = [self.start_loading(self.inventory_group, "Checking packages & units…")]
        self.run_async(inventory.scan_all, self._on_inventory_scanned)

    def _on_inventory_scanned(self, result, error) -> bool:
        for row in list(self._inventory_rows):
            self.inventory_group.remove(row)
        self._inventory_rows = []

        if error:
            self.inventory_summary_row.set_title("Scan failed")
            self.inventory_summary_row.set_subtitle(esc(error))
            return False

        active = sum(1 for f in result if f.status == "fail")
        present = sum(1 for f in result if f.status == "warn")
        self.inventory_summary_row.set_title(
            f"{active} active service(s), {present} installed-but-inactive, out of {len(result)} checked"
        )

        for finding in result:
            row = Adw.ActionRow(title=esc(finding.title), subtitle=esc(finding.detail))
            row.add_prefix(Gtk.Image.new_from_icon_name(STATUS_ICON.get(finding.status, "dialog-question-symbolic")))
            row.add_suffix(Gtk.Label(label=finding.status.upper(), css_classes=["dim-label"]))
            self.inventory_group.add(row)
            self._inventory_rows.append(row)
        return False

    # -- Account & File Hygiene ----------------------------------------------

    def _scan_hygiene(self) -> None:
        self.hygiene_summary_row.set_title("Scanning accounts & files…")
        self.clear_rows(self.hygiene_group, self._hygiene_rows)
        self._hygiene_rows = [self.start_loading(self.hygiene_group, "Checking accounts, homes, and permissions…")]
        self.run_async(account_hygiene.scan_all, self._on_hygiene_scanned)

    def _on_hygiene_scanned(self, result, error) -> bool:
        for row in list(self._hygiene_rows):
            self.hygiene_group.remove(row)
        self._hygiene_rows = []

        if error:
            self.hygiene_summary_row.set_title("Scan failed")
            self.hygiene_summary_row.set_subtitle(esc(error))
            return False

        failed = sum(1 for f in result if f.status == "fail")
        warned = sum(1 for f in result if f.status == "warn")
        self.hygiene_summary_row.set_title(f"{failed} finding(s), {warned} warning(s), out of {len(result)} checked")

        for finding in result:
            row = Adw.ActionRow(title=esc(finding.title), subtitle=esc(finding.detail))
            row.add_prefix(Gtk.Image.new_from_icon_name(STATUS_ICON.get(finding.status, "dialog-question-symbolic")))
            row.add_suffix(Gtk.Label(label=finding.status.upper(), css_classes=["dim-label"]))
            self.hygiene_group.add(row)
            self._hygiene_rows.append(row)
        return False
