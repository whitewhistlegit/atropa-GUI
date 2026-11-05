"""atropa.ui.pages.boot_security - Disk encryption status and Secure Boot (sbctl)."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import boot_security
from atropa.ui.pages import BasePage, esc


class BootSecurityPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        encryption_group = self.add_group(
            "Root Filesystem Encryption",
            "Whether the disk holding / is protected by LUKS - the difference between a stolen "
            "laptop's files being readable and not.",
        )
        self.encryption_row = Adw.ActionRow(title="Checking…")
        encryption_group.add(self.encryption_row)

        self.crypttab_group = self.add_group("Encrypted Volumes (/etc/crypttab)")
        self._crypttab_rows: list[Adw.ActionRow] = []

        secure_boot_group = self.add_group(
            "Secure Boot",
            "Firmware verification of the boot chain. It needs a firmware that supports it, keys "
            "enrolled, and every boot file signed.",
        )
        self.secure_boot_row = Adw.ActionRow(title="Checking…")
        secure_boot_group.add(self.secure_boot_row)
        self.sbctl_row = Adw.ActionRow(title="sbctl")
        secure_boot_group.add(self.sbctl_row)

        setup_group = self.add_group(
            "Set Up Secure Boot with sbctl",
            "These change the machine's boot chain and firmware keys. Enrolling keys keeps Microsoft's, "
            "so option ROMs and peripherals that rely on them keep working. The firmware must be in "
            "setup mode for enrollment; Atropa can't put it there.",
        )
        self.create_keys_btn = self._action_button(
            "Create keys",
            "Create your own Secure Boot keys with sbctl?",
            "sbctl generates a key pair and a certificate under /var/lib/sbctl. Nothing is enrolled in "
            "the firmware yet, so this is safe to do now.",
            "Create",
            boot_security.create_keys,
        )
        self.enroll_keys_btn = self._action_button(
            "Enroll keys",
            "Enroll your keys in the firmware?",
            "Only works while the firmware is in setup mode. sbctl enrolls your keys and keeps "
            "Microsoft's (--microsoft), then turns Secure Boot on if the firmware allows it. A machine "
            "that can't boot afterwards needs its firmware settings reset.",
            "Enroll",
            boot_security.enroll_keys,
        )
        self.sign_btn = self._action_button(
            "Sign boot files",
            "Sign every boot file?",
            "sbctl signs the bootloader, kernel and initramfs it finds. Do this after enrolling keys "
            "and after every kernel or bootloader update, or the firmware won't boot them.",
            "Sign",
            boot_security.sign_all,
        )
        for button in (self.create_keys_btn, self.enroll_keys_btn, self.sign_btn):
            setup_group.add(button)

        self._sbctl_installed = False
        self.refresh()

    def _action_button(self, label, heading, body, danger_label, work_fn) -> Adw.ActionRow:
        row = Adw.ActionRow(title=label)
        button = Gtk.Button(label=label, valign=Gtk.Align.CENTER)
        button.connect("clicked", lambda _b: self._confirm_action(heading, body, danger_label, work_fn))
        row.add_suffix(button)
        return row

    def _confirm_action(self, heading: str, body: str, danger_label: str, work_fn) -> None:
        self.confirm(
            heading,
            body,
            danger_label,
            lambda: self.run_action(work_fn, self.handle_command_result),
        )

    def refresh(self) -> None:
        self.encryption_row.set_title("Checking…")
        self.encryption_row.set_subtitle("")
        self.run_async(boot_security.overview, self._on_overview_loaded)

    def _on_overview_loaded(self, result, error) -> bool:
        if error:
            self.encryption_row.set_title("Couldn't check boot security")
            self.encryption_row.set_subtitle(esc(error))
            return False

        report = result
        self._render_encryption(report)
        self._render_secure_boot(report)
        self._render_sbctl(report)
        return False

    def _render_encryption(self, report: boot_security.BootSecurityReport) -> None:
        self.clear_rows(self.crypttab_group, self._crypttab_rows)
        self._crypttab_rows = []

        if report.encryption is None:
            self.encryption_row.set_title("Couldn't check encryption")
            self.encryption_row.set_subtitle(esc(report.encryption_error))
            return

        status = report.encryption
        if status.encrypted is True:
            self.encryption_row.set_title("Root is encrypted (LUKS)")
        elif status.encrypted is False:
            self.encryption_row.set_title("Root is not encrypted")
        else:
            self.encryption_row.set_title("Couldn't tell")
        self.encryption_row.set_subtitle(esc(status.detail))

        for entry in status.crypttab:
            options = f" · options: {entry.options}" if entry.options else ""
            row = Adw.ActionRow(
                title=esc(entry.name),
                subtitle=esc(f"{entry.device} · key file: {entry.keyfile}{options}"),
            )
            self.crypttab_group.add(row)
            self._crypttab_rows.append(row)

    def _render_secure_boot(self, report: boot_security.BootSecurityReport) -> None:
        if report.secure_boot is None:
            self.secure_boot_row.set_title("Couldn't read Secure Boot state")
            self.secure_boot_row.set_subtitle(esc(report.secure_boot_error))
        else:
            status = report.secure_boot
            if status.supported is False:
                self.secure_boot_row.set_title("Not applicable (legacy BIOS boot)")
            elif status.enabled is True:
                self.secure_boot_row.set_title("Secure Boot is enabled")
            elif status.enabled is False:
                self.secure_boot_row.set_title("Secure Boot is disabled")
            else:
                self.secure_boot_row.set_title("Secure Boot state unknown")
            source = f" (read with {status.source})" if status.source else ""
            self.secure_boot_row.set_subtitle(esc(f"{status.detail}{source}"))

    def _render_sbctl(self, report: boot_security.BootSecurityReport) -> None:
        if report.sbctl is None:
            self.sbctl_row.set_title("Couldn't read sbctl status")
            self.sbctl_row.set_subtitle(esc(report.sbctl_error))
            self._sbctl_installed = False
        else:
            status = report.sbctl
            self._sbctl_installed = status.installed
            self.sbctl_row.set_title("sbctl installed" if status.installed else "sbctl not installed")
            details = [status.detail]
            if status.vendor_keys:
                details.append(f"Vendor keys: {status.vendor_keys}")
            self.sbctl_row.set_subtitle(esc(" · ".join(d for d in details if d)))

        for row in (self.create_keys_btn, self.enroll_keys_btn, self.sign_btn):
            row.set_sensitive(self._sbctl_installed)
