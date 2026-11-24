"""atropa.ui.pages.kernels - Kernels module (installed kernels, a fallback, leftover module folders)."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import kernels, pacman
from atropa.ui.pages import BasePage, esc


class KernelsPage(BasePage):
    def __init__(self) -> None:
        super().__init__()
        self._state: kernels.KernelStatus | None = None
        self._grub_names: set[str] | None = None
        self._kernel_rows: list = []
        self._warning_rows: list = []
        self._leftover_rows: list = []

        self.warning_group = self.add_group("Needs attention")
        self.kernel_group = self.add_group(
            "Installed kernels",
            "Keeping a second kernel means a broken update still leaves something to boot.",
        )

        self.add_kernel_group = self.add_group("Add a kernel")
        self.add_row = Adw.ComboRow(title="Kernel")
        self.add_row.set_use_markup(False)
        self.install_btn = Gtk.Button(label="Install", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        self.install_btn.connect("clicked", self._on_install_clicked)
        self.add_row.add_suffix(self.install_btn)
        self.add_row.connect("notify::selected", self._on_offered_selected)
        self.add_kernel_group.add(self.add_row)
        self._offered: list[str] = []

        self.leftover_group = self.add_group(
            "Leftover module folders",
            "Folders in /usr/lib/modules that old kernels left behind - usually DKMS-built drivers.",
        )

        self.refresh()

    # -- loading ------------------------------------------------------------

    def refresh(self) -> None:
        for group, attr in (
            (self.warning_group, "_warning_rows"),
            (self.kernel_group, "_kernel_rows"),
            (self.leftover_group, "_leftover_rows"),
        ):
            self.clear_rows(group, getattr(self, attr))
            setattr(self, attr, [])
        self._kernel_rows = [self.start_loading(self.kernel_group, "Reading kernels…")]
        grub_names = self._grub_names
        self.run_async(lambda: kernels.status(grub_names), self._on_loaded)

    def _row(self, group, attr: str, title: str, subtitle: str = "") -> Adw.ActionRow:
        row = Adw.ActionRow(title=esc(title))
        if subtitle:
            row.set_subtitle(esc(subtitle))
        group.add(row)
        getattr(self, attr).append(row)
        return row

    def _on_loaded(self, state, error) -> bool:
        self.clear_rows(self.kernel_group, self._kernel_rows)
        self._kernel_rows = []
        if error:
            self._row(self.kernel_group, "_kernel_rows", "Couldn't read the installed kernels", str(error))
            return False
        self._state = state

        found = kernels.warnings(state)
        self.warning_group.set_visible(bool(found))
        for text in found:
            row = self._row(self.warning_group, "_warning_rows", text)
            row.set_title_lines(0)
            row.add_prefix(Gtk.Image.new_from_icon_name("dialog-warning-symbolic"))

        unchecked = any(k.boot_entry is None for k in state.kernels) and state.bootloader == "grub"
        for kernel in state.kernels:
            self._add_kernel_row(kernel, state)
        if unchecked:
            row = self._row(
                self.kernel_group, "_kernel_rows", "Boot entries not checked",
                "grub.cfg is only readable by root; checking asks for your password",
            )
            button = Gtk.Button(label="Check", valign=Gtk.Align.CENTER)
            button.connect("clicked", self._on_check_grub_clicked)
            row.add_suffix(button)

        installed = {k.pkgbase for k in state.kernels}
        self._offered = [name for name in kernels.OFFERED if name not in installed]
        self.add_row.set_model(Gtk.StringList.new(self._offered))
        self.add_row.set_subtitle(
            kernels.OFFERED[self._offered[0]] if self._offered else "Every kernel Atropa offers is installed"
        )
        self.install_btn.set_sensitive(bool(self._offered))

        self.leftover_group.set_visible(bool(state.leftovers))
        for leftover in state.leftovers:
            row = self._row(
                self.leftover_group, "_leftover_rows", leftover.release, f"{leftover.size_mb} MB · {leftover.reason}"
            )
            if leftover.removable:
                button = Gtk.Button(label="Remove", valign=Gtk.Align.CENTER)
                button.connect("clicked", self._on_remove_leftover_clicked, leftover.release)
                row.add_suffix(button)
        removable = [lo for lo in state.leftovers if lo.removable]
        if len(removable) > 1:
            total = round(sum(lo.size_mb for lo in removable), 1)
            row = self._row(self.leftover_group, "_leftover_rows", f"All {len(removable)} leftover folders", f"{total} MB")
            button = Gtk.Button(label="Remove all", valign=Gtk.Align.CENTER, css_classes=["destructive-action"])
            button.connect("clicked", self._on_remove_all_leftovers_clicked, [lo.release for lo in removable])
            row.add_suffix(button)
        return False

    def _add_kernel_row(self, kernel: kernels.Kernel, state: kernels.KernelStatus) -> None:
        details = [kernel.version or kernel.release]
        if kernel.running:
            details.append("running")
        if state.dkms:
            details.append("headers installed" if kernel.headers else "no headers")
        details.append({True: "has a boot entry", False: "no boot entry", None: "boot entry not checked"}[kernel.boot_entry])
        row = self._row(self.kernel_group, "_kernel_rows", kernel.pkgbase, " · ".join(details))

        if state.dkms and not kernel.headers:
            button = Gtk.Button(label="Install headers", valign=Gtk.Align.CENTER)
            button.connect("clicked", self._on_install_headers_clicked, kernel.pkgbase)
            row.add_suffix(button)
        if kernel.boot_entry is False and state.bootloader == "systemd-boot":
            button = Gtk.Button(label="Add boot entry", valign=Gtk.Align.CENTER)
            button.connect("clicked", self._on_add_entry_clicked, kernel.pkgbase)
            row.add_suffix(button)

        remove = Gtk.Button(label="Remove", valign=Gtk.Align.CENTER, css_classes=["flat"])
        if kernel.running:
            remove.set_sensitive(False)
            remove.set_tooltip_text("This is the running kernel - boot another one first")
        elif len(state.kernels) == 1:
            remove.set_sensitive(False)
            remove.set_tooltip_text("The only kernel installed")
        remove.connect("clicked", self._on_remove_clicked, kernel.pkgbase)
        row.add_suffix(remove)

    # -- actions ------------------------------------------------------------

    def _on_offered_selected(self, row: Adw.ComboRow, _pspec) -> None:
        index = row.get_selected()
        if 0 <= index < len(self._offered):
            row.set_subtitle(kernels.OFFERED[self._offered[index]])

    def _on_check_grub_clicked(self, _btn: Gtk.Button) -> None:
        def done(names, error) -> bool:
            if error:
                self.notify(f"Couldn't check grub.cfg: {error}", is_error=True)
                return False
            self._grub_names = names
            self.refresh()
            return False

        self.run_action(kernels.check_grub_entries, done)

    def _on_install_clicked(self, _btn: Gtk.Button) -> None:
        index = self.add_row.get_selected()
        if not 0 <= index < len(self._offered):
            return
        name = self._offered[index]
        headers = " and its headers (DKMS is in use)" if self._state and self._state.dkms else ""
        regenerate = " GRUB's menu is regenerated afterwards." if self._state and self._state.bootloader == "grub" else ""
        self.confirm(
            f"Install {name}?",
            f"Installs {name}{headers} with pacman and builds its initramfs.{regenerate}",
            "Install",
            lambda: self.run_action(lambda: kernels.install(name), self._install_done(name)),
            destructive=False,
        )

    def _install_done(self, name: str):
        def done(result, error) -> bool:
            if isinstance(error, pacman.PartialUpgradeError):
                self.confirm(
                    "Upgrade the system first?",
                    f"{error}\n\nAtropa can upgrade everything and install {name} in the same step "
                    "(pacman -Syu). That can take a while.",
                    "Upgrade and install",
                    lambda: self.run_action(lambda: kernels.install(name, upgrade=True), self._done(f"{name} installed")),
                    destructive=False,
                )
                return False
            return self._done(f"{name} installed")(result, error)

        return done

    def _on_install_headers_clicked(self, _btn: Gtk.Button, pkgbase: str) -> None:
        self.run_action(lambda: kernels.install_headers(pkgbase), self._done(f"{pkgbase}-headers installed"))

    def _on_add_entry_clicked(self, _btn: Gtk.Button, pkgbase: str) -> None:
        try:
            path, content = kernels.entry_for(pkgbase)
        except (RuntimeError, ValueError, OSError) as exc:
            self.notify(str(exc), is_error=True)
            return
        self.confirm(
            f"Add a boot entry for {pkgbase}?",
            f"Writes {path}, a copy of the running kernel's entry (same kernel options):\n\n{content}",
            "Add entry",
            lambda: self.run_action(lambda: kernels.add_boot_entry(pkgbase), self._done("Boot entry added")),
            destructive=False,
        )

    def _on_remove_clicked(self, _btn: Gtk.Button, pkgbase: str) -> None:
        self.confirm(
            f"Remove {pkgbase}?",
            f"Removes {pkgbase} and its headers with pacman, and its boot entry from GRUB's menu "
            "(on systemd-boot, an entry you wrote yourself stays).",
            "Remove",
            lambda: self.run_action(lambda: kernels.remove(pkgbase), self._done(f"{pkgbase} removed")),
        )

    def _on_remove_leftover_clicked(self, _btn: Gtk.Button, release: str) -> None:
        self.run_action(lambda: kernels.remove_leftover(release), self._done(f"Removed {release}"))

    def _on_remove_all_leftovers_clicked(self, _btn: Gtk.Button, releases: list[str]) -> None:
        def remove_all():
            result = None
            for release in releases:
                result = kernels.remove_leftover(release)
                if not result.ok:
                    return result
            return result

        self.confirm(
            f"Remove {len(releases)} leftover folders?",
            "Deletes these folders from /usr/lib/modules. No installed kernel uses them; the helper "
            "checks each one again (no package owns it, no kernel/ tree, not the running kernel).",
            "Remove all",
            lambda: self.run_action(remove_all, self._done("Leftover folders removed")),
        )

    def _done(self, message: str):
        def done(result, error) -> bool:
            self._grub_names = None  # the menu may have changed: read it again
            self.handle_command_result(result, error, message)
            return False

        return done
