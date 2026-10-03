"""
atropa.ui.pages.refpolicy_build
---------------------------------
Build, install, and activate a custom SELinux Reference Policy source
tree (e.g. atropa-refpolicy). See backend/refpolicy_build.py's docstring
for the full risk-tier rationale behind keeping Build/Install/Activate as
three separate, separately-confirmed actions rather than one button.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, Gtk  # noqa: E402

from atropa.backend import refpolicy_build
from atropa.ui.pages import BasePage, esc


class RefpolicyBuildPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self._source_dir: str | None = None

        intro_group = self.add_group(
            "Build a Custom Policy Source Tree",
            "For a refpolicy fork/source tree you maintain yourself (e.g. one with Arch-specific paths and "
            "contexts already fixed) - not for installing a prebuilt AUR package, which stays a manual "
            "'install it with your AUR helper first' step everywhere else in Atropa. Three separate stages, "
            "each with its own confirmation: Build only compiles (no root, no effect on this system at all). "
            "Install writes the compiled policy to disk but does not make it active. Activate is the "
            "consequential one - it's what actually switches the system to boot into this policy.",
        )

        self.source_row = Adw.ActionRow(title="Source directory", subtitle="Not selected")
        pick_btn = Gtk.Button(label="Choose…", valign=Gtk.Align.CENTER)
        pick_btn.connect("clicked", lambda _b: self._on_pick_source_dir())
        self.source_row.add_suffix(pick_btn)
        intro_group.add(self.source_row)

        self.build_btn = Gtk.Button(label="Build (make conf all)", valign=Gtk.Align.CENTER, sensitive=False)
        self.build_btn.connect("clicked", lambda _b: self._on_build_clicked())
        build_row = Adw.ActionRow(title="1. Build", subtitle="Compiles everything - unprivileged, no system effect")
        build_row.add_suffix(self.build_btn)
        intro_group.add(build_row)

        self.install_btn = Gtk.Button(label="Install (make install)", valign=Gtk.Align.CENTER, sensitive=False)
        self.install_btn.connect("clicked", lambda _b: self._on_install_clicked())
        install_row = Adw.ActionRow(
            title="2. Install", subtitle="Writes to /etc/selinux and /usr/share/selinux - does not activate it"
        )
        install_row.add_suffix(self.install_btn)
        intro_group.add(install_row)

        activate_group = self.add_group(
            "3. Activate — switches the system to boot into this policy",
            "This is the consequential step. It edits /etc/selinux/config (backed up first), maps the "
            "default login to the SELinux user below so an interactive session lands in the right domain "
            "for a targeted-style policy, and schedules a full filesystem relabel. It does NOT reboot and "
            "does NOT touch any kernel boot parameter or bootloader config, ever - the switch only fully "
            "takes effect after you reboot yourself, on your own schedule.",
        )
        self.policy_name_entry = Adw.EntryRow(title="Policy name (matches build.conf's NAME)")
        activate_group.add(self.policy_name_entry)
        self.login_seuser_entry = Adw.EntryRow(title="Default login SELinux user")
        self.login_seuser_entry.set_text("unconfined_u")
        activate_group.add(self.login_seuser_entry)
        self.activate_btn = Gtk.Button(
            label="Activate…", valign=Gtk.Align.CENTER, css_classes=["destructive-action"]
        )
        self.activate_btn.connect("clicked", lambda _b: self._on_activate_clicked())
        activate_row = Adw.ActionRow(title="Switch active policy")
        activate_row.add_suffix(self.activate_btn)
        activate_group.add(activate_row)

    def refresh(self) -> None:
        pass  # nothing to auto-load - everything here starts from an explicit user action

    # -- source directory -----------------------------------------------------

    def _on_pick_source_dir(self) -> None:
        dialog = Gtk.FileDialog()
        dialog.select_folder(self.get_root(), None, self._on_source_dir_chosen)

    def _on_source_dir_chosen(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            gfile = dialog.select_folder_finish(result)
        except Exception:  # noqa: BLE001 - user cancelled or dialog error
            return
        path = gfile.get_path() if gfile else None
        if not path:
            return
        self._source_dir = path
        self.source_row.set_subtitle(esc(path))
        self.build_btn.set_sensitive(True)

    # -- build (unprivileged) --------------------------------------------------

    def _on_build_clicked(self) -> None:
        if not self._source_dir:
            return
        source_dir = self._source_dir
        self.confirm(
            "Build this policy source tree?",
            f"Runs 'make conf all' in {source_dir}. Unprivileged - compiles into the source tree's own "
            "build output only, no effect anywhere else on this system.",
            "Build",
            lambda: self.run_streaming_operation(
                "Building policy", lambda on_line: refpolicy_build.build(source_dir, on_line), self._on_build_done
            ),
        )

    def _on_build_done(self, result, error) -> bool:
        handled = self.handle_command_result(result, error, success_message="Build finished")
        if not error and getattr(result, "ok", True):
            self.install_btn.set_sensitive(True)
        return handled

    # -- install (privileged, not active yet) -----------------------------------

    def _on_install_clicked(self) -> None:
        if not self._source_dir:
            return
        source_dir = self._source_dir
        self.confirm(
            "Install this policy?",
            f"Runs 'make install' in {source_dir} (needs authentication). Writes the compiled policy under "
            "/etc/selinux and /usr/share/selinux, but does NOT make it the active policy - the system keeps "
            "running whatever it's running now until you use Activate below.",
            "Install",
            lambda: self.run_streaming_operation(
                "Installing policy",
                lambda on_line: refpolicy_build.install(source_dir, on_line),
                lambda result, error: self.handle_command_result(result, error, success_message="Install finished"),
            ),
        )

    # -- activate (privileged, consequential) ------------------------------------

    def _on_activate_clicked(self) -> None:
        policy_name = self.policy_name_entry.get_text().strip()
        login_seuser = self.login_seuser_entry.get_text().strip() or "unconfined_u"
        if not policy_name:
            self.notify("Enter the policy name first (matches build.conf's NAME)", is_error=True)
            return

        self.confirm(
            f"Switch the active policy to '{policy_name}'?",
            f"Sets SELINUXTYPE={policy_name} in /etc/selinux/config, maps the default login to "
            f"{login_seuser}, and schedules a full filesystem relabel. This does NOT reboot and does NOT "
            "touch kernel boot parameters or bootloader config - you still need to reboot yourself for "
            "the switch and relabel to actually take effect. Make sure Install has already succeeded for "
            "this exact policy name before doing this.",
            "Activate",
            lambda: self.run_async(
                lambda: refpolicy_build.activate(policy_name, login_seuser), self._on_activate_done
            ),
        )

    def _on_activate_done(self, results, error) -> bool:
        if error:
            self.notify(f"Error: {error}", is_error=True)
            return False
        if not results:
            return False
        if not results[-1].ok:
            self.notify(f"Activate failed: {results[-1].stderr.strip()[:150]}", is_error=True)
            return False
        self.notify("Policy switch scheduled - reboot to complete it (relabel will run automatically on boot)")
        return False
