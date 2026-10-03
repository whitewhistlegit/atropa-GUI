"""atropa.ui.pages.profiles - Security Profiles: export/import a portable security-configuration profile."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, Gtk  # noqa: E402

from atropa.backend import profiles
from atropa.ui.pages import BasePage, esc

_SECTION_LABELS = {
    "quicksetup": "Quick-setup modules (firewall, fail2ban, sysctl, faillock, AppArmor, auditd, USBGuard, SELinux)",
    "apparmor_profiles": "AppArmor profile modes",
    "selinux_booleans": "SELinux booleans",
    "ssh": "SSH hardening (root login, password auth, port)",
}


class ProfilesPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        export_group = self.add_group(
            "Export",
            "Save this machine's current security configuration (which quick-setup modules are "
            "active, AppArmor profile modes, SELinux booleans, SSH hardening settings) as a "
            "portable file - to clone the same posture onto another machine, or keep as a "
            "known-good baseline to check drift against later.",
        )
        export_row = Adw.ActionRow(title="Export current configuration")
        export_btn = Gtk.Button(label="Export…", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        export_btn.connect("clicked", self._on_export_clicked)
        export_row.add_suffix(export_btn)
        export_group.add(export_row)

        import_group = self.add_group(
            "Import",
            "Load a profile exported from this or another machine, review exactly what it "
            "contains, choose which parts to apply, then apply it. Anything a section refers "
            "to that doesn't exist on this machine is skipped and reported, never guessed at.",
        )
        self.import_row = Adw.ActionRow(title="No profile loaded")
        load_btn = Gtk.Button(label="Load Profile…", valign=Gtk.Align.CENTER)
        load_btn.connect("clicked", self._on_load_clicked)
        self.import_row.add_suffix(load_btn)
        import_group.add(self.import_row)

        self.section_group = self.add_group("Sections to apply")
        self.section_group.set_visible(False)
        self._section_checks: dict[str, Gtk.CheckButton] = {}
        for key in profiles.SECTIONS:
            row = Adw.ActionRow(title=_SECTION_LABELS[key])
            default_selected = key != "ssh"  # SSH carries real remote-lockout risk - opt-in only
            check = Gtk.CheckButton(active=default_selected, valign=Gtk.Align.CENTER)
            row.add_prefix(check)
            if key == "ssh":
                warning_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
                warning_icon.set_tooltip_text(
                    "A valid sshd config that still doesn't fit this machine (e.g. disabling "
                    "password auth without a key set up here) isn't caught by the automatic "
                    "rollback - double-check you have another way in first."
                )
                row.add_suffix(warning_icon)
            self._section_checks[key] = check
            self.section_group.add(row)

        apply_row = Adw.ActionRow(title="Apply the sections checked above")
        self.apply_btn = Gtk.Button(label="Apply Import", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        self.apply_btn.set_sensitive(False)
        self.apply_btn.connect("clicked", self._on_apply_clicked)
        apply_row.add_suffix(self.apply_btn)
        self.section_group.add(apply_row)

        self._loaded_profile: dict | None = None

    def refresh(self) -> None:
        pass  # nothing to auto-refresh - export/import are both explicit user actions

    # --------------------------------------------------------- export --

    def _on_export_clicked(self, _btn: Gtk.Button) -> None:
        self.run_async(profiles.export_profile, self._on_exported)

    def _on_exported(self, result, error) -> bool:
        if error:
            self.notify(f"Couldn't build export: {error}", is_error=True)
            return False

        dialog = Gtk.FileDialog()
        dialog.set_initial_name("atropa-profile.json")
        dialog.save(self.get_root(), None, lambda d, r: self._on_save_location_chosen(d, r, result))
        return False

    def _on_save_location_chosen(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult, profile: dict) -> None:
        try:
            gfile = dialog.save_finish(result)
        except Exception:  # noqa: BLE001 - user cancelled or dialog error, nothing to do
            return
        if not gfile:
            return
        path = gfile.get_path()
        if not path:
            return
        try:
            profiles.save_profile_to_file(profile, path)
        except OSError as exc:
            self.notify(f"Couldn't save profile: {exc}", is_error=True)
            return
        self.notify(f"Profile saved to {path}")

    # --------------------------------------------------------- import --

    def _on_load_clicked(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileDialog()
        filt = Gtk.FileFilter()
        filt.set_name("Atropa profile (.json)")
        filt.add_pattern("*.json")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filt)
        dialog.set_filters(filters)
        dialog.open(self.get_root(), None, self._on_file_chosen)

    def _on_file_chosen(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            gfile = dialog.open_finish(result)
        except Exception:  # noqa: BLE001 - user cancelled or dialog error, nothing to do
            return
        if not gfile:
            return
        path = gfile.get_path()
        if not path:
            return
        try:
            profile = profiles.load_profile_from_file(path)
        except ValueError as exc:
            self.notify(str(exc), is_error=True)
            return

        self._loaded_profile = profile
        summary = profiles.summarize_profile(profile)
        detail = (
            f"{len(summary.quicksetup_keys)} quick-setup module(s), "
            f"{summary.apparmor_profile_count} AppArmor profile(s), "
            f"{summary.selinux_boolean_count} SELinux boolean(s)"
            f"{', has SSH settings' if summary.has_ssh_section else ''}"
        )
        self.import_row.set_title(esc(f"Loaded: {summary.hostname}"))
        self.import_row.set_subtitle(esc(f"Exported {summary.exported_at} · {detail}"))
        self.section_group.set_visible(True)
        self.apply_btn.set_sensitive(True)

    def _selected_sections(self) -> list[str]:
        return [key for key, check in self._section_checks.items() if check.get_active()]

    def _on_apply_clicked(self, _btn: Gtk.Button) -> None:
        if self._loaded_profile is None:
            return
        sections = self._selected_sections()
        if not sections:
            self.notify("Nothing selected", is_error=True)
            return

        labels = ", ".join(_SECTION_LABELS[key] for key in sections)
        body = f"This will apply: {labels}."
        if "ssh" in sections:
            body += (
                " SSH settings are included - a valid config that still doesn't fit this "
                "machine won't be caught by the automatic rollback."
            )

        self.confirm(
            "Apply this profile?",
            body,
            "Apply",
            lambda: self.run_streaming_operation(
                "Applying Security Profile",
                lambda on_line: profiles.import_profile(self._loaded_profile, sections, on_line),
                self._on_import_done,
            ),
        )

    def _on_import_done(self, result, error) -> bool:
        if error:
            self.notify(f"Error: {error}", is_error=True)
        elif result is not None:
            failed = [key for key, res in result.items() if not res.ok]
            if failed:
                self.notify(f"Finished with issues: {', '.join(failed)}", is_error=True)
            else:
                self.notify("Profile applied")
        return False
