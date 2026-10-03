"""atropa.ui.pages.apparmor - AppArmor module: profiles, rule toggles, denial review."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import apparmor
from atropa.ui.pages import BasePage, esc


class ApparmorPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        profiles_group = self.add_group(
            "Profiles",
            "Loaded AppArmor profiles. Complain mode logs violations without blocking them - "
            "useful while tuning a profile. 'Manage rules' edits real network/capability toggles.",
        )
        self.profiles_group = profiles_group

        denials_group = self.add_group(
            "Recent Denials",
            "There's no 'audit2allow' for AppArmor - suggested rules are built from the denial's "
            "own fields, so review them before appending.",
        )
        self.denials_group = denials_group
        refresh_row = Adw.ActionRow(title="Source: kernel log (journalctl -k)")
        refresh_btn = Gtk.Button(label="Refresh", valign=Gtk.Align.CENTER)
        refresh_btn.connect("clicked", lambda _b: self._load_denials())
        refresh_row.add_suffix(refresh_btn)
        denials_group.add(refresh_row)

        self.refresh()

    def refresh(self) -> None:
        self.clear_rows(self.profiles_group, getattr(self, "_profile_rows", []))
        self._profile_rows = [self.start_loading(self.profiles_group, "Loading profiles…")]
        self.run_async(apparmor.list_profiles, self._on_profiles_loaded)
        self._load_denials()

    def _load_denials(self) -> None:
        self.clear_rows(self.denials_group, getattr(self, "_denial_rows", []))
        self._denial_rows = [self.start_loading(self.denials_group, "Loading denials…")]
        self.run_async(apparmor.list_denials, self._on_denials_loaded)

    # -- profiles -----------------------------------------------------

    def _on_profiles_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_profile_rows", [])):
            self.profiles_group.remove(row)
        self._profile_rows = []

        if error:
            row = Adw.ActionRow(title="Couldn't load profiles", subtitle=esc(error))
            self.profiles_group.add(row)
            self._profile_rows.append(row)
            return False

        if not result:
            row = Adw.ActionRow(title="No profiles loaded")
            self.profiles_group.add(row)
            self._profile_rows.append(row)
            return False

        for profile in result:
            row = Adw.ActionRow(title=esc(profile.path), subtitle=f"mode: {profile.mode}")

            for mode in ("enforce", "complain", "disable"):
                btn = Gtk.Button(label=mode.capitalize(), valign=Gtk.Align.CENTER, css_classes=["flat"])
                if mode == profile.mode:
                    btn.set_sensitive(False)
                btn.connect("clicked", self._on_set_mode, profile.path, mode)
                row.add_suffix(btn)

            manage_btn = Gtk.Button(label="Manage rules", valign=Gtk.Align.CENTER)
            manage_btn.connect("clicked", self._on_manage_rules, profile.path)
            row.add_suffix(manage_btn)

            self.profiles_group.add(row)
            self._profile_rows.append(row)
        return False

    def _on_set_mode(self, _btn: Gtk.Button, profile_path: str, mode: str) -> None:
        verb = {"enforce": "Switch to enforcing", "complain": "Switch to complain mode", "disable": "Disable"}[mode]
        self.confirm(
            f"{verb} for {profile_path}?",
            {
                "enforce": "Violations will be blocked, not just logged.",
                "complain": "Violations will be logged but allowed - useful while tuning.",
                "disable": "This profile will no longer confine the program at all.",
            }[mode],
            verb,
            lambda: self.run_async(lambda: apparmor.set_profile_mode(profile_path, mode), self.handle_command_result),
        )

    def _on_manage_rules(self, _btn: Gtk.Button, profile_path: str) -> None:
        profile_file = apparmor.resolve_profile_file(profile_path)
        if not profile_file:
            self.notify(f"Couldn't find a profile file for {profile_path}", is_error=True)
            return
        self.run_async(
            lambda: apparmor.profile_toggle_states(profile_file),
            lambda r, e: self._show_manage_dialog(profile_file, r, e),
        )

    def _show_manage_dialog(self, profile_file: str, states, error) -> bool:
        if error:
            self.notify(f"Couldn't read profile: {error}", is_error=True)
            return False

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)

        cap_label = Gtk.Label(label="Capabilities", xalign=0, css_classes=["heading"])
        box.append(cap_label)
        for cap, desc in apparmor.COMMON_CAPABILITIES:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            label = Gtk.Label(label=f"{cap} - {desc}", xalign=0, hexpand=True, wrap=True)
            switch = Gtk.Switch(valign=Gtk.Align.CENTER, active=states["capabilities"].get(cap, False))
            switch.connect("state-set", self._on_toggle_capability, profile_file, cap)
            row.append(label)
            row.append(switch)
            box.append(row)

        net_label = Gtk.Label(label="Network", xalign=0, css_classes=["heading"], margin_top=12)
        box.append(net_label)
        for spec, desc in apparmor.COMMON_NETWORK_RULES:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            label = Gtk.Label(label=f"{spec} - {desc}", xalign=0, hexpand=True, wrap=True)
            switch = Gtk.Switch(valign=Gtk.Align.CENTER, active=states["network"].get(spec, False))
            switch.connect("state-set", self._on_toggle_network, profile_file, spec)
            row.append(label)
            row.append(switch)
            box.append(row)

        scroller = Gtk.ScrolledWindow(min_content_height=360, min_content_width=420)
        scroller.set_child(box)

        dialog = Adw.AlertDialog(heading=f"Manage rules: {profile_file.rsplit('/', 1)[-1]}")
        dialog.set_extra_child(scroller)
        dialog.add_response("close", "Close")
        dialog.present(self.get_root())
        return False

    def _on_toggle_capability(self, _switch: Gtk.Switch, state: bool, profile_file: str, capability: str) -> bool:
        self.run_async(lambda: apparmor.set_capability_rule(profile_file, capability, state), self.handle_command_result)
        return False

    def _on_toggle_network(self, _switch: Gtk.Switch, state: bool, profile_file: str, spec: str) -> bool:
        self.run_async(lambda: apparmor.set_network_rule(profile_file, spec, state), self.handle_command_result)
        return False

    # -- denials -----------------------------------------------------

    def _on_denials_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_denial_rows", [])):
            self.denials_group.remove(row)
        self._denial_rows = []

        if error:
            self.notify(f"Couldn't read denials: {error}", is_error=True)
            return False

        if not result:
            row = Adw.ActionRow(title="No denials found recently")
            self.denials_group.add(row)
            self._denial_rows.append(row)
            return False

        for raw_line in reversed(result[-50:]):
            summary = self._summarize_denial(raw_line)
            row = Adw.ActionRow(title=esc(summary), subtitle=esc(raw_line[:160]))

            why_btn = Gtk.Button(label="Why?", valign=Gtk.Align.CENTER, css_classes=["flat"])
            why_btn.connect("clicked", self._on_why_clicked, raw_line)
            row.add_suffix(why_btn)

            suggest_btn = Gtk.Button(label="Suggest rule", valign=Gtk.Align.CENTER)
            suggest_btn.connect("clicked", self._on_suggest_clicked, raw_line)
            row.add_suffix(suggest_btn)

            self.denials_group.add(row)
            self._denial_rows.append(row)
        return False

    @staticmethod
    def _summarize_denial(raw_line: str) -> str:
        comm = apparmor._extract_field(raw_line, "comm")
        operation = apparmor._extract_field(raw_line, "operation")
        name = apparmor._extract_field(raw_line, "name")
        parts = []
        if comm:
            parts.append(comm)
        if operation:
            parts.append(f"denied {operation}")
        if name:
            parts.append(f"on {name}")
        return " ".join(parts) if parts else "AppArmor denial"

    def _on_why_clicked(self, _btn: Gtk.Button, raw_line: str) -> None:
        self.run_async(lambda: apparmor.explain_denial(raw_line), self._on_why_result)

    def _on_why_result(self, result, error) -> bool:
        dialog = Adw.AlertDialog(heading="Why was this denied?")
        dialog.set_body(esc(error) if error else esc(result))
        dialog.add_response("close", "Close")
        dialog.present(self.get_root())
        return False

    def _on_suggest_clicked(self, _btn: Gtk.Button, raw_line: str) -> None:
        self.run_async(lambda: apparmor.generate_rule_suggestion(raw_line), lambda r, e: self._on_suggestion_ready(r, e, raw_line))

    def _on_suggestion_ready(self, result, error, raw_line: str) -> bool:
        if error:
            self.notify(f"Error: {error}", is_error=True)
            return False

        profile_name = apparmor._extract_field(raw_line, "profile")
        entry = Gtk.Entry(text=result)
        entry.set_hexpand(True)

        dialog = Adw.AlertDialog(
            heading="Suggested rule",
            body=f"For profile: {profile_name or 'unknown'}. Review and edit before appending.",
        )
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        if profile_name:
            dialog.add_response("append", "Append & Reload")
            dialog.set_response_appearance("append", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_dlg, response: str) -> None:
            if response == "append" and profile_name:
                rule_text = entry.get_text().strip()
                if not rule_text or rule_text.startswith("#"):
                    self.notify("No usable rule to append", is_error=True)
                    return
                profile_file = apparmor.resolve_profile_file(profile_name)
                if not profile_file:
                    self.notify(f"Couldn't find a profile file for {profile_name}", is_error=True)
                    return
                self.run_async(lambda: apparmor.append_rule_to_profile(profile_file, rule_text), self.handle_command_result)

        dialog.connect("response", on_response)
        dialog.present(self.get_root())
        return False
