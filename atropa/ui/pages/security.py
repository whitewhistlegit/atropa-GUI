"""atropa.ui.pages.security - Security module (firewall, SSH hardening)."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import security
from atropa.ui.pages import BasePage, esc


class SecurityPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        fw_group = self.add_group("Firewall")
        self.fw_status_row = Adw.ActionRow(title="Checking firewall status…")
        self.fw_toggle = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.fw_toggle.connect("state-set", self._on_firewall_toggle)
        self.fw_status_row.add_suffix(self.fw_toggle)
        fw_group.add(self.fw_status_row)

        self.port_row = Adw.EntryRow(title="Port to allow (e.g. 8080 or 8080/udp)")
        allow_btn = Gtk.Button(label="Allow", valign=Gtk.Align.CENTER)
        allow_btn.connect("clicked", self._on_allow_port)
        deny_btn = Gtk.Button(label="Deny", valign=Gtk.Align.CENTER)
        deny_btn.connect("clicked", self._on_deny_port)
        self.port_row.add_suffix(allow_btn)
        self.port_row.add_suffix(deny_btn)
        fw_group.add(self.port_row)

        self.rules_group = self.add_group("Active Rules")

        ssh_group = self.add_group("SSH Hardening")
        self.ssh_status_row = Adw.ActionRow(title="Checking SSH status…")
        ssh_group.add(self.ssh_status_row)

        self.root_login_row = Adw.SwitchRow(title="Allow root login over SSH")
        self.root_login_row.connect("notify::active", self._on_root_login_toggled)
        ssh_group.add(self.root_login_row)

        self.password_auth_row = Adw.SwitchRow(title="Allow password authentication (vs. keys only)")
        self.password_auth_row.connect("notify::active", self._on_password_auth_toggled)
        ssh_group.add(self.password_auth_row)

        self.ssh_port_row = Adw.SpinRow.new_with_range(1, 65535, 1)
        self.ssh_port_row.set_title("SSH port")
        apply_port_btn = Gtk.Button(label="Apply", valign=Gtk.Align.CENTER)
        apply_port_btn.connect("clicked", self._on_apply_ssh_port)
        self.ssh_port_row.add_suffix(apply_port_btn)
        ssh_group.add(self.ssh_port_row)

        self.max_auth_tries_row = Adw.SpinRow.new_with_range(1, 20, 1)
        self.max_auth_tries_row.set_title("Max auth tries")
        self.max_auth_tries_row.set_subtitle("CIS recommends 4 or fewer, to limit brute-force guessing")
        apply_tries_btn = Gtk.Button(label="Apply", valign=Gtk.Align.CENTER)
        apply_tries_btn.connect("clicked", self._on_apply_max_auth_tries)
        self.max_auth_tries_row.add_suffix(apply_tries_btn)
        ssh_group.add(self.max_auth_tries_row)

        self.log_level_row = Adw.ActionRow(title="Log level", subtitle="CIS recommends INFO or VERBOSE")
        info_btn = Gtk.Button(label="INFO", valign=Gtk.Align.CENTER)
        info_btn.connect("clicked", lambda _b: self._on_set_log_level("INFO"))
        verbose_btn = Gtk.Button(label="VERBOSE", valign=Gtk.Align.CENTER)
        verbose_btn.connect("clicked", lambda _b: self._on_set_log_level("VERBOSE"))
        self.log_level_row.add_suffix(info_btn)
        self.log_level_row.add_suffix(verbose_btn)
        ssh_group.add(self.log_level_row)

        self.x11_forwarding_row = Adw.SwitchRow(title="Allow X11 forwarding")
        self.x11_forwarding_row.connect("notify::active", self._on_x11_forwarding_toggled)
        ssh_group.add(self.x11_forwarding_row)

        self.ignore_rhosts_row = Adw.SwitchRow(
            title="Ignore .rhosts/.shosts files", subtitle="CIS recommends on - these are a legacy, weaker trust mechanism"
        )
        self.ignore_rhosts_row.connect("notify::active", self._on_ignore_rhosts_toggled)
        ssh_group.add(self.ignore_rhosts_row)

        self.hostbased_auth_row = Adw.SwitchRow(title="Allow host-based authentication")
        self.hostbased_auth_row.connect("notify::active", self._on_hostbased_auth_toggled)
        ssh_group.add(self.hostbased_auth_row)

        self.permit_empty_passwords_row = Adw.SwitchRow(title="Allow empty passwords")
        self.permit_empty_passwords_row.connect("notify::active", self._on_permit_empty_passwords_toggled)
        ssh_group.add(self.permit_empty_passwords_row)

        self.permit_user_environment_row = Adw.SwitchRow(title="Allow user environment overrides")
        self.permit_user_environment_row.connect("notify::active", self._on_permit_user_environment_toggled)
        ssh_group.add(self.permit_user_environment_row)

        sudo_group = self.add_group("Sudo")
        self.sudo_row = Adw.ActionRow(title="sudoers syntax check")
        check_btn = Gtk.Button(label="Check", valign=Gtk.Align.CENTER)
        check_btn.connect("clicked", self._on_check_sudoers)
        self.sudo_row.add_suffix(check_btn)
        sudo_group.add(self.sudo_row)

        self._suppress_signals = False
        self.refresh()

    def refresh(self) -> None:
        self.clear_rows(self.rules_group, getattr(self, "_rule_rows", []))
        self._rule_rows = [self.start_loading(self.rules_group, "Loading firewall rules…")]
        self.run_async(security.firewall_status, self._on_firewall_loaded)
        self.run_async(security.ssh_status, self._on_ssh_loaded)

    def _on_firewall_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_rule_rows", [])):
            self.rules_group.remove(row)
        self._rule_rows = []

        if error:
            self.fw_status_row.set_title("Could not read firewall status")
            self.fw_status_row.set_subtitle(esc(error))
            return False

        status = result
        self._suppress_signals = True
        if status.backend == "none":
            self.fw_status_row.set_title("No firewall installed")
            self.fw_status_row.set_subtitle("Install 'ufw' or 'firewalld' to manage a firewall here")
            self.fw_toggle.set_sensitive(False)
        else:
            self.fw_status_row.set_title(f"{status.backend} — {'active' if status.active else 'inactive'}")
            self.fw_toggle.set_sensitive(True)
            self.fw_toggle.set_active(status.active)
        self._suppress_signals = False

        for rule in status.rules[:30]:
            row = Adw.ActionRow(title=esc(rule.strip()))
            self.rules_group.add(row)
            self._rule_rows.append(row)
        return False

    def _on_ssh_loaded(self, result, error) -> bool:
        if error:
            self.ssh_status_row.set_title("Could not read SSH status")
            self.ssh_status_row.set_subtitle(esc(error))
            return False

        status = result
        self._suppress_signals = True
        if not status.installed:
            self.ssh_status_row.set_title("OpenSSH is not installed")
        else:
            self.ssh_status_row.set_title(f"sshd is {'running' if status.running else 'stopped'}")
        self.root_login_row.set_active(status.root_login.lower() in ("yes", "true"))
        self.password_auth_row.set_active(status.password_auth.lower() in ("yes", "true"))
        if status.port.isdigit():
            self.ssh_port_row.set_value(int(status.port))
        if status.max_auth_tries.isdigit():
            self.max_auth_tries_row.set_value(int(status.max_auth_tries))
        self.log_level_row.set_subtitle(
            f"Currently: {status.log_level} · CIS recommends INFO or VERBOSE"
        )
        self.x11_forwarding_row.set_active(status.x11_forwarding.lower() in ("yes", "true"))
        self.ignore_rhosts_row.set_active(status.ignore_rhosts.lower() in ("yes", "true"))
        self.hostbased_auth_row.set_active(status.hostbased_authentication.lower() in ("yes", "true"))
        self.permit_empty_passwords_row.set_active(status.permit_empty_passwords.lower() in ("yes", "true"))
        self.permit_user_environment_row.set_active(status.permit_user_environment.lower() in ("yes", "true"))
        self._suppress_signals = False
        return False

    def _on_firewall_toggle(self, _switch: Gtk.Switch, state: bool) -> bool:
        if self._suppress_signals:
            return False
        if state:
            self.run_async(security.firewall_enable, self.handle_command_result)
        else:
            self.run_async(security.firewall_disable, self.handle_command_result)
        return False

    def _on_allow_port(self, _btn: Gtk.Button) -> None:
        self._apply_port(allow=True)

    def _on_deny_port(self, _btn: Gtk.Button) -> None:
        self._apply_port(allow=False)

    def _apply_port(self, allow: bool) -> None:
        raw = self.port_row.get_text().strip()
        if not raw:
            self.notify("Enter a port first")
            return
        if "/" in raw:
            port, proto = raw.split("/", 1)
        else:
            port, proto = raw, "tcp"
        fn = security.firewall_allow_port if allow else security.firewall_deny_port
        self.run_async(lambda: fn(port, proto), self.handle_command_result)

    def _on_root_login_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_signals:
            return
        self.run_async(lambda: security.set_ssh_root_login(switch.get_active()), self.handle_command_result)

    def _on_password_auth_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_signals:
            return
        self.run_async(lambda: security.set_ssh_password_auth(switch.get_active()), self.handle_command_result)

    def _on_apply_ssh_port(self, _btn: Gtk.Button) -> None:
        port = int(self.ssh_port_row.get_value())
        self.run_async(lambda: security.set_ssh_port(port), self.handle_command_result)

    def _on_apply_max_auth_tries(self, _btn: Gtk.Button) -> None:
        count = int(self.max_auth_tries_row.get_value())
        self.run_async(lambda: security.set_ssh_max_auth_tries(count), self.handle_command_result)

    def _on_set_log_level(self, level: str) -> None:
        self.run_async(lambda: security.set_ssh_log_level(level), self.handle_command_result)

    def _on_x11_forwarding_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_signals:
            return
        self.run_async(lambda: security.set_ssh_x11_forwarding(switch.get_active()), self.handle_command_result)

    def _on_ignore_rhosts_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_signals:
            return
        self.run_async(lambda: security.set_ssh_ignore_rhosts(switch.get_active()), self.handle_command_result)

    def _on_hostbased_auth_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_signals:
            return
        self.run_async(
            lambda: security.set_ssh_hostbased_authentication(switch.get_active()), self.handle_command_result
        )

    def _on_permit_empty_passwords_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_signals:
            return
        self.run_async(
            lambda: security.set_ssh_permit_empty_passwords(switch.get_active()), self.handle_command_result
        )

    def _on_permit_user_environment_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_signals:
            return
        self.run_async(
            lambda: security.set_ssh_permit_user_environment(switch.get_active()), self.handle_command_result
        )

    def _on_check_sudoers(self, _btn: Gtk.Button) -> None:
        self.run_async(security.sudoers_check, lambda result, error: self._on_sudo_check_done(result, error))

    def _on_sudo_check_done(self, result, error) -> bool:
        if error:
            self.sudo_row.set_subtitle(esc(f"Error: {error}"))
        else:
            self.sudo_row.set_subtitle(esc(result.strip() or "OK"))
        return False
