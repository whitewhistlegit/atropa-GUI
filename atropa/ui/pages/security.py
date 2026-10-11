"""atropa.ui.pages.security - Security module (firewall, SSH hardening)."""

from __future__ import annotations

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import security
from atropa.ui.pages import BasePage, esc

# PermitRootLogin values, in the order the combo row lists them.
ROOT_LOGIN_CHOICES = [
    ("no", "Not allowed"),
    ("prohibit-password", "Keys only (OpenSSH default)"),
    ("forced-commands-only", "Keys with a forced command only"),
    ("yes", "Allowed, with a password too"),
]
ROOT_LOGIN_WARNINGS = {
    "no": "Root can't log in over SSH at all, not even with a key. If you reach this machine as root, make "
    "sure another account can log in over SSH and use sudo first.",
    "prohibit-password": "Root can log in over SSH only with a key. If you log in as root with a password, "
    "add your key to /root/.ssh/authorized_keys first.",
    "forced-commands-only": "Root can log in only with a key that has a command= option, and only to run "
    "that command.",
    "yes": "Root can log in over SSH with a password - the account brute-force attacks try first.",
}


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

        # A combo, not a switch: "off" used to mean both "no" and the OpenSSH
        # default "prohibit-password", so getting from one to the other meant
        # passing through "yes" (root password logins) on the way.
        self.root_login_row = Adw.ComboRow(title="Root login over SSH")
        self.root_login_row.set_model(Gtk.StringList.new([label for _value, label in ROOT_LOGIN_CHOICES]))
        self.root_login_row.connect("notify::selected", self._on_root_login_selected)
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
        self._ssh_status: security.SshStatus | None = None
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
        self._ssh_status = status
        self._suppress_signals = True
        if not status.installed:
            self.ssh_status_row.set_title("OpenSSH is not installed")
        else:
            self.ssh_status_row.set_title(f"sshd is {'running' if status.running else 'stopped'}")
        if status.unreadable_includes:
            self.ssh_status_row.set_subtitle(
                esc(f"Couldn't read {', '.join(status.unreadable_includes)} - sshd may use different values than shown")
            )
        else:
            self.ssh_status_row.set_subtitle("")

        # Switches show what sshd actually uses: a keyword sshd_config never
        # sets means OpenSSH's default (e.g. password logins are allowed).
        def is_yes(name: str) -> bool:
            return status.effective(name).lower() in ("yes", "true")

        root_login = status.effective("root_login").lower().replace("without-password", "prohibit-password")
        values = [value for value, _label in ROOT_LOGIN_CHOICES]
        if root_login in values:
            self.root_login_row.set_selected(values.index(root_login))
        self.password_auth_row.set_active(is_yes("password_auth"))
        if status.port.isdigit():
            self.ssh_port_row.set_value(int(status.port))
        if status.effective("max_auth_tries").isdigit():
            self.max_auth_tries_row.set_value(int(status.effective("max_auth_tries")))
        default_note = " (OpenSSH default)" if status.log_level == "unknown" else ""
        self.log_level_row.set_subtitle(
            f"Currently: {status.effective('log_level')}{default_note} · CIS recommends INFO or VERBOSE"
        )
        self.x11_forwarding_row.set_active(is_yes("x11_forwarding"))
        self.ignore_rhosts_row.set_active(is_yes("ignore_rhosts"))
        self.hostbased_auth_row.set_active(is_yes("hostbased_authentication"))
        self.permit_empty_passwords_row.set_active(is_yes("permit_empty_passwords"))
        self.permit_user_environment_row.set_active(is_yes("permit_user_environment"))
        self._suppress_signals = False
        return False

    def _on_firewall_toggle(self, switch: Gtk.Switch, state: bool) -> bool:
        if self._suppress_signals:
            return False
        if state:
            body = "Incoming connections that no rule allows get blocked."
            ssh = self._ssh_status
            if ssh is not None and ssh.installed:
                ports = ssh.ports or ["22"]
                body += (
                    f" sshd listens on port {', '.join(ports)} - if you reach this machine over SSH, allow "
                    f"{'them' if len(ports) > 1 else 'it'} first (Quick Setup does this for you)."
                )
            confirm = ("Turn on the firewall?", body, "Turn On")
        else:
            confirm = ("Turn off the firewall?", "Every incoming connection is allowed while it's off.", "Turn Off")
        work_fn = security.firewall_enable if state else security.firewall_disable
        return self.apply_switch(switch, state, work_fn, confirm=confirm)

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
        self.run_action(lambda: fn(port, proto), self.handle_command_result)

    # -- SSH ---------------------------------------------------------------

    def _apply_ssh(self, work_fn, confirm: tuple[str, str, str] | None = None) -> None:
        """
        Runs an sshd_config change, then re-reads sshd_config whatever the
        outcome - the switches move the moment they're clicked, so after a
        failure, a refusal or a cancelled confirmation they'd otherwise keep
        showing a setting that was never applied.
        """

        def resync() -> None:
            self.run_async(security.ssh_status, self._on_ssh_loaded)

        def done(result, error) -> bool:
            self.handle_command_result(result, error, refresh=False)
            resync()
            return False

        def start() -> None:
            if not self.run_action(work_fn, done):
                resync()

        if confirm is None:
            start()
        else:
            heading, body, label = confirm
            self.confirm(heading, body, label, start, on_cancel=resync)

    def _on_root_login_selected(self, row: Adw.ComboRow, _pspec) -> None:
        if self._suppress_signals:
            return
        value, label = ROOT_LOGIN_CHOICES[row.get_selected()]
        self._apply_ssh(
            lambda: security.set_ssh_permit_root_login(value),
            confirm=(f'Set root login over SSH to "{label}"?', ROOT_LOGIN_WARNINGS[value], "Change"),
        )

    def _on_password_auth_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_signals:
            return
        allow = switch.get_active()
        confirm = None
        if not allow:
            body = (
                "Logging in over SSH will need a key in the account's ~/.ssh/authorized_keys. Without one, "
                "you lose remote access to this machine."
            )
            if not _has_authorized_keys():
                body += " You don't have one yourself (~/.ssh/authorized_keys is missing or empty)."
            confirm = ("Turn off SSH password logins?", body, "Turn Off")
        self._apply_ssh(lambda: security.set_ssh_password_auth(allow), confirm=confirm)

    def _on_apply_ssh_port(self, _btn: Gtk.Button) -> None:
        port = int(self.ssh_port_row.get_value())
        current = ", ".join(self._ssh_status.ports or ["22"]) if self._ssh_status else "its current port"
        self._apply_ssh(
            lambda: security.set_ssh_port(port),
            confirm=(
                f"Move sshd to port {port}?",
                f"sshd stops listening on {current} once it reloads. Allow {port}/tcp in the firewall "
                f"first, or you can lose SSH access. With SELinux enforcing, the port also needs the "
                f"ssh_port_t label (semanage port -a -t ssh_port_t -p tcp {port}).",
                "Move",
            ),
        )

    def _on_apply_max_auth_tries(self, _btn: Gtk.Button) -> None:
        count = int(self.max_auth_tries_row.get_value())
        self._apply_ssh(lambda: security.set_ssh_max_auth_tries(count))

    def _on_set_log_level(self, level: str) -> None:
        self._apply_ssh(lambda: security.set_ssh_log_level(level))

    def _on_x11_forwarding_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_signals:
            return
        allow = switch.get_active()
        self._apply_ssh(lambda: security.set_ssh_x11_forwarding(allow))

    def _on_ignore_rhosts_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_signals:
            return
        enabled = switch.get_active()
        self._apply_ssh(lambda: security.set_ssh_ignore_rhosts(enabled))

    def _on_hostbased_auth_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_signals:
            return
        allow = switch.get_active()
        self._apply_ssh(lambda: security.set_ssh_hostbased_authentication(allow))

    def _on_permit_empty_passwords_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_signals:
            return
        allow = switch.get_active()
        confirm = None
        if allow:
            confirm = (
                "Allow empty passwords over SSH?",
                "Any account without a password could then log in over SSH without one.",
                "Allow",
            )
        self._apply_ssh(lambda: security.set_ssh_permit_empty_passwords(allow), confirm=confirm)

    def _on_permit_user_environment_toggled(self, switch: Adw.SwitchRow, _pspec) -> None:
        if self._suppress_signals:
            return
        allow = switch.get_active()
        self._apply_ssh(lambda: security.set_ssh_permit_user_environment(allow))

    def _on_check_sudoers(self, _btn: Gtk.Button) -> None:
        self.run_async(security.sudoers_check, lambda result, error: self._on_sudo_check_done(result, error))

    def _on_sudo_check_done(self, result, error) -> bool:
        if error:
            self.sudo_row.set_subtitle(esc(f"Error: {error}"))
            return False
        output = (result.stdout or result.stderr).strip()
        if result.ok:
            self.sudo_row.set_subtitle(esc(output or "OK"))
        else:
            self.sudo_row.set_subtitle(esc(f"Problem: {output or f'visudo exited with {result.returncode}'}"))
        return False


def _has_authorized_keys() -> bool:
    try:
        return (Path.home() / ".ssh" / "authorized_keys").stat().st_size > 0
    except OSError:
        return False
