"""atropa.ui.pages.hardening - Hardening module: kernel/service hardening + audit rollup."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import audit_rules, hardening
from atropa.ui.pages import BasePage, esc

STATUS_ICON = {
    "pass": "emblem-ok-symbolic",
    "warn": "dialog-warning-symbolic",
    "fail": "dialog-error-symbolic",
    "info": "dialog-information-symbolic",
}


class HardeningPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        # --- Audit rollup -----------------------------------------------------
        self.audit_group = self.add_group(
            "Security Audit", "A rollup of the checks below - re-run any time after making changes"
        )
        self.audit_summary_row = Adw.ActionRow(title="Running audit…")
        rerun_btn = Gtk.Button(label="Re-run audit", valign=Gtk.Align.CENTER)
        rerun_btn.connect("clicked", lambda _b: self._run_audit())
        self.audit_summary_row.add_suffix(rerun_btn)
        self.audit_group.add(self.audit_summary_row)

        # --- Kernel hardening (sysctl) -----------------------------------------
        sysctl_group = self.add_group(
            "Kernel Hardening (sysctl)",
            "Curated set of kernel/network settings. Applying writes "
            f"{hardening.SYSCTL_HARDENING_FILE} and reloads sysctl live.",
        )
        self._sysctl_checks: dict[str, Gtk.CheckButton] = {}
        for key, recommended, desc in hardening.SYSCTL_RECOMMENDATIONS:
            row = Adw.ActionRow(title=key, subtitle=desc)
            check = Gtk.CheckButton(valign=Gtk.Align.CENTER)
            row.add_prefix(check)
            row.set_activatable_widget(check)
            self._sysctl_checks[key] = check
            sysctl_group.add(row)

        apply_sysctl_btn = Gtk.Button(label="Apply selected settings", css_classes=["suggested-action"])
        apply_sysctl_btn.set_margin_top(8)
        apply_sysctl_btn.connect("clicked", self._on_apply_sysctl)
        select_all_btn = Gtk.Button(label="Select all recommended")
        select_all_btn.set_margin_top(8)
        select_all_btn.connect("clicked", self._on_select_all_sysctl)
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_box.append(select_all_btn)
        btn_box.append(apply_sysctl_btn)
        sysctl_group.add(btn_box)

        # --- fail2ban -----------------------------------------------------
        f2b_group = self.add_group("fail2ban", "Bans IPs after repeated failed login attempts")
        self.f2b_row = Adw.ActionRow(title="Checking fail2ban…")
        self.f2b_toggle = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.f2b_toggle.connect("state-set", self._on_f2b_toggle)
        self.f2b_row.add_suffix(self.f2b_toggle)
        f2b_group.add(self.f2b_row)
        protect_ssh_btn = Gtk.Button(label="Protect SSH (enable sshd jail)", valign=Gtk.Align.CENTER)
        protect_ssh_btn.connect("clicked", lambda _b: self.run_async(hardening.fail2ban_protect_ssh, self.handle_command_result))
        f2b_group.add(protect_ssh_btn)

        # --- AppArmor -----------------------------------------------------
        aa_group = self.add_group("AppArmor", "Mandatory access control confining what programs can do")
        self.aa_row = Adw.ActionRow(title="Checking AppArmor…")
        aa_enable_btn = Gtk.Button(label="Enable service", valign=Gtk.Align.CENTER)
        aa_enable_btn.connect("clicked", lambda _b: self.run_async(hardening.apparmor_enable_service, self.handle_command_result))
        self.aa_row.add_suffix(aa_enable_btn)
        aa_group.add(self.aa_row)
        aa_note = Adw.ActionRow(
            title="Kernel parameter required",
            subtitle="Add apparmor=1 security=apparmor to your bootloader kernel parameters, then reboot. "
            "Atropa doesn't edit boot parameters automatically to avoid an unbootable system.",
        )
        aa_group.add(aa_note)

        # --- USBGuard -----------------------------------------------------
        ug_group = self.add_group("USBGuard", "Blocks unauthorized USB devices (BadUSB protection)")
        self.ug_row = Adw.ActionRow(title="Checking USBGuard…")
        ug_generate_btn = Gtk.Button(label="Generate policy & enable", valign=Gtk.Align.CENTER)
        ug_generate_btn.connect("clicked", self._on_usbguard_enable)
        self.ug_row.add_suffix(ug_generate_btn)
        ug_group.add(self.ug_row)
        ug_note = Adw.ActionRow(
            title="Heads up",
            subtitle="This allow-lists devices plugged in right now. Anything plugged in later needs approval "
            "(e.g. 'usbguard allow-device') or it will be blocked - including USB keyboards/drives.",
        )
        ug_group.add(ug_note)

        # --- auditd -----------------------------------------------------
        ad_group = self.add_group("auditd", "Kernel-level audit logging (who did what, when)")
        self.ad_row = Adw.ActionRow(title="Checking auditd…")
        self.ad_toggle = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.ad_toggle.connect("state-set", self._on_auditd_toggle)
        self.ad_row.add_suffix(self.ad_toggle)
        ad_group.add(self.ad_row)

        # --- Vulnerability scan -----------------------------------------------------
        cve_group = self.add_group("Known Vulnerabilities (arch-audit)", "Checks installed packages against the Arch Security Team's CVE feed")
        self.cve_row = Adw.ActionRow(title="Not yet scanned")
        scan_btn = Gtk.Button(label="Scan now", valign=Gtk.Align.CENTER)
        scan_btn.connect("clicked", self._on_scan_cve_clicked)
        self.cve_row.add_suffix(scan_btn)
        cve_group.add(self.cve_row)
        self.cve_results_group = self.add_group("Advisories")
        self.cve_results_group.set_visible(False)

        # --- Login lockout policy -----------------------------------------------------
        lock_group = self.add_group("Login Lockout Policy (pam_faillock)", "Lock an account out after repeated failed logins")
        self.faillock_status_row = Adw.ActionRow(title="Checking…")
        lock_group.add(self.faillock_status_row)
        self.deny_row = Adw.SpinRow.new_with_range(1, 20, 1)
        self.deny_row.set_title("Failed attempts before lockout")
        self.deny_row.set_value(5)
        lock_group.add(self.deny_row)
        self.unlock_row = Adw.SpinRow.new_with_range(30, 3600, 30)
        self.unlock_row.set_title("Lockout duration (seconds)")
        self.unlock_row.set_value(600)
        lock_group.add(self.unlock_row)
        apply_lock_btn = Gtk.Button(label="Apply lockout policy", css_classes=["suggested-action"])
        apply_lock_btn.set_margin_top(8)
        apply_lock_btn.connect("clicked", self._on_apply_faillock)
        lock_group.add(apply_lock_btn)

        # --- Password complexity policy -----------------------------------------------------
        pwq_group = self.add_group(
            "Password Complexity Policy (pam_pwquality)",
            "CIS recommends a 14+ character minimum, plus at least one digit/uppercase/lowercase/special character",
        )
        self.pwquality_status_row = Adw.ActionRow(title="Checking…")
        pwq_group.add(self.pwquality_status_row)
        self.minlen_row = Adw.SpinRow.new_with_range(1, 128, 1)
        self.minlen_row.set_title("Minimum password length")
        self.minlen_row.set_value(14)
        pwq_group.add(self.minlen_row)
        apply_pwq_btn = Gtk.Button(
            label="Apply CIS-recommended complexity policy", css_classes=["suggested-action"]
        )
        apply_pwq_btn.set_margin_top(8)
        apply_pwq_btn.connect("clicked", self._on_apply_password_complexity)
        pwq_group.add(apply_pwq_btn)

        # --- Audit rules (CIS) -----------------------------------------------------
        self.audit_rules_group = self.add_group(
            "Audit Rules (CIS)",
            "Actual auditd rule content - who changed identity files, sudoers, the system clock, or "
            "network identity - not just whether auditd is running. A watch rule for a path that "
            "doesn't exist on this system (some come from RHEL/Debian-era conventions Arch doesn't "
            "have) is skipped automatically rather than failing the whole set.",
        )
        apply_all_audit_btn = Gtk.Button(label="Apply All", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        apply_all_audit_btn.connect("clicked", self._on_apply_all_audit_rules)
        apply_all_row = Adw.ActionRow(title="Apply every rule set in one pass")
        apply_all_row.add_suffix(apply_all_audit_btn)
        self.audit_rules_group.add(apply_all_row)
        self._audit_rule_rows: dict[str, Adw.ActionRow] = {}
        self._audit_rule_status_icons: dict[str, Gtk.Image] = {}
        for rule_set in audit_rules.RULE_SETS:
            row = Adw.ActionRow(title=esc(rule_set.title), subtitle=esc(rule_set.description))
            status_icon = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
            status_icon.set_visible(False)
            row.add_prefix(status_icon)
            apply_btn = Gtk.Button(label="Apply", valign=Gtk.Align.CENTER)
            apply_btn.connect("clicked", self._on_apply_one_audit_rule_set, rule_set.key)
            row.add_suffix(apply_btn)
            self.audit_rules_group.add(row)
            self._audit_rule_rows[rule_set.key] = row
            self._audit_rule_status_icons[rule_set.key] = status_icon

        self._suppress_signals = False
        self.refresh()

    # -- loading -----------------------------------------------------------

    def refresh(self) -> None:
        self.run_async(hardening.get_sysctl_status, self._on_sysctl_loaded)
        self.run_async(hardening.fail2ban_status, self._on_f2b_loaded)
        self.run_async(hardening.apparmor_status, self._on_aa_loaded)
        self.run_async(hardening.usbguard_status, self._on_ug_loaded)
        self.run_async(hardening.auditd_status, self._on_ad_loaded)
        self.run_async(hardening.faillock_status, self._on_faillock_loaded)
        self.run_async(hardening.pwquality_status, self._on_pwquality_loaded)
        self._refresh_audit_rule_statuses()
        self._run_audit()

    def _refresh_audit_rule_statuses(self) -> None:
        for rule_set in audit_rules.RULE_SETS:
            self.run_async(
                lambda key=rule_set.key: audit_rules.is_audit_rule_set_active(key),
                lambda result, error, key=rule_set.key: self._on_audit_rule_status_loaded(result, error, key),
            )

    def _on_audit_rule_status_loaded(self, result, error, key: str) -> bool:
        icon = self._audit_rule_status_icons.get(key)
        if icon is None:
            return False
        icon.set_visible(bool(result) and not error)
        return False

    def _run_audit(self) -> None:
        self.audit_summary_row.set_title("Running audit…")
        self.clear_rows(self.audit_group, getattr(self, "_audit_rows", []))
        self._audit_rows = [self.start_loading(self.audit_group, "Running checks…")]
        self.run_async(hardening.run_audit, self._on_audit_loaded)

    def _on_audit_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_audit_rows", [])):
            self.audit_group.remove(row)
        self._audit_rows = []

        if error:
            self.audit_summary_row.set_title("Audit failed")
            self.audit_summary_row.set_subtitle(esc(error))
            return False

        passed = sum(1 for c in result if c.status == "pass")
        total = sum(1 for c in result if c.status in ("pass", "warn", "fail"))
        self.audit_summary_row.set_title(f"{passed}/{total} checks passed")

        for check in result:
            row = Adw.ActionRow(title=esc(check.name), subtitle=esc(check.detail))
            row.add_prefix(Gtk.Image.new_from_icon_name(STATUS_ICON.get(check.status, "dialog-information-symbolic")))
            self.audit_group.add(row)
            self._audit_rows.append(row)
        return False

    def _on_sysctl_loaded(self, result, error) -> bool:
        if error:
            self.notify(f"Couldn't read sysctl status: {error}", is_error=True)
            return False
        for setting in result:
            check = self._sysctl_checks.get(setting.key)
            if check:
                check.set_active(setting.is_hardened)
        return False

    def _on_f2b_loaded(self, result, error) -> bool:
        self._suppress_signals = True
        if error or not result.installed:
            self.f2b_row.set_title("fail2ban not installed")
            self.f2b_row.set_subtitle("pacman -S fail2ban")
            self.f2b_toggle.set_sensitive(False)
        else:
            jails = ", ".join(result.extra.get("jails", [])) or "no jails active"
            self.f2b_row.set_title(f"fail2ban is {'active' if result.active else 'inactive'}")
            self.f2b_row.set_subtitle(jails)
            self.f2b_toggle.set_sensitive(True)
            self.f2b_toggle.set_active(result.active)
        self._suppress_signals = False
        return False

    def _on_aa_loaded(self, result, error) -> bool:
        if error or not result.installed:
            self.aa_row.set_title("AppArmor not installed")
            self.aa_row.set_subtitle("pacman -S apparmor")
        else:
            kernel = "enforcing" if result.extra.get("kernel_enabled") else "kernel param not set"
            self.aa_row.set_title(f"Service {'active' if result.active else 'inactive'}")
            self.aa_row.set_subtitle(kernel)
        return False

    def _on_ug_loaded(self, result, error) -> bool:
        if error or not result.installed:
            self.ug_row.set_title("USBGuard not installed")
            self.ug_row.set_subtitle("pacman -S usbguard")
        else:
            policy = "has device policy" if result.extra.get("has_policy") else "no policy generated yet"
            self.ug_row.set_title(f"USBGuard is {'active' if result.active else 'inactive'}")
            self.ug_row.set_subtitle(policy)
        return False

    def _on_ad_loaded(self, result, error) -> bool:
        self._suppress_signals = True
        if error or not result.installed:
            self.ad_row.set_title("auditd not installed")
            self.ad_row.set_subtitle("pacman -S audit")
            self.ad_toggle.set_sensitive(False)
        else:
            self.ad_row.set_title(f"auditd is {'active' if result.active else 'inactive'}")
            self.ad_toggle.set_sensitive(True)
            self.ad_toggle.set_active(result.active)
        self._suppress_signals = False
        return False

    def _on_faillock_loaded(self, result, error) -> bool:
        if error:
            self.faillock_status_row.set_title("Couldn't read faillock status")
            self.faillock_status_row.set_subtitle(str(error))
            return False
        if not result["wired"]:
            self.faillock_status_row.set_title("pam_faillock isn't wired into the login stack")
            self.faillock_status_row.set_subtitle(
                "Add 'auth required pam_faillock.so' to /etc/pam.d/system-login manually - "
                "Atropa won't auto-edit PAM to avoid a lockout risk"
            )
        else:
            self.faillock_status_row.set_title("pam_faillock is active")
            self.faillock_status_row.set_subtitle(f"deny={result['deny']}, unlock_time={result['unlock_time']}")
        return False

    def _on_pwquality_loaded(self, result, error) -> bool:
        if error:
            self.pwquality_status_row.set_title("Couldn't read password policy")
            self.pwquality_status_row.set_subtitle(str(error))
            return False
        if not result["wired"]:
            self.pwquality_status_row.set_title("pam_pwquality isn't wired into the login stack")
            self.pwquality_status_row.set_subtitle(
                "Add 'password requisite pam_pwquality.so' to /etc/pam.d/system-login manually - "
                "Atropa won't auto-edit PAM to avoid a lockout risk"
            )
        else:
            self.pwquality_status_row.set_title("pam_pwquality is active")
            self.pwquality_status_row.set_subtitle(
                f"minlen={result['minlen']}, dcredit={result['dcredit']}, ucredit={result['ucredit']}, "
                f"lcredit={result['lcredit']}, ocredit={result['ocredit']}, retry={result['retry']}"
            )
        return False

    # -- actions -----------------------------------------------------------

    def _on_select_all_sysctl(self, _btn: Gtk.Button) -> None:
        for check in self._sysctl_checks.values():
            check.set_active(True)

    def _on_apply_sysctl(self, _btn: Gtk.Button) -> None:
        selected = [key for key, check in self._sysctl_checks.items() if check.get_active()]
        if not selected:
            self.notify("Select at least one setting first")
            return
        self.confirm(
            "Apply kernel hardening settings?",
            f"This writes {len(selected)} setting(s) to {hardening.SYSCTL_HARDENING_FILE} and reloads sysctl.",
            "Apply",
            lambda: self.run_async(lambda: hardening.apply_sysctl_hardening(selected), self.handle_command_result),
        )

    def _on_f2b_toggle(self, _switch: Gtk.Switch, state: bool) -> bool:
        if self._suppress_signals:
            return False
        fn = hardening.fail2ban_enable if state else hardening.fail2ban_disable
        self.run_async(fn, self.handle_command_result)
        return False

    def _on_usbguard_enable(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Generate USB policy and enable enforcement?",
            "Devices connected right now will be allow-listed. Anything plugged in "
            "afterward (including a USB keyboard) will be blocked until approved. "
            "Make sure you have another way to control this machine before continuing.",
            "Enable USBGuard",
            lambda: self.run_async(hardening.usbguard_generate_and_enable, self.handle_command_result),
        )

    def _on_auditd_toggle(self, _switch: Gtk.Switch, state: bool) -> bool:
        if self._suppress_signals:
            return False
        fn = hardening.auditd_enable if state else hardening.auditd_disable
        self.run_async(fn, self.handle_command_result)
        return False

    def _on_scan_cve_clicked(self, _btn: Gtk.Button) -> None:
        self.cve_row.set_title("Scanning…")
        self.cve_results_group.set_visible(True)
        self.clear_rows(self.cve_results_group, getattr(self, "_cve_rows", []))
        self._cve_rows = [self.start_loading(self.cve_results_group, "Scanning installed packages…")]
        self.run_async(hardening.vulnerability_scan, self._on_cve_scan_done)

    def _on_cve_scan_done(self, result, error) -> bool:
        for row in list(getattr(self, "_cve_rows", [])):
            self.cve_results_group.remove(row)
        self._cve_rows = []

        if error:
            self.cve_row.set_title("Scan failed")
            self.cve_row.set_subtitle(str(error))
            return False

        self.cve_results_group.set_visible(bool(result))
        if not result:
            self.cve_row.set_title("No known vulnerabilities found")
            self.cve_row.set_subtitle("")
        else:
            self.cve_row.set_title(f"{len(result)} advisory line(s) found")
            for line in result[:100]:
                row = Adw.ActionRow(title=line)
                self.cve_results_group.add(row)
                self._cve_rows.append(row)
        return False

    def _on_apply_faillock(self, _btn: Gtk.Button) -> None:
        deny = int(self.deny_row.get_value())
        unlock_time = int(self.unlock_row.get_value())
        self.run_async(lambda: hardening.set_faillock_policy(deny, unlock_time), self.handle_command_result)

    def _on_apply_password_complexity(self, _btn: Gtk.Button) -> None:
        minlen = int(self.minlen_row.get_value())
        self.confirm(
            "Apply CIS-recommended password complexity?",
            f"Sets minlen={minlen} plus dcredit/ucredit/lcredit/ocredit=-1 and retry=3 in pwquality.conf "
            "(at least one digit/uppercase/lowercase/special character required, 3 tries before rejection). "
            "Only takes effect if pam_pwquality is already wired into the login stack.",
            "Apply",
            lambda: self.run_async(
                lambda: hardening.set_password_complexity_policy(minlen=minlen), self.handle_command_result
            ),
        )

    def _on_apply_one_audit_rule_set(self, _btn: Gtk.Button, key: str) -> None:
        self.run_async(lambda: audit_rules.apply_audit_rule_set(key), self.handle_command_result)

    def _on_apply_all_audit_rules(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Apply all CIS audit rule sets?",
            "Writes each applicable rule set to its own file under /etc/audit/rules.d/, then reloads "
            "auditd's rules once at the end. A rule set with nothing applicable on this system "
            "(e.g. a watch path Arch doesn't have) is skipped rather than failing.",
            "Apply All",
            lambda: self.run_async(audit_rules.apply_all_rule_sets, self._on_apply_all_audit_done),
        )

    def _on_apply_all_audit_done(self, result, error) -> bool:
        if error:
            self.notify(f"Error: {error}", is_error=True)
        elif result is not None:
            failed = [key for key, res in result.items() if not res.ok]
            if failed:
                self.notify(f"Finished with issues: {', '.join(failed)}", is_error=True)
            else:
                self.notify("Audit rules applied")
        self.refresh()
        return False
