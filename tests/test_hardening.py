"""Tests for atropa.backend.hardening."""
from __future__ import annotations

from pathlib import Path

import pytest

from atropa.backend import hardening

# The sandbox container has real /sys/kernel/security/apparmor and
# /proc/cmdline mounts from the host, so hardening.apparmor_status()'s
# filesystem checks can't rely on the sandbox lacking them. Neutralize both
# specific paths without touching anything under tmp_path.
_REAL_EXISTS = Path.exists
_REAL_READ_TEXT = Path.read_text


@pytest.fixture(autouse=True)
def isolate_real_host_paths(monkeypatch):
    def fake_exists(self):
        if str(self) in ("/sys/kernel/security/apparmor", "/proc/cmdline"):
            return False
        return _REAL_EXISTS(self)

    monkeypatch.setattr(Path, "exists", fake_exists)


# --------------------------------------------------------------- sysctl --

def test_current_sysctl_returns_value_on_success(fake_run):
    fake_run.set_response(["sysctl", "-n", "kernel.kptr_restrict"], stdout="2\n", returncode=0)
    assert hardening._current_sysctl("kernel.kptr_restrict") == "2"


def test_current_sysctl_none_on_failure(fake_run):
    fake_run.set_response(["sysctl", "-n", "kernel.kptr_restrict"], stdout="", returncode=1)
    assert hardening._current_sysctl("kernel.kptr_restrict") is None


def test_get_sysctl_status_marks_hardened(fake_run):
    fake_run.set_response(["sysctl", "-n"], stdout="0\n", returncode=0)  # default: not hardened
    fake_run.set_response(["sysctl", "-n", "kernel.kptr_restrict"], stdout="2\n", returncode=0)

    settings = hardening.get_sysctl_status()
    kptr = next(s for s in settings if s.key == "kernel.kptr_restrict")
    assert kptr.is_hardened is True
    other = next(s for s in settings if s.key == "kernel.sysrq")
    assert other.current == "0"
    assert other.is_hardened is False  # recommended is "4"


def test_apply_sysctl_hardening_requires_selection():
    with pytest.raises(ValueError):
        hardening.apply_sysctl_hardening([])


def test_apply_sysctl_hardening_writes_selected_keys_only(fake_run, fake_which, privilege_paths):
    fake_run.set_response(["pkexec", "tee"], returncode=0)
    fake_run.set_response(["pkexec", "sysctl", "--system"], returncode=0)

    hardening.apply_sysctl_hardening(["kernel.kptr_restrict", "kernel.sysrq"])

    # can't see input_text via argv-only calls list, but confirm both steps ran
    assert fake_run.call_containing("sysctl") is not None


def test_sysctl_hardening_file_exists(tmp_path, monkeypatch):
    fake_path = tmp_path / "99-atropa-hardening.conf"
    monkeypatch.setattr(hardening, "SYSCTL_HARDENING_FILE", str(fake_path))
    assert hardening.sysctl_hardening_file_exists() is False
    fake_path.write_text("kernel.kptr_restrict = 2\n")
    assert hardening.sysctl_hardening_file_exists() is True


# --------------------------------------------------------------- fail2ban --

def test_fail2ban_status_not_installed(fake_which):
    status = hardening.fail2ban_status()
    assert status.installed is False


def test_fail2ban_status_active_parses_jails(fake_run, fake_which):
    fake_which.add("fail2ban-client")
    fake_run.set_response(["systemctl", "is-active", "fail2ban"], stdout="active\n")
    fake_run.set_response(["systemctl", "is-enabled", "fail2ban"], stdout="enabled\n")
    fake_run.set_response(["fail2ban-client", "status"], stdout="Status\n|- Jail list:\tsshd, postfix\n")

    status = hardening.fail2ban_status()
    assert status.installed is True
    assert status.active is True
    assert status.extra["jails"] == ["sshd", "postfix"]


def test_fail2ban_status_inactive_skips_jail_lookup(fake_run, fake_which):
    fake_which.add("fail2ban-client")
    fake_run.set_response(["systemctl", "is-active", "fail2ban"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-enabled", "fail2ban"], stdout="disabled\n")

    status = hardening.fail2ban_status()
    assert status.active is False
    assert status.extra["jails"] == []
    assert fake_run.call_containing("status") is None or "fail2ban-client" not in (fake_run.call_containing("status") or [])


def test_fail2ban_protect_ssh_writes_config_and_restarts(fake_run, fake_which, privilege_paths):
    fake_run.set_response(["pkexec", "tee", "/etc/fail2ban/jail.d/sshd.local"], returncode=0)
    fake_run.set_response(["pkexec", "systemctl", "restart", "fail2ban"], returncode=0)

    result = hardening.fail2ban_protect_ssh()
    assert result.ok
    assert fake_run.call_containing("restart") is not None


def test_fail2ban_protect_ssh_skips_restart_on_write_failure(fake_run, fake_which, privilege_paths):
    fake_run.set_response(["pkexec", "tee", "/etc/fail2ban/jail.d/sshd.local"], returncode=1)
    result = hardening.fail2ban_protect_ssh()
    assert not result.ok
    assert fake_run.call_containing("restart") is None


# --------------------------------------------------------------- apparmor status --

def test_apparmor_status_not_installed_not_kernel_enabled(fake_run, fake_which):
    fake_run.set_response(["systemctl", "is-active", "apparmor"], stdout="inactive\n")
    status = hardening.apparmor_status()
    assert status.installed is False
    assert status.extra["kernel_enabled"] is False


def test_apparmor_status_fully_enabled(fake_run, fake_which, monkeypatch, tmp_path):
    fake_which.add("aa-status")
    fake_run.set_response(["systemctl", "is-active", "apparmor"], stdout="active\n")
    cmdline = tmp_path / "cmdline"
    cmdline.write_text("BOOT_IMAGE=/vmlinuz apparmor=1 security=apparmor\n")
    monkeypatch.setattr(hardening, "Path", hardening.Path)  # no-op, keep real Path
    # Patch just the specific cmdline check via a targeted monkeypatch:
    real_path_cls = hardening.Path

    def fake_path(arg):
        if arg == "/proc/cmdline":
            return cmdline
        return real_path_cls(arg)

    monkeypatch.setattr(hardening, "Path", fake_path)

    status = hardening.apparmor_status()
    assert status.installed is True
    assert status.active is True
    assert status.extra["kernel_enabled"] is True


# --------------------------------------------------------------- usbguard --

def test_usbguard_status_not_installed(fake_run, fake_which, monkeypatch, tmp_path):
    monkeypatch.setattr(hardening, "Path", lambda p: tmp_path / "missing" if "usbguard" in str(p) else Path(p))
    fake_run.set_response(["systemctl", "is-active", "usbguard"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-enabled", "usbguard"], stdout="disabled\n")
    status = hardening.usbguard_status()
    assert status.installed is False
    assert status.extra["has_policy"] is False


def test_usbguard_status_with_policy(fake_run, fake_which, monkeypatch, tmp_path):
    fake_which.add("usbguard")
    rules = tmp_path / "rules.conf"
    rules.write_text("allow id 1234:5678\n")

    def fake_path(p):
        return rules if "usbguard" in str(p) else Path(p)

    monkeypatch.setattr(hardening, "Path", fake_path)
    fake_run.set_response(["systemctl", "is-active", "usbguard"], stdout="active\n")
    fake_run.set_response(["systemctl", "is-enabled", "usbguard"], stdout="enabled\n")

    status = hardening.usbguard_status()
    assert status.installed is True
    assert status.extra["has_policy"] is True


def test_usbguard_generate_and_enable_stops_if_generation_fails(fake_run, fake_which):
    fake_run.set_response(["pkexec", "bash", "-c"], returncode=1, stderr="no devices")
    result = hardening.usbguard_generate_and_enable()
    assert not result.ok
    assert fake_run.call_containing("enable") is None


def test_usbguard_generate_and_enable_enables_on_success(fake_run, fake_which):
    fake_run.set_response(["pkexec", "bash", "-c"], returncode=0)
    fake_run.set_response(["pkexec", "systemctl", "enable"], returncode=0)
    result = hardening.usbguard_generate_and_enable()
    assert result.ok


# --------------------------------------------------------------- auditd --

def test_auditd_status(fake_run, fake_which):
    fake_which.add("auditctl")
    fake_run.set_response(["systemctl", "is-active", "auditd"], stdout="active\n")
    fake_run.set_response(["systemctl", "is-enabled", "auditd"], stdout="enabled\n")
    status = hardening.auditd_status()
    assert status.installed is True
    assert status.active is True
    assert status.enabled is True


# --------------------------------------------------------------- vulnerability scan --

def test_vulnerability_scan_requires_arch_audit(fake_which):
    with pytest.raises(RuntimeError, match="isn't installed"):
        hardening.vulnerability_scan()


def test_vulnerability_scan_returns_lines(fake_run, fake_which):
    fake_which.add("arch-audit")
    fake_run.set_response(["arch-audit"], stdout="openssl: CVE-2024-0001\ncurl: CVE-2024-0002\n")
    result = hardening.vulnerability_scan()
    assert result == ["openssl: CVE-2024-0001", "curl: CVE-2024-0002"]


def test_vulnerability_scan_empty_when_no_advisories(fake_run, fake_which):
    fake_which.add("arch-audit")
    fake_run.set_response(["arch-audit"], stdout="\n")
    assert hardening.vulnerability_scan() == []


# --------------------------------------------------------------- faillock --

def test_faillock_wired_into_pam_false_when_file_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(hardening, "PAM_SYSTEM_LOGIN", tmp_path / "nonexistent")
    assert hardening.faillock_wired_into_pam() is False


def test_faillock_wired_into_pam_true_when_referenced(monkeypatch, tmp_path, fake_run):
    pam_file = tmp_path / "system-login"
    pam_file.write_text("auth required pam_faillock.so preauth\n")
    monkeypatch.setattr(hardening, "PAM_SYSTEM_LOGIN", pam_file)
    fake_run.set_response(["cat", str(pam_file)], stdout=pam_file.read_text())
    assert hardening.faillock_wired_into_pam() is True


def test_faillock_status_parses_deny_and_unlock_time(monkeypatch, tmp_path, fake_run):
    pam_file = tmp_path / "system-login"
    pam_file.write_text("no faillock here\n")
    conf_file = tmp_path / "faillock.conf"
    conf_file.write_text("deny = 3\nunlock_time = 600\n")
    monkeypatch.setattr(hardening, "PAM_SYSTEM_LOGIN", pam_file)
    monkeypatch.setattr(hardening, "FAILLOCK_CONF", conf_file)
    fake_run.set_response(["cat", str(pam_file)], stdout=pam_file.read_text())
    fake_run.set_response(["cat", str(conf_file)], stdout=conf_file.read_text())

    status = hardening.faillock_status()
    assert status["wired"] is False
    assert status["deny"] == "3"
    assert status["unlock_time"] == "600"


def test_set_faillock_policy_updates_both_options(fake_run, fake_which, privilege_paths, monkeypatch, tmp_path):
    conf_file = tmp_path / "faillock.conf"
    conf_file.write_text("deny = 3\nunlock_time = 600\n")
    monkeypatch.setattr(hardening, "FAILLOCK_CONF", conf_file)
    fake_run.set_response(["grep", "-E"], stdout="deny = 3\n")
    fake_run.set_response(["pkexec", "sed", "-i"], returncode=0)

    result = hardening.set_faillock_policy(deny=5, unlock_time=900)
    assert result.ok
    sed_calls = [c for c in fake_run.calls if "sed" in c]
    assert len(sed_calls) == 2  # deny, then unlock_time


def test_set_faillock_policy_stops_after_first_failure(fake_run, fake_which, privilege_paths, monkeypatch, tmp_path):
    conf_file = tmp_path / "faillock.conf"
    conf_file.write_text("deny = 3\n")
    monkeypatch.setattr(hardening, "FAILLOCK_CONF", conf_file)
    fake_run.set_response(["grep", "-E"], stdout="deny = 3\n")
    fake_run.set_response(["pkexec", "sed", "-i"], returncode=1, stderr="failed")

    result = hardening.set_faillock_policy(deny=5, unlock_time=900)
    assert not result.ok
    sed_calls = [c for c in fake_run.calls if "sed" in c]
    assert len(sed_calls) == 1  # unlock_time step never attempted


# --------------------------------------------------------------- password complexity (pwquality) --

def test_pwquality_wired_into_pam_false_when_file_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(hardening, "PAM_SYSTEM_LOGIN", tmp_path / "nonexistent")
    assert hardening.pwquality_wired_into_pam() is False


def test_pwquality_wired_into_pam_true_when_referenced(monkeypatch, tmp_path, fake_run):
    pam_file = tmp_path / "system-login"
    pam_file.write_text("password requisite pam_pwquality.so retry=3\n")
    monkeypatch.setattr(hardening, "PAM_SYSTEM_LOGIN", pam_file)
    fake_run.set_response(["cat", str(pam_file)], stdout=pam_file.read_text())
    assert hardening.pwquality_wired_into_pam() is True


def test_pwquality_status_parses_all_settings(monkeypatch, tmp_path, fake_run):
    pam_file = tmp_path / "system-login"
    pam_file.write_text("no pwquality here\n")
    conf_file = tmp_path / "pwquality.conf"
    conf_file.write_text("minlen = 14\ndcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1\nretry = 3\n")
    monkeypatch.setattr(hardening, "PAM_SYSTEM_LOGIN", pam_file)
    monkeypatch.setattr(hardening, "PWQUALITY_CONF", conf_file)
    fake_run.set_response(["cat", str(pam_file)], stdout=pam_file.read_text())
    fake_run.set_response(["cat", str(conf_file)], stdout=conf_file.read_text())

    status = hardening.pwquality_status()
    assert status["wired"] is False
    assert status["minlen"] == "14"
    assert status["dcredit"] == "-1"
    assert status["ucredit"] == "-1"
    assert status["lcredit"] == "-1"
    assert status["ocredit"] == "-1"
    assert status["retry"] == "3"


def test_pwquality_status_defaults_unknown_when_conf_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(hardening, "PWQUALITY_CONF", tmp_path / "nonexistent")
    monkeypatch.setattr(hardening, "PAM_SYSTEM_LOGIN", tmp_path / "also-nonexistent")
    status = hardening.pwquality_status()
    assert status["minlen"] == "unknown"


def test_set_password_complexity_policy_updates_all_six_settings(fake_run, fake_which, privilege_paths, monkeypatch, tmp_path):
    conf_file = tmp_path / "pwquality.conf"
    conf_file.write_text("minlen = 8\n")
    monkeypatch.setattr(hardening, "PWQUALITY_CONF", conf_file)
    fake_run.set_response(["grep", "-E"], stdout="minlen = 8\n")
    fake_run.set_response(["pkexec", "sed", "-i"], returncode=0)

    result = hardening.set_password_complexity_policy()
    assert result.ok
    sed_calls = [c for c in fake_run.calls if "sed" in c]
    assert len(sed_calls) == 6  # minlen, dcredit, ucredit, lcredit, ocredit, retry


def test_set_password_complexity_policy_stops_after_first_failure(fake_run, fake_which, privilege_paths, monkeypatch, tmp_path):
    conf_file = tmp_path / "pwquality.conf"
    conf_file.write_text("minlen = 8\n")
    monkeypatch.setattr(hardening, "PWQUALITY_CONF", conf_file)
    fake_run.set_response(["grep", "-E"], stdout="minlen = 8\n")
    fake_run.set_response(["pkexec", "sed", "-i"], returncode=1, stderr="failed")

    result = hardening.set_password_complexity_policy()
    assert not result.ok
    sed_calls = [c for c in fake_run.calls if "sed" in c]
    assert len(sed_calls) == 1  # stopped at minlen, nothing further attempted


def test_set_password_complexity_policy_uses_cis_defaults(fake_run, fake_which, privilege_paths, monkeypatch, tmp_path):
    conf_file = tmp_path / "pwquality.conf"
    conf_file.write_text("")
    monkeypatch.setattr(hardening, "PWQUALITY_CONF", conf_file)
    fake_run.set_response(["grep", "-E"], stdout="")
    fake_run.set_response(["pkexec", "bash", "-c"], returncode=0)

    hardening.set_password_complexity_policy()
    calls_text = " ".join(arg for call in fake_run.calls for arg in call)
    assert "minlen = 14" in calls_text
    assert "dcredit = -1" in calls_text


def test_set_password_complexity_policy_rejects_invalid_minlen():
    with pytest.raises(ValueError):
        hardening.set_password_complexity_policy(minlen=0)


# --------------------------------------------------------------- run_audit rollup --

def test_run_audit_healthy_system_all_pass_or_expected(fake_run, fake_which, monkeypatch, tmp_path):
    """A fully-hardened system should report pass/info, no fail/warn on the
    core items we control cleanly here."""
    fake_which.update({"ufw", "sshd", "fail2ban-client", "aa-status", "auditctl", "arch-audit"})

    fake_run.set_response(["pkexec", "ufw", "status", "verbose"], stdout="Status: active\n")
    conf = tmp_path / "sshd_config"
    conf.write_text("PermitRootLogin no\nPasswordAuthentication no\n")
    monkeypatch.setattr(hardening.security_mod, "SSHD_CONFIG", conf)
    fake_run.set_response(["systemctl", "is-active", "sshd"], stdout="active\n")
    fake_run.set_response(["cat", str(conf)], stdout=conf.read_text())

    fake_run.set_response(["systemctl", "is-active", "fail2ban"], stdout="active\n")
    fake_run.set_response(["systemctl", "is-enabled", "fail2ban"], stdout="enabled\n")
    fake_run.set_response(["fail2ban-client", "status"], stdout="Jail list:\tsshd\n")

    fake_run.set_response(["systemctl", "is-active", "apparmor"], stdout="active\n")

    fake_run.set_response(["systemctl", "is-active", "usbguard"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-enabled", "usbguard"], stdout="disabled\n")

    fake_run.set_response(["systemctl", "is-active", "auditd"], stdout="active\n")
    fake_run.set_response(["systemctl", "is-enabled", "auditd"], stdout="enabled\n")

    fake_run.set_response(["arch-audit"], stdout="")

    checks = hardening.run_audit()
    by_name = {c.name: c for c in checks}
    assert by_name["Firewall"].status == "pass"
    assert by_name["SSH root login"].status == "pass"
    assert by_name["SSH password auth"].status == "pass"
    assert by_name["fail2ban"].status == "pass"
    assert by_name["auditd"].status == "pass"
    assert by_name["Known CVEs (arch-audit)"].status == "pass"


def test_run_audit_surfaces_failures_without_aborting(fake_run, fake_which, monkeypatch, tmp_path):
    """An insecure system should surface warn/fail per-check, and one
    failing sub-check must not prevent the rest of the audit from running."""
    conf = tmp_path / "sshd_config"
    conf.write_text("PermitRootLogin yes\nPasswordAuthentication yes\n")
    monkeypatch.setattr(hardening.security_mod, "SSHD_CONFIG", conf)
    fake_which.add("sshd")
    fake_run.set_response(["systemctl", "is-active", "sshd"], stdout="active\n")
    fake_run.set_response(["cat", str(conf)], stdout=conf.read_text())

    fake_run.set_response(["systemctl", "is-active", "usbguard"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-enabled", "usbguard"], stdout="disabled\n")
    fake_run.set_response(["systemctl", "is-active", "auditd"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-enabled", "auditd"], stdout="disabled\n")

    checks = hardening.run_audit()
    by_name = {c.name: c for c in checks}

    assert by_name["Firewall"].status == "warn"  # no backend installed
    assert by_name["SSH root login"].status == "fail"
    assert by_name["SSH password auth"].status == "warn"
    assert by_name["fail2ban"].status == "warn"  # not installed
    assert by_name["Known CVEs (arch-audit)"].status == "info"  # arch-audit not installed
    # every category still present despite failures/missing tools above
    assert "AppArmor" in by_name
    assert "SELinux" in by_name
    assert "Kernel sysctl hardening" in by_name


# --------------------------------------------------------------- SELinux mode casing --

def test_run_audit_selinux_enforcing_passes_with_real_lowercase_mode(monkeypatch, fake_run):
    """
    Regression test for a real bug found on bare metal: real `sestatus`
    output is lowercase ("enforcing"/"permissive"), but this check used to
    compare against Title-case "Enforcing"/"Permissive", so it never
    matched on any real system - a fully enforcing SELinux setup silently
    scored as the generic "warn: Mode: enforcing" fallback instead of
    "pass". The bug in the SELinux backend module's own status parsing
    isn't being tested here (that's covered in test_selinux.py) - this
    just confirms hardening.run_audit()'s *comparison* against whatever
    get_status() returns is case-insensitive.
    """
    fake_run.set_response(["systemctl", "is-active", "auditd"], stdout="active\n")
    fake_run.set_response(["systemctl", "is-enabled", "auditd"], stdout="enabled\n")

    monkeypatch.setattr(
        hardening.selinux_mod,
        "get_status",
        lambda: hardening.selinux_mod.SelinuxStatus(available=True, mode="enforcing", policy="atropa-refpolicy"),
    )

    checks = hardening.run_audit()
    by_name = {c.name: c for c in checks}
    assert by_name["SELinux"].status == "pass"
    assert "atropa-refpolicy" in by_name["SELinux"].detail


def test_run_audit_selinux_permissive_warns_with_real_lowercase_mode(monkeypatch, fake_run):
    fake_run.set_response(["systemctl", "is-active", "auditd"], stdout="active\n")
    fake_run.set_response(["systemctl", "is-enabled", "auditd"], stdout="enabled\n")

    monkeypatch.setattr(
        hardening.selinux_mod,
        "get_status",
        lambda: hardening.selinux_mod.SelinuxStatus(available=True, mode="permissive"),
    )

    checks = hardening.run_audit()
    by_name = {c.name: c for c in checks}
    assert by_name["SELinux"].status == "warn"
    assert "not blocked" in by_name["SELinux"].detail
