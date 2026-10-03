"""Tests for atropa.backend.quicksetup."""
from __future__ import annotations

from pathlib import Path

import pytest

from atropa.backend import quicksetup

# The sandbox container this runs in has a real /sys/fs/selinux mount (from
# the host), even though SELinux itself isn't in use here - same issue
# handled in test_selinux.py. Neutralize it the same way so is_available()
# reflects the fake_which fixture instead of the host's real filesystem.
_REAL_PATH_EXISTS = Path.exists


@pytest.fixture(autouse=True)
def no_real_selinux_fs(monkeypatch):
    def fake_exists(self):
        if str(self) == "/sys/fs/selinux":
            return False
        return _REAL_PATH_EXISTS(self)

    monkeypatch.setattr(Path, "exists", fake_exists)


# --------------------------------------------------------------- catalog sanity --

def test_catalog_keys_are_unique():
    keys = [item.key for item in quicksetup.CATALOG]
    assert len(keys) == len(set(keys))


def test_catalog_every_item_has_title_and_description():
    for item in quicksetup.CATALOG:
        assert item.title
        assert item.description


def test_usbguard_defaults_unselected_with_a_risk_note():
    usbguard = next(item for item in quicksetup.CATALOG if item.key == "usbguard")
    assert usbguard.default_selected is False
    assert usbguard.risk_note


def test_order_covers_every_catalog_key():
    assert set(quicksetup._ORDER) == {item.key for item in quicksetup.CATALOG}


# --------------------------------------------------------------- firewall (safety-critical) --

def test_apply_firewall_installs_when_backend_missing(fake_run, fake_which, monkeypatch):
    # fake_which can't reflect "ufw now exists" the instant the mocked
    # install call succeeds, so simulate that transition directly: backend
    # detection reports "none" once (triggering the install path), then
    # "ufw" from then on (as it would after a real install).
    from atropa.backend import security

    call_count = {"n": 0}

    def fake_backend():
        call_count["n"] += 1
        return "none" if call_count["n"] == 1 else "ufw"

    monkeypatch.setattr(security, "firewall_backend", fake_backend)

    fake_run.set_response(["pkexec", "pacman", "-S", "--noconfirm", "ufw"], returncode=0)
    fake_run.set_response(["pkexec", "ufw", "status", "verbose"], stdout="Status: inactive\n")
    fake_run.set_response(["systemctl", "is-active", "sshd"], stdout="inactive\n")
    fake_run.set_response(["pkexec", "ufw", "allow"], returncode=0)
    fake_run.set_response(["pkexec", "ufw", "--force", "enable"], returncode=0)

    result = quicksetup._apply_firewall(lambda _l: None)
    assert result.ok
    assert fake_run.call_containing("pacman") is not None


def test_apply_firewall_allows_ssh_port_before_enabling(fake_run, fake_which, monkeypatch, tmp_path):
    """The critical safety guarantee: SSH must be allowed BEFORE the
    firewall is enabled, using whatever port sshd is actually configured
    on - never enable-then-allow, which could cut off the current session
    in the gap between the two commands."""
    from atropa.backend import security

    conf = tmp_path / "sshd_config"
    conf.write_text("Port 2222\n")
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)

    fake_which.add("ufw")
    fake_which.add("sshd")
    fake_run.set_response(["pkexec", "ufw", "status", "verbose"], stdout="Status: inactive\n")
    fake_run.set_response(["systemctl", "is-active", "sshd"], stdout="active\n")
    fake_run.set_response(["cat", str(conf)], stdout=conf.read_text())
    fake_run.set_response(["pkexec", "ufw", "allow"], returncode=0)
    fake_run.set_response(["pkexec", "ufw", "--force", "enable"], returncode=0)

    quicksetup._apply_firewall(lambda _l: None)

    allow_index = next(i for i, c in enumerate(fake_run.calls) if "allow" in c)
    enable_index = next(i for i, c in enumerate(fake_run.calls) if "enable" in c)
    assert allow_index < enable_index
    assert any("2222" in arg for arg in fake_run.calls[allow_index])


def test_apply_firewall_skips_when_already_active(fake_run, fake_which):
    fake_which.add("ufw")
    fake_run.set_response(["pkexec", "ufw", "status", "verbose"], stdout="Status: active\n")

    result = quicksetup._apply_firewall(lambda _l: None)
    assert result.ok
    assert fake_run.call_containing("enable") is None


def test_apply_firewall_stops_if_install_fails(fake_run, fake_which):
    fake_run.set_response(["pkexec", "pacman", "-S", "--noconfirm", "ufw"], returncode=1, stderr="no network")
    result = quicksetup._apply_firewall(lambda _l: None)
    assert not result.ok
    assert fake_run.call_containing("enable") is None


# --------------------------------------------------------------- fail2ban --

def test_apply_fail2ban_installs_enables_and_protects_ssh(fake_run, fake_which):
    fake_run.set_response(["pkexec", "pacman", "-S", "--noconfirm", "fail2ban"], returncode=0)
    fake_run.set_response(["systemctl", "is-active", "fail2ban"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-enabled", "fail2ban"], stdout="disabled\n")
    fake_run.set_response(["pkexec", "systemctl", "enable", "fail2ban", "--now"], returncode=0)
    fake_run.set_response(["pkexec", "tee", "/etc/fail2ban/jail.d/sshd.local"], returncode=0)
    fake_run.set_response(["pkexec", "systemctl", "restart", "fail2ban"], returncode=0)

    result = quicksetup._apply_fail2ban(lambda _l: None)
    assert result.ok
    assert any("jail.d" in arg for call in fake_run.calls for arg in call)


def test_apply_fail2ban_skips_install_when_already_present(fake_run, fake_which):
    fake_which.add("fail2ban-client")
    fake_run.set_response(["systemctl", "is-active", "fail2ban"], stdout="active\n")
    fake_run.set_response(["pkexec", "tee", "/etc/fail2ban/jail.d/sshd.local"], returncode=0)
    fake_run.set_response(["pkexec", "systemctl", "restart", "fail2ban"], returncode=0)

    quicksetup._apply_fail2ban(lambda _l: None)
    assert fake_run.call_containing("pacman") is None


# --------------------------------------------------------------- sysctl --

def test_apply_sysctl_applies_all_recommended_keys(fake_run, fake_which, privilege_paths):
    fake_run.set_response(["sysctl", "-n"], stdout="0\n")
    fake_run.set_response(["pkexec", "tee"], returncode=0)
    fake_run.set_response(["pkexec", "sysctl", "--system"], returncode=0)

    result = quicksetup._apply_sysctl(lambda _l: None)
    assert result.ok


# --------------------------------------------------------------- faillock --

def test_apply_faillock_skips_when_not_wired_into_pam(monkeypatch, tmp_path):
    from atropa.backend import hardening
    monkeypatch.setattr(hardening, "PAM_SYSTEM_LOGIN", tmp_path / "nonexistent")

    lines = []
    result = quicksetup._apply_faillock(lines.append)
    assert result.ok
    assert "skip" in result.stdout.lower()
    assert any("PAM" in line for line in lines)


def test_apply_faillock_applies_when_wired_in(fake_run, fake_which, privilege_paths, monkeypatch, tmp_path):
    from atropa.backend import hardening
    pam_file = tmp_path / "system-login"
    pam_file.write_text("auth required pam_faillock.so preauth\n")
    monkeypatch.setattr(hardening, "PAM_SYSTEM_LOGIN", pam_file)
    conf_file = tmp_path / "faillock.conf"
    conf_file.write_text("deny = 3\nunlock_time = 600\n")
    monkeypatch.setattr(hardening, "FAILLOCK_CONF", conf_file)
    fake_run.set_response(["cat", str(pam_file)], stdout=pam_file.read_text())
    fake_run.set_response(["grep", "-E"], stdout="deny = 3\n")
    fake_run.set_response(["pkexec", "sed", "-i"], returncode=0)

    result = quicksetup._apply_faillock(lambda _l: None)
    assert result.ok


# --------------------------------------------------------------- apparmor --

def test_apply_apparmor_installs_when_missing(fake_run, fake_which):
    fake_run.set_response(["pkexec", "pacman", "-S", "--noconfirm", "apparmor"], returncode=0)
    fake_run.set_response(["systemctl", "is-active", "apparmor"], stdout="inactive\n")
    fake_run.set_response(["pkexec", "systemctl", "enable", "apparmor", "--now"], returncode=0)

    result = quicksetup._apply_apparmor(lambda _l: None)
    assert result.ok


def test_apply_apparmor_warns_when_kernel_not_enabled(fake_run, fake_which):
    fake_which.add("aa-status")
    fake_run.set_response(["systemctl", "is-active", "apparmor"], stdout="inactive\n")
    fake_run.set_response(["pkexec", "systemctl", "enable", "apparmor", "--now"], returncode=0)

    lines = []
    quicksetup._apply_apparmor(lines.append)
    assert any("kernel parameter" in line or "reboot" in line for line in lines)


# --------------------------------------------------------------- auditd --

def test_apply_auditd_installs_and_enables(fake_run, fake_which):
    fake_run.set_response(["pkexec", "pacman", "-S", "--noconfirm", "audit"], returncode=0)
    fake_run.set_response(["systemctl", "is-active", "auditd"], stdout="inactive\n")
    fake_run.set_response(["pkexec", "systemctl", "enable", "auditd", "--now"], returncode=0)

    result = quicksetup._apply_auditd(lambda _l: None)
    assert result.ok


# --------------------------------------------------------------- usbguard --

def test_apply_usbguard_installs_generates_and_enables(fake_run, fake_which):
    fake_run.set_response(["pkexec", "pacman", "-S", "--noconfirm", "usbguard"], returncode=0)
    fake_run.set_response(["pkexec", "bash", "-c"], returncode=0)
    fake_run.set_response(["pkexec", "systemctl", "enable"], returncode=0)

    result = quicksetup._apply_usbguard(lambda _l: None)
    assert result.ok


# --------------------------------------------------------------- selinux (never auto-enforce) --

def test_apply_selinux_installs_tools_when_missing(fake_run, fake_which):
    # is_available() is False here (sestatus not in fake_which, and the
    # sandbox's real /sys/fs/selinux is neutralized by the autouse fixture
    # above) - so after installing tools, the function should stop and
    # report that kernel enablement is still a manual step, not proceed to
    # call sestatus at all.
    fake_run.set_response(
        ["pkexec", "pacman", "-S", "--noconfirm", "policycoreutils", "checkpolicy", "audit"], returncode=0
    )

    lines = []
    result = quicksetup._apply_selinux(lines.append)
    assert result.ok
    assert "not automated" in result.stdout or "manual step" in result.stdout
    assert fake_run.call_containing("sestatus") is None


def test_apply_selinux_never_sets_enforcing(fake_run, fake_which):
    """quicksetup must never flip SELinux straight to enforcing - permissive
    is the only mode it will set, so a bad policy doesn't lock the user out."""
    fake_which.add("sestatus")
    fake_run.set_response(
        ["sestatus"],
        stdout="SELinux status:                 enabled\nCurrent mode:                    disabled\n",
    )
    fake_run.set_response(["pkexec", "setenforce", "0"], returncode=0)
    fake_run.set_response(["pkexec", "sed", "-i"], returncode=0)

    quicksetup._apply_selinux(lambda _l: None)

    assert fake_run.call_containing("setenforce") is None or "1" not in (fake_run.call_containing("setenforce") or [])


def test_apply_selinux_skips_when_already_permissive_or_enforcing(fake_run, fake_which):
    fake_which.add("sestatus")
    fake_run.set_response(
        ["sestatus"],
        stdout="SELinux status:                 enabled\nCurrent mode:                    permissive\n",
    )
    result = quicksetup._apply_selinux(lambda _l: None)
    assert result.ok
    assert fake_run.call_containing("setenforce") is None


# --------------------------------------------------------------- apply_items orchestration --

def test_apply_items_runs_in_fixed_safe_order_regardless_of_input_order(fake_run, fake_which, privilege_paths):
    fake_which.update({"ufw", "fail2ban-client", "sestatus"})
    fake_run.set_response(["pkexec", "ufw", "status", "verbose"], stdout="Status: active\n")
    fake_run.set_response(["systemctl", "is-active", "fail2ban"], stdout="active\n")
    fake_run.set_response(["pkexec", "tee"], returncode=0)
    fake_run.set_response(["pkexec", "systemctl", "restart", "fail2ban"], returncode=0)
    fake_run.set_response(["sysctl", "-n"], stdout="0\n")
    fake_run.set_response(["pkexec", "sysctl", "--system"], returncode=0)
    fake_run.set_response(["sestatus"], stdout="SELinux status: enabled\nCurrent mode: permissive\n")

    lines = []
    # deliberately reversed / scrambled order in the input
    quicksetup.apply_items(["selinux", "sysctl", "firewall", "fail2ban"], lines.append)

    joined = "\n".join(lines)
    firewall_pos = joined.index("=== Firewall ===")
    fail2ban_pos = joined.index("=== fail2ban ===")
    sysctl_pos = joined.index("=== Kernel sysctl hardening ===")
    selinux_pos = joined.index("=== SELinux ===")
    assert firewall_pos < fail2ban_pos < sysctl_pos < selinux_pos


def test_apply_items_only_runs_requested_keys(fake_run, fake_which):
    fake_which.add("ufw")
    fake_run.set_response(["pkexec", "ufw", "status", "verbose"], stdout="Status: active\n")

    lines = []
    results = quicksetup.apply_items(["firewall"], lines.append)

    assert set(results.keys()) == {"firewall"}
    assert "=== fail2ban ===" not in "\n".join(lines)


def test_apply_items_continues_after_one_step_fails(fake_run, fake_which, privilege_paths):
    """One failing step (e.g. a package install error) must not prevent
    later steps in the batch from running."""
    fake_run.set_response(["pkexec", "pacman", "-S", "--noconfirm", "ufw"], returncode=1, stderr="network error")
    fake_run.set_response(["sysctl", "-n"], stdout="0\n")
    fake_run.set_response(["pkexec", "tee"], returncode=0)
    fake_run.set_response(["pkexec", "sysctl", "--system"], returncode=0)

    results = quicksetup.apply_items(["firewall", "sysctl"], lambda _l: None)

    assert not results["firewall"].ok
    assert results["sysctl"].ok


def test_apply_single_runs_exactly_that_item(fake_run, fake_which):
    fake_which.add("ufw")
    fake_run.set_response(["pkexec", "ufw", "status", "verbose"], stdout="Status: active\n")

    lines = []
    result = quicksetup.apply_single("firewall", lines.append)
    assert result.ok
    assert any("Firewall" in line for line in lines)


def test_apply_single_unknown_key_raises_keyerror():
    with pytest.raises(KeyError):
        quicksetup.apply_single("not-a-real-key", lambda _l: None)


# --------------------------------------------------------------- status_summary --

def test_status_summary_covers_every_catalog_key(fake_run, fake_which):
    fake_run.set_response(["systemctl", "is-active", "fail2ban"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-active", "apparmor"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-active", "auditd"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-active", "usbguard"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-enabled", "usbguard"], stdout="disabled\n")

    summary = quicksetup.status_summary()
    assert set(summary.keys()) == {item.key for item in quicksetup.CATALOG}


def test_status_summary_faillock_reports_pam_wiring_state(monkeypatch, tmp_path, fake_run, fake_which):
    from atropa.backend import hardening
    monkeypatch.setattr(hardening, "PAM_SYSTEM_LOGIN", tmp_path / "nonexistent")
    summary = quicksetup.status_summary()
    assert "manual step required" in summary["faillock"]
