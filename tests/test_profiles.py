"""Tests for atropa.backend.profiles."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from atropa.backend import profiles

# Same sandbox-environment leak as test_selinux.py/test_quicksetup.py: this
# container has a real /sys/fs/selinux mount from the host.
_REAL_EXISTS = Path.exists


@pytest.fixture(autouse=True)
def no_real_selinux_fs(monkeypatch):
    def fake_exists(self):
        if str(self) == "/sys/fs/selinux":
            return False
        return _REAL_EXISTS(self)

    monkeypatch.setattr(Path, "exists", fake_exists)


# --------------------------------------------------------------- export --

def test_export_profile_has_required_top_level_fields(fake_run, fake_which):
    profile = profiles.export_profile()
    assert profile["atropa_profile_version"] == profiles.PROFILE_VERSION
    assert "exported_at" in profile
    assert "hostname" in profile
    assert "quicksetup_keys" in profile
    assert "apparmor_profiles" in profile
    assert "selinux_booleans" in profile
    assert "ssh" in profile


def test_export_profile_captures_configured_quicksetup_keys(fake_run, fake_which):
    fake_which.update({"ufw", "fail2ban-client"})
    fake_run.set_response(["pkexec", "ufw", "status", "verbose"], stdout="Status: active\n")
    fake_run.set_response(["systemctl", "is-active", "fail2ban"], stdout="active\n")
    fake_run.set_response(["systemctl", "is-active", "apparmor"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-active", "auditd"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-active", "usbguard"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-enabled", "usbguard"], stdout="disabled\n")

    profile = profiles.export_profile()
    assert "firewall" in profile["quicksetup_keys"]
    assert "fail2ban" in profile["quicksetup_keys"]
    assert "auditd" not in profile["quicksetup_keys"]


def test_export_profile_ssh_section_none_when_not_installed(fake_run, fake_which):
    fake_run.set_response(["systemctl", "is-active", "sshd"], stdout="inactive\n")
    profile = profiles.export_profile()
    assert profile["ssh"] is None


def test_export_profile_ssh_section_populated_when_installed(fake_run, fake_which, monkeypatch, tmp_path):
    from atropa.backend import security

    fake_which.add("sshd")
    conf = tmp_path / "sshd_config"
    conf.write_text("Port 2222\nPermitRootLogin no\nPasswordAuthentication no\n")
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)
    fake_run.set_response(["systemctl", "is-active", "sshd"], stdout="active\n")
    fake_run.set_response(["cat", str(conf)], stdout=conf.read_text())

    profile = profiles.export_profile()
    assert profile["ssh"] == {"root_login": "no", "password_auth": "no", "port": "2222"}


def test_export_profile_ssh_section_records_unknown_for_default_config(fake_run, fake_which, monkeypatch, tmp_path):
    # Arch's stock sshd_config only has these as comments - OpenSSH's built-in
    # defaults apply, and the export must not pass "22" off as a real setting.
    from atropa.backend import security

    fake_which.add("sshd")
    conf = tmp_path / "sshd_config"
    conf.write_text("#Port 22\n#PermitRootLogin prohibit-password\n#PasswordAuthentication yes\nUsePAM yes\n")
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)
    fake_run.set_response(["cat", str(conf)], stdout=conf.read_text())

    profile = profiles.export_profile()
    assert profile["ssh"] == {"root_login": "unknown", "password_auth": "unknown", "port": "unknown"}


def test_export_profile_apparmor_profiles_empty_when_unavailable(fake_run, fake_which):
    profile = profiles.export_profile()
    assert profile["apparmor_profiles"] == {}


def test_export_profile_apparmor_profiles_captured_when_available(fake_run, fake_which):
    fake_which.add("aa-status")
    fake_run.set_response(
        ["pkexec", "aa-status"],
        stdout="1 profiles are loaded.\n1 profiles are in enforce mode.\n   /usr/bin/firefox\n",
    )
    profile = profiles.export_profile()
    assert profile["apparmor_profiles"] == {"/usr/bin/firefox": "enforce"}


# --------------------------------------------------------------- summarize --

def test_summarize_profile_reads_back_export(fake_run, fake_which):
    profile = profiles.export_profile()
    summary = profiles.summarize_profile(profile)
    assert summary.hostname == profile["hostname"]
    assert summary.exported_at == profile["exported_at"]


def test_summarize_profile_handles_missing_optional_fields():
    summary = profiles.summarize_profile({"hostname": "x", "exported_at": "y"})
    assert summary.quicksetup_keys == []
    assert summary.apparmor_profile_count == 0
    assert summary.selinux_boolean_count == 0
    assert summary.has_ssh_section is False


# --------------------------------------------------------------- save/load file --

def test_save_and_load_round_trip(tmp_path, fake_run, fake_which):
    profile = profiles.export_profile()
    path = tmp_path / "profile.json"
    profiles.save_profile_to_file(profile, str(path))

    loaded = profiles.load_profile_from_file(str(path))
    assert loaded == profile


def test_load_profile_missing_file_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="Couldn't read"):
        profiles.load_profile_from_file(str(tmp_path / "nonexistent.json"))


def test_load_profile_bad_json_raises_value_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not json{{{")
    with pytest.raises(ValueError, match="bad JSON"):
        profiles.load_profile_from_file(str(path))


def test_load_profile_wrong_version_raises_value_error(tmp_path):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"atropa_profile_version": 999}))
    with pytest.raises(ValueError, match="Unsupported profile version"):
        profiles.load_profile_from_file(str(path))


# --------------------------------------------------------------- import: quicksetup section --

def test_import_quicksetup_section_reapplies_captured_keys(fake_run, fake_which, privilege_paths):
    fake_which.add("ufw")
    fake_run.set_response(["pkexec", "ufw", "status", "verbose"], stdout="Status: active\n")

    profile = {"atropa_profile_version": 1, "hostname": "x", "exported_at": "y", "quicksetup_keys": ["firewall"]}
    results = profiles.import_profile(profile, ["quicksetup"], lambda _l: None)
    assert "firewall" in results
    assert results["firewall"].ok


def test_import_quicksetup_section_ignores_unknown_keys(fake_run, fake_which):
    profile = {"quicksetup_keys": ["not-a-real-key"]}
    results = profiles.import_profile(profile, ["quicksetup"], lambda _l: None)
    assert results == {}


# --------------------------------------------------------------- import: apparmor --

def test_import_apparmor_skips_when_unavailable(fake_run, fake_which):
    lines = []
    profiles.import_profile({"apparmor_profiles": {"/usr/bin/firefox": "enforce"}}, ["apparmor_profiles"], lines.append)
    assert any("isn't available" in line for line in lines)


def test_import_apparmor_skips_profiles_not_present_on_target(fake_run, fake_which):
    fake_which.add("aa-status")
    fake_run.set_response(["pkexec", "aa-status"], stdout="1 profiles are loaded.\n1 profiles are in enforce mode.\n   /usr/bin/other-app\n")

    lines = []
    profiles.import_profile({"apparmor_profiles": {"/usr/bin/firefox": "enforce"}}, ["apparmor_profiles"], lines.append)
    assert any("not present on this machine" in line for line in lines)


def test_import_apparmor_applies_matching_profiles(fake_run, fake_which):
    fake_which.add("aa-status")
    fake_which.add("aa-enforce")
    fake_run.set_response(["pkexec", "aa-status"], stdout="1 profiles are loaded.\n1 profiles are in complain mode.\n   /usr/bin/firefox\n")
    fake_run.set_response(["pkexec", "aa-enforce", "/usr/bin/firefox"], returncode=0)

    lines = []
    results = profiles.import_profile({"apparmor_profiles": {"/usr/bin/firefox": "enforce"}}, ["apparmor_profiles"], lines.append)
    assert results["apparmor_profiles"].ok
    assert fake_run.call_containing("aa-enforce") is not None


def test_import_apparmor_skips_modes_atropa_cannot_set(fake_run, fake_which):
    # AppArmor 4's aa-status lists profiles in "unconfined" (and kill/prompt)
    # mode - these used to raise ValueError and abort the whole import.
    fake_which.add("aa-status")
    fake_run.set_response(
        ["pkexec", "aa-status"],
        stdout="2 profiles are loaded.\n1 profiles are in enforce mode.\n   /usr/bin/foo\n"
        "1 profiles are in unconfined mode.\n   firefox\n",
    )
    lines = []
    results = profiles.import_profile(
        {"apparmor_profiles": {"firefox": "unconfined"}, "ssh": None}, ["apparmor_profiles", "ssh"], lines.append
    )
    assert results["apparmor_profiles"].ok
    assert results["ssh"].ok  # later sections still ran
    assert any("can only set enforce/complain" in line for line in lines)
    assert fake_run.call_containing("aa-complain") is None and fake_run.call_containing("aa-enforce") is None


def test_import_apparmor_leaves_profiles_already_in_that_mode(fake_run, fake_which):
    fake_which.add("aa-status")
    fake_which.add("aa-enforce")
    fake_run.set_response(["pkexec", "aa-status"], stdout="1 profiles are loaded.\n1 profiles are in enforce mode.\n   /usr/bin/firefox\n")

    results = profiles.import_profile({"apparmor_profiles": {"/usr/bin/firefox": "enforce"}}, ["apparmor_profiles"], lambda _l: None)
    assert results["apparmor_profiles"].ok
    assert fake_run.call_containing("aa-enforce") is None


# --------------------------------------------------------------- import: selinux --

def test_import_selinux_skips_when_unavailable(fake_run, fake_which):
    lines = []
    profiles.import_profile({"selinux_booleans": {"httpd_can_network_connect": True}}, ["selinux_booleans"], lines.append)
    assert any("isn't available" in line for line in lines)


def test_import_selinux_skips_booleans_not_present(fake_run, fake_which):
    fake_which.add("sestatus")
    fake_which.add("getsebool")
    fake_run.set_response(["sestatus"], stdout="SELinux status: enabled\nCurrent mode: permissive\n")
    fake_run.set_response(["getsebool", "-a"], stdout="ssh_sysadm_login --> off\n")

    lines = []
    profiles.import_profile(
        {"selinux_booleans": {"httpd_can_network_connect": True}}, ["selinux_booleans"], lines.append
    )
    assert any("not present on this machine" in line for line in lines)


def test_import_selinux_applies_matching_booleans(fake_run, fake_which):
    fake_which.add("sestatus")
    fake_which.add("getsebool")
    fake_run.set_response(["sestatus"], stdout="SELinux status: enabled\nCurrent mode: permissive\n")
    fake_run.set_response(["getsebool", "-a"], stdout="ssh_sysadm_login --> off\n")

    results = profiles.import_profile(
        {"selinux_booleans": {"ssh_sysadm_login": True}}, ["selinux_booleans"], lambda _l: None
    )
    assert results["selinux_booleans"].ok
    assert fake_run.call_containing("setsebool") is not None


def test_import_selinux_skips_values_that_are_not_booleans(fake_run, fake_which):
    # bool("off") is True - a hand-edited string must not be read as "on".
    fake_which.add("sestatus")
    fake_which.add("getsebool")
    fake_run.set_response(["sestatus"], stdout="SELinux status: enabled\nCurrent mode: permissive\n")
    fake_run.set_response(["getsebool", "-a"], stdout="ssh_sysadm_login --> off\n")

    lines = []
    results = profiles.import_profile({"selinux_booleans": {"ssh_sysadm_login": "off"}}, ["selinux_booleans"], lines.append)
    assert results["selinux_booleans"].ok
    assert fake_run.call_containing("setsebool") is None
    assert any("isn't true/false" in line for line in lines)


def test_import_selinux_leaves_booleans_already_at_that_value(fake_run, fake_which):
    fake_which.add("sestatus")
    fake_which.add("getsebool")
    fake_run.set_response(["sestatus"], stdout="SELinux status: enabled\nCurrent mode: permissive\n")
    fake_run.set_response(["getsebool", "-a"], stdout="ssh_sysadm_login --> on\n")

    results = profiles.import_profile({"selinux_booleans": {"ssh_sysadm_login": True}}, ["selinux_booleans"], lambda _l: None)
    assert results["selinux_booleans"].ok
    assert fake_run.call_containing("setsebool") is None


# --------------------------------------------------------------- import: ssh --

def test_import_ssh_section_missing_is_a_noop(fake_run, fake_which):
    results = profiles.import_profile({"ssh": None}, ["ssh"], lambda _l: None)
    assert results["ssh"].ok


def test_import_ssh_applies_each_setting(fake_run, fake_which, privilege_paths, monkeypatch, tmp_path):
    from atropa.backend import security

    conf = tmp_path / "sshd_config"
    conf.write_text("PermitRootLogin yes\nPasswordAuthentication yes\nPort 22\n")
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)
    fake_run.set_response(["grep", "-Ei"], stdout="PermitRootLogin yes\n")
    fake_run.set_response(["pkexec", "sed", "-i"], returncode=0)
    fake_run.set_response(["pkexec", "sshd", "-t"], returncode=0)
    fake_run.set_response(["pkexec", "systemctl", "reload", "sshd"], returncode=0)

    ssh_section = {"root_login": "no", "password_auth": "no", "port": "2222"}
    results = profiles.import_profile({"ssh": ssh_section}, ["ssh"], lambda _l: None)
    assert results["ssh"].ok


def test_import_ssh_invalid_port_is_skipped_not_crashed(fake_run, fake_which, privilege_paths, monkeypatch, tmp_path):
    from atropa.backend import security

    conf = tmp_path / "sshd_config"
    conf.write_text("Port 22\n")
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)

    lines = []
    results = profiles.import_profile({"ssh": {"port": "not-a-port"}}, ["ssh"], lines.append)
    assert results["ssh"].ok  # falls back to the "no ssh settings applied" default, no crash
    assert any("isn't a valid number" in line for line in lines)


def _sshd_edits(fake_run) -> list[list[str]]:
    return [c for c in fake_run.calls if c[:2] in (["pkexec", "sed"], ["pkexec", "bash"], ["pkexec", "sshd"])]


def test_import_ssh_leaves_unknown_settings_alone(fake_run, fake_which):
    """A profile exported from a stock sshd_config records "unknown" for all
    three - importing it must not touch the target's sshd at all (it used to
    set PermitRootLogin no + PasswordAuthentication no, a lockout risk)."""
    lines = []
    results = profiles.import_profile(
        {"ssh": {"root_login": "unknown", "password_auth": "unknown", "port": "unknown"}}, ["ssh"], lines.append
    )
    assert results["ssh"].ok
    assert _sshd_edits(fake_run) == []
    assert sum("didn't set it explicitly" in line for line in lines) == 3


def test_import_ssh_replays_prohibit_password_exactly(fake_run, fake_which, privilege_paths, monkeypatch, tmp_path):
    from atropa.backend import security

    conf = tmp_path / "sshd_config"
    conf.write_text("PermitRootLogin yes\n")
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)
    fake_run.set_response(["grep", "-Ei"], stdout="PermitRootLogin yes\n")

    results = profiles.import_profile({"ssh": {"root_login": "prohibit-password"}}, ["ssh"], lambda _l: None)
    assert results["ssh"].ok
    sed_call = fake_run.call_containing("sed")
    assert sed_call is not None and "PermitRootLogin prohibit-password" in sed_call[4]


def test_import_ssh_never_writes_values_outside_sshd_keywords(fake_run, fake_which):
    # Profile files can come from elsewhere; their values reach a sed expression.
    lines = []
    results = profiles.import_profile(
        {"ssh": {"root_login": "yes/e;touch /tmp/pwned;#", "password_auth": "maybe", "port": "70000"}},
        ["ssh"],
        lines.append,
    )
    assert results["ssh"].ok
    assert _sshd_edits(fake_run) == []
    assert any("isn't a value Atropa can apply" in line for line in lines)
    assert any("outside 1-65535" in line for line in lines)


def test_import_ssh_reports_a_rejected_change_as_failed(fake_run, fake_which, privilege_paths, monkeypatch, tmp_path):
    from atropa.backend import security

    conf = tmp_path / "sshd_config"
    conf.write_text("PasswordAuthentication yes\n")
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)
    fake_run.set_response(["grep", "-Ei"], stdout="PasswordAuthentication yes\n")
    fake_run.set_response(["pkexec", "sshd", "-t"], returncode=1, stderr="bad config")

    results = profiles.import_profile({"ssh": {"password_auth": "no"}}, ["ssh"], lambda _l: None)
    assert not results["ssh"].ok


def test_import_keeps_going_when_a_section_raises(fake_run, fake_which, monkeypatch):
    def boom(_profiles, _on_line):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(profiles, "_import_apparmor_profiles", boom)
    results = profiles.import_profile(
        {"apparmor_profiles": {"x": "enforce"}, "ssh": None}, ["apparmor_profiles", "ssh"], lambda _l: None
    )
    assert not results["apparmor_profiles"].ok
    assert results["ssh"].ok


# --------------------------------------------------------------- import: section independence --

def test_import_only_runs_requested_sections(fake_run, fake_which):
    results = profiles.import_profile(
        {"quicksetup_keys": [], "apparmor_profiles": {"/x": "enforce"}, "selinux_booleans": {}, "ssh": None},
        ["apparmor_profiles"],
        lambda _l: None,
    )
    assert set(results.keys()) == {"apparmor_profiles"}
