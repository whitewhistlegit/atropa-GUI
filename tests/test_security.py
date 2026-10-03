"""Tests for atropa.backend.security, with emphasis on the SSH hardening
validate-before-reload / auto-rollback path, since a bug there can lock out
remote access."""
from __future__ import annotations

import pytest

from atropa.backend import security


# --------------------------------------------------------------- firewall --

def test_firewall_backend_prefers_ufw(fake_which):
    fake_which.add("ufw")
    fake_which.add("firewall-cmd")
    assert security.firewall_backend() == "ufw"


def test_firewall_backend_falls_back_to_firewalld(fake_which):
    fake_which.add("firewall-cmd")
    assert security.firewall_backend() == "firewalld"


def test_firewall_backend_none_when_neither_installed(fake_which):
    assert security.firewall_backend() == "none"


def test_firewall_status_ufw_active(fake_run, fake_which):
    fake_which.add("ufw")
    fake_run.set_response(
        ["pkexec", "ufw", "status", "verbose"],
        stdout="Status: active\nLogging: on (low)\n22/tcp ALLOW IN Anywhere\n",
    )
    status = security.firewall_status()
    assert status.backend == "ufw"
    assert status.active is True
    assert "22/tcp ALLOW IN Anywhere" in status.rules
    assert not any(r.startswith("Status") for r in status.rules)


def test_firewall_status_ufw_inactive(fake_run, fake_which):
    fake_which.add("ufw")
    fake_run.set_response(["pkexec", "ufw", "status", "verbose"], stdout="Status: inactive\n")
    assert security.firewall_status().active is False


def test_firewall_status_firewalld(fake_run, fake_which):
    fake_which.add("firewall-cmd")
    fake_run.set_response(["systemctl", "is-active", "firewalld"], stdout="active\n")
    fake_run.set_response(["pkexec", "firewall-cmd", "--list-all"], stdout="public\n  services: ssh\n")
    status = security.firewall_status()
    assert status.backend == "firewalld"
    assert status.active is True


def test_firewall_status_none_backend(fake_which):
    status = security.firewall_status()
    assert status.backend == "none"
    assert status.active is False


def test_firewall_enable_no_backend_raises(fake_which):
    with pytest.raises(RuntimeError, match="No firewall backend"):
        security.firewall_enable()


def test_firewall_enable_ufw(fake_run, fake_which):
    fake_which.add("ufw")
    security.firewall_enable()
    assert fake_run.last_call() == ["pkexec", "ufw", "--force", "enable"]


def test_firewall_allow_port_firewalld_reloads_on_success(fake_run, fake_which):
    fake_which.add("firewall-cmd")
    fake_run.set_response(["pkexec", "firewall-cmd", "--permanent", "--add-port"], returncode=0)
    security.firewall_allow_port("8080", "tcp")
    assert fake_run.call_containing("--reload") is not None


def test_firewall_allow_port_firewalld_skips_reload_on_failure(fake_run, fake_which):
    fake_which.add("firewall-cmd")
    fake_run.set_response(["pkexec", "firewall-cmd", "--permanent", "--add-port"], returncode=1)
    security.firewall_allow_port("8080", "tcp")
    assert fake_run.call_containing("--reload") is None


# --------------------------------------------------------------- ssh_status --

def test_ssh_status_not_installed(fake_run, fake_which):
    fake_run.set_response(["systemctl", "is-active", "sshd"], stdout="inactive\n")
    status = security.ssh_status()
    assert status.installed is False
    assert status.running is False


def test_ssh_status_parses_config(fake_run, fake_which, monkeypatch, tmp_path):
    fake_which.add("sshd")
    conf = tmp_path / "sshd_config"
    conf.write_text(
        "# comment\nPort 2222\nPermitRootLogin no\nPasswordAuthentication yes\n"
    )
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)
    fake_run.set_response(["systemctl", "is-active", "sshd"], stdout="active\n")
    fake_run.set_response(["cat", str(conf)], stdout=conf.read_text())

    status = security.ssh_status()
    assert status.installed is True
    assert status.running is True
    assert status.port == "2222"
    assert status.root_login == "no"
    assert status.password_auth == "yes"


def test_ssh_status_defaults_when_config_missing(fake_run, fake_which, monkeypatch, tmp_path):
    monkeypatch.setattr(security, "SSHD_CONFIG", tmp_path / "does-not-exist")
    fake_run.set_response(["systemctl", "is-active", "sshd"], stdout="inactive\n")
    status = security.ssh_status()
    assert status.port == "22"
    assert status.root_login == "unknown"


# --------------------------------------------------------------- _set_sshd_option --

def test_set_sshd_option_replaces_existing_line(
    fake_run, fake_which, privilege_paths, monkeypatch, tmp_path
):
    conf = tmp_path / "sshd_config"
    conf.write_text("PermitRootLogin yes\n")
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)

    fake_run.set_response(["grep", "-Ei"], stdout="PermitRootLogin yes\n")
    fake_run.set_response(["pkexec", "sed", "-i"], returncode=0)
    fake_run.set_response(["pkexec", "sshd", "-t"], returncode=0)
    fake_run.set_response(["pkexec", "systemctl", "reload", "sshd"], returncode=0)

    result = security.set_ssh_root_login(False)

    assert result.ok
    assert fake_run.call_containing("sed") is not None
    # append form ("bash -c ... >> ...") must NOT have been used
    assert fake_run.call_containing("bash") is None


def test_set_sshd_option_appends_when_missing(
    fake_run, fake_which, privilege_paths, monkeypatch, tmp_path
):
    conf = tmp_path / "sshd_config"
    conf.write_text("# nothing relevant here\n")
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)

    fake_run.set_response(["grep", "-Ei"], stdout="")  # not found -> append path
    fake_run.set_response(["pkexec", "bash", "-c"], returncode=0)
    fake_run.set_response(["pkexec", "sshd", "-t"], returncode=0)
    fake_run.set_response(["pkexec", "systemctl", "reload", "sshd"], returncode=0)

    result = security.set_ssh_port(2222)

    assert result.ok
    append_call = fake_run.call_containing("bash")
    assert append_call is not None
    assert "Port 2222" in append_call[-1]


def test_set_sshd_option_rolls_back_on_failed_validation(
    fake_run, fake_which, privilege_paths, monkeypatch, tmp_path
):
    """The critical safety path: if `sshd -t` fails after the edit, the
    previous config must be restored and sshd must NEVER be reloaded."""
    conf = tmp_path / "sshd_config"
    conf.write_text("PermitRootLogin yes\n")
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)

    fake_run.set_response(["grep", "-Ei"], stdout="PermitRootLogin yes\n")
    fake_run.set_response(["pkexec", "sed", "-i"], returncode=0)
    fake_run.set_response(["pkexec", "sshd", "-t"], returncode=1, stderr="syntax error on line 1")
    fake_run.set_response(["pkexec", "tee", str(conf)], returncode=0)

    with pytest.raises(RuntimeError, match="failed validation"):
        security.set_ssh_root_login(False)

    # restore_file should have been invoked (tee to the original path)
    assert fake_run.call_containing("tee") is not None
    # reload must never have been called
    assert fake_run.call_containing("reload") is None


def test_set_sshd_option_no_backup_available_still_raises_but_skips_restore(
    fake_run, fake_which, privilege_paths, monkeypatch, tmp_path
):
    """If the config didn't exist before (nothing to back up), a failed
    validation should still raise, without attempting a restore call."""
    conf = tmp_path / "sshd_config"  # never created
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)

    fake_run.set_response(["grep", "-Ei"], stdout="")
    fake_run.set_response(["pkexec", "bash", "-c"], returncode=0)
    fake_run.set_response(["pkexec", "sshd", "-t"], returncode=1, stderr="bad config")

    with pytest.raises(RuntimeError, match="failed validation"):
        security.set_ssh_port(2222)

    assert fake_run.call_containing("tee") is None


def test_set_sshd_option_stops_early_if_edit_command_fails(
    fake_run, fake_which, privilege_paths, monkeypatch, tmp_path
):
    conf = tmp_path / "sshd_config"
    conf.write_text("PermitRootLogin yes\n")
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)

    fake_run.set_response(["grep", "-Ei"], stdout="PermitRootLogin yes\n")
    fake_run.set_response(["pkexec", "sed", "-i"], returncode=1, stderr="sed failed")

    result = security.set_ssh_root_login(False)
    assert not result.ok
    # sshd -t should never be reached if the edit itself failed
    assert fake_run.call_containing("sshd") is None


def test_sudoers_check_prefers_stdout(fake_run):
    fake_run.set_response(["visudo", "-cf", "/etc/sudoers"], stdout="/etc/sudoers: parsed OK\n")
    assert "parsed OK" in security.sudoers_check()


# --------------------------------------------------------------- extended SSH status (CIS depth) --

def test_ssh_status_parses_all_cis_fields(fake_run, fake_which, monkeypatch, tmp_path):
    fake_which.add("sshd")
    conf = tmp_path / "sshd_config"
    conf.write_text(
        "Port 22\n"
        "PermitRootLogin no\n"
        "PasswordAuthentication no\n"
        "LogLevel VERBOSE\n"
        "X11Forwarding no\n"
        "MaxAuthTries 4\n"
        "IgnoreRhosts yes\n"
        "HostbasedAuthentication no\n"
        "PermitEmptyPasswords no\n"
        "PermitUserEnvironment no\n"
    )
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)
    fake_run.set_response(["systemctl", "is-active", "sshd"], stdout="active\n")
    fake_run.set_response(["cat", str(conf)], stdout=conf.read_text())

    status = security.ssh_status()
    assert status.log_level == "VERBOSE"
    assert status.x11_forwarding == "no"
    assert status.max_auth_tries == "4"
    assert status.ignore_rhosts == "yes"
    assert status.hostbased_authentication == "no"
    assert status.permit_empty_passwords == "no"
    assert status.permit_user_environment == "no"


def test_ssh_status_permit_fields_dont_collide_with_each_other_or_root_login(fake_run, fake_which, monkeypatch, tmp_path):
    """PermitRootLogin, PermitEmptyPasswords, and PermitUserEnvironment all
    start with 'permit' - confirm each line only ever sets its own field."""
    fake_which.add("sshd")
    conf = tmp_path / "sshd_config"
    conf.write_text("PermitRootLogin yes\nPermitEmptyPasswords no\nPermitUserEnvironment yes\n")
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)
    fake_run.set_response(["systemctl", "is-active", "sshd"], stdout="active\n")
    fake_run.set_response(["cat", str(conf)], stdout=conf.read_text())

    status = security.ssh_status()
    assert status.root_login == "yes"
    assert status.permit_empty_passwords == "no"
    assert status.permit_user_environment == "yes"


def test_set_ssh_log_level_valid_values(fake_run, fake_which):
    security.set_ssh_log_level("VERBOSE")
    assert any("LogLevel VERBOSE" in arg for call in fake_run.calls for arg in call)


def test_set_ssh_log_level_rejects_invalid_value():
    with pytest.raises(ValueError):
        security.set_ssh_log_level("DEBUG3")


def test_set_ssh_x11_forwarding(fake_run, fake_which):
    security.set_ssh_x11_forwarding(False)
    assert any("X11Forwarding no" in arg for call in fake_run.calls for arg in call)


def test_set_ssh_max_auth_tries(fake_run, fake_which):
    security.set_ssh_max_auth_tries(4)
    assert any("MaxAuthTries 4" in arg for call in fake_run.calls for arg in call)


def test_set_ssh_max_auth_tries_rejects_less_than_one():
    with pytest.raises(ValueError):
        security.set_ssh_max_auth_tries(0)


def test_set_ssh_ignore_rhosts(fake_run, fake_which):
    security.set_ssh_ignore_rhosts(True)
    assert any("IgnoreRhosts yes" in arg for call in fake_run.calls for arg in call)


def test_set_ssh_hostbased_authentication(fake_run, fake_which):
    security.set_ssh_hostbased_authentication(False)
    assert any("HostbasedAuthentication no" in arg for call in fake_run.calls for arg in call)


def test_set_ssh_permit_empty_passwords(fake_run, fake_which):
    security.set_ssh_permit_empty_passwords(False)
    assert any("PermitEmptyPasswords no" in arg for call in fake_run.calls for arg in call)


def test_set_ssh_permit_user_environment(fake_run, fake_which):
    security.set_ssh_permit_user_environment(False)
    assert any("PermitUserEnvironment no" in arg for call in fake_run.calls for arg in call)
