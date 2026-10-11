"""Tests for atropa.backend.security, with emphasis on the SSH hardening
validate-before-reload / auto-rollback path, since a bug there can lock out
remote access."""
from __future__ import annotations

import pytest

from atropa.backend import security
from atropa.backend.privilege import CommandResult


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
    fake_run.set_response(["systemctl", "is-active", "firewalld"], stdout="active\n")
    fake_run.set_response(["pkexec", "firewall-cmd", "--permanent", "--add-port"], returncode=0)
    security.firewall_allow_port("8080", "tcp")
    assert fake_run.call_containing("--reload") is not None


def test_firewall_allow_port_firewalld_skips_reload_on_failure(fake_run, fake_which):
    fake_which.add("firewall-cmd")
    fake_run.set_response(["systemctl", "is-active", "firewalld"], stdout="active\n")
    fake_run.set_response(["pkexec", "firewall-cmd", "--permanent", "--add-port"], returncode=1)
    security.firewall_allow_port("8080", "tcp")
    assert fake_run.call_containing("--reload") is None


def test_firewall_allow_port_firewalld_reports_failed_reload(fake_run, fake_which):
    fake_which.add("firewall-cmd")
    fake_run.set_response(["systemctl", "is-active", "firewalld"], stdout="active\n")
    fake_run.set_response(["pkexec", "firewall-cmd", "--permanent", "--add-port"], returncode=0)
    fake_run.set_response(["pkexec", "firewall-cmd", "--reload"], returncode=1, stderr="reload failed")
    result = security.firewall_allow_port("8080", "tcp")
    assert not result.ok
    assert "reload failed" in result.stderr


def test_firewall_allow_port_firewalld_stopped_uses_offline_cmd(fake_run, fake_which):
    # firewall-cmd fails outright while the daemon is stopped, so the rule
    # has to go into the permanent config via firewall-offline-cmd.
    fake_which.add("firewall-cmd")
    fake_run.set_response(["systemctl", "is-active", "firewalld"], stdout="inactive\n", returncode=3)
    result = security.firewall_allow_port("2222", "tcp")
    assert result.ok
    assert fake_run.last_call() == ["pkexec", "firewall-offline-cmd", "--add-port=2222/tcp"]
    assert fake_run.call_containing("firewall-cmd") is None


def test_firewall_deny_port_firewalld_stopped_uses_offline_cmd(fake_run, fake_which):
    fake_which.add("firewall-cmd")
    fake_run.set_response(["systemctl", "is-active", "firewalld"], stdout="inactive\n", returncode=3)
    security.firewall_deny_port("8080", "udp")
    assert fake_run.last_call() == ["pkexec", "firewall-offline-cmd", "--remove-port=8080/udp"]


# --------------------------------------------------------------- ssh_status --

@pytest.fixture
def sshd_conf(monkeypatch, tmp_path):
    """A temp sshd_config wired in as SSHD_CONFIG - stock-Arch-like by
    default: the settings only as commented-out templates."""
    conf = tmp_path / "sshd_config"
    conf.write_text("#Port 22\n#PermitRootLogin prohibit-password\n#PasswordAuthentication yes\nUsePAM yes\n")
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)
    return conf


def _written_configs(fake_run, conf) -> list[str]:
    """The content of every privileged write to sshd_config, in order."""
    return [text for call, text in zip(fake_run.calls, fake_run.inputs) if call == ["pkexec", "tee", str(conf)]]


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
    assert status.port_explicit is False
    assert status.root_login == "unknown"


def test_ssh_status_port_explicit_only_for_uncommented_port_line(fake_run, fake_which, monkeypatch, tmp_path):
    conf = tmp_path / "sshd_config"
    monkeypatch.setattr(security, "SSHD_CONFIG", conf)

    conf.write_text("#Port 22\n")
    fake_run.set_response(["cat", str(conf)], stdout=conf.read_text())
    assert security.ssh_status().port_explicit is False

    conf.write_text("Port 2222\n")
    fake_run.set_response(["cat", str(conf)], stdout=conf.read_text())
    assert security.ssh_status().port_explicit is True


def test_ssh_status_first_value_wins(fake_run, fake_which, sshd_conf):
    # The old parser let the last line win; sshd keeps the first.
    sshd_conf.write_text("PasswordAuthentication no\nPasswordAuthentication yes\n")
    assert security.ssh_status().password_auth == "no"


def test_ssh_status_reads_includes_where_they_appear(fake_run, fake_which, sshd_conf):
    dropins = sshd_conf.parent / "sshd_config.d"
    dropins.mkdir()
    (dropins / "50-cloud-init.conf").write_text("PasswordAuthentication yes\n")
    sshd_conf.write_text("Include sshd_config.d/*.conf\nPasswordAuthentication no\n")
    assert security.ssh_status().password_auth == "yes"


def test_ssh_status_ignores_match_blocks_until_match_all(fake_run, fake_which, sshd_conf):
    sshd_conf.write_text(
        "PermitRootLogin no\nMatch User admin\n    PermitRootLogin yes\n    PasswordAuthentication yes\n"
        "Match all\nX11Forwarding yes\n"
    )
    status = security.ssh_status()
    assert status.root_login == "no"
    assert status.password_auth == "unknown"  # only set inside the Match block
    assert status.x11_forwarding == "yes"  # global again after Match all


def test_ssh_status_match_inside_an_include_ends_with_that_file(fake_run, fake_which, sshd_conf):
    dropins = sshd_conf.parent / "sshd_config.d"
    dropins.mkdir()
    (dropins / "20-sftp.conf").write_text("Match Group sftp\n    PasswordAuthentication yes\n")
    sshd_conf.write_text("Include sshd_config.d/*.conf\nPasswordAuthentication no\n")
    assert security.ssh_status().password_auth == "no"


def test_ssh_status_collects_every_listening_port(fake_run, fake_which, sshd_conf):
    sshd_conf.write_text("Port 22\nPort 2222\nListenAddress 10.0.0.1:8022\nListenAddress 192.168.1.5\n")
    status = security.ssh_status()
    assert status.port == "22"
    assert status.ports == ["22", "2222", "8022"]


def test_ssh_status_accepts_equals_syntax_and_trailing_comments(fake_run, fake_which, sshd_conf):
    sshd_conf.write_text("PasswordAuthentication=no  # keys only\nMaxAuthTries 3 # CIS\n")
    status = security.ssh_status()
    assert status.password_auth == "no"
    assert status.max_auth_tries == "3"


def test_ssh_status_reports_includes_it_cannot_read(fake_run, fake_which, sshd_conf, monkeypatch):
    from pathlib import Path

    dropins = sshd_conf.parent / "sshd_config.d"
    dropins.mkdir()
    secret = dropins / "40-secret.conf"
    secret.write_text("PasswordAuthentication yes\n")
    sshd_conf.write_text("Include sshd_config.d/*.conf\nPasswordAuthentication no\n")
    real_read_text = Path.read_text

    def read_text(self, *args, **kwargs):
        if self == secret:
            raise PermissionError(13, "Permission denied")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)
    status = security.ssh_status()
    assert status.unreadable_includes == [str(secret)]


def test_effective_falls_back_to_openssh_defaults():
    status = security.SshStatus(installed=True, running=True)
    assert status.effective("password_auth") == "yes"
    assert status.effective("root_login") == "prohibit-password"
    assert security.SshStatus(installed=True, running=True, password_auth="no").effective("password_auth") == "no"


def test_set_ssh_permit_root_login_writes_exact_value(fake_run, fake_which, privilege_paths, sshd_conf):
    sshd_conf.write_text("PermitRootLogin yes\n")
    assert security.set_ssh_permit_root_login("Prohibit-Password").ok
    assert _written_configs(fake_run, sshd_conf) == ["PermitRootLogin prohibit-password\n"]


@pytest.mark.parametrize("value", ["unknown", "", "maybe", "yes/e;touch /tmp/pwned;#"])
def test_set_ssh_permit_root_login_rejects_anything_sshd_does_not_accept(fake_run, fake_which, value):
    # The value ends up inside a sed expression - only sshd's own keywords may get there.
    with pytest.raises(ValueError):
        security.set_ssh_permit_root_login(value)
    assert fake_run.calls == []


# --------------------------------------------------------------- _set_sshd_option --
#
# Edits are checked on the content actually written (stdin of the privileged
# tee), against sshd's own rules: first value wins, Match blocks are
# conditional, Includes are read where they appear.

def test_set_sshd_option_replaces_first_global_line_in_place(fake_run, fake_which, privilege_paths, sshd_conf):
    sshd_conf.write_text("Port 22\nPermitRootLogin yes\nUsePAM yes\n")
    assert security.set_ssh_root_login(False).ok
    assert _written_configs(fake_run, sshd_conf) == ["Port 22\nPermitRootLogin no\nUsePAM yes\n"]
    assert fake_run.last_call() == ["pkexec", "systemctl", "try-reload-or-restart", "sshd"]


def test_set_sshd_option_uncomments_the_template_line(fake_run, fake_which, privilege_paths, sshd_conf):
    assert security.set_ssh_password_auth(False).ok
    assert _written_configs(fake_run, sshd_conf) == [
        "#Port 22\n#PermitRootLogin prohibit-password\nPasswordAuthentication no\nUsePAM yes\n"
    ]


def test_set_sshd_option_never_edits_match_blocks(fake_run, fake_which, privilege_paths, sshd_conf):
    """The old replace-every-line sed rewrote the only PasswordAuthentication
    line - inside a Match block - so the global default (yes) stayed in
    effect while Atropa reported key-only auth."""
    sshd_conf.write_text("Port 22\nMatch Address 192.168.1.0/24\n    PasswordAuthentication yes\n")
    assert security.set_ssh_password_auth(False).ok
    assert _written_configs(fake_run, sshd_conf) == [
        "Port 22\nPasswordAuthentication no\nMatch Address 192.168.1.0/24\n    PasswordAuthentication yes\n"
    ]


def test_set_sshd_option_inserts_before_a_trailing_match_not_at_eof(fake_run, fake_which, privilege_paths, sshd_conf):
    # Appending at the end used to put the line inside the last Match block.
    sshd_conf.write_text("UsePAM yes\nMatch User git\n    AllowTcpForwarding no\n")
    assert security.set_ssh_x11_forwarding(False).ok
    assert _written_configs(fake_run, sshd_conf) == [
        "UsePAM yes\nX11Forwarding no\nMatch User git\n    AllowTcpForwarding no\n"
    ]


def test_set_sshd_option_goes_above_an_include_that_would_override_it(fake_run, fake_which, privilege_paths, sshd_conf):
    dropins = sshd_conf.parent / "sshd_config.d"
    dropins.mkdir()
    (dropins / "50-cloud-init.conf").write_text("PasswordAuthentication yes\n")
    # sshd reads the drop-in first, so this "no" line never applied.
    sshd_conf.write_text("Include sshd_config.d/*.conf\nPasswordAuthentication no\n")

    assert security.set_ssh_password_auth(False).ok
    assert _written_configs(fake_run, sshd_conf) == [
        "PasswordAuthentication no\nInclude sshd_config.d/*.conf\nPasswordAuthentication no\n"
    ]


def test_set_sshd_option_leaves_an_unrelated_include_alone(fake_run, fake_which, privilege_paths, sshd_conf):
    dropins = sshd_conf.parent / "sshd_config.d"
    dropins.mkdir()
    (dropins / "10-keepalive.conf").write_text("ClientAliveInterval 60\n")
    sshd_conf.write_text("Include sshd_config.d/*.conf\n#PasswordAuthentication yes\n")

    assert security.set_ssh_password_auth(False).ok
    assert _written_configs(fake_run, sshd_conf) == ["Include sshd_config.d/*.conf\nPasswordAuthentication no\n"]


def test_set_sshd_option_inserts_when_missing(fake_run, fake_which, privilege_paths, sshd_conf):
    sshd_conf.write_text("# nothing relevant here\n")
    assert security.set_ssh_port(2222).ok
    assert _written_configs(fake_run, sshd_conf) == ["# nothing relevant here\nPort 2222\n"]


def test_set_sshd_option_already_in_effect_writes_nothing(fake_run, fake_which, sshd_conf):
    sshd_conf.write_text("PasswordAuthentication no\n")
    assert security.set_ssh_password_auth(False).ok
    assert fake_run.calls == []


def test_set_sshd_option_restores_the_original_when_validation_fails(
    fake_run, fake_which, privilege_paths, sshd_conf
):
    """The critical safety path: if `sshd -t` rejects the edit, the previous
    content goes back and sshd is NEVER reloaded."""
    sshd_conf.write_text("PermitRootLogin yes\n")
    fake_run.set_response(["pkexec", "sshd", "-t"], returncode=1, stderr="syntax error on line 1")

    with pytest.raises(RuntimeError, match="Restored the previous config"):
        security.set_ssh_root_login(False)

    assert _written_configs(fake_run, sshd_conf) == ["PermitRootLogin no\n", "PermitRootLogin yes\n"]
    assert fake_run.call_containing("try-reload-or-restart") is None


def test_set_sshd_option_says_so_when_the_restore_also_fails(fake_which, privilege_paths, sshd_conf, monkeypatch):
    # The old message claimed "Reverted to the previous config" even when the
    # restore was never attempted or failed.
    sshd_conf.write_text("PermitRootLogin yes\n")
    tee_calls = []

    def fake_privileged(argv, input_text=None, timeout=600):
        if argv[0] == "tee":
            tee_calls.append(input_text)
            ok = len(tee_calls) == 1  # the edit lands, the restore fails
            return CommandResult(0 if ok else 1, "", "" if ok else "Read-only file system")
        if argv[:2] == ["sshd", "-t"]:
            return CommandResult(1, "", "bad option")
        raise AssertionError(f"unexpected privileged call {argv}")

    monkeypatch.setattr(security, "run_privileged", fake_privileged)
    with pytest.raises(RuntimeError, match="ALSO failed") as excinfo:
        security.set_ssh_root_login(False)
    assert "Read-only file system" in str(excinfo.value)


def test_set_sshd_option_missing_config_raises_without_writing(fake_run, fake_which, monkeypatch, tmp_path):
    monkeypatch.setattr(security, "SSHD_CONFIG", tmp_path / "missing")
    with pytest.raises(RuntimeError, match="doesn't exist"):
        security.set_ssh_port(2222)
    assert fake_run.calls == []


def test_set_sshd_option_stops_if_writing_fails(fake_run, fake_which, privilege_paths, sshd_conf):
    sshd_conf.write_text("PermitRootLogin yes\n")
    fake_run.set_response(["pkexec", "tee"], returncode=1, stderr="permission denied")
    assert not security.set_ssh_root_login(False).ok
    assert fake_run.call_containing("-t") is None  # sshd -t never reached


def test_set_ssh_port_refuses_when_sshd_listens_on_several_ports(fake_run, fake_which, sshd_conf):
    # Port lines accumulate - rewriting one of several isn't "setting the port".
    sshd_conf.write_text("Port 22\nPort 443\n")
    with pytest.raises(ValueError, match="several"):
        security.set_ssh_port(2222)
    assert fake_run.calls == []


def test_edit_treats_lines_after_match_all_as_global_again():
    text = "Match User git\n    X11Forwarding yes\nMatch all\nX11Forwarding yes\n"
    out = security._edit_sshd_global_option(text, "X11Forwarding", "no", lambda _value, _key: False)
    assert out == "Match User git\n    X11Forwarding yes\nMatch all\nX11Forwarding no\n"


def test_edit_rewrites_later_dead_duplicates_to_match(fake_run, fake_which):
    text = "PasswordAuthentication yes\nUsePAM yes\nPasswordAuthentication yes\n"
    out = security._edit_sshd_global_option(text, "PasswordAuthentication", "no", lambda _value, _key: False)
    assert out == "PasswordAuthentication no\nUsePAM yes\nPasswordAuthentication no\n"


def test_sudoers_check_runs_visudo_as_root(fake_run, fake_which):
    # sudoers is 0440 root:root - unprivileged visudo can only report "Permission denied".
    fake_run.set_response(["pkexec", "visudo", "-cf", "/etc/sudoers"], stdout="/etc/sudoers: parsed OK\n")
    result = security.sudoers_check()
    assert result.ok
    assert "parsed OK" in result.stdout
    assert fake_run.last_call() == ["pkexec", "visudo", "-cf", "/etc/sudoers"]


def test_sudoers_check_reports_visudo_failure_via_exit_status(fake_run, fake_which):
    fake_run.set_response(
        ["pkexec", "visudo", "-cf", "/etc/sudoers"], returncode=1, stderr=">>> /etc/sudoers: syntax error near line 9 <<<\n"
    )
    assert not security.sudoers_check().ok


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


def test_set_ssh_log_level_valid_values(fake_run, fake_which, privilege_paths, sshd_conf):
    security.set_ssh_log_level("VERBOSE")
    assert "LogLevel VERBOSE\n" in _written_configs(fake_run, sshd_conf)[0]


def test_set_ssh_log_level_rejects_invalid_value():
    with pytest.raises(ValueError):
        security.set_ssh_log_level("DEBUG3")


def test_set_ssh_x11_forwarding(fake_run, fake_which, privilege_paths, sshd_conf):
    security.set_ssh_x11_forwarding(False)
    assert "X11Forwarding no\n" in _written_configs(fake_run, sshd_conf)[0]


def test_set_ssh_max_auth_tries(fake_run, fake_which, privilege_paths, sshd_conf):
    security.set_ssh_max_auth_tries(4)
    assert "MaxAuthTries 4\n" in _written_configs(fake_run, sshd_conf)[0]


def test_set_ssh_max_auth_tries_rejects_less_than_one():
    with pytest.raises(ValueError):
        security.set_ssh_max_auth_tries(0)


def test_set_ssh_ignore_rhosts(fake_run, fake_which, privilege_paths, sshd_conf):
    security.set_ssh_ignore_rhosts(True)
    assert "IgnoreRhosts yes\n" in _written_configs(fake_run, sshd_conf)[0]


def test_set_ssh_hostbased_authentication(fake_run, fake_which, privilege_paths, sshd_conf):
    security.set_ssh_hostbased_authentication(False)
    assert "HostbasedAuthentication no\n" in _written_configs(fake_run, sshd_conf)[0]


def test_set_ssh_permit_empty_passwords(fake_run, fake_which, privilege_paths, sshd_conf):
    security.set_ssh_permit_empty_passwords(False)
    assert "PermitEmptyPasswords no\n" in _written_configs(fake_run, sshd_conf)[0]


def test_set_ssh_permit_user_environment(fake_run, fake_which, privilege_paths, sshd_conf):
    security.set_ssh_permit_user_environment(False)
    assert "PermitUserEnvironment no\n" in _written_configs(fake_run, sshd_conf)[0]
