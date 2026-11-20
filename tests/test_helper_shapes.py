"""
The helper's command validators against what the backend really sends.

The literal-argv test in test_helper.py covers calls written out in full;
these run the backend functions that build their argv at runtime and check
that every privileged call they make passes the helper, in the tier the
design puts it in. Then the other direction: shapes an attacker reusing a
remembered authorization would want, which must be refused.
"""

from __future__ import annotations

import pytest

from atropa import helper
from atropa.backend import (
    apparmor, disk_health, network, pacman, security, selinux, services, system_config, users,
)


def _privileged(fake_run) -> list[list[str]]:
    return [call[1:] for call in fake_run.calls if call[:1] == ["pkexec"]]


def _tier(argv: list[str]) -> str:
    if argv[0] in helper.COMMANDS:
        return helper.validate_command(argv)[0]
    return helper.ASK if helper.needs_fresh_auth(argv) else helper.KEEP


@pytest.mark.parametrize(
    ("call", "tier"),
    [
        (lambda: services.start("sshd.service"), helper.KEEP),
        (lambda: services.stop("cups.socket"), helper.KEEP),
        (lambda: services.restart("systemd-zram-setup@zram0.service"), helper.KEEP),
        (lambda: services.enable("fstrim.timer", now=True), helper.KEEP),
        (lambda: services.disable("bluetooth.service", now=False), helper.KEEP),
        (lambda: pacman.remove(["foo", "lib32-bar"], purge_config=True), helper.KEEP),
        (lambda: pacman.remove(["python-gobject"]), helper.KEEP),
        (lambda: network.connect_wifi("Café net"), helper.KEEP),
        (lambda: network.set_static_ip("Wired 1", "192.168.1.50/24", "192.168.1.1", ["1.1.1.1", "9.9.9.9"]), helper.KEEP),
        (lambda: network.set_dhcp("Wired 1"), helper.KEEP),
        (lambda: network.toggle_networking(False), helper.KEEP),
        (lambda: selinux.set_boolean("ssh_sysadm_login", True), helper.KEEP),
        (lambda: selinux.set_booleans({"a_b": True, "c_d": False}), helper.KEEP),
        (lambda: selinux.restorecon("/home/me/.ssh"), helper.KEEP),
        (lambda: system_config.set_hostname("my-laptop"), helper.KEEP),
        (lambda: system_config.set_timezone("Europe/Amsterdam"), helper.KEEP),
        (lambda: system_config.set_locale("nl_NL.UTF-8"), helper.KEEP),
        (lambda: system_config.set_keymap("us"), helper.KEEP),
        (lambda: disk_health.vacuum_journal("500M"), helper.KEEP),
        (lambda: users.create_user("bob", full_name="Bob B", extra_groups=["wheel", "audio"]), helper.ASK),
        (lambda: users.modify_user("bob", full_name="Robert", lock=True), helper.ASK),
        (lambda: users.delete_user("bob", remove_home=True), helper.ASK),
        (lambda: users.set_password("bob", "hunter2"), helper.ASK),
        (lambda: users.create_group("devs"), helper.ASK),
        (lambda: users.delete_group("devs"), helper.ASK),
    ],
)
def test_backend_argv_passes_the_helper_in_its_tier(fake_run, fake_which, call, tier):
    fake_which.update({"nmcli", "setsebool", "restorecon", "useradd", "usermod", "userdel", "chpasswd"})
    call()
    sent = _privileged(fake_run)
    assert sent, "the call made no privileged command"
    for argv in sent:
        assert _tier(argv) == tier, argv


def test_apparmor_mode_change_passes(fake_run, fake_which, tmp_path, monkeypatch):
    fake_which.add("aa-complain")
    monkeypatch.setattr(helper, "_resolved", lambda path: helper._normal(path))
    apparmor.set_profile_mode("/etc/apparmor.d/usr.bin.example", "complain")
    [argv] = _privileged(fake_run)
    assert helper.validate_command(argv) == (helper.KEEP, ["/etc/apparmor.d/usr.bin.example"])


def test_firewall_ports_pass(fake_run, fake_which):
    fake_which.add("ufw")
    security.firewall_allow_port("2222")
    security.firewall_deny_port("51820", "udp")
    for argv in _privileged(fake_run):
        assert helper.validate_command(argv)[0] == helper.KEEP


def test_selinux_mode_change_is_ask_tier(fake_run, fake_which, tmp_path, monkeypatch):
    config = tmp_path / "config"
    config.write_text("SELINUX=enforcing\n")
    monkeypatch.setattr(selinux, "SELINUX_CONFIG", config)
    selinux.set_mode(False)
    sent = _privileged(fake_run)
    assert ["setenforce", "0"] in sent
    # (the config edit went to a tmp path here; /etc/selinux/config itself
    # is in test_root_equivalent_operations_need_the_ask_helper)
    assert _tier(["setenforce", "0"]) == helper.ASK


# --------------------------------------------------------------- refused --

@pytest.mark.parametrize(
    "argv",
    [
        # package files and alternative configs run arbitrary root code
        ["pacman", "-U", "/home/me/evil.pkg.tar.zst"],
        ["pacman", "-S", "--needed", "--noconfirm", "--config", "/home/me/pacman.conf", "x"],
        ["pacman", "-S", "--needed", "--noconfirm", "--hookdir=/home/me/hooks", "x"],
        ["pacman", "-S", "--needed", "--noconfirm", "-r", "/home/me/root"],
        ["pacman", "-Syu", "--noconfirm", "extra"],
        ["pacman", "-Rs", "--noconfirm"],
        # unit files from $HOME, other verbs
        ["systemctl", "enable", "/home/me/evil.service"],
        ["systemctl", "link", "/home/me/evil.service"],
        ["systemctl", "start", "--now", "sshd"],
        ["systemctl", "edit", "sshd"],
        ["systemctl", "set-environment", "LD_PRELOAD=/home/me/x.so"],
        ["systemctl", "start", "-H", "host"],
        # a different make target or a second -C
        ["make", "-C", "/tmp", "install", "load", "-f", "/home/me/Makefile"],
        ["make", "-C", "/tmp", "shell"],
        # kernel knobs and file reads
        ["sysctl", "-w", "kernel.core_pattern=|/home/me/x"],
        ["cat", "/etc/shadow"],
        ["cat", "--", "/etc/gshadow"],
        ["grep", "-r", "", "/etc"],
        ["systemd-tmpfiles", "--create", "/home/me/evil.conf"],
        # helpers reused for something else
        ["sbctl", "sign", "-s", "/home/me/evil.efi"],
        ["sbctl", "sign", "-s", "-o", "/boot/x", "/home/me/evil.efi"],
        ["semodule", "-i", "/home/me/notamodule"],
        ["journalctl", "--vacuum-size=1G", "--rotate"],
        ["journalctl", "-f"],
        ["smartctl", "-H", "--json", "/dev/../etc/passwd"],
        ["smartctl", "-s", "on", "/dev/sda"],
        ["ufw", "allow", "from", "any"],
        ["ufw", "reset"],
        ["flatpak", "install", "-y", "evil"],
        ["fwupdmgr", "install", "/home/me/firmware.cab"],
        ["nmcli", "connection", "modify", "Wired 1", "connection.permissions", ""],
        ["nmcli", "connection", "modify", "Wired 1", "ipv4.addresses", "x", "ipv4.gateway", "1.1.1.1",
         "ipv4.dns", "", "ipv4.method", "manual"],
        ["nmcli", "device", "disconnect", "--help"],
        ["hostnamectl", "set-hostname", "-H"],
        ["timedatectl", "set-timezone", "../../home/me/zone"],
        ["localectl", "set-locale", "LANG=x", "LC_ALL=y"],
        ["setsebool", "-P", "allow_execmem", "maybe"],
        ["bootctl", "set-timeout", "--esp-path=/home/me"],
        ["grub-mkconfig", "-o", "/etc/sudoers"],
        ["visudo", "-f", "/etc/sudoers"],
        ["setenforce", "Permissive"],
        ["useradd", "-o", "-u", "0", "toor"],
        ["useradd", "-m", "-s", "/home/me/shell", "bob"],
        ["usermod", "-p", "hash", "root"],
        ["userdel", "root"],
        ["chpasswd", "-e"],
        ["semanage", "fcontext", "-a", "-t", "bin_t", "/home/me/x"],
    ],
)
def test_shapes_atropa_never_sends_are_refused(argv):
    with pytest.raises(helper.Refused):
        helper.validate_command(argv)


@pytest.mark.parametrize(
    "argv",
    [
        ["chpasswd"],
        ["useradd", "-m", "-s", "/bin/bash", "bob"],
        ["usermod", "-G", "wheel", "bob"],
        ["setenforce", "0"],
        ["true"],
        ["sbctl", "enroll-keys", "--microsoft"],
        ["tee", "/etc/pacman.conf"],
        ["tee", "/etc/ssh/sshd_config"],
        ["replace-in-file", "/etc/selinux/config", "^SELINUX=.*$", "SELINUX=permissive"],
        ["tee", "/etc/default/grub"],
        ["tee", "/etc/sysctl.d/99-atropa-hardening.conf"],
        ["tee", "/etc/fail2ban/jail.d/sshd.local"],
        ["tee", "/etc/apparmor.d/usr.bin.example"],
        ["chown", "-R", "-h", "--from=0:0", "1000:1000", "--", "/home/me/refpolicy"],
    ],
)
def test_root_equivalent_operations_need_the_ask_helper(argv):
    assert helper.needs_fresh_auth(argv)
    with pytest.raises(helper.Refused, match="asks for a password every time"):
        helper.handle(argv, b"", tier=helper.KEEP)


@pytest.mark.parametrize(
    "argv",
    [
        ["systemctl", "restart", "sshd"],
        ["pacman", "-Syu", "--noconfirm"],
        ["tee", "/etc/pacman.d/mirrorlist"],
        ["tee", "/etc/locale.gen"],
        ["shadow-status"],
        ["semodule", "-l"],
    ],
)
def test_ordinary_operations_stay_in_the_keep_tier(argv):
    assert not helper.needs_fresh_auth(argv)
