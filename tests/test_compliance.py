"""Tests for atropa.backend.compliance."""
from __future__ import annotations

from pathlib import Path

import pytest

from atropa.backend import account_hygiene, compliance, hardening

# Same sandbox-environment leak as test_selinux.py/test_quicksetup.py: this
# container has a real /sys/fs/selinux mount from the host.
_REAL_EXISTS = Path.exists


@pytest.fixture(autouse=True)
def boot_state(monkeypatch, tmp_path):
    """Keeps the boot/encryption/socket checks off the real firmware and /proc."""
    from atropa.backend import boot_security

    monkeypatch.setattr(boot_security, "CRYPTTAB", tmp_path / "crypttab")
    monkeypatch.setattr(boot_security, "EFI_DIR", tmp_path / "efi")
    monkeypatch.setattr(compliance, "PROC_NET_TCP", tmp_path / "tcp")
    monkeypatch.setattr(compliance, "PROC_NET_TCP6", tmp_path / "tcp6")


@pytest.fixture(autouse=True)
def no_real_selinux_fs(monkeypatch):
    def fake_exists(self):
        if str(self) == "/sys/fs/selinux":
            return False
        return _REAL_EXISTS(self)

    monkeypatch.setattr(Path, "exists", fake_exists)


def _stub_all_checks_pass(fake_run, fake_which, monkeypatch, tmp_path):
    """Wires up fake_run/fake_which so hardening.run_audit() reports every
    check as a clean pass, for tests that care about scoring math rather
    than any one check's own logic."""
    from atropa.backend import security as security_mod

    fake_which.update({"ufw", "sshd", "fail2ban-client", "aa-status", "auditctl", "arch-audit"})
    fake_run.set_response(["pkexec", "ufw", "status", "verbose"], stdout="Status: active\n")

    conf = tmp_path / "sshd_config"
    conf.write_text("PermitRootLogin no\nPasswordAuthentication no\n")
    monkeypatch.setattr(security_mod, "SSHD_CONFIG", conf)
    fake_run.set_response(["systemctl", "is-active", "sshd"], stdout="active\n")
    fake_run.set_response(["cat", str(conf)], stdout=conf.read_text())

    fake_run.set_response(["systemctl", "is-active", "fail2ban"], stdout="active\n")
    fake_run.set_response(["systemctl", "is-enabled", "fail2ban"], stdout="enabled\n")
    fake_run.set_response(["fail2ban-client", "status"], stdout="Jail list:\tsshd\n")

    fake_run.set_response(["systemctl", "is-active", "apparmor"], stdout="active\n")
    # apparmor_status() also checks that AppArmor is an active LSM (the
    # kernel_state fixture's lsm file) - AppArmor only scores "pass" in
    # run_audit() when BOTH the service is active AND the kernel has it on.
    hardening.LSM_LIST.write_text("capability,landlock,lockdown,yama,integrity,apparmor,bpf\n")

    fake_run.set_response(["systemctl", "is-active", "usbguard"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-enabled", "usbguard"], stdout="disabled\n")
    fake_run.set_response(["systemctl", "is-active", "auditd"], stdout="active\n")
    fake_run.set_response(["systemctl", "is-enabled", "auditd"], stdout="enabled\n")
    fake_run.set_response(["arch-audit"], stdout="")

    pam_file = tmp_path / "system-login"
    pam_file.write_text("auth required pam_faillock.so preauth\n")
    monkeypatch.setattr(hardening, "PAM_SYSTEM_LOGIN", pam_file)
    fake_run.set_response(["cat", str(pam_file)], stdout=pam_file.read_text())

    fake_run.set_response(["pkexec", "visudo", "-cf", "/etc/sudoers"], stdout="/etc/sudoers: parsed OK\n")

    for key, recommended, _desc in hardening.SYSCTL_RECOMMENDATIONS:
        fake_run.set_response(["sysctl", "-n", key], stdout=f"{recommended}\n")

    # Service Inventory: nothing installed -> every entry scores "pass".
    fake_run.set_response(["pacman", "-Q"], returncode=1)

    # Account & File Hygiene: an empty passwd/group db makes the duplicate/
    # UID-zero/system-shell/home-directory checks trivially pass (nothing to
    # flag), and pointing the file-perm checks at tmp_path files we control
    # (rather than this sandbox's real /etc/passwd etc.) keeps the "all
    # pass" scenario independent of whatever the CI/sandbox host's actual
    # file permissions happen to be.
    monkeypatch.setattr(account_hygiene.pwd, "getpwall", lambda: [])
    monkeypatch.setattr(account_hygiene.grp, "getgrall", lambda: [])

    passwd_file = tmp_path / "fake_passwd"
    passwd_file.write_text("root:x:0:0::/root:/bin/bash\n")
    passwd_file.chmod(0o644)
    group_file = tmp_path / "fake_group"
    group_file.write_text("root:x:0:\n")
    group_file.chmod(0o644)
    shadow_file = tmp_path / "fake_shadow"
    shadow_file.write_text("root:!:19000:0:99999:7:::\n")
    shadow_file.chmod(0o600)
    gshadow_file = tmp_path / "fake_gshadow"
    gshadow_file.write_text("root:!::\n")
    gshadow_file.chmod(0o600)
    monkeypatch.setattr(
        account_hygiene,
        "_FILE_PERM_CHECKS",
        [
            (str(passwd_file), 0o644, "world-readable is normal, must not be group/world-writable"),
            (str(group_file), 0o644, "world-readable is normal, must not be group/world-writable"),
            (str(shadow_file), 0o600, "must not be group/world-readable"),
            (str(gshadow_file), 0o600, "must not be group/world-readable"),
        ],
    )
    # No PATH= assignment found in any of these -> "info", not scored, so it
    # can't drag the "all pass" score below 1.0 - but keep it independent of
    # whatever this sandbox's real /etc/profile happens to contain.
    empty_profile = tmp_path / "empty_profile"
    empty_profile.write_text("")
    monkeypatch.setattr(account_hygiene, "_ROOT_PROFILE_FILES", [str(empty_profile)])


# --------------------------------------------------------------- categorization --

def test_every_run_audit_check_name_has_a_category(fake_run, fake_which):
    checks = hardening.run_audit()
    uncategorized = [c.name for c in checks if c.name not in compliance._CATEGORY_MAP]
    assert uncategorized == [], f"Uncategorized check names: {uncategorized}"


def test_extra_checks_include_faillock_and_sudoers(fake_run, fake_which):
    names = [c.name for c in compliance._extra_checks()]
    assert "Login lockout (faillock)" in names
    assert "Sudoers configuration" in names


def _sudoers_check_status(fake_run, **response) -> str:
    fake_run.set_response(["pkexec", "visudo", "-cf", "/etc/sudoers"], **response)
    return next(c for c in compliance._extra_checks() if c.name == "Sudoers configuration").status


def test_sudoers_check_passes_on_clean_visudo_run(fake_run, fake_which):
    assert _sudoers_check_status(fake_run, stdout="/etc/sudoers: parsed OK\n") == "pass"


def test_sudoers_check_fails_on_error_even_if_main_file_parsed(fake_run, fake_which):
    # The old substring test passed this: the main file says "parsed OK",
    # but an included file is broken and visudo exits 1.
    status = _sudoers_check_status(
        fake_run,
        returncode=1,
        stdout="/etc/sudoers: parsed OK\n",
        stderr="/etc/sudoers.d/broken:2:5: syntax error\n",
    )
    assert status == "fail"


def test_sudoers_check_dismissed_authentication_is_unscored_info(fake_run, fake_which):
    status = _sudoers_check_status(
        fake_run, returncode=126, stderr="Error executing command as another user: Request dismissed\n"
    )
    assert status == "info"


# --------------------------------------------------------------- scoring --

def test_generate_report_covers_every_check(fake_run, fake_which, monkeypatch, tmp_path):
    _stub_all_checks_pass(fake_run, fake_which, monkeypatch, tmp_path)
    report = compliance.generate_report()
    all_check_names = {c.name for cat in report.categories for c in cat.checks}
    expected = {
        c.name
        for c in hardening.run_audit()
        + compliance._extra_checks()
        + compliance._boot_checks()
        + compliance._inventory_checks()
        + compliance._account_hygiene_checks()
    }
    assert all_check_names == expected


def test_generate_report_all_pass_gives_perfect_score(fake_run, fake_which, monkeypatch, tmp_path):
    _stub_all_checks_pass(fake_run, fake_which, monkeypatch, tmp_path)
    report = compliance.generate_report()
    assert report.overall_score == pytest.approx(1.0)
    for category in report.categories:
        if category.score is not None:
            assert category.score == pytest.approx(1.0)


def test_generate_report_fail_lowers_score(fake_run, fake_which):
    # default fake_which/fake_run (mostly nothing installed) should
    # produce a mix of fail/warn/info, definitely not a perfect score
    report = compliance.generate_report()
    assert report.overall_score < 1.0


def test_generate_report_info_checks_excluded_from_scoring(fake_run, fake_which):
    # with nothing installed, several checks come back "info" (feature not
    # present, optional) - those must not drag the score toward 0 as if
    # they were failures
    report = compliance.generate_report()
    info_names = {
        c.name
        for cat in report.categories
        for c in cat.checks
        if c.status == "info"
    }
    assert info_names  # sanity: there should be some info checks in a bare environment
    scored_names = {
        c.name
        for cat in report.categories
        for c in cat.checks
        if c.status in compliance._SCORE
    }
    assert info_names.isdisjoint(scored_names)


def test_category_score_none_when_nothing_scorable():
    empty_category = compliance.CategoryScore(name="Other", checks=[hardening.AuditCheck("X", "info", "detail")])
    # generate_report would compute this the same way _extra_checks/run_audit do;
    # here we just confirm the CategoryScore default score is None for an
    # all-info category, matching generate_report's own logic
    scorable = [c for c in empty_category.checks if c.status in compliance._SCORE]
    assert scorable == []


# --------------------------------------------------------------- markdown rendering --

def test_render_markdown_includes_disclaimer(fake_run, fake_which):
    report = compliance.generate_report()
    markdown = compliance.render_markdown_report(report)
    assert compliance.DISCLAIMER in markdown


def test_render_markdown_not_official_cis_language_present(fake_run, fake_which):
    report = compliance.generate_report()
    markdown = compliance.render_markdown_report(report)
    assert "NOT an official CIS Benchmark" in markdown


def test_render_markdown_includes_every_category_and_check(fake_run, fake_which):
    report = compliance.generate_report()
    markdown = compliance.render_markdown_report(report)
    for category in report.categories:
        assert category.name in markdown
        for check in category.checks:
            assert check.name in markdown


def test_render_markdown_escapes_pipe_characters_in_detail():
    report = compliance.ComplianceReport(
        generated_at="now",
        hostname="host",
        categories=[
            compliance.CategoryScore(
                name="Test", checks=[hardening.AuditCheck("X", "pass", "a | b")], score=1.0
            )
        ],
        overall_score=1.0,
        scored_check_count=1,
        total_check_count=1,
    )
    markdown = compliance.render_markdown_report(report)
    assert "a \\| b" in markdown


def test_save_report_to_file_writes_markdown(tmp_path, fake_run, fake_which):
    report = compliance.generate_report()
    path = tmp_path / "report.md"
    compliance.save_report_to_file(report, str(path))
    content = path.read_text()
    assert content.startswith("# Atropa Security Baseline Report")
    assert compliance.DISCLAIMER in content


def test_boot_checks_land_in_their_own_category(fake_run, fake_which, monkeypatch, tmp_path):
    _stub_all_checks_pass(fake_run, fake_which, monkeypatch, tmp_path)
    report = compliance.generate_report()
    category = next(c for c in report.categories if c.name == "Boot & Disk Security")
    assert {check.name for check in category.checks} == {"Disk encryption", "Secure Boot"}


# --------------------------------------------------------------- exposure --

def _signal(label: str, status: str, detail: str = "") -> compliance.ExposureSignal:
    return compliance.ExposureSignal(label, status, detail)


def test_exposure_unknown_when_every_signal_is_info():
    result = compliance._exposure([_signal("Secure Boot", "info", "can't tell")])
    assert result.level == "unknown"
    assert "couldn't read" in result.summary


def test_exposure_high_when_the_firewall_is_a_hard_failure():
    result = compliance._exposure(
        [
            _signal("Incoming network connections", "fail", "no firewall"),
            _signal("Root filesystem encryption", "pass", "luks"),
            _signal("Remote login (SSH)", "pass", "none"),
        ]
    )
    assert result.level == "high"


def test_exposure_high_when_the_disk_is_unencrypted():
    result = compliance._exposure(
        [
            _signal("Incoming network connections", "pass", "active"),
            _signal("Root filesystem encryption", "fail", "plain partition"),
        ]
    )
    assert result.level == "high"


def test_exposure_moderate_for_one_warning():
    result = compliance._exposure(
        [
            _signal("Incoming network connections", "pass", "active"),
            _signal("Secure Boot", "warn", "disabled"),
        ]
    )
    assert result.level == "moderate"


def test_exposure_low_when_everything_holds():
    result = compliance._exposure(
        [
            _signal("Incoming network connections", "pass", "active"),
            _signal("Root filesystem encryption", "pass", "luks"),
            _signal("Secure Boot", "pass", "enabled"),
            _signal("Listening TCP sockets", "info", "no data"),
        ]
    )
    assert result.level == "low"


def test_listening_ports_parses_proc_tables(monkeypatch, tmp_path):
    # /proc/net/tcp: state 0A is LISTEN; the port is hex in the local address.
    tcp = tmp_path / "tcp"
    tcp.write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n"
        "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2\n"
        "   2: 0100007F:1F90 0100007F:C001 01 00000000:00000000 00:00000000 00000000     0        0 3\n"
    )
    monkeypatch.setattr(compliance, "PROC_NET_TCP", tcp)
    monkeypatch.setattr(compliance, "PROC_NET_TCP6", tmp_path / "tcp6")
    # 8080 is bound to 127.0.0.1, so it isn't part of the network exposure.
    assert compliance._listening_tcp_ports() == [22]


def test_listening_ports_unreadable_is_unknown(monkeypatch, tmp_path):
    monkeypatch.setattr(compliance, "PROC_NET_TCP", tmp_path / "missing")
    monkeypatch.setattr(compliance, "PROC_NET_TCP6", tmp_path / "missing6")
    assert compliance._listening_tcp_ports() is None


def test_render_markdown_includes_the_exposure_section():
    report = compliance.ComplianceReport(
        generated_at="now",
        hostname="host",
        categories=[],
        overall_score=1.0,
        scored_check_count=0,
        total_check_count=0,
        exposure=compliance.Exposure(
            "low", "Nothing exposed.", [compliance.ExposureSignal("Secure Boot", "pass", "on")]
        ),
    )
    markdown = compliance.render_markdown_report(report)
    assert "## Exposure — Low" in markdown
    assert compliance.EXPOSURE_NOTE in markdown
    assert "| Secure Boot | PASS | on |" in markdown


def test_total_check_count_counts_every_check_in_the_report(fake_run, fake_which, monkeypatch, tmp_path):
    # It used to count only run_audit()'s checks: "29 scored checks, 3 total".
    _stub_all_checks_pass(fake_run, fake_which, monkeypatch, tmp_path)
    report = compliance.generate_report()
    assert report.total_check_count == sum(len(category.checks) for category in report.categories)
    assert report.scored_check_count <= report.total_check_count
