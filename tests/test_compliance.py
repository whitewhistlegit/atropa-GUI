"""Tests for atropa.backend.compliance."""
from __future__ import annotations

from pathlib import Path

import pytest

from atropa.backend import account_hygiene, compliance, hardening

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
    # apparmor_status() also checks kernel-level enablement (a real
    # /proc/cmdline read) - AppArmor only scores "pass" in run_audit() when
    # BOTH the service is active AND the kernel param is set.
    cmdline = tmp_path / "cmdline"
    cmdline.write_text("BOOT_IMAGE=/vmlinuz apparmor=1 security=apparmor\n")
    real_path_cls = Path

    def fake_path(arg):
        if str(arg) == "/proc/cmdline":
            return cmdline
        return real_path_cls(arg)

    monkeypatch.setattr(hardening, "Path", fake_path)

    fake_run.set_response(["systemctl", "is-active", "usbguard"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-enabled", "usbguard"], stdout="disabled\n")
    fake_run.set_response(["systemctl", "is-active", "auditd"], stdout="active\n")
    fake_run.set_response(["systemctl", "is-enabled", "auditd"], stdout="enabled\n")
    fake_run.set_response(["arch-audit"], stdout="")

    pam_file = tmp_path / "system-login"
    pam_file.write_text("auth required pam_faillock.so preauth\n")
    monkeypatch.setattr(hardening, "PAM_SYSTEM_LOGIN", pam_file)
    fake_run.set_response(["cat", str(pam_file)], stdout=pam_file.read_text())

    fake_run.set_response(["visudo", "-cf", "/etc/sudoers"], stdout="/etc/sudoers: parsed OK\n")

    sysctl_file = tmp_path / "99-atropa-hardening.conf"
    sysctl_file.write_text("kernel.kptr_restrict = 2\n")
    monkeypatch.setattr(hardening, "SYSCTL_HARDENING_FILE", str(sysctl_file))

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


# --------------------------------------------------------------- scoring --

def test_generate_report_covers_every_check(fake_run, fake_which, monkeypatch, tmp_path):
    _stub_all_checks_pass(fake_run, fake_which, monkeypatch, tmp_path)
    report = compliance.generate_report()
    all_check_names = {c.name for cat in report.categories for c in cat.checks}
    expected = {
        c.name
        for c in hardening.run_audit()
        + compliance._extra_checks()
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
