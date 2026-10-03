"""Tests for atropa.backend.audit_rules."""
from __future__ import annotations

import pytest

from atropa.backend import audit_rules


# --------------------------------------------------------------- catalog sanity --

def test_rule_set_keys_are_unique():
    keys = [r.key for r in audit_rules.RULE_SETS]
    assert len(keys) == len(set(keys))


def test_every_rule_set_has_title_and_description():
    for rule_set in audit_rules.RULE_SETS:
        assert rule_set.title
        assert rule_set.description


def test_every_rule_set_has_at_least_one_rule_or_watch_path():
    for rule_set in audit_rules.RULE_SETS:
        assert rule_set.syscall_rules or rule_set.watch_paths


# --------------------------------------------------------------- _applicable_lines (path skipping) --

def test_applicable_lines_includes_syscall_rules_unconditionally(monkeypatch, tmp_path):
    rule_set = audit_rules._RULE_SETS_BY_KEY["time-change"]
    monkeypatch.setattr(audit_rules.Path, "exists", lambda self: False)
    lines = audit_rules._applicable_lines(rule_set)
    assert any("adjtimex" in line for line in lines)


def test_applicable_lines_skips_watch_path_that_does_not_exist(monkeypatch):
    rule_set = audit_rules._RULE_SETS_BY_KEY["logins"]
    monkeypatch.setattr(audit_rules.Path, "exists", lambda self: False)
    lines = audit_rules._applicable_lines(rule_set)
    assert lines == []


def test_applicable_lines_includes_watch_path_that_exists(monkeypatch):
    rule_set = audit_rules._RULE_SETS_BY_KEY["scope"]

    def fake_exists(self):
        return str(self) == "/etc/sudoers"

    monkeypatch.setattr(audit_rules.Path, "exists", fake_exists)
    lines = audit_rules._applicable_lines(rule_set)
    assert lines == ["-w /etc/sudoers -p wa -k scope"]


def test_applicable_lines_real_arch_system_skips_faillog_and_tallylog(monkeypatch):
    """Arch doesn't ship /var/log/faillog or /var/log/tallylog by default
    (legacy RHEL/Debian-era paths) - confirm the 'logins' set degrades
    gracefully to just what's actually present, rather than failing
    outright or writing rules for paths that don't exist."""
    rule_set = audit_rules._RULE_SETS_BY_KEY["logins"]

    def fake_exists(self):
        return str(self) in ("/var/log/wtmp", "/var/log/btmp")

    monkeypatch.setattr(audit_rules.Path, "exists", fake_exists)
    lines = audit_rules._applicable_lines(rule_set)
    assert len(lines) == 2
    assert all("wtmp" in line or "btmp" in line for line in lines)


# --------------------------------------------------------------- is_audit_rule_set_active --

def test_is_audit_rule_set_active_true_when_key_present(fake_run, fake_which):
    fake_run.set_response(["pkexec", "auditctl", "-l"], stdout="-w /etc/passwd -p wa -k identity\n")
    assert audit_rules.is_audit_rule_set_active("identity") is True


def test_is_audit_rule_set_active_false_when_key_absent(fake_run, fake_which):
    fake_run.set_response(["pkexec", "auditctl", "-l"], stdout="-w /etc/sudoers -p wa -k scope\n")
    assert audit_rules.is_audit_rule_set_active("identity") is False


def test_is_audit_rule_set_active_false_when_command_fails(fake_run, fake_which):
    fake_run.set_response(["pkexec", "auditctl", "-l"], returncode=1, stderr="denied")
    assert audit_rules.is_audit_rule_set_active("identity") is False


def test_is_audit_rule_set_active_unknown_key():
    assert audit_rules.is_audit_rule_set_active("not-a-real-key") is False


# --------------------------------------------------------------- apply_audit_rule_set --

def test_apply_audit_rule_set_unknown_key_raises():
    with pytest.raises(ValueError, match="Unknown audit rule set"):
        audit_rules.apply_audit_rule_set("not-a-real-key")


def test_apply_audit_rule_set_writes_file_and_reloads(fake_run, fake_which, monkeypatch):
    monkeypatch.setattr(audit_rules.Path, "exists", lambda self: False)  # only syscall rules apply
    fake_run.set_response(["pkexec", "mkdir", "-p", str(audit_rules.AUDIT_RULES_DIR)], returncode=0)
    fake_run.set_response(
        ["pkexec", "tee", str(audit_rules.AUDIT_RULES_DIR / "50-time-change.rules")], returncode=0
    )
    fake_run.set_response(["pkexec", "augenrules", "--load"], returncode=0)

    result = audit_rules.apply_audit_rule_set("time-change")
    assert result.ok
    assert fake_run.call_containing("augenrules") is not None


def test_apply_audit_rule_set_noop_when_nothing_applicable(fake_run, fake_which, monkeypatch):
    monkeypatch.setattr(audit_rules.Path, "exists", lambda self: False)
    result = audit_rules.apply_audit_rule_set("logins")  # no syscall rules, all watch paths "missing"
    assert result.ok
    assert "nothing applicable" in result.stdout
    assert fake_run.calls == []


def test_apply_audit_rule_set_stops_if_mkdir_fails(fake_run, fake_which, monkeypatch):
    monkeypatch.setattr(audit_rules.Path, "exists", lambda self: False)
    fake_run.set_response(["pkexec", "mkdir", "-p", str(audit_rules.AUDIT_RULES_DIR)], returncode=1, stderr="denied")

    result = audit_rules.apply_audit_rule_set("time-change")
    assert not result.ok
    assert fake_run.call_containing("tee") is None
    assert fake_run.call_containing("augenrules") is None


def test_apply_audit_rule_set_stops_if_write_fails(fake_run, fake_which, monkeypatch):
    monkeypatch.setattr(audit_rules.Path, "exists", lambda self: False)
    fake_run.set_response(["pkexec", "mkdir", "-p", str(audit_rules.AUDIT_RULES_DIR)], returncode=0)
    fake_run.set_response(
        ["pkexec", "tee", str(audit_rules.AUDIT_RULES_DIR / "50-time-change.rules")], returncode=1, stderr="disk full"
    )

    result = audit_rules.apply_audit_rule_set("time-change")
    assert not result.ok
    assert fake_run.call_containing("augenrules") is None


# --------------------------------------------------------------- apply_all_rule_sets --

def test_apply_all_rule_sets_writes_every_applicable_set(fake_run, fake_which, monkeypatch):
    monkeypatch.setattr(audit_rules.Path, "exists", lambda self: False)  # only syscall-based sets apply
    fake_run.set_response(["pkexec", "mkdir", "-p", str(audit_rules.AUDIT_RULES_DIR)], returncode=0)
    fake_run.set_response(["pkexec", "tee"], returncode=0)
    fake_run.set_response(["pkexec", "augenrules", "--load"], returncode=0)

    results = audit_rules.apply_all_rule_sets()

    # time-change and system-locale have syscall rules (always applicable);
    # identity/logins/scope are pure watch-path sets, all "missing" here
    assert results["time-change"].ok
    assert results["system-locale"].ok
    assert "nothing applicable" in results["identity"].stdout
    assert "nothing applicable" in results["logins"].stdout
    assert "nothing applicable" in results["scope"].stdout


def test_apply_all_rule_sets_reloads_exactly_once(fake_run, fake_which, monkeypatch):
    monkeypatch.setattr(audit_rules.Path, "exists", lambda self: False)
    fake_run.set_response(["pkexec", "mkdir", "-p", str(audit_rules.AUDIT_RULES_DIR)], returncode=0)
    fake_run.set_response(["pkexec", "tee"], returncode=0)
    fake_run.set_response(["pkexec", "augenrules", "--load"], returncode=0)

    audit_rules.apply_all_rule_sets()

    reload_calls = [c for c in fake_run.calls if "augenrules" in c]
    assert len(reload_calls) == 1


def test_apply_all_rule_sets_skips_reload_when_nothing_written(fake_run, fake_which, monkeypatch):
    """If every rule set is a no-op on this system (nothing applicable
    anywhere), there's nothing to reload - confirm it doesn't reload
    pointlessly."""
    monkeypatch.setattr(audit_rules.Path, "exists", lambda self: False)

    def all_missing(rule_set):
        return []

    monkeypatch.setattr(audit_rules, "_applicable_lines", all_missing)
    audit_rules.apply_all_rule_sets()
    assert fake_run.calls == []


def test_apply_all_rule_sets_reports_reload_failure_separately(fake_run, fake_which, monkeypatch):
    monkeypatch.setattr(audit_rules.Path, "exists", lambda self: False)
    fake_run.set_response(["pkexec", "mkdir", "-p", str(audit_rules.AUDIT_RULES_DIR)], returncode=0)
    fake_run.set_response(["pkexec", "tee"], returncode=0)
    fake_run.set_response(["pkexec", "augenrules", "--load"], returncode=1, stderr="bad rule syntax")

    results = audit_rules.apply_all_rule_sets()
    assert results["time-change"].ok  # the write itself succeeded
    assert "_reload" in results
    assert not results["_reload"].ok


def test_apply_all_rule_sets_one_write_failure_does_not_block_others(fake_run, fake_which, monkeypatch):
    monkeypatch.setattr(audit_rules.Path, "exists", lambda self: False)
    fake_run.set_response(["pkexec", "mkdir", "-p", str(audit_rules.AUDIT_RULES_DIR)], returncode=0)
    fake_run.set_response(
        ["pkexec", "tee", str(audit_rules.AUDIT_RULES_DIR / "50-time-change.rules")], returncode=1, stderr="fail"
    )
    fake_run.set_response(
        ["pkexec", "tee", str(audit_rules.AUDIT_RULES_DIR / "50-system-locale.rules")], returncode=0
    )
    fake_run.set_response(["pkexec", "augenrules", "--load"], returncode=0)

    results = audit_rules.apply_all_rule_sets()
    assert not results["time-change"].ok
    assert results["system-locale"].ok
