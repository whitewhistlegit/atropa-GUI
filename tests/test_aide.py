"""Tests for atropa.backend.aide."""
from __future__ import annotations

import subprocess

from atropa.backend import aide


def _install_streaming(monkeypatch, lines, returncode=0):
    class Stdout:
        def __iter__(self):
            return iter(lines)

    class FakePopen:
        def __init__(self, argv, **kwargs):
            self.args = argv
            self.stdout = Stdout()
            self.stdin = None

        def wait(self, timeout=None):
            return returncode

    monkeypatch.setattr(subprocess, "Popen", FakePopen)


# --------------------------------------------------------------- is_installed / baseline --

def test_is_installed_true(monkeypatch):
    monkeypatch.setattr(aide.shutil, "which", lambda name: "/usr/bin/aide" if name == "aide" else None)
    assert aide.is_installed() is True


def test_is_installed_false(monkeypatch):
    monkeypatch.setattr(aide.shutil, "which", lambda name: None)
    assert aide.is_installed() is False


def test_baseline_initialized_true_when_active_db_exists(monkeypatch):
    monkeypatch.setattr(aide.Path, "exists", lambda self: str(self) == aide.DB_ACTIVE_CANDIDATES[0])
    assert aide.baseline_initialized() is True


def test_baseline_initialized_false_when_no_db(monkeypatch):
    monkeypatch.setattr(aide.Path, "exists", lambda self: False)
    assert aide.baseline_initialized() is False


# --------------------------------------------------------------- timer detection --

def test_detect_timer_unit_finds_first_match(fake_run):
    fake_run.set_response(["systemctl", "list-unit-files", "aidecheck.timer"], returncode=1)
    fake_run.set_response(["systemctl", "list-unit-files", "aide.timer"], stdout="aide.timer enabled\n")
    assert aide.detect_timer_unit() == "aide.timer"


def test_detect_timer_unit_none_when_nothing_matches(fake_run):
    fake_run.set_response(["systemctl", "list-unit-files"], returncode=1)
    assert aide.detect_timer_unit() is None


def test_detect_timer_unit_prefers_first_candidate(fake_run):
    for unit in aide.TIMER_CANDIDATES:
        fake_run.set_response(["systemctl", "list-unit-files", unit], stdout=f"{unit} enabled\n")
    assert aide.detect_timer_unit() == aide.TIMER_CANDIDATES[0]


# --------------------------------------------------------------- get_status --

def test_get_status_not_installed_short_circuits(monkeypatch):
    monkeypatch.setattr(aide.shutil, "which", lambda name: None)
    status = aide.get_status()
    assert status.installed is False
    assert status.timer_unit is None
    assert status.baseline_initialized is False


def test_get_status_installed_with_active_timer(monkeypatch, fake_run):
    monkeypatch.setattr(aide.shutil, "which", lambda name: "/usr/bin/aide")
    monkeypatch.setattr(aide.Path, "exists", lambda self: True)
    fake_run.set_response(["systemctl", "list-unit-files", "aidecheck.timer"], stdout="aidecheck.timer enabled\n")
    fake_run.set_response(["systemctl", "is-active", "aidecheck.timer"], stdout="active\n")
    fake_run.set_response(["systemctl", "is-enabled", "aidecheck.timer"], stdout="enabled\n")

    status = aide.get_status()
    assert status.installed is True
    assert status.config_exists is True
    assert status.baseline_initialized is True
    assert status.timer_unit == "aidecheck.timer"
    assert status.timer_active is True
    assert status.timer_enabled is True


def test_get_status_installed_no_timer_found(monkeypatch, fake_run):
    monkeypatch.setattr(aide.shutil, "which", lambda name: "/usr/bin/aide")
    monkeypatch.setattr(aide.Path, "exists", lambda self: False)
    fake_run.set_response(["systemctl", "list-unit-files"], returncode=1)

    status = aide.get_status()
    assert status.timer_unit is None
    assert status.timer_active is False
    assert status.timer_enabled is False


# --------------------------------------------------------------- initialize_baseline --

def test_initialize_baseline_promotes_new_db(monkeypatch, fake_which, fake_run):
    _install_streaming(monkeypatch, ["Start timestamp: ...", "aide --init finished"], returncode=0)
    monkeypatch.setattr(aide, "_find_existing", lambda candidates: candidates[0] if candidates == aide.DB_NEW_CANDIDATES else None)
    fake_run.set_response(["pkexec", "cp", aide.DB_NEW_CANDIDATES[0], aide.DB_NEW_CANDIDATES[0].replace(".new", "")], returncode=0)

    lines = []
    result = aide.initialize_baseline(lines.append)
    assert result.ok
    assert any("Promoting" in line for line in lines)


def test_initialize_baseline_fails_if_no_new_db_found(monkeypatch, fake_which):
    _install_streaming(monkeypatch, ["aide --init finished"], returncode=0)
    monkeypatch.setattr(aide, "_find_existing", lambda candidates: None)

    lines = []
    result = aide.initialize_baseline(lines.append)
    assert not result.ok
    assert any("no new database file" in line for line in lines)


def test_initialize_baseline_stops_if_init_itself_fails(monkeypatch, fake_which):
    _install_streaming(monkeypatch, ["aide: error"], returncode=1)
    result = aide.initialize_baseline(lambda line: None)
    assert not result.ok


def test_update_baseline_is_same_mechanism_as_initialize(monkeypatch, fake_which, fake_run):
    _install_streaming(monkeypatch, ["aide --init finished"], returncode=0)
    monkeypatch.setattr(aide, "_find_existing", lambda candidates: candidates[0] if candidates == aide.DB_NEW_CANDIDATES else None)
    fake_run.set_response(["pkexec", "cp", aide.DB_NEW_CANDIDATES[0], aide.DB_NEW_CANDIDATES[0].replace(".new", "")], returncode=0)

    result = aide.update_baseline(lambda line: None)
    assert result.ok


# --------------------------------------------------------------- run_check --

def test_run_check_forwards_lines(monkeypatch, fake_which):
    _install_streaming(monkeypatch, ["Start timestamp: ...", "Summary:", "Added entries: 0"], returncode=0)
    lines = []
    result = aide.run_check(lines.append)
    assert result.ok
    assert "Summary:" in lines


# --------------------------------------------------------------- parse_check_summary --

def test_parse_check_summary_clean():
    output = "Summary:\n  Total number of entries:\t100\n  Added entries:\t\t0\n  Removed entries:\t\t0\n  Changed entries:\t\t0\n"
    summary = aide.parse_check_summary(output)
    assert summary is not None
    assert summary.added == 0
    assert summary.removed == 0
    assert summary.changed == 0
    assert summary.clean is True


def test_parse_check_summary_with_changes():
    output = (
        "AIDE found differences between database and filesystem!!\n"
        "Summary:\n"
        "  Total number of entries:\t48213\n"
        "  Added entries:\t\t1\n"
        "  Removed entries:\t\t0\n"
        "  Changed entries:\t\t3\n"
        "---------------------------------------------------\n"
        "Added entries:\n"
    )
    summary = aide.parse_check_summary(output)
    assert summary == aide.CheckSummary(added=1, removed=0, changed=3)
    assert summary.clean is False


def test_parse_check_summary_returns_none_when_no_summary_present():
    assert aide.parse_check_summary("aide: couldn't open config file\n") is None


# --------------------------------------------------------------- enable/disable timer --

def test_enable_timer(fake_run, fake_which):
    fake_run.set_response(["systemctl", "enable", "--now", "aide.timer"], returncode=0)
    result = aide.enable_timer("aide.timer")
    assert result.ok
    assert fake_run.last_call() == ["pkexec", "systemctl", "enable", "--now", "aide.timer"]


def test_disable_timer(fake_run, fake_which):
    fake_run.set_response(["systemctl", "disable", "--now", "aide.timer"], returncode=0)
    result = aide.disable_timer("aide.timer")
    assert result.ok
    assert fake_run.last_call() == ["pkexec", "systemctl", "disable", "--now", "aide.timer"]
