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

def test_parse_check_summary_zero_counts_in_summary_block():
    output = "Summary:\n  Total number of entries:\t100\n  Added entries:\t\t0\n  Removed entries:\t\t0\n  Changed entries:\t\t0\n"
    summary = aide.parse_check_summary(output)
    assert summary is not None
    assert summary.added == 0
    assert summary.removed == 0
    assert summary.changed == 0
    assert summary.clean is True


def test_parse_check_summary_real_clean_run_has_no_summary_block():
    # What AIDE actually prints when nothing changed (report_plain.c only
    # emits "Summary:" when there are differences) - used to parse as None,
    # i.e. "no summary could be parsed", for the best possible outcome.
    output = (
        "Start timestamp: 2026-10-11 05:00:00 +0000 (AIDE 0.18.8)\n"
        "AIDE found NO differences between database and filesystem. Looks okay!!\n"
        "\n"
        "Number of entries:\t48211\n"
    )
    assert aide.parse_check_summary(output) == aide.CheckSummary(added=0, removed=0, changed=0)


def test_parse_check_summary_old_aide_clean_wording():
    assert aide.parse_check_summary("### All files match AIDE database. Looks okay!\n").clean is True


def test_parse_check_summary_exit_status_zero_means_clean():
    # aide --check exits 0 only when there are no differences.
    assert aide.parse_check_summary("", returncode=0).clean is True


def test_parse_check_summary_error_exit_without_report_is_none():
    assert aide.parse_check_summary("aide: couldn't open config file\n", returncode=17) is None


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



# --------------------------------------------------------------- root-only /var/lib/aide --

def _db_dir_unsearchable(monkeypatch):
    real_exists = aide.Path.exists

    def exists(self, *args, **kwargs):
        if str(self).startswith("/var/lib/aide/"):
            raise PermissionError(13, "Permission denied", str(self))
        return real_exists(self, *args, **kwargs)

    monkeypatch.setattr(aide.Path, "exists", exists)


def test_baseline_initialized_is_unknown_when_the_db_dir_is_root_only(monkeypatch):
    # Used to raise PermissionError on Python 3.11-3.13 (False on 3.14).
    _db_dir_unsearchable(monkeypatch)
    assert aide.baseline_initialized() is None


def test_initialize_baseline_promotes_through_a_root_only_db_dir(monkeypatch, fake_which, fake_run):
    # The new database can't be seen from here - root's cp is asked instead of
    # calling a successful --init a failure.
    _install_streaming(monkeypatch, ["aide --init finished"], returncode=0)
    _db_dir_unsearchable(monkeypatch)
    first, second = aide.DB_NEW_CANDIDATES
    fake_run.set_response(["pkexec", "cp", first], returncode=1, stderr="cp: cannot stat: No such file or directory")
    fake_run.set_response(["pkexec", "cp", second], returncode=0)

    result = aide.initialize_baseline(lambda _line: None)
    assert result.ok
    assert [c for c in fake_run.calls if c[:2] == ["pkexec", "cp"]] == [
        ["pkexec", "cp", first, first.replace(".new", "")],
        ["pkexec", "cp", second, second.replace(".new", "")],
    ]


# ------------------------------------------------------- check report ----

REPORT = """Start timestamp: 2026-11-05 03:00:00 +0100 (AIDE 0.18.8)

Added entries:
--------------------
f++++++++++++++++: /etc/new.conf
d++++++++++++++++: /opt/newdir

Removed entries:
--------------------
f----------------: /etc/old.conf

Changed entries:
--------------------
f > ... : /etc/passwd
d = ... : /var/lib

Detailed information about changes:
--------------------
File: /etc/passwd
  Size     : 1234

Summary:
  Total number of entries:\t100
  Added entries:\t\t2
  Removed entries:\t\t1
  Changed entries:\t\t2
"""


def test_parse_check_entries_reads_each_section():
    entries = aide.parse_check_entries(REPORT)

    assert [(entry.kind, entry.path) for entry in entries] == [
        ("added", "/etc/new.conf"),
        ("added", "/opt/newdir"),
        ("removed", "/etc/old.conf"),
        ("changed", "/etc/passwd"),
        ("changed", "/var/lib"),
    ]


def test_parse_check_entries_keeps_the_marker_column_as_detail():
    entries = aide.parse_check_entries(REPORT)
    assert entries[0].detail == "++++++++++++++++"
    assert entries[4].detail == "= ..."


def test_parse_check_entries_ignores_the_summary_counts_and_detailed_block():
    paths = [entry.path for entry in aide.parse_check_entries(REPORT)]
    assert "/etc/passwd" in paths
    assert "1234" not in paths  # the "Size : 1234" line of the detailed block


def test_parse_check_entries_clean_output_has_none():
    assert aide.parse_check_entries("AIDE found NO differences between database and filesystem. Looks okay!!\n") == []


def test_parse_check_entries_handles_paths_with_spaces():
    output = "Added entries:\n--------------------\nf++++++++++++++++: /opt/my file.conf\n"
    assert aide.parse_check_entries(output)[0].path == "/opt/my file.conf"


def test_build_check_record_combines_summary_entries_and_time():
    record = aide.build_check_record(REPORT, when="2026-11-05T03:01:02+01:00")
    assert record.checked_at == "2026-11-05T03:01:02+01:00"
    assert record.summary.added == 2
    assert record.summary.changed == 2
    assert len(record.entries) == 5
    assert record.clean is False


def test_build_check_record_clean_run_is_clean():
    record = aide.build_check_record("AIDE found NO differences between database and filesystem.\n", returncode=0)
    assert record.clean is True
    assert record.entries == []


# ------------------------------------------------------ last-check state --

def test_save_and_load_check_record_roundtrip(tmp_path, monkeypatch):
    path = tmp_path / "aide_last_check.json"
    monkeypatch.setattr(aide, "LAST_CHECK_FILE", path)
    record = aide.build_check_record(REPORT, when="2026-11-05T03:01:02+01:00")

    aide.save_check_record(record)

    assert aide.load_check_record() == record


def test_load_check_record_missing_is_none(tmp_path, monkeypatch):
    monkeypatch.setattr(aide, "LAST_CHECK_FILE", tmp_path / "nope.json")
    assert aide.load_check_record() is None


def test_load_check_record_corrupt_is_none(tmp_path, monkeypatch):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(aide, "LAST_CHECK_FILE", path)
    assert aide.load_check_record() is None


def test_load_check_record_drops_unknown_entry_kinds(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    path.write_text(
        '{"checked_at": "now", "summary": null, "entries": ['
        '{"kind": "deleted", "path": "/etc/x"},'
        '{"kind": "added", "path": "/etc/y"}]}',
        encoding="utf-8",
    )
    monkeypatch.setattr(aide, "LAST_CHECK_FILE", path)

    record = aide.load_check_record()

    assert [entry.path for entry in record.entries] == ["/etc/y"]


def test_clear_check_record_removes_the_file(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(aide, "LAST_CHECK_FILE", path)
    aide.clear_check_record()
    assert not path.exists()


# ------------------------------------------------------- config check ----

def test_check_config_runs_aide_config_check_as_root(fake_run):
    fake_run.set_response(["pkexec", "aide", "--config-check"], stdout="")
    result = aide.check_config()
    assert result.ok
    assert fake_run.last_call() == ["pkexec", "aide", "--config-check"]


def test_check_config_reports_a_bad_config(fake_run):
    fake_run.set_response(
        ["pkexec", "aide", "--config-check"],
        stderr="/etc/aide.conf:12: unknown rule",
        returncode=1,
    )
    result = aide.check_config()
    assert not result.ok
    assert "unknown rule" in result.stderr


# -------------------------------------------------------- timer details --

def test_timer_details_parses_systemctl_show(fake_run):
    fake_run.set_response(
        ["systemctl", "show", "aide.timer"],
        stdout=(
            "NextElapseUSecRealtime=Thu 2026-11-06 00:00:00 CET\n"
            "LastTriggerUSec=Wed 2026-11-05 00:00:00 CET\n"
            "Result=success\n"
        ),
    )

    details = aide.timer_details("aide.timer")

    assert details.next_run == "Thu 2026-11-06 00:00:00 CET"
    assert details.last_run == "Wed 2026-11-05 00:00:00 CET"
    assert details.result == "success"


def test_timer_details_unset_properties_are_empty(fake_run):
    fake_run.set_response(["systemctl", "show", "aide.timer"], stdout="NextElapseUSecRealtime=\n")
    details = aide.timer_details("aide.timer")
    assert details.next_run == ""
    assert details.last_run == ""


def test_timer_details_failure_is_an_error(fake_run):
    fake_run.set_response(["systemctl", "show", "aide.timer"], stderr="Unit aide.timer not found", returncode=1)
    try:
        aide.timer_details("aide.timer")
    except RuntimeError as exc:
        assert "not found" in str(exc)
    else:
        raise AssertionError("expected RuntimeError")
