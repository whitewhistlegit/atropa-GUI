"""Tests for atropa.backend.boot_report."""

from __future__ import annotations

import pytest

from atropa.backend import boot_report

JOURNAL_COMMAND = ["journalctl", "-b", "-p", "err", "--no-pager", "-o", "short-iso"]
CRASH_COMMAND = ["coredumpctl", "--no-pager", "list"]


@pytest.fixture(autouse=True)
def fixed_uptime(monkeypatch, tmp_path):
    """recent_crashes() derives --since from /proc/uptime; keep it off the host."""
    path = tmp_path / "uptime-autouse"
    path.write_text("1000.0 2000.0\n", encoding="utf-8")
    monkeypatch.setattr(boot_report, "PROC_UPTIME", path)
    return path

JOURNAL_SAMPLE = """\
2026-11-05T02:00:00+0100 hostname NetworkManager[812]: <error> [123] dhcp4 timeout
2026-11-05T02:01:00+0100 hostname kernel: usb 1-1: device not accepting address
"""

CRASH_SAMPLE = """\
TIME                           PID  UID  GID SIG     COREFILE EXE
Thu 2026-11-05 01:59:00 CET   1234 1000 1000 SIGSEGV present  /usr/bin/nautilus
Thu 2026-11-05 02:00:00 CET   4321 1000 1000 SIGABRT missing  /usr/lib/firefox/firefox
"""


def _uptime(tmp_path, monkeypatch, text: str | None):
    path = tmp_path / "uptime"
    if text is not None:
        path.write_text(text, encoding="utf-8")
    monkeypatch.setattr(boot_report, "PROC_UPTIME", path)
    return path


# --------------------------------------------------------------------- uptime --

def test_uptime_seconds_reads_the_first_field(fake_run, tmp_path, monkeypatch):
    _uptime(tmp_path, monkeypatch, "8040.55 99999.00\n")
    assert boot_report.uptime_seconds() == 8040.55
    assert fake_run.calls == []


def test_uptime_seconds_missing_file_is_none(fake_run, tmp_path, monkeypatch):
    _uptime(tmp_path, monkeypatch, None)
    assert boot_report.uptime_seconds() is None


@pytest.mark.parametrize("text", ["", "not-a-number 12345.00\n", "   \n"])
def test_uptime_seconds_malformed_file_is_none(fake_run, tmp_path, monkeypatch, text):
    _uptime(tmp_path, monkeypatch, text)
    assert boot_report.uptime_seconds() is None


# ------------------------------------------------------------- journal_errors --

def test_journal_errors_parses_program_and_message(fake_run, fake_which):
    fake_which.add("journalctl")
    fake_run.set_response(["journalctl"], stdout=JOURNAL_SAMPLE)

    assert boot_report.journal_errors() == [
        boot_report.BootProblem("journal", "NetworkManager", "<error> [123] dhcp4 timeout"),
        boot_report.BootProblem("journal", "kernel", "usb 1-1: device not accepting address"),
    ]
    assert fake_run.calls == [JOURNAL_COMMAND]


def test_journal_errors_skips_blank_and_unparsable_lines(fake_run, fake_which):
    fake_which.add("journalctl")
    fake_run.set_response(
        ["journalctl"],
        stdout="\n"
        "-- No entries --\n"
        "2026-11-05T02:00:00+0100 hostname prog[1]: real error\n"
        "garbage with only three fields\n",
    )

    assert boot_report.journal_errors() == [boot_report.BootProblem("journal", "prog", "real error")]


def test_journal_errors_caps_the_result_at_limit(fake_run, fake_which):
    fake_which.add("journalctl")
    fake_run.set_response(
        ["journalctl"],
        stdout="".join(
            f"2026-11-05T02:0{index}:00+0100 hostname prog[{index}]: error {index}\n" for index in range(5)
        ),
    )

    problems = boot_report.journal_errors(limit=2)
    assert [problem.detail for problem in problems] == ["error 0", "error 1"]


def test_journal_errors_nonzero_exit_reports_stderr(fake_run, fake_which):
    fake_which.add("journalctl")
    fake_run.set_response(["journalctl"], stderr="No journal files were found.", returncode=1)

    with pytest.raises(RuntimeError, match="No journal files were found."):
        boot_report.journal_errors()


def test_journal_errors_nonzero_exit_without_stderr_reports_status(fake_run, fake_which):
    fake_which.add("journalctl")
    fake_run.set_response(["journalctl"], returncode=1)

    with pytest.raises(RuntimeError, match="journalctl exited with status 1"):
        boot_report.journal_errors()


def test_journal_errors_missing_journalctl_is_an_error(fake_run, fake_which):
    with pytest.raises(RuntimeError, match="comes with systemd"):
        boot_report.journal_errors()
    assert fake_run.calls == []


# --------------------------------------------------------------- failed_units --

def test_failed_units_reuses_system_health_parsing(fake_run):
    fake_run.set_response(
        ["systemctl", "--failed"],
        stdout="● sshd.service loaded failed failed OpenSSH Daemon\n",
    )

    assert boot_report.failed_units() == [boot_report.BootProblem("unit", "sshd.service", "OpenSSH Daemon")]
    assert fake_run.calls == [["systemctl", "--failed", "--no-legend", "--no-pager", "--plain"]]


def test_failed_units_error_is_not_an_empty_list(fake_run):
    fake_run.set_response(["systemctl", "--failed"], stderr="Access denied", returncode=1)

    with pytest.raises(RuntimeError, match="Access denied"):
        boot_report.failed_units()


# ------------------------------------------------------------- recent_crashes --

def test_recent_crashes_ignores_the_size_column_after_the_exe(fake_run, fake_which):
    # Real coredumpctl output has a SIZE column after EXE ("-" or "599.8K").
    # Reading the last field as the program named every crash "-".
    fake_which.add("coredumpctl")
    fake_run.set_response(
        ["coredumpctl"],
        stdout="TIME PID UID GID SIG COREFILE EXE SIZE\n"
        "Thu 2026-11-05 02:00:00 CET 1 2 3 SIGSEGV present /usr/bin/nautilus -\n",
    )

    assert boot_report.recent_crashes() == [
        boot_report.BootProblem("crash", "nautilus", "SIGSEGV, core file present"),
    ]


def test_recent_crashes_parses_signal_exe_and_core_status(fake_run, fake_which):
    fake_which.add("coredumpctl")
    fake_run.set_response(["coredumpctl"], stdout=CRASH_SAMPLE)

    assert boot_report.recent_crashes() == [
        boot_report.BootProblem("crash", "nautilus", "SIGSEGV, core file present"),
        boot_report.BootProblem("crash", "firefox", "SIGABRT, core file missing"),
    ]
    # --since keeps three-week-old dumps off a "since this boot" page.
    call = fake_run.calls[0]
    assert call[:2] == ["coredumpctl", "--no-pager"]
    assert "--since" in call
    assert call[call.index("--since") + 1].startswith("@")
    assert call[-1] == "list"


def test_recent_crashes_without_uptime_lists_everything(fake_run, fake_which, tmp_path, monkeypatch):
    _uptime(tmp_path, monkeypatch, None)
    fake_which.add("coredumpctl")
    fake_run.set_response(["coredumpctl"], stdout="No coredumps found.\n")

    boot_report.recent_crashes()

    assert fake_run.calls[0] == CRASH_COMMAND  # no --since filter to derive


def test_recent_crashes_keeps_the_unknown_program_fallback(fake_run, fake_which):
    fake_which.add("coredumpctl")
    fake_run.set_response(
        ["coredumpctl"],
        stdout="TIME PID UID GID SIG COREFILE EXE\n"
        "Thu 2026-11-05 02:00:00 CET 1 2 3 SIGILL none /\n",
    )

    assert boot_report.recent_crashes() == [boot_report.BootProblem("crash", "Unknown program", "SIGILL, core file none")]


@pytest.mark.parametrize("stdout", ["No coredumps found.\n", "TIME PID UID GID SIG COREFILE EXE\n", ""])
def test_recent_crashes_without_data_rows_is_empty(fake_run, fake_which, stdout):
    fake_which.add("coredumpctl")
    fake_run.set_response(["coredumpctl"], stdout=stdout)
    assert boot_report.recent_crashes() == []


def test_recent_crashes_skips_rows_without_a_signal(fake_run, fake_which):
    fake_which.add("coredumpctl")
    fake_run.set_response(
        ["coredumpctl"],
        stdout="TIME PID UID GID SIG COREFILE EXE\n"
        "Thu 2026-11-05 02:00:00 CET 1 2 3 ??? present /usr/bin/mystery\n"
        "Thu 2026-11-05 02:01:00 CET 4 5 6 SIGBUS none /opt/broken\n",
    )

    assert boot_report.recent_crashes() == [boot_report.BootProblem("crash", "broken", "SIGBUS, core file none")]


def test_recent_crashes_caps_the_result_at_limit(fake_run, fake_which):
    fake_which.add("coredumpctl")
    fake_run.set_response(
        ["coredumpctl"],
        stdout="TIME PID UID GID SIG COREFILE EXE\n"
        + "".join(f"Thu 2026-11-05 02:00:0{i} CET 1 2 3 SIGSEGV present /usr/bin/app{i}\n" for i in range(5)),
    )

    assert [problem.title for problem in boot_report.recent_crashes(limit=3)] == ["app0", "app1", "app2"]


def test_recent_crashes_nonzero_exit_reports_stderr(fake_run, fake_which):
    fake_which.add("coredumpctl")
    fake_run.set_response(["coredumpctl"], stderr="Failed to connect to bus", returncode=1)

    with pytest.raises(RuntimeError, match="Failed to connect to bus"):
        boot_report.recent_crashes()


def test_recent_crashes_nonzero_exit_without_stderr_reports_status(fake_run, fake_which):
    fake_which.add("coredumpctl")
    fake_run.set_response(["coredumpctl"], returncode=1)

    with pytest.raises(RuntimeError, match="coredumpctl exited with status 1"):
        boot_report.recent_crashes()


def test_recent_crashes_missing_coredumpctl_is_an_error(fake_run, fake_which):
    with pytest.raises(RuntimeError, match="comes with systemd"):
        boot_report.recent_crashes()
    assert fake_run.calls == []


# -------------------------------------------------------------------- collect --

def test_collect_assembles_every_source(tmp_path, monkeypatch):
    _uptime(tmp_path, monkeypatch, "8040.00 99999.00\n")
    monkeypatch.setattr(boot_report, "journal_errors", lambda: [boot_report.BootProblem("journal", "prog", "boom")])
    monkeypatch.setattr(boot_report, "failed_units", lambda: [boot_report.BootProblem("unit", "sshd.service")])
    monkeypatch.setattr(boot_report, "recent_crashes", lambda: [boot_report.BootProblem("crash", "app", "SIGSEGV")])

    report = boot_report.collect()

    assert report.journal == [boot_report.BootProblem("journal", "prog", "boom")]
    assert report.units == [boot_report.BootProblem("unit", "sshd.service")]
    assert report.crashes == [boot_report.BootProblem("crash", "app", "SIGSEGV")]
    assert report.uptime == 8040.0
    assert report.errors == {}


def test_collect_keeps_other_sources_when_one_fails(tmp_path, monkeypatch):
    _uptime(tmp_path, monkeypatch, "60.00 99999.00\n")
    monkeypatch.setattr(
        boot_report, "journal_errors", lambda: (_ for _ in ()).throw(RuntimeError("no journal access"))
    )
    monkeypatch.setattr(boot_report, "failed_units", lambda: [boot_report.BootProblem("unit", "backup.service")])
    monkeypatch.setattr(boot_report, "recent_crashes", lambda: [boot_report.BootProblem("crash", "app", "SIGSEGV")])

    report = boot_report.collect()

    assert report.errors == {"journal": "no journal access"}
    assert report.journal == []
    assert report.units == [boot_report.BootProblem("unit", "backup.service")]
    assert report.crashes == [boot_report.BootProblem("crash", "app", "SIGSEGV")]
    assert report.uptime == 60.0


def test_collect_records_every_failure_and_blanks_uptime(monkeypatch):
    def fail(message: str):
        return lambda: (_ for _ in ()).throw(RuntimeError(message))

    monkeypatch.setattr(boot_report, "journal_errors", fail("journal down"))
    monkeypatch.setattr(boot_report, "failed_units", fail("systemd down"))
    monkeypatch.setattr(boot_report, "recent_crashes", fail("coredumpctl down"))
    monkeypatch.setattr(boot_report, "uptime_seconds", fail("proc gone"))

    report = boot_report.collect()

    assert report.errors == {"journal": "journal down", "units": "systemd down", "crashes": "coredumpctl down"}
    assert report.uptime is None
    assert report.journal == report.units == report.crashes == []
