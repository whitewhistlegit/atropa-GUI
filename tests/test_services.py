"""Tests for atropa.backend.services."""
from __future__ import annotations

from atropa.backend import services


def test_list_services_parses_and_enriches_enabled_state(fake_run):
    fake_run.set_response(
        ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain"],
        stdout=(
            "sshd.service loaded active running OpenSSH Daemon\n"
            "cups.service loaded inactive dead CUPS Printer Service\n"
        ),
    )
    fake_run.set_response(["systemctl", "is-enabled", "sshd.service"], stdout="enabled\n")
    fake_run.set_response(["systemctl", "is-enabled", "cups.service"], stdout="disabled\n")

    result = services.list_services()

    assert len(result) == 2
    assert result[0] == services.Service(
        unit="sshd.service", load="loaded", active="active", sub="running",
        description="OpenSSH Daemon", enabled="enabled",
    )
    assert result[1].enabled == "disabled"


def test_list_services_skips_malformed_lines(fake_run):
    fake_run.set_response(
        ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain"],
        stdout="onlytwo fields\n",
    )
    assert services.list_services() == []


def test_list_services_unknown_when_is_enabled_blank(fake_run):
    fake_run.set_response(
        ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain"],
        stdout="foo.service loaded active running Foo\n",
    )
    fake_run.set_response(["systemctl", "is-enabled", "foo.service"], stdout="")
    result = services.list_services()
    assert result[0].enabled == "unknown"


def test_status_prefers_stdout_falls_back_to_stderr(fake_run):
    fake_run.set_response(["systemctl", "status", "foo.service", "--no-pager"], stdout="", stderr="not found")
    assert services.status("foo.service") == "not found"


def test_start_stop_restart_use_privileged(fake_run, fake_which):
    services.start("sshd")
    assert fake_run.last_call() == ["pkexec", "systemctl", "start", "sshd"]
    services.stop("sshd")
    assert fake_run.last_call() == ["pkexec", "systemctl", "stop", "sshd"]
    services.restart("sshd")
    assert fake_run.last_call() == ["pkexec", "systemctl", "restart", "sshd"]


def test_enable_without_now(fake_run, fake_which):
    services.enable("sshd")
    assert fake_run.last_call() == ["pkexec", "systemctl", "enable", "sshd"]


def test_enable_with_now(fake_run, fake_which):
    services.enable("sshd", now=True)
    assert fake_run.last_call() == ["pkexec", "systemctl", "enable", "sshd", "--now"]


def test_disable_with_now(fake_run, fake_which):
    services.disable("sshd", now=True)
    assert fake_run.last_call() == ["pkexec", "systemctl", "disable", "sshd", "--now"]


def test_journal_tail_passes_line_count(fake_run):
    fake_run.set_response(["journalctl", "-u", "sshd"], stdout="log lines\n")
    assert services.journal_tail("sshd", lines=50) == "log lines\n"
    assert fake_run.last_call() == ["journalctl", "-u", "sshd", "-n", "50", "--no-pager"]
