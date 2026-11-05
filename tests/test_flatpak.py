"""Tests for atropa.backend.flatpak."""

from __future__ import annotations

import subprocess

import pytest

from atropa.backend import flatpak

LIST_ARGV = ["flatpak", "list", "--app", "--columns=application,version,origin,branch"]
UPDATES_ARGV = ["flatpak", "remote-ls", "--updates", "--columns=application,version,branch,origin"]


def _record_streaming(monkeypatch, name):
    """Replaces a streaming runner and records (argv, timeout) instead of running it."""
    calls = []

    def runner(argv, on_line, timeout):
        calls.append((argv, timeout))
        return flatpak.CommandResult(0, "", "")

    monkeypatch.setattr(flatpak, name, runner)
    return calls


# -------------------------------------------------------------- installation --


def test_flatpak_installed_follows_shutil_which(fake_which):
    assert flatpak.flatpak_installed() is False
    fake_which.add("flatpak")
    assert flatpak.flatpak_installed() is True


# --------------------------------------------------------- installed apps --


def test_installed_apps_parses_tab_columns(fake_run, fake_which):
    fake_which.add("flatpak")
    fake_run.set_response(
        LIST_ARGV,
        stdout="org.gnome.Calculator\t45.0\tflathub\tstable\norg.mozilla.firefox\t128.0\tflathub\tstable\n",
    )

    assert flatpak.installed_apps() == [
        flatpak.InstalledApp("org.gnome.Calculator", "45.0", "flathub", "stable"),
        flatpak.InstalledApp("org.mozilla.firefox", "128.0", "flathub", "stable"),
    ]
    assert fake_run.calls == [LIST_ARGV]


def test_installed_apps_tolerates_missing_columns_and_blank_lines(fake_run, fake_which):
    fake_which.add("flatpak")
    fake_run.set_response(LIST_ARGV, stdout="\norg.gnome.Maps\t45.0\n\n")

    assert flatpak.installed_apps() == [flatpak.InstalledApp("org.gnome.Maps", "45.0", "", "")]


def test_installed_apps_is_empty_for_empty_output(fake_run, fake_which):
    fake_which.add("flatpak")
    fake_run.set_response(LIST_ARGV, stdout="\n\n")

    assert flatpak.installed_apps() == []


def test_installed_apps_requires_flatpak(fake_run, fake_which):
    with pytest.raises(RuntimeError, match="pacman -S flatpak"):
        flatpak.installed_apps()
    assert fake_run.calls == []


def test_installed_apps_reports_a_failed_command(fake_run, fake_which):
    fake_which.add("flatpak")
    fake_run.set_response(LIST_ARGV, stderr="error: no installations found", returncode=1)

    with pytest.raises(RuntimeError, match="no installations found"):
        flatpak.installed_apps()


def test_installed_apps_failure_without_stderr_names_the_exit_status(fake_run, fake_which):
    fake_which.add("flatpak")
    fake_run.set_response(LIST_ARGV, returncode=17)

    with pytest.raises(RuntimeError, match="status 17"):
        flatpak.installed_apps()


# ---------------------------------------------------------------- updates --


def test_available_updates_parses_tab_columns(fake_run, fake_which):
    fake_which.add("flatpak")
    fake_run.set_response(
        UPDATES_ARGV,
        stdout="org.gnome.Calculator\t45.1\tstable\tflathub\n",
    )

    assert flatpak.available_updates() == [
        flatpak.AppUpdate("org.gnome.Calculator", "45.1", "stable", "flathub"),
    ]
    assert fake_run.calls == [UPDATES_ARGV]


def test_available_updates_tolerates_missing_columns(fake_run, fake_which):
    fake_which.add("flatpak")
    fake_run.set_response(UPDATES_ARGV, stdout="org.gnome.Maps\t45.0\n")

    assert flatpak.available_updates() == [flatpak.AppUpdate("org.gnome.Maps", "45.0", "", "")]


def test_available_updates_understands_the_no_updates_sentence(fake_run, fake_which):
    fake_which.add("flatpak")
    fake_run.set_response(UPDATES_ARGV, stdout="No updates.\n")

    assert flatpak.available_updates() == []


def test_available_updates_empty_output_is_no_updates(fake_run, fake_which):
    fake_which.add("flatpak")
    fake_run.set_response(UPDATES_ARGV, stdout="")

    assert flatpak.available_updates() == []


def test_available_updates_reports_a_failed_command(fake_run, fake_which):
    fake_which.add("flatpak")
    fake_run.set_response(UPDATES_ARGV, stderr="error: remote flathub not found", returncode=1)

    with pytest.raises(RuntimeError, match="remote flathub not found"):
        flatpak.available_updates()


def test_available_updates_requires_flatpak(fake_run, fake_which):
    with pytest.raises(RuntimeError, match="pacman -S flatpak"):
        flatpak.available_updates()
    assert fake_run.calls == []


# ------------------------------------------------------------ system install --


def test_system_wide_true_when_system_apps_exist(fake_run, fake_which):
    fake_which.add("flatpak")
    fake_run.set_response(["flatpak", "list", "--system"], stdout="org.gnome.Calculator\n")

    assert flatpak.system_wide() is True
    assert fake_run.calls == [["flatpak", "list", "--system", "--columns=application"]]


def test_system_wide_false_when_no_system_apps(fake_run, fake_which):
    fake_which.add("flatpak")
    fake_run.set_response(["flatpak", "list", "--system"], stdout="\n")

    assert flatpak.system_wide() is False


def test_system_wide_false_on_nonzero_exit(fake_run, fake_which):
    fake_which.add("flatpak")
    fake_run.set_response(["flatpak", "list", "--system"], stderr="error", returncode=1)

    assert flatpak.system_wide() is False


def test_system_wide_false_when_tool_is_missing(fake_run, fake_which):
    assert flatpak.system_wide() is False
    assert fake_run.calls == []


# --------------------------------------------------------------- streaming --


def test_update_all_uses_unprivileged_streaming_for_user_installs(monkeypatch, fake_which):
    fake_which.add("flatpak")
    monkeypatch.setattr(flatpak, "system_wide", lambda: False)
    calls = _record_streaming(monkeypatch, "run_unprivileged_streaming")
    monkeypatch.setattr(flatpak, "run_privileged_streaming", lambda *a, **k: pytest.fail("must not escalate"))

    result = flatpak.update_all(lambda _line: None)

    assert result.ok
    assert calls == [(["flatpak", "update", "-y", "--noninteractive"], 3600)]


def test_update_all_uses_privileged_streaming_for_system_installs(monkeypatch, fake_which):
    fake_which.add("flatpak")
    monkeypatch.setattr(flatpak, "system_wide", lambda: True)
    calls = _record_streaming(monkeypatch, "run_privileged_streaming")
    monkeypatch.setattr(flatpak, "run_unprivileged_streaming", lambda *a, **k: pytest.fail("must escalate"))

    result = flatpak.update_all(lambda _line: None)

    assert result.ok
    assert calls == [(["flatpak", "update", "-y", "--noninteractive"], 3600)]


def test_update_all_streams_lines_through_pkexec(monkeypatch, fake_which):
    fake_which.add("flatpak")
    monkeypatch.setattr(flatpak, "system_wide", lambda: True)
    captured = {}

    class FakeStdout:
        def __iter__(self):
            return iter(["Updating org.gnome.Calculator…", "done"])

    class FakePopen:
        def __init__(self, argv, **kwargs):
            captured["argv"] = argv
            self.stdout = FakeStdout()
            self.stdin = None

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    seen = []

    result = flatpak.update_all(seen.append)

    assert result.ok
    assert captured["argv"] == ["pkexec", "flatpak", "update", "-y", "--noninteractive"]
    assert seen == ["Updating org.gnome.Calculator…", "done"]


def test_remove_unused_uses_privileged_streaming_and_its_own_timeout(monkeypatch, fake_which):
    fake_which.add("flatpak")
    monkeypatch.setattr(flatpak, "system_wide", lambda: True)
    calls = _record_streaming(monkeypatch, "run_privileged_streaming")

    result = flatpak.remove_unused(lambda _line: None)

    assert result.ok
    assert calls == [
        (["flatpak", "uninstall", "--unused", "-y", "--noninteractive"], 1800),
    ]


def test_remove_unused_uses_unprivileged_streaming_for_user_installs(monkeypatch, fake_which):
    fake_which.add("flatpak")
    monkeypatch.setattr(flatpak, "system_wide", lambda: False)
    calls = _record_streaming(monkeypatch, "run_unprivileged_streaming")
    monkeypatch.setattr(flatpak, "run_privileged_streaming", lambda *a, **k: pytest.fail("must not escalate"))

    result = flatpak.remove_unused(lambda _line: None)

    assert result.ok
    assert calls == [(["flatpak", "uninstall", "--unused", "-y", "--noninteractive"], 1800)]
