"""Tests for atropa.backend.privilege — the core run/backup/log layer."""
from __future__ import annotations

import json
import subprocess

import pytest

from atropa.backend import privilege
from atropa.backend.privilege import PrivilegeError


# --------------------------------------------------------------- _run/CommandResult --

def test_run_unprivileged_ok(fake_run):
    fake_run.set_response(["echo", "hi"], stdout="hi\n", returncode=0)
    result = privilege.run_unprivileged(["echo", "hi"])
    assert result.ok
    assert result.stdout == "hi\n"
    assert result.returncode == 0


def test_run_unprivileged_failure_not_ok(fake_run):
    fake_run.set_response(["false"], stdout="", stderr="boom", returncode=1)
    result = privilege.run_unprivileged(["false"])
    assert not result.ok
    assert result.stderr == "boom"


def test_run_missing_binary_raises_privilege_error(fake_run, monkeypatch):
    def raise_not_found(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(subprocess, "run", raise_not_found)
    with pytest.raises(PrivilegeError, match="Command not found"):
        privilege.run_unprivileged(["nonexistent-tool"])


def test_run_timeout_raises_privilege_error(fake_run, monkeypatch):
    def raise_timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="slow", timeout=1)

    monkeypatch.setattr(subprocess, "run", raise_timeout)
    with pytest.raises(PrivilegeError, match="timed out"):
        privilege.run_unprivileged(["slow-tool"])


# --------------------------------------------------------------- run_privileged --

def test_run_privileged_uses_pkexec_when_available(fake_run, fake_which):
    fake_run.set_response(["pkexec"], stdout="ok", returncode=0)
    privilege.run_privileged(["systemctl", "restart", "sshd"])
    assert fake_run.last_call() == ["pkexec", "systemctl", "restart", "sshd"]


def test_run_privileged_falls_back_to_sudo_when_no_pkexec(fake_run, fake_which):
    fake_which.discard("pkexec")
    fake_which.add("sudo")
    privilege.run_privileged(["systemctl", "restart", "sshd"])
    assert fake_run.last_call() == ["sudo", "-A", "systemctl", "restart", "sshd"]


def test_run_privileged_raises_when_neither_available(fake_run, fake_which):
    fake_which.discard("pkexec")
    with pytest.raises(PrivilegeError, match="Neither pkexec nor sudo"):
        privilege.run_privileged(["systemctl", "restart", "sshd"])


def test_run_privileged_prefers_pkexec_over_sudo(fake_run, fake_which):
    fake_which.add("sudo")  # both present
    privilege.run_privileged(["whoami"])
    assert fake_run.last_call()[0] == "pkexec"


# --------------------------------------------------------------- backup_file --

def test_backup_file_returns_none_when_source_missing(privilege_paths, tmp_path):
    missing = tmp_path / "does-not-exist.conf"
    assert privilege.backup_file(str(missing)) is None


def test_backup_file_copies_content_and_writes_manifest(privilege_paths, tmp_path):
    src = tmp_path / "sshd_config"
    src.write_text("PermitRootLogin yes\n")

    backup_name = privilege.backup_file(str(src))

    assert backup_name is not None
    assert backup_name.startswith("sshd_config.")
    assert backup_name.endswith(".bak")

    backup_path = privilege_paths.backup_dir / backup_name
    assert backup_path.read_text() == "PermitRootLogin yes\n"

    manifest_lines = privilege_paths.manifest.read_text().strip().splitlines()
    assert len(manifest_lines) == 1
    entry = json.loads(manifest_lines[0])
    assert entry["original_path"] == str(src)
    assert entry["backup_file"] == backup_name


def test_backup_file_falls_back_to_privileged_read_on_permission_error(
    privilege_paths, tmp_path, monkeypatch, fake_run, fake_which
):
    src = tmp_path / "protected.conf"
    src.write_text("secret=1\n")

    def raise_permission_error(self, *a, **k):
        raise PermissionError()

    monkeypatch.setattr("pathlib.Path.read_bytes", raise_permission_error)
    fake_run.set_response(["pkexec", "cat", str(src)], stdout="secret=1\n", returncode=0)

    backup_name = privilege.backup_file(str(src))
    assert backup_name is not None
    assert (privilege_paths.backup_dir / backup_name).read_text() == "secret=1\n"


def test_backup_file_read_failure_returns_none(
    privilege_paths, tmp_path, monkeypatch, fake_run, fake_which
):
    src = tmp_path / "protected.conf"
    src.write_text("secret=1\n")

    def raise_permission_error(self, *a, **k):
        raise PermissionError()

    monkeypatch.setattr("pathlib.Path.read_bytes", raise_permission_error)
    fake_run.set_response(["pkexec", "cat", str(src)], stdout="", stderr="denied", returncode=1)

    assert privilege.backup_file(str(src)) is None


# --------------------------------------------------------------- restore_file --

def test_restore_file_writes_content_back(privilege_paths, tmp_path, fake_run, fake_which):
    backup = privilege_paths.backup_dir / "sshd_config.20260101_000000_000000.bak"
    privilege_paths.backup_dir.mkdir(parents=True, exist_ok=True)
    backup.write_text("PermitRootLogin no\n")

    target = "/etc/ssh/sshd_config"
    fake_run.set_response(["pkexec", "tee", target], stdout="", returncode=0)

    result = privilege.restore_file(backup.name, target)

    assert result.ok
    call = fake_run.last_call()
    assert call == ["pkexec", "tee", target]


def test_restore_file_missing_backup_raises(privilege_paths):
    with pytest.raises(PrivilegeError, match="no longer exists"):
        privilege.restore_file("nope.bak", "/etc/ssh/sshd_config")


# --------------------------------------------------------------- listing helpers --

def test_list_backups_empty_when_no_manifest(privilege_paths):
    assert privilege.list_backups() == []


def test_list_backups_most_recent_first(privilege_paths):
    privilege_paths.backup_dir.mkdir(parents=True, exist_ok=True)
    with open(privilege_paths.manifest, "w", encoding="utf-8") as f:
        f.write(json.dumps({"timestamp": "1", "original_path": "/a", "backup_file": "a.bak"}) + "\n")
        f.write(json.dumps({"timestamp": "2", "original_path": "/b", "backup_file": "b.bak"}) + "\n")

    entries = privilege.list_backups()
    assert [e["original_path"] for e in entries] == ["/b", "/a"]


def test_list_backups_skips_corrupt_lines(privilege_paths):
    privilege_paths.backup_dir.mkdir(parents=True, exist_ok=True)
    with open(privilege_paths.manifest, "w", encoding="utf-8") as f:
        f.write("not json\n")
        f.write(json.dumps({"timestamp": "1", "original_path": "/a", "backup_file": "a.bak"}) + "\n")

    entries = privilege.list_backups()
    assert len(entries) == 1


def test_get_recent_actions_empty_when_no_log(privilege_paths):
    assert privilege.get_recent_actions() == []


def test_get_recent_actions_most_recent_first_and_limited(privilege_paths):
    privilege_paths.log_path.write_text("line1\nline2\nline3\n")
    actions = privilege.get_recent_actions(limit=2)
    assert actions == ["line3", "line2"]


# --------------------------------------------------------------- run_privileged_streaming --

class _FakeStdout:
    """Iterable stand-in for Popen.stdout that yields pre-scripted lines."""

    def __init__(self, lines: list[str]):
        self._lines = lines

    def __iter__(self):
        return iter(self._lines)


class _FakeStdin:
    """Stand-in for Popen.stdin that remembers what was written even after close()."""

    def __init__(self):
        self.written = ""
        self.closed = False

    def write(self, text):
        self.written += text

    def close(self):
        self.closed = True


class _FakePopen:
    """Minimal stand-in for subprocess.Popen used by run_privileged_streaming."""

    def __init__(self, argv, stdout_lines=None, returncode=0, wait_raises=None, stdin_writable=True):
        self.args = argv
        self.stdout = _FakeStdout(stdout_lines or [])
        self.stdin = _FakeStdin() if stdin_writable else None
        self._returncode = returncode
        self._wait_raises = wait_raises

    def wait(self, timeout=None):
        if self._wait_raises:
            raise self._wait_raises
        return self._returncode


def test_run_privileged_streaming_calls_on_line_for_each_line(monkeypatch, fake_which):
    calls = []
    fake_popen = _FakePopen(None, stdout_lines=["downloading 10%", "downloading 50%", "done"], returncode=0)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: fake_popen)

    result = privilege.run_privileged_streaming(["pacman", "-Syu", "--noconfirm"], on_line=calls.append)

    assert calls == ["downloading 10%", "downloading 50%", "done"]
    assert result.ok
    assert result.stdout == "downloading 10%\ndownloading 50%\ndone"
    assert result.stderr == ""


def test_run_privileged_streaming_uses_pkexec_prefix(monkeypatch, fake_which):
    captured_argv = {}

    def fake_popen_factory(argv, **kwargs):
        captured_argv["argv"] = argv
        return _FakePopen(argv, stdout_lines=[])

    monkeypatch.setattr(subprocess, "Popen", fake_popen_factory)
    privilege.run_privileged_streaming(["restorecon", "-Rv", "/home"], on_line=lambda _l: None)
    assert captured_argv["argv"] == ["pkexec", "restorecon", "-Rv", "/home"]


def test_run_privileged_streaming_reports_nonzero_returncode(monkeypatch, fake_which):
    fake_popen = _FakePopen(None, stdout_lines=["error: something broke"], returncode=1)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: fake_popen)

    result = privilege.run_privileged_streaming(["pacman", "-Syu"], on_line=lambda _l: None)
    assert not result.ok
    assert result.returncode == 1


def test_run_privileged_streaming_missing_binary_raises(monkeypatch, fake_which):
    def raise_not_found(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(subprocess, "Popen", raise_not_found)
    with pytest.raises(PrivilegeError, match="Command not found"):
        privilege.run_privileged_streaming(["nonexistent-tool"], on_line=lambda _l: None)


def test_run_privileged_streaming_timeout_kills_process_and_raises(monkeypatch, fake_which):
    fake_popen = _FakePopen(None, stdout_lines=[], wait_raises=subprocess.TimeoutExpired(cmd="slow", timeout=1))
    killed = []
    fake_popen.kill = lambda: killed.append(True)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: fake_popen)

    with pytest.raises(PrivilegeError, match="timed out"):
        privilege.run_privileged_streaming(["pacman", "-Syu"], on_line=lambda _l: None, timeout=1)
    assert killed == [True]


def test_run_privileged_streaming_writes_input_text_to_stdin(monkeypatch, fake_which):
    fake_popen = _FakePopen(None, stdout_lines=[])
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: fake_popen)

    privilege.run_privileged_streaming(["some-tool"], on_line=lambda _l: None, input_text="hello\n")
    assert fake_popen.stdin.written == "hello\n"
    assert fake_popen.stdin.closed


def test_run_privileged_streaming_no_pkexec_falls_back_to_sudo(monkeypatch, fake_which):
    fake_which.discard("pkexec")
    fake_which.add("sudo")
    captured_argv = {}

    def fake_popen_factory(argv, **kwargs):
        captured_argv["argv"] = argv
        return _FakePopen(argv, stdout_lines=[])

    monkeypatch.setattr(subprocess, "Popen", fake_popen_factory)
    privilege.run_privileged_streaming(["pacman", "-Syu"], on_line=lambda _l: None)
    assert captured_argv["argv"] == ["sudo", "-A", "pacman", "-Syu"]


# --------------------------------------------------------------- run_unprivileged_streaming --

def test_run_unprivileged_streaming_calls_on_line_for_each_line(monkeypatch):
    calls = []
    fake_popen = _FakePopen(None, stdout_lines=["compiling base", "compiling modules", "done"], returncode=0)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: fake_popen)

    result = privilege.run_unprivileged_streaming(["make", "-C", "/src", "conf", "all"], on_line=calls.append)

    assert calls == ["compiling base", "compiling modules", "done"]
    assert result.ok
    assert result.stdout == "compiling base\ncompiling modules\ndone"


def test_run_unprivileged_streaming_never_uses_pkexec_prefix(monkeypatch):
    """No fake_which fixture at all - if this accidentally routed through
    _resolve_privileged_prefix(), it would raise PrivilegeError since
    pkexec/sudo aren't faked as available here."""
    captured_argv = {}

    def fake_popen_factory(argv, **kwargs):
        captured_argv["argv"] = argv
        return _FakePopen(argv, stdout_lines=[])

    monkeypatch.setattr(subprocess, "Popen", fake_popen_factory)
    privilege.run_unprivileged_streaming(["make", "-C", "/src", "all"], on_line=lambda _l: None)
    assert captured_argv["argv"] == ["make", "-C", "/src", "all"]


def test_run_unprivileged_streaming_reports_nonzero_returncode(monkeypatch):
    fake_popen = _FakePopen(None, stdout_lines=["error: module failed to compile"], returncode=1)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: fake_popen)

    result = privilege.run_unprivileged_streaming(["make", "all"], on_line=lambda _l: None)
    assert not result.ok
    assert result.returncode == 1


def test_run_unprivileged_streaming_missing_binary_raises(monkeypatch):
    def raise_not_found(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(subprocess, "Popen", raise_not_found)
    with pytest.raises(PrivilegeError, match="Command not found"):
        privilege.run_unprivileged_streaming(["nonexistent-tool"], on_line=lambda _l: None)


def test_run_unprivileged_streaming_timeout_kills_process_and_raises(monkeypatch):
    fake_popen = _FakePopen(None, stdout_lines=[], wait_raises=subprocess.TimeoutExpired(cmd="slow", timeout=1))
    killed = []
    fake_popen.kill = lambda: killed.append(True)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: fake_popen)

    with pytest.raises(PrivilegeError, match="timed out"):
        privilege.run_unprivileged_streaming(["make", "all"], on_line=lambda _l: None, timeout=1)
    assert killed == [True]
