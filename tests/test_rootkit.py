"""Tests for atropa.backend.rootkit."""

from __future__ import annotations

import json

import pytest

from atropa.backend import rootkit
from atropa.backend.privilege import CommandResult


def _fake_streaming(monkeypatch, lines, returncode=1):
    captured = {}

    def fake(argv, on_line, input_text=None, timeout=None):
        captured["argv"] = argv
        captured["timeout"] = timeout
        for line in lines:
            on_line(line)
        return CommandResult(returncode, "\n".join(lines), "")

    monkeypatch.setattr(rootkit, "run_privileged_streaming", fake)
    return captured


# ------------------------------------------------------------ installed/

def test_is_installed_when_the_binary_is_root_only(monkeypatch, tmp_path):
    # Arch ships rkhunter 0700 root:root; shutil.which() is false for a normal
    # user even though the package is installed. Existence is what counts.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    binary = bin_dir / "rkhunter"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o700)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setattr(rootkit.shutil, "which", lambda _name: None)

    assert rootkit.is_installed() is True


def test_is_installed_false_when_absent(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(rootkit.shutil, "which", lambda _name: None)
    monkeypatch.setattr(rootkit, "STANDARD_BIN", tmp_path / "missing")

    assert rootkit.is_installed() is False


def test_status_reports_installed_and_database_time(fake_which, monkeypatch, tmp_path):
    fake_which.add("rkhunter")
    db = tmp_path / "db"
    db.mkdir()
    (db / "mirrors.dat").write_text("x")
    (db / "signatures").mkdir()
    monkeypatch.setattr(rootkit, "DB_DIR", db)

    status = rootkit.status()

    assert status.installed is True
    assert status.database_updated.startswith("20")


def test_status_handles_a_missing_database(fake_which, monkeypatch, tmp_path):
    fake_which.add("rkhunter")
    monkeypatch.setattr(rootkit, "DB_DIR", tmp_path / "missing")
    assert rootkit.status().database_updated == ""


def test_scan_refuses_without_rkhunter(monkeypatch, fake_which):
    monkeypatch.setattr(rootkit, "_binary_path", lambda: None)
    with pytest.raises(RuntimeError, match="pacman -S rkhunter"):
        rootkit.scan(lambda _line: None)


# ---------------------------------------------------------------- scans/

def test_scan_streams_the_fixed_helper_operation(fake_which, monkeypatch):
    fake_which.add("rkhunter")
    captured = _fake_streaming(monkeypatch, ["[ Warning ] something"])

    result = rootkit.scan(lambda _line: None)

    assert result.returncode == 1
    assert captured["argv"] == ["rootkit-scan"]
    assert captured["timeout"] == 3600


def test_scan_filters_gnu_grep_noise_from_rkhunter(fake_which, monkeypatch):
    fake_which.add("rkhunter")
    seen = []

    def fake(argv, on_line, input_text=None, timeout=None):
        on_line("egrep: warning: egrep is obsolescent; using grep -E")
        on_line("grep: warning: stray \\ before +")
        on_line("[ Warning ] The file '/usr/bin/foo' has changed")
        return CommandResult(1, "", "")

    monkeypatch.setattr(rootkit, "run_privileged_streaming", fake)

    rootkit.scan(seen.append)

    assert seen == ["[ Warning ] The file '/usr/bin/foo' has changed"]


def test_visible_keeps_real_warnings():
    assert rootkit._visible("[ Warning ] something") is True
    assert rootkit._visible("Warning: hidden file") is True
    assert rootkit._visible("egrep: warning: egrep is obsolescent; using grep -E") is False
    assert rootkit._visible("grep: warning: stray \\ before +") is False


def test_update_signatures_uses_the_helper_operation(fake_run, fake_which):
    fake_which.add("rkhunter")
    fake_run.set_response(["pkexec", "rootkit-update"], stdout="updated\n")

    assert rootkit.update_signatures().ok
    assert fake_run.last_call() == ["pkexec", "rootkit-update"]


def test_update_baseline_uses_the_helper_operation(fake_run, fake_which):
    fake_which.add("rkhunter")
    fake_run.set_response(["pkexec", "rootkit-baseline"], stdout="baseline\n")

    assert rootkit.update_baseline().ok
    assert fake_run.last_call() == ["pkexec", "rootkit-baseline"]


def test_update_refuses_without_rkhunter(monkeypatch, fake_which):
    monkeypatch.setattr(rootkit, "_binary_path", lambda: None)
    with pytest.raises(RuntimeError, match="rkhunter"):
        rootkit.update_signatures()


# -------------------------------------------------------------- parsing/

def test_parse_warnings_handles_both_output_shapes():
    output = (
        "[ Warning ] The file '/usr/bin/foo' has changed\n"
        "[ Info ] Kernel module check\n"
        "Warning: hidden file /dev/.x\n"
        "[ Warning ] The file '/usr/bin/foo' has changed\n"
        "Rootkit checks...\n"
    )

    warnings = rootkit.parse_warnings(output)

    assert warnings == [
        "[ Warning ] The file '/usr/bin/foo' has changed",
        "Warning: hidden file /dev/.x",
    ]


def test_parse_warnings_clean_output_is_empty():
    assert rootkit.parse_warnings("Checking system...\nAll checks passed\n") == []


def test_build_scan_record_keeps_warnings_and_time():
    record = rootkit.build_scan_record("Warning: x\n", 1, when="2026-11-07T04:00:00+01:00")
    assert record.checked_at == "2026-11-07T04:00:00+01:00"
    assert record.returncode == 1
    assert record.warnings == ["Warning: x"]
    assert record.has_warnings is True


def test_clean_scan_record_has_no_warnings():
    record = rootkit.build_scan_record("", 0)
    assert record.warnings == []
    assert record.has_warnings is False


# ---------------------------------------------------------------- state/

def test_scan_record_roundtrip(tmp_path, monkeypatch):
    path = tmp_path / "scan.json"
    monkeypatch.setattr(rootkit, "LAST_SCAN_FILE", path)
    record = rootkit.build_scan_record("Warning: x\nWarning: y\n", 1, when="2026-11-07T04:00:00+01:00")

    rootkit.save_scan_record(record)

    assert rootkit.load_scan_record() == record


def test_scan_record_missing_is_none(tmp_path, monkeypatch):
    monkeypatch.setattr(rootkit, "LAST_SCAN_FILE", tmp_path / "missing.json")
    assert rootkit.load_scan_record() is None


def test_scan_record_corrupt_is_none(tmp_path, monkeypatch):
    path = tmp_path / "bad.json"
    path.write_text("{nope", encoding="utf-8")
    monkeypatch.setattr(rootkit, "LAST_SCAN_FILE", path)
    assert rootkit.load_scan_record() is None


def test_scan_record_drops_non_string_warnings(tmp_path, monkeypatch):
    path = tmp_path / "scan.json"
    path.write_text(
        json.dumps({"checked_at": "now", "returncode": 1, "warnings": ["ok", 3, None]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(rootkit, "LAST_SCAN_FILE", path)
    assert rootkit.load_scan_record().warnings == ["ok"]


def test_clear_scan_record_removes_the_file(tmp_path, monkeypatch):
    path = tmp_path / "scan.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(rootkit, "LAST_SCAN_FILE", path)
    rootkit.clear_scan_record()
    assert not path.exists()
