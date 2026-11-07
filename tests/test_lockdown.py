"""Tests for atropa.backend.lockdown."""

from __future__ import annotations

import json

import pytest

from atropa.backend import lockdown


def _reads(fake_run, networking="enabled", wifi="enabled", active="active", enabled="enabled"):
    fake_run.set_response(["nmcli", "networking"], stdout=networking + "\n")
    fake_run.set_response(["nmcli", "radio", "wifi"], stdout=wifi + "\n")
    fake_run.set_response(["systemctl", "is-active", "bluetooth"], stdout=active + "\n")
    fake_run.set_response(["systemctl", "is-enabled", "bluetooth"], stdout=enabled + "\n")


def _privileged_calls(fake_run):
    return [call for call in fake_run.calls if call and call[0] == "pkexec"]


def _snapshot(networking=True, wifi=True, bluetooth_active=True):
    return lockdown.RadioSnapshot(networking, wifi, bluetooth_active, True, "2026-11-07T04:00:00+01:00")


def test_enable_turns_off_bluetooth_wifi_then_networking(fake_run, fake_which):
    fake_which.add("nmcli")
    _reads(fake_run)

    assert lockdown.enable().ok

    assert _privileged_calls(fake_run) == [
        ["pkexec", "systemctl", "stop", "bluetooth"],
        ["pkexec", "nmcli", "radio", "wifi", "off"],
        ["pkexec", "nmcli", "networking", "off"],
    ]


def test_enable_saves_the_prior_state(fake_run, fake_which):
    fake_which.add("nmcli")
    _reads(fake_run, networking="disabled", wifi="enabled", active="inactive")

    lockdown.enable()

    saved = json.loads(lockdown.LOCKDOWN_FILE.read_text())
    assert saved["networking"] is False
    assert saved["wifi"] is True
    assert saved["bluetooth_active"] is False


def test_enable_skips_bluetooth_when_it_was_not_running(fake_run, fake_which):
    fake_which.add("nmcli")
    _reads(fake_run, active="inactive")

    lockdown.enable()

    assert ["pkexec", "systemctl", "stop", "bluetooth"] not in fake_run.calls
    assert ["pkexec", "nmcli", "networking", "off"] in fake_run.calls


def test_enable_refuses_over_ssh(monkeypatch, fake_run, fake_which):
    fake_which.add("nmcli")
    monkeypatch.setenv("SSH_CONNECTION", "10.0.0.2 1234 10.0.0.1 22")

    with pytest.raises(RuntimeError, match="over SSH"):
        lockdown.enable()

    assert not lockdown.LOCKDOWN_FILE.exists()
    assert fake_run.calls == []


def test_enable_refuses_without_networkmanager(fake_run, fake_which):
    with pytest.raises(RuntimeError, match="NetworkManager"):
        lockdown.enable()
    assert fake_run.calls == []


def test_enable_rolls_back_when_a_step_fails(fake_run, fake_which):
    fake_which.add("nmcli")
    _reads(fake_run)
    fake_run.set_response(["pkexec", "nmcli", "radio", "wifi", "off"], returncode=1, stderr="radio locked")

    with pytest.raises(RuntimeError, match="Wi-Fi radio"):
        lockdown.enable()

    calls = _privileged_calls(fake_run)
    assert ["pkexec", "systemctl", "stop", "bluetooth"] in calls
    assert ["pkexec", "systemctl", "start", "bluetooth"] in calls  # rolled back
    assert ["pkexec", "nmcli", "networking", "off"] not in calls
    assert not lockdown.LOCKDOWN_FILE.exists()


def test_disable_restores_only_what_was_on(fake_run):
    lockdown.save_snapshot(_snapshot(networking=True, wifi=False, bluetooth_active=True))

    assert lockdown.disable().ok

    assert _privileged_calls(fake_run) == [
        ["pkexec", "nmcli", "networking", "on"],
        ["pkexec", "systemctl", "start", "bluetooth"],
    ]
    assert not lockdown.LOCKDOWN_FILE.exists()


def test_disable_with_nothing_to_restore_just_clears(fake_run):
    lockdown.save_snapshot(_snapshot(networking=False, wifi=False, bluetooth_active=False))

    assert lockdown.disable().ok
    assert _privileged_calls(fake_run) == []
    assert not lockdown.LOCKDOWN_FILE.exists()


def test_disable_is_an_error_when_not_active(fake_run):
    with pytest.raises(RuntimeError, match="isn't active"):
        lockdown.disable()


def test_status_reports_active_and_current_radios(fake_run, fake_which):
    fake_which.add("nmcli")
    lockdown.save_snapshot(_snapshot())
    _reads(fake_run, networking="disabled", wifi="disabled", active="inactive")

    status = lockdown.status()

    assert status.active is True
    assert status.networking is False
    assert status.wifi is False
    assert status.bluetooth_active is False
    assert status.snapshot.networking is True


def test_status_tolerates_unreadable_nmcli(fake_run, fake_which):
    fake_which.add("nmcli")
    fake_run.set_response(["nmcli", "networking"], returncode=1, stderr="no daemon")

    status = lockdown.status()

    assert status.active is False
    assert status.networking is None


def test_corrupt_state_file_reads_as_inactive(monkeypatch, tmp_path):
    path = tmp_path / "lockdown.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(lockdown, "LOCKDOWN_FILE", path)

    assert lockdown.load_snapshot() is None
    assert lockdown.is_active() is False


def test_snapshot_roundtrip():
    snapshot = _snapshot()
    lockdown.save_snapshot(snapshot)
    assert lockdown.load_snapshot() == snapshot
    lockdown.clear_snapshot()
    assert lockdown.load_snapshot() is None
