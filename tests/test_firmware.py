"""Tests for atropa.backend.firmware."""

from __future__ import annotations

import json

import pytest

from atropa.backend import firmware
from atropa.backend.privilege import CommandResult


def _devices_payload(payload) -> str:
    return json.dumps(payload)


# ---------------------------------------------------------------- installed --

def test_fwupd_installed_follows_which(fake_which):
    assert firmware.fwupd_installed() is False
    fake_which.add("fwupdmgr")
    assert firmware.fwupd_installed() is True


# ------------------------------------------------------------------ devices --

def test_devices_parses_uppercase_json_and_runs_exact_command(fake_run, fake_which):
    fake_which.add("fwupdmgr")
    fake_run.set_response(
        ["fwupdmgr", "get-devices", "--json"],
        stdout=_devices_payload(
            {
                "Devices": [
                    {
                        "Name": "ThinkPad Embedded Controller",
                        "DeviceId": "8b7c0e1a",
                        "Version": "1.2.3",
                        "Vendor": "Lenovo",
                    }
                ]
            }
        ),
    )

    assert firmware.devices() == [
        firmware.FirmwareDevice("ThinkPad Embedded Controller", "8b7c0e1a", "1.2.3", "Lenovo")
    ]
    assert fake_run.calls == [["fwupdmgr", "get-devices", "--json"]]


def test_devices_accepts_lowercase_keys_a_bare_list_and_keeps_partial_entries(fake_run, fake_which):
    fake_which.add("fwupdmgr")
    fake_run.set_response(
        ["fwupdmgr", "get-devices", "--json"],
        stdout=_devices_payload(
            [
                {"name": "NVMe SSD", "deviceId": "nvme-1", "version": "2.0", "vendor": "Acme"},
                {"deviceId": "id-only", "version": "1.0"},
                {"Version": "9.9"},  # neither name nor id -> metadata noise, skipped
            ]
        ),
    )

    assert firmware.devices() == [
        firmware.FirmwareDevice("NVMe SSD", "nvme-1", "2.0", "Acme"),
        firmware.FirmwareDevice("", "id-only", "1.0", ""),
    ]


def test_devices_accepts_lowercase_devices_dict(fake_run, fake_which):
    fake_which.add("fwupdmgr")
    fake_run.set_response(
        ["fwupdmgr", "get-devices", "--json"],
        stdout=_devices_payload({"devices": [{"name": "Dock", "deviceId": "dock-1", "version": "3.1"}]}),
    )

    assert firmware.devices() == [firmware.FirmwareDevice("Dock", "dock-1", "3.1", "")]


def test_devices_without_fwupd_raises_install_hint_and_runs_nothing(fake_run, fake_which):
    with pytest.raises(RuntimeError, match="pacman -S fwupd"):
        firmware.devices()
    assert fake_run.calls == []


def test_devices_nonzero_exit_surfaces_stderr(fake_run, fake_which):
    fake_which.add("fwupdmgr")
    fake_run.set_response(
        ["fwupdmgr", "get-devices", "--json"],
        stderr="Failed to connect to daemon: permission denied",
        returncode=1,
    )
    with pytest.raises(RuntimeError, match="Failed to connect to daemon"):
        firmware.devices()


def test_devices_malformed_json_is_a_readable_error(fake_run, fake_which):
    fake_which.add("fwupdmgr")
    fake_run.set_response(["fwupdmgr", "get-devices", "--json"], stdout="{not json")
    with pytest.raises(RuntimeError, match="didn't print the expected JSON"):
        firmware.devices()


def test_devices_empty_output_is_a_readable_error(fake_run, fake_which):
    fake_which.add("fwupdmgr")
    fake_run.set_response(["fwupdmgr", "get-devices", "--json"], stdout="")
    with pytest.raises(RuntimeError, match="didn't print the expected JSON"):
        firmware.devices()


# ------------------------------------------------------------------ updates --

def test_updates_uses_first_release_version_and_skips_current_devices(fake_run, fake_which):
    fake_which.add("fwupdmgr")
    fake_run.set_response(
        ["fwupdmgr", "get-updates", "--json"],
        stdout=_devices_payload(
            {
                "Devices": [
                    {
                        "Name": "EC",
                        "DeviceId": "ec-1",
                        "Version": "1.0",
                        "Releases": [{"Version": "1.3"}, {"Version": "1.1"}],
                    },
                    {  # first release is the newest and equals current -> nothing to do
                        "Name": "SSD",
                        "DeviceId": "ssd-1",
                        "Version": "2.0",
                        "Releases": [{"Version": "2.0"}],
                    },
                    {  # no releases at all -> falls back to Version, which equals current
                        "Name": "Dock",
                        "DeviceId": "dock-1",
                        "Version": "3.0",
                        "Releases": [],
                    },
                    {  # empty release version is ignored; the next real one counts
                        "Name": "Keyboard",
                        "DeviceId": "kbd-1",
                        "Version": "4.0",
                        "Releases": [{"Version": ""}, {"Version": "4.1"}],
                    },
                ]
            }
        ),
    )

    assert firmware.updates() == [
        firmware.FirmwareUpdate("EC", "ec-1", "1.0", "1.3"),
        firmware.FirmwareUpdate("Keyboard", "kbd-1", "4.0", "4.1"),
    ]
    assert fake_run.calls == [["fwupdmgr", "get-updates", "--json"]]


def test_updates_empty_json_means_none_available(fake_run, fake_which):
    fake_which.add("fwupdmgr")
    fake_run.set_response(["fwupdmgr", "get-updates", "--json"], stdout="")
    assert firmware.updates() == []


def test_updates_malformed_json_means_none_available(fake_run, fake_which):
    fake_which.add("fwupdmgr")
    fake_run.set_response(["fwupdmgr", "get-updates", "--json"], stdout="No updates available")
    assert firmware.updates() == []


def test_updates_nonzero_exit_with_no_updates_text_means_none_available(fake_run, fake_which):
    fake_which.add("fwupdmgr")
    fake_run.set_response(
        ["fwupdmgr", "get-updates", "--json"],
        stdout="No updates available for this system",
        returncode=2,
    )
    assert firmware.updates() == []


def test_updates_nonzero_exit_without_no_updates_text_raises(fake_run, fake_which):
    fake_which.add("fwupdmgr")
    fake_run.set_response(
        ["fwupdmgr", "get-updates", "--json"],
        stderr="Failed to load metadata: network unreachable",
        returncode=1,
    )
    with pytest.raises(RuntimeError, match="network unreachable"):
        firmware.updates()


def test_updates_without_fwupd_raises_install_hint(fake_run, fake_which):
    with pytest.raises(RuntimeError, match="pacman -S fwupd"):
        firmware.updates()
    assert fake_run.calls == []


# ------------------------------------------------------------------ actions --

def test_refresh_runs_privileged_fwupdmgr_refresh(fake_run, fake_which):
    fake_run.set_response(["pkexec", "fwupdmgr", "refresh", "--force"], stdout="Successfully refreshed")
    result = firmware.refresh()

    assert result.ok
    assert fake_run.calls == [["pkexec", "fwupdmgr", "refresh", "--force"]]


def test_install_updates_streams_privileged_update_with_long_timeout(monkeypatch):
    captured = {}

    def fake_streaming(argv, on_line, input_text=None, timeout=None):
        captured["argv"] = argv
        captured["timeout"] = timeout
        on_line("Updating firmware…")
        return CommandResult(0, "Updating firmware…\n", "")

    monkeypatch.setattr(firmware, "run_privileged_streaming", fake_streaming)
    lines: list[str] = []
    result = firmware.install_updates(lines.append)

    assert captured == {"argv": ["fwupdmgr", "update", "-y"], "timeout": 3600}
    assert lines == ["Updating firmware…"]
    assert result.ok
