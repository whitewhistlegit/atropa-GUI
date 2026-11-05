"""
atropa.backend.firmware
--------------------------
Firmware devices and updates through fwupd, the standard firmware-update
daemon on Arch.

Everything read-only (listing devices, listing pending updates) runs as the
current user, so opening the page never prompts for a password. The two
actions fwupd needs root for - refreshing metadata and applying updates -
go through privilege.run_privileged()/run_privileged_streaming(), like every
other state-changing call in Atropa.

fwupdmgr's ``--json`` output has changed shape over the years (and the
``Devices`` key is capitalised in some versions, lowercase in others), so the
parsing here accepts both and a bare list. An update's available version is
the first release fwupd lists; when fwupd lists none, the device's own
``Version`` is the fallback, matching what ``fwupdmgr get-updates`` shows for
a device that is already current.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from typing import Callable

from .privilege import CommandResult, run_privileged, run_privileged_streaming, run_unprivileged

FWUPDMGR = "fwupdmgr"
FWUPD_MISSING = "fwupd isn't installed - install it with: pacman -S fwupd"


@dataclass
class FirmwareDevice:
    name: str
    device_id: str
    version: str
    vendor: str = ""


@dataclass
class FirmwareUpdate:
    name: str
    device_id: str
    current_version: str
    available_version: str


def fwupd_installed() -> bool:
    """True when fwupdmgr is on PATH - looks the tool up each call so installing it takes effect without a restart."""
    return shutil.which(FWUPDMGR) is not None


def _field(entry: dict, *keys: str) -> str:
    """The first non-None value among ``keys`` as a string (fwupd mixes casing between versions)."""
    for key in keys:
        value = entry.get(key)
        if value is not None:
            return str(value)
    return ""


def _entries(stdout: str) -> list | None:
    """
    The device list inside fwupdmgr's JSON, or None when stdout isn't JSON
    at all (older fwupd releases printed plain text even with --json).
    """
    text = (stdout or "").strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("Devices", "devices"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return None


def _identity(entry: dict) -> tuple[str, str]:
    return (
        _field(entry, "Name", "name"),
        _field(entry, "DeviceId", "deviceId", "DeviceID", "device_id"),
    )


def devices() -> list[FirmwareDevice]:
    """List the firmware devices fwupd knows about; raises when fwupd can't answer."""
    if not fwupd_installed():
        raise RuntimeError(FWUPD_MISSING)

    result = run_unprivileged([FWUPDMGR, "get-devices", "--json"], timeout=60)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"fwupdmgr get-devices exited with status {result.returncode}")

    entries = _entries(result.stdout)
    if entries is None:
        # Returning [] here would claim "no devices" when fwupd actually
        # printed something we couldn't read - an error the page can show is
        # more honest than an empty list.
        raise RuntimeError("Couldn't parse fwupdmgr's device list - it didn't print the expected JSON")

    found = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name, device_id = _identity(entry)
        if not name and not device_id:
            continue  # fwupd's JSON sometimes carries metadata-only entries
        found.append(
            FirmwareDevice(
                name=name,
                device_id=device_id,
                version=_field(entry, "Version", "version"),
                vendor=_field(entry, "Vendor", "vendor"),
            )
        )
    return found


def updates() -> list[FirmwareUpdate]:
    """
    List pending firmware updates.

    fwupd reports "nothing to do" in more than one way: valid JSON with an
    empty device list, empty stdout, or a nonzero exit with "No updates" in
    the text. All of those mean the same thing to the page, so they all
    become [] instead of an error toast every time the user opens it.
    """
    if not fwupd_installed():
        raise RuntimeError(FWUPD_MISSING)

    result = run_unprivileged([FWUPDMGR, "get-updates", "--json"], timeout=120)
    if not result.ok:
        if "no updates" in f"{result.stdout}\n{result.stderr}".lower():
            return []
        raise RuntimeError(result.stderr.strip() or f"fwupdmgr get-updates exited with status {result.returncode}")

    entries = _entries(result.stdout)
    if entries is None:
        return []  # empty output or the older plain-text "No updates available"

    found = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name, device_id = _identity(entry)
        if not name and not device_id:
            continue

        current = _field(entry, "Version", "version")
        available = ""
        releases = entry.get("Releases", entry.get("releases"))
        if isinstance(releases, list):
            for release in releases:
                if not isinstance(release, dict):
                    continue
                version = _field(release, "Version", "version")
                if version:
                    available = version
                    break
        if not available:
            # A device with no release list reports its own Version; when
            # that equals current there is nothing to install for it.
            available = current
        if not available or available == current:
            continue
        found.append(FirmwareUpdate(name, device_id, current, available))
    return found


def refresh() -> CommandResult:
    """Ask fwupd to download fresh metadata from the LVFS (needs root to write its cache)."""
    return run_privileged([FWUPDMGR, "refresh", "--force"])


def install_updates(on_line: Callable[[str], None]) -> CommandResult:
    """
    Apply every pending update, streaming fwupd's progress to ``on_line``.

    fwupd can take many minutes (downloading, flashing, verifying) and can
    reboot the machine itself when the firmware requires it, so this gets
    the same long timeout as a full system upgrade rather than the 10-minute
    default for privileged calls.
    """
    return run_privileged_streaming([FWUPDMGR, "update", "-y"], on_line, timeout=3600)
