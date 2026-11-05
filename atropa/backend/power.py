"""
atropa.backend.power
-----------------------
Power and memory: power profiles, battery charge limits, and swap/zram state.

Everything here is read-only unless the caller explicitly asks for a change
(``set_profile``, ``set_charge_limit``, ``enable_zram``). The read-only parts
deliberately return empty/None instead of raising when a tool is missing or
answers non-zero, because a desktop has no battery and a VM has no
``power-profiles-daemon`` - neither should make the Power page unusable.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from .privilege import CommandResult, backup_file, run_privileged, run_unprivileged

POWER_SUPPLY = Path("/sys/class/power_supply")
PROC_SWAPS = Path("/proc/swaps")
PROC_MEMINFO = Path("/proc/meminfo")
SYS_POWER_STATE = Path("/sys/power/state")
ZRAM_GENERATOR_CONF = Path("/etc/systemd/zram-generator.conf")

# powerprofilesctl only knows these three; rejecting anything else here means
# a bad call is a ValueError, not a confusing polkit prompt for nothing.
PROFILE_NAMES = ("power-saver", "balanced", "performance")
_BATTERY_NAME = re.compile(r"^BAT\d+$")


def _read_text(path: Path) -> str | None:
    """The file's text, or None when it can't be read at all."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _read_int(path: Path) -> int | None:
    """A single integer in a sysfs file; None when missing or malformed."""
    text = _read_text(path)
    if text is None:
        return None
    try:
        return int(text.strip())
    except ValueError:
        return None


# ------------------------------------------------------------------ profiles --


def profiles() -> list[str]:
    """
    The profile names power-profiles-daemon offers, in its own order.

    Empty when the daemon (or its tool) isn't installed or answers non-zero:
    that's a normal state on many systems, not an error worth a toast.
    """
    if shutil.which("powerprofilesctl") is None:
        return []

    result = run_unprivileged(["powerprofilesctl", "list"], timeout=20)
    if not result.ok:
        return []

    names: list[str] = []
    for raw in result.stdout.splitlines():
        # Profile lines look like "* balanced:"; the indented details below
        # them (Driver:, Degraded:) end in values, not a colon.
        line = raw.strip()
        if line.startswith("*"):
            line = line[1:].strip()
        if not line.endswith(":"):
            continue
        name = line[:-1].strip()
        if not name or name == "Driver":
            continue
        names.append(name)
    return names


def current_profile() -> str | None:
    """The active profile, or None when the tool is missing or can't answer."""
    if shutil.which("powerprofilesctl") is None:
        return None

    result = run_unprivileged(["powerprofilesctl", "get"], timeout=20)
    if not result.ok:
        return None
    return result.stdout.strip() or None


def set_profile(name: str) -> CommandResult:
    """
    Switch profiles. Deliberately unprivileged: power-profiles-daemon asks
    polkit itself, and wrapping this in pkexec would prompt for a password
    the daemon doesn't need.
    """
    if name not in PROFILE_NAMES:
        raise ValueError(f"Unknown power profile {name!r}")
    return run_unprivileged(["powerprofilesctl", "set", name], timeout=30)


def tlp_active() -> bool:
    """True when TLP is the running power-management service."""
    result = run_unprivileged(["systemctl", "is-active", "tlp"], timeout=20)
    return result.stdout.strip() == "active"


# ------------------------------------------------------------------- battery --


@dataclass
class Battery:
    name: str
    capacity: int | None
    status: str
    charge_limit: int | None
    charge_limit_path: Path


def batteries() -> list[Battery]:
    """One entry per /sys/class/power_supply/BAT*; empty on desktops."""
    try:
        bases = sorted(POWER_SUPPLY.glob("BAT*"))
    except OSError:
        return []

    found: list[Battery] = []
    for base in bases:
        # charge_control_end_threshold only exists on hardware/firmware that
        # supports a charge limit; its absence is exactly what the UI checks.
        limit_path = base / "charge_control_end_threshold"
        status_text = _read_text(base / "status")
        found.append(
            Battery(
                name=base.name,
                capacity=_read_int(base / "capacity"),
                status=(status_text or "").strip(),
                charge_limit=_read_int(limit_path),
                charge_limit_path=limit_path,
            )
        )
    return found


def set_charge_limit(name: str, limit: int) -> CommandResult:
    """Persist a charge threshold through the sysfs file, as root."""
    if not isinstance(name, str) or not _BATTERY_NAME.match(name):
        raise ValueError(f"{name!r} isn't a battery name (expected BAT0, BAT1, ...)")
    if not isinstance(limit, int) or not 0 <= limit <= 100:
        raise ValueError("charge limit must be a whole number from 0 to 100")

    path = POWER_SUPPLY / name / "charge_control_end_threshold"
    # Writing sysfs directly fails with an unhelpful EACCES; say plainly that
    # this battery has no such control instead of letting tee report it.
    try:
        exists = path.exists()
    except OSError:
        exists = False
    if not exists:
        raise RuntimeError(f"{path} doesn't exist - this battery has no charge limit control")

    # The trailing newline is what sysfs expects; without it some drivers
    # reject the write while tee still exits 0.
    return run_privileged(["tee", str(path)], input_text=f"{limit}\n")


# ---------------------------------------------------------------------- zram --


@dataclass
class ZramDevice:
    name: str
    size: str
    data: str


def zram_devices() -> list[ZramDevice]:
    """Active zram block devices; empty when zramctl is absent or fails."""
    if shutil.which("zramctl") is None:
        return []

    result = run_unprivileged(
        ["zramctl", "--noheadings", "--output", "NAME,DISKSIZE,DATA"],
        timeout=20,
    )
    if not result.ok:
        return []

    devices: list[ZramDevice] = []
    for raw in result.stdout.splitlines():
        parts = raw.split()
        if len(parts) < 2:
            # A half-written line is worse than no line: skip it rather than
            # inventing a device with a blank size.
            continue
        devices.append(ZramDevice(parts[0], parts[1], parts[2] if len(parts) >= 3 else ""))
    return devices


def swap_total_mb() -> int:
    """Total swap from /proc/swaps, in MiB; 0 when there's no swap at all."""
    text = _read_text(PROC_SWAPS)
    if text is None:
        return 0

    total_kib = 0
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 3:
            continue  # header ("Filename Type Size ...") or a short line
        try:
            total_kib += int(parts[2])
        except ValueError:
            continue
    return total_kib // 1024


@dataclass
class HibernateStatus:
    supported: bool
    swap_mb: int
    ram_mb: int
    detail: str


def _gb(mb: int) -> str:
    """Human-readable GB for a MiB value, without a trailing ".0"."""
    size = mb / 1024
    return str(int(size)) if size == int(size) else f"{size:.1f}"


def _ram_total_mb() -> int:
    text = _read_text(PROC_MEMINFO)
    if text is None:
        return 0
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator or key.strip() != "MemTotal":
            continue
        fields = value.split()
        if not fields:
            return 0
        try:
            return int(fields[0]) // 1024
        except ValueError:
            return 0
    return 0


def hibernate_status() -> HibernateStatus:
    """
    Whether hibernation is advertised, and whether the available swap is big
    enough for it. The kernel only offers "disk" when the swap setup can hold
    a full RAM image, so the two checks answer different questions.
    """
    state_text = _read_text(SYS_POWER_STATE)
    supported = state_text is not None and "disk" in state_text.split()
    ram_mb = _ram_total_mb()
    swap_mb = swap_total_mb()

    if swap_mb == 0:
        detail = "no swap - hibernation needs at least RAM-size swap"
    elif swap_mb < ram_mb:
        detail = f"swap {_gb(swap_mb)} GB vs RAM {_gb(ram_mb)} GB - hibernate may fail"
    else:
        detail = "swap and RAM look sufficient"

    return HibernateStatus(supported, swap_mb, ram_mb, detail)


@dataclass
class ZramConfig:
    path: Path
    exists: bool
    content: str


def zram_config() -> ZramConfig:
    """
    zram-generator's config file, for showing what's already set up.

    A missing file is a normal "not configured yet"; an unreadable one
    reports exists=True with empty content, because offering "enable zram"
    over a config we couldn't read would silently overwrite it.
    """
    try:
        content = ZRAM_GENERATOR_CONF.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ZramConfig(ZRAM_GENERATOR_CONF, False, "")
    except OSError:
        return ZramConfig(ZRAM_GENERATOR_CONF, True, "")
    return ZramConfig(ZRAM_GENERATOR_CONF, True, content)


def enable_zram(size_mb: int) -> CommandResult:
    """
    Write a zram-generator config and start it. Returns the first step that
    failed, so the caller can show what actually went wrong rather than the
    last command's status.
    """
    if not isinstance(size_mb, int) or not 256 <= size_mb <= 65536:
        raise ValueError("zram size must be a whole number of MB from 256 to 65536")

    installed = run_unprivileged(["pacman", "-Q", "zram-generator"], timeout=20)
    if not installed.ok:
        raise RuntimeError("zram-generator isn't installed - install it with: pacman -S zram-generator")

    # Back up a hand-written config before replacing it, like every other
    # file Atropa edits.
    backup_file(str(ZRAM_GENERATOR_CONF))
    content = f"[zram0]\nzram-size = {size_mb}\n"
    written = run_privileged(["tee", str(ZRAM_GENERATOR_CONF)], input_text=content)
    if not written.ok:
        return written

    reloaded = run_privileged(["systemctl", "daemon-reload"])
    if not reloaded.ok:
        return reloaded

    # The template unit is what actually creates the device from the config.
    return run_privileged(["systemctl", "start", "systemd-zram-setup@zram0.service"])
