"""
atropa.backend.disk_health
-----------------------------
Disk health and space, plus the routine cleanup Arch desktops accumulate:

- SMART health through ``smartctl -H`` (smartmontools)
- mounted filesystems and their usage through ``df``
- periodic TRIM (``fstrim.timer``)
- journal, ``~/.cache`` and coredump sizes, and the privileged cleanup for
  each

README-style probes are deliberately read-only: the page can be opened
without a password prompt. Only the three cleanup actions escalate through
privilege.run_privileged().

smartctl's exit status is a bitmask, and its bits 3 (disk failing) and 4
(pre-fail attribute at/below threshold) mean the disk is unhealthy even when
``-H`` printed PASSED - so a status is never derived from the process exit
code alone.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from .privilege import CommandResult, run_privileged, run_unprivileged

# Patched in tests: reading the developer's real ~/.cache from a unit test
# would both be slow and delete their files in the clear_user_cache tests.
CACHE_DIR = Path.home() / ".cache"

# "Archived and active journals take up 1.2G in the file system."
JOURNAL_USAGE_RE = re.compile(r"take up\s+(\d+(?:\.\d+)?)\s*([KMGT]?)(?:i?B)?", re.IGNORECASE | re.DOTALL)
VACUUM_SIZE_RE = re.compile(r"^\d+[KMG]$")

_JOURNAL_UNITS = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
_SMART_VERDICT_MARKERS = ("overall-health", "smart health status", "health status")


@dataclass
class SmartStatus:
    device: str
    passed: bool | None  # None = smartctl printed no verdict at all
    detail: str  # the line worth showing as a subtitle


@dataclass
class Usage:
    target: str
    size: int
    used: int
    free: int
    percent: int


@dataclass
class FstrimStatus:
    installed: bool
    enabled: bool
    active: bool


def list_disks() -> list[str]:
    """Whole disks (not partitions) as /dev nodes, from lsblk's disk rows."""
    result = run_unprivileged(["lsblk", "-dn", "-o", "NAME,TYPE"], timeout=20)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"lsblk exited with status {result.returncode}")

    disks = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[1] != "disk":
            continue
        disks.append(f"/dev/{fields[0]}")
    return disks


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _verdict_line(text: str) -> str:
    for line in (text or "").splitlines():
        lowered = line.lower()
        if any(marker in lowered for marker in _SMART_VERDICT_MARKERS):
            return line.strip()
    return ""


def _probe_error_line(stdout: str, stderr: str) -> str:
    """
    Why smartctl couldn't answer, when it didn't.

    smartctl prints "Smartctl open device: ... failed: Permission denied" on
    stdout, not stderr, so a first-line fallback showed the version banner -
    which is what made an unreadable disk look like a mystery instead of an
    obvious permission problem.
    """
    for line in f"{stdout}\n{stderr}".splitlines():
        lowered = line.lower()
        if any(marker in lowered for marker in ("failed", "denied", "unable", "permission", "error")):
            return line.strip()
    return ""


def smart_status(device: str) -> SmartStatus:
    """
    Read one disk's SMART health.

    Never raises just because smartctl exited nonzero: its exit code reports
    conditions like "disk is failing" (exactly what we're asking), and a disk
    it can't open still needs a row. The page shows ``detail`` as the row's
    subtitle, which is where smartctl's own error text ends up.
    """
    result = run_unprivileged(["smartctl", "-H", device], timeout=30)

    # Only the verdict line counts. A whole-output substring check ("does
    # 'failed' appear anywhere") marked a perfectly healthy disk as failing
    # when smartctl couldn't open it at all: its error reads "Smartctl open
    # device: /dev/nvme0n1 failed: No such device". That is a probe failure,
    # not a SMART verdict, and must stay None ("couldn't tell").
    verdict = _verdict_line(result.stdout)
    passed: bool | None = None
    if verdict:
        lowered = verdict.lower()
        if "failed" in lowered:
            passed = False
        elif "passed" in lowered or "ok" in lowered:
            passed = True
    # Bits 3 (disk failing) and 4 (pre-fail attribute now below threshold).
    if result.returncode & 0x18:
        passed = False

    if verdict:
        detail = verdict
    else:
        # No verdict means the probe didn't get far enough. Say why (usually
        # "Permission denied") instead of showing the version banner, which
        # told the user nothing.
        detail = (
            _probe_error_line(result.stdout, result.stderr)
            or _first_line(result.stderr)
            or _first_line(result.stdout)
        )
    return SmartStatus(device, passed, detail)


def smart_status_privileged(device: str) -> SmartStatus:
    """
    Read SMART health as root, through pkexec.

    Unprivileged smartctl works on some SATA setups but is refused on most
    NVMe/ATA devices, which is why the page offers this as an explicit
    action rather than prompting just to draw a status row. `--json` is
    parsed instead of the human text: smartctl puts a failed open's reason
    in `smartctl.messages`, and that is the only useful thing to show.
    """
    result = run_privileged(["smartctl", "-H", "--json", device], timeout=120)
    try:
        data = json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            f"smartctl didn't return JSON for {device}: "
            f"{(result.stderr or result.stdout).strip()[:200] or 'no output'}"
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"smartctl returned unexpected JSON for {device}")

    smartctl_block = data.get("smartctl") if isinstance(data.get("smartctl"), dict) else {}
    messages = []
    for message in smartctl_block.get("messages", []):
        if isinstance(message, dict) and message.get("string"):
            messages.append(str(message["string"]).strip())

    status = data.get("smart_status")
    passed: bool | None = None
    if isinstance(status, dict) and isinstance(status.get("passed"), bool):
        passed = bool(status["passed"])
    # Bits 3 (disk failing) and 4 (pre-fail attribute below threshold), from
    # either smartctl's own JSON exit_status or its process status.
    exit_status = smartctl_block.get("exit_status", 0)
    if isinstance(exit_status, int) and exit_status & 0x18:
        passed = False
    if result.returncode & 0x18:
        passed = False

    if passed is None:
        detail = "; ".join(messages) or "smartctl reported no health verdict"
    elif messages:
        detail = "; ".join(messages)
    else:
        detail = f"SMART overall-health: {'PASSED' if passed else 'FAILED'}"
    return SmartStatus(device, passed, detail)


def filesystems() -> list[Usage]:
    """Parsed df rows for real filesystems, sizes in bytes."""
    result = run_unprivileged(
        ["df", "-B1", "--output=target,size,used,avail,pcent", "-x", "tmpfs", "-x", "devtmpfs", "-x", "efivarfs"],
        timeout=20,
    )
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"df exited with status {result.returncode}")

    usages = []
    for line in result.stdout.splitlines()[1:]:  # first line is the header
        fields = line.split()
        if len(fields) < 5:
            continue
        try:
            usages.append(
                Usage(
                    target=fields[0],
                    size=int(fields[1]),
                    used=int(fields[2]),
                    free=int(fields[3]),
                    percent=int(fields[4].rstrip("%")),
                )
            )
        except ValueError:
            continue  # a malformed row shouldn't hide every other mount
    return usages


def fstrim_status() -> FstrimStatus:
    """Whether fstrim exists and its timer is enabled/active."""
    installed = shutil.which("fstrim") is not None
    enabled = False
    active = False

    enabled_result = run_unprivileged(["systemctl", "is-enabled", "fstrim.timer"], timeout=10)
    if enabled_result.returncode == 0:
        enabled = True
    elif enabled_result.returncode == 4:  # "not-found": the unit (and util-linux) isn't there
        installed = False
        enabled = False
    # rc 1 means "disabled" - a normal answer, not an error.

    active_result = run_unprivileged(["systemctl", "is-active", "fstrim.timer"], timeout=10)
    if active_result.returncode == 0:
        active = True
    return FstrimStatus(installed, enabled, active)


def enable_fstrim() -> CommandResult:
    """Enable and start fstrim.timer now (the timer then trims weekly)."""
    return run_privileged(["systemctl", "enable", "--now", "fstrim.timer"])


def journal_usage() -> int:
    """Bytes the persistent journal takes on disk; raises when journalctl can't say."""
    result = run_unprivileged(["journalctl", "--disk-usage"], timeout=20)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"journalctl --disk-usage exited with status {result.returncode}")

    match = JOURNAL_USAGE_RE.search(result.stdout)
    if match is None:
        raise RuntimeError(
            f"Couldn't parse journalctl --disk-usage: {result.stdout.strip()[:200] or 'no output'}"
        )
    amount, unit = match.groups()
    return int(float(amount) * _JOURNAL_UNITS[unit.upper()])


def cache_size() -> int | None:
    """Bytes in ~/.cache, or None when it's missing or du can't read it."""
    if not CACHE_DIR.is_dir():
        return None
    result = run_unprivileged(["du", "-sb", str(CACHE_DIR)], timeout=60)
    if not result.ok:
        return None
    first = (result.stdout.split() or [""])[0]
    try:
        return int(first)
    except ValueError:
        return None


def vacuum_journal(size: str = "200M") -> CommandResult:
    """Drop the oldest archived journal entries until the journal fits in ``size``."""
    if not VACUUM_SIZE_RE.match(size):
        raise ValueError(f"{size!r} isn't a journal size like 200M or 1G")
    return run_privileged(["journalctl", f"--vacuum-size={size}"])


def clean_coredumps() -> CommandResult:
    """Let systemd-tmpfiles remove coredumps past their configured age."""
    return run_privileged(["systemd-tmpfiles", "--clean"])


def clear_user_cache() -> int:
    """
    Delete the direct children of ~/.cache and return how many were removed.

    Symlinks are unlinked rather than followed: a cached download pointing at
    a directory elsewhere must never turn "clear the cache" into deleting
    that directory's contents.
    """
    if not CACHE_DIR.is_dir():
        return 0

    removed = 0
    try:
        children = list(CACHE_DIR.iterdir())
    except FileNotFoundError:
        return 0  # removed between the check and the listing
    for child in children:
        try:
            if child.is_symlink() or not child.is_dir():
                child.unlink()
            else:
                shutil.rmtree(child)
        except FileNotFoundError:
            continue
        removed += 1
    return removed
