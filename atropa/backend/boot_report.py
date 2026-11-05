"""
atropa.backend.boot_report
------------------------------
Answers "what went wrong since this machine booted" from three independent
sources: journal errors, failed systemd units, and coredumpctl's crash list.

Each source is read on its own. A machine where coredumpctl has nothing to
say (or journal access is denied) still gets the other two groups, and
uptime is read separately so a broken /proc entry only blanks the summary.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from time import time

from . import system_health
from .privilege import run_unprivileged

PROC_UPTIME = Path("/proc/uptime")

_SIGNAL_RE = re.compile(r"SIG[A-Z0-9]+")
# The COREFILE column coredumpctl prints when it has an opinion about the file.
_CORE_STATUSES = {"present", "missing", "none"}


@dataclass
class BootProblem:
    source: str  # "journal", "unit", or "crash"
    title: str
    detail: str = ""


@dataclass
class BootReport:
    journal: list[BootProblem] = field(default_factory=list)
    units: list[BootProblem] = field(default_factory=list)
    crashes: list[BootProblem] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    uptime: float | None = None


def uptime_seconds() -> float | None:
    """The first field of /proc/uptime, or None when it can't be read."""
    try:
        fields = PROC_UPTIME.read_text(encoding="utf-8", errors="replace").split()
    except OSError:
        return None
    if not fields:
        return None
    try:
        return float(fields[0])
    except ValueError:
        return None


def journal_errors(limit: int = 50) -> list[BootProblem]:
    """Errors from this boot's journal, newest last, capped at `limit`."""
    if shutil.which("journalctl") is None:
        raise RuntimeError("journalctl isn't installed - it comes with systemd")

    result = run_unprivileged(
        ["journalctl", "-b", "-p", "err", "--no-pager", "-o", "short-iso"],
        timeout=30,
    )
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"journalctl exited with status {result.returncode}")

    problems: list[BootProblem] = []
    for raw in result.stdout.splitlines():
        if len(problems) >= limit:
            break
        # short-iso: "<timestamp> <host> <identifier> <message>". Identifiers
        # look like "kernel:" or "NetworkManager[812]:" and always keep their
        # trailing colon, which is what tells a real entry apart from
        # journalctl's "-- No entries --" legend.
        parts = raw.strip().split(None, 3)
        if len(parts) < 4:
            continue
        _timestamp, _host, identifier, message = parts
        if not identifier.endswith(":"):
            continue
        title = identifier.split("[", 1)[0].rstrip(":")
        if not title:
            continue
        problems.append(BootProblem("journal", title, message))
    return problems


def failed_units() -> list[BootProblem]:
    # system_health already parses systemctl --failed; reusing it keeps the
    # two pages from disagreeing about what a failed unit is.
    return [
        BootProblem("unit", unit.name, unit.description)
        for unit in system_health.failed_units()
    ]


def _boot_epoch() -> int | None:
    """Seconds-since-the-epoch at which this machine booted, or None."""
    uptime = uptime_seconds()
    return int(time() - uptime) if uptime is not None else None


def recent_crashes(limit: int = 20) -> list[BootProblem]:
    """
    Coredumps recorded since boot, from `coredumpctl list`.

    --since matters: coredumps persist across reboots, and without it a
    three-week-old baloo crash filled the "since this boot" page. If uptime
    can't be read, list without the filter rather than hide crashes.
    """
    if shutil.which("coredumpctl") is None:
        raise RuntimeError("coredumpctl isn't installed - it comes with systemd")

    argv = ["coredumpctl", "--no-pager"]
    boot_epoch = _boot_epoch()
    if boot_epoch is not None:
        argv.extend(["--since", f"@{boot_epoch}"])
    argv.append("list")
    result = run_unprivileged(argv, timeout=30)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"coredumpctl exited with status {result.returncode}")

    problems: list[BootProblem] = []
    for raw in result.stdout.splitlines():
        if len(problems) >= limit:
            break
        line = raw.strip()
        if not line or "No coredumps" in line or line.startswith("TIME"):
            continue
        fields = line.split()
        # The header's "SIG" column has no value; a data row's signal is the
        # only token shaped like SIGSEGV/SIGABRT/...
        signal_index = next(
            (index for index, field in enumerate(fields) if _SIGNAL_RE.fullmatch(field)),
            None,
        )
        if signal_index is None:
            continue
        # Column order is fixed: ... SIG COREFILE EXE [SIZE]. SIZE is often
        # "-", so "the last field is the exe" read the size as a program name
        # and every crash came out titled "-".
        core = fields[signal_index + 1] if signal_index + 1 < len(fields) else ""
        exe = fields[signal_index + 2] if signal_index + 2 < len(fields) else ""
        signal = fields[signal_index]
        title = os.path.basename(exe) or "Unknown program"
        detail = f"{signal}, core file {core}" if core.lower() in _CORE_STATUSES else signal
        problems.append(BootProblem("crash", title, detail))
    return problems


def collect() -> BootReport:
    """Run every source, keeping each one's failure local to its own group."""
    report = BootReport()

    try:
        report.journal = journal_errors()
    except Exception as exc:  # noqa: BLE001 - one unreadable source must not blank the rest
        report.errors["journal"] = str(exc)

    try:
        report.units = failed_units()
    except Exception as exc:  # noqa: BLE001
        report.errors["units"] = str(exc)

    try:
        report.crashes = recent_crashes()
    except Exception as exc:  # noqa: BLE001
        report.errors["crashes"] = str(exc)

    try:
        report.uptime = uptime_seconds()
    except Exception:  # noqa: BLE001 - uptime is cosmetic; the summary above still matters
        report.uptime = None

    return report
