"""
atropa.backend.aide
--------------------
CIS DIL Phase 3: AIDE filesystem integrity checking (CIS 1.3).

AIDE was dropped from Arch's official repos and is AUR-only now (confirmed
via the Arch forums, not assumed) - matching the existing posture for
paru/yay themselves (see dependencies.py), Atropa never builds/installs
it: this module only manages it once it's already on the system, the same
trust boundary already drawn everywhere else that touches AUR-only
tooling. There's no `install()` function here on purpose.

Confirmed working over 72+ hours on a real bare-metal SELinux-enabled
Arch install using the `aide-selinux` AUR package rather than plain
`aide` - the latter has had real build failures in the wild (e.g. against
newer nettle versions), while `aide-selinux` built cleanly for that
install. Both provide the same `aide` binary this module looks for via
`shutil.which`, so nothing here needs to know or care which one is
actually installed - worth knowing as a troubleshooting note if a user
reports `is_installed()` returning False after a failed AUR build,
though, since "try aide-selinux instead" is a real fix, not a guess.

Scheduling deliberately doesn't add a second timer: the AUR `aide` package
already ships its own systemd .service/.timer pair for periodic checks,
but the exact unit names have shifted across package revisions
(`aide.timer` vs `aidecheck.timer` are both documented in the wild).
`detect_timer_unit()` probes the known candidate names via `systemctl
list-unit-files` rather than hardcoding one, and every function here that
touches "the timer" operates on whichever one is actually found - this
module never defines a duplicate unit of its own. If a future package
revision ships a name not in TIMER_CANDIDATES, detect_timer_unit()
correctly reports None (unmanaged) rather than guessing wrong.

The two operations that actually touch the filesystem tree
(`initialize_baseline()` / `run_check()`, and `update_baseline()` which is
the same mechanism as init) all stream their output rather than block
silently - `aide --init`/`--check` walk the whole configured tree, which
can genuinely take minutes on a big disk, so this needs the same
`run_privileged_streaming` progress pattern already used for a full
pacman upgrade and an SELinux relabel, not a frozen-looking page in the
meantime.
"""

from __future__ import annotations

import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .privilege import CommandResult, run_privileged, run_privileged_streaming, run_unprivileged

CONFIG_FILE = "/etc/aide.conf"
DB_ACTIVE_CANDIDATES = ["/var/lib/aide/aide.db.gz", "/var/lib/aide/aide.db"]
DB_NEW_CANDIDATES = ["/var/lib/aide/aide.db.new.gz", "/var/lib/aide/aide.db.new"]

# Checked in this order, first match wins - see module docstring.
TIMER_CANDIDATES = ["aidecheck.timer", "aide.timer", "aide-check.timer"]


def is_installed() -> bool:
    return shutil.which("aide") is not None


def _find_existing(candidates: list[str]) -> str | None:
    for path in candidates:
        if Path(path).exists():
            return path
    return None


def baseline_initialized() -> bool:
    return _find_existing(DB_ACTIVE_CANDIDATES) is not None


def _unit_exists(unit: str) -> bool:
    return unit in run_unprivileged(["systemctl", "list-unit-files", unit]).stdout


def detect_timer_unit() -> str | None:
    for unit in TIMER_CANDIDATES:
        if _unit_exists(unit):
            return unit
    return None


@dataclass
class AideStatus:
    installed: bool
    config_exists: bool
    baseline_initialized: bool
    timer_unit: str | None
    timer_active: bool
    timer_enabled: bool


def get_status() -> AideStatus:
    installed = is_installed()
    if not installed:
        return AideStatus(False, False, False, None, False, False)

    timer = detect_timer_unit()
    active = False
    enabled = False
    if timer:
        active = run_unprivileged(["systemctl", "is-active", timer]).stdout.strip() == "active"
        enabled = run_unprivileged(["systemctl", "is-enabled", timer]).stdout.strip() == "enabled"

    return AideStatus(
        installed=True,
        config_exists=Path(CONFIG_FILE).exists(),
        baseline_initialized=baseline_initialized(),
        timer_unit=timer,
        timer_active=active,
        timer_enabled=enabled,
    )


def initialize_baseline(on_line: Callable[[str], None]) -> CommandResult:
    """
    `aide --init` writes a fresh database to the "new" path only - it never
    touches the active one. Promoting it (the copy at the end) is what
    actually makes it the baseline future checks compare against, so this
    always does both steps as one privileged operation rather than leaving
    "initialized but not promoted" as a state the UI has to explain.
    """
    result = run_privileged_streaming(["aide", "--init"], on_line)
    if not result.ok:
        return result

    new_db = _find_existing(DB_NEW_CANDIDATES)
    if not new_db:
        on_line("aide --init reported success, but no new database file was found to promote.")
        return CommandResult(returncode=1, stdout=result.stdout, stderr="No new database file found after --init")

    active_db = new_db.replace(".new", "")
    on_line(f"Promoting {new_db} -> {active_db}")
    return run_privileged(["cp", new_db, active_db])


def update_baseline(on_line: Callable[[str], None]) -> CommandResult:
    """
    Re-baseline after reviewing a check's reported changes and confirming
    they're legitimate. Deliberately the same mechanism as
    initialize_baseline() - kept as a separate entry point because the
    *meaning* to a human is different (first-time setup vs "I looked at
    the diff and it's fine"), even though the commands run are identical.
    """
    return initialize_baseline(on_line)


def run_check(on_line: Callable[[str], None]) -> CommandResult:
    """
    `aide --check` walks the whole configured tree comparing it against
    the active database - can take minutes, hence streaming. AIDE's exit
    code is meaningful here (non-zero doesn't mean "the command failed"
    the way it does for most tools - AIDE returns specific non-zero codes
    for added/removed/changed entries), so callers should parse
    .stdout via parse_check_summary() rather than trusting .ok alone.
    """
    return run_privileged_streaming(["aide", "--check"], on_line)


@dataclass
class CheckSummary:
    added: int
    removed: int
    changed: int

    @property
    def clean(self) -> bool:
        return self.added == 0 and self.removed == 0 and self.changed == 0


_SUMMARY_RE = re.compile(
    r"Added entries:\s*(\d+).*?Removed entries:\s*(\d+).*?Changed entries:\s*(\d+)",
    re.DOTALL,
)


def parse_check_summary(output: str) -> CheckSummary | None:
    """
    Parses aide --check's own "Summary:" block. Returns None if the output
    doesn't match the expected shape (e.g. AIDE errored before producing a
    summary) rather than guessing at zeros - a missing summary is a
    different, worse situation than a genuinely clean 0/0/0 summary, and
    the two must never look the same to a caller.
    """
    match = _SUMMARY_RE.search(output)
    if not match:
        return None
    return CheckSummary(added=int(match.group(1)), removed=int(match.group(2)), changed=int(match.group(3)))


def enable_timer(unit: str) -> CommandResult:
    return run_privileged(["systemctl", "enable", "--now", unit])


def disable_timer(unit: str) -> CommandResult:
    return run_privileged(["systemctl", "disable", "--now", unit])
