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

import json
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .privilege import CommandResult, path_exists, run_privileged, run_privileged_streaming, run_unprivileged

CONFIG_FILE = "/etc/aide.conf"
DB_ACTIVE_CANDIDATES = ["/var/lib/aide/aide.db.gz", "/var/lib/aide/aide.db"]
DB_NEW_CANDIDATES = ["/var/lib/aide/aide.db.new.gz", "/var/lib/aide/aide.db.new"]

# Checked in this order, first match wins - see module docstring.
TIMER_CANDIDATES = ["aidecheck.timer", "aide.timer", "aide-check.timer"]

# Last check's summary and changed paths, kept between launches so the page
# still says something useful after the streaming dialog is gone. Per-user
# state (the check itself runs as root, but the UI writes this).
LAST_CHECK_FILE = Path.home() / ".local" / "share" / "atropa" / "aide_last_check.json"


def is_installed() -> bool:
    return shutil.which("aide") is not None


def _find_existing(candidates: list[str]) -> str | None:
    """The first candidate known to exist (one that can't be checked doesn't count)."""
    for path in candidates:
        if path_exists(path):
            return path
    return None


def _unknowable(candidates: list[str]) -> list[str]:
    """Candidates whose existence can't be told without root - /var/lib/aide is often 0700."""
    return [path for path in candidates if path_exists(path) is None]


def baseline_initialized() -> bool | None:
    """True/False, or None when the database directory can't be looked into without root."""
    if _find_existing(DB_ACTIVE_CANDIDATES) is not None:
        return True
    return None if _unknowable(DB_ACTIVE_CANDIDATES) else False


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
    baseline_initialized: bool | None  # None: couldn't tell without root
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
    # Can't look into a root-only database directory: try each possible new
    # database in turn and let root's cp do the looking, rather than calling
    # a successful --init a failure.
    candidates = [new_db] if new_db else _unknowable(DB_NEW_CANDIDATES)
    if not candidates:
        on_line("aide --init reported success, but no new database file was found to promote.")
        return CommandResult(returncode=1, stdout=result.stdout, stderr="No new database file found after --init")

    for candidate in candidates:
        active_db = candidate.replace(".new", "")
        on_line(f"Promoting {candidate} -> {active_db}")
        promote = run_privileged(["cp", candidate, active_db])
        if promote.ok:
            break
    return promote


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
    for added/removed/changed entries), so callers should pass .stdout and
    .returncode to parse_check_summary() rather than trusting .ok alone.
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

# AIDE >= 0.16 / AIDE <= 0.15 wording of a clean run.
_NO_DIFFERENCES_RE = re.compile(r"found NO differences between|All files match AIDE database")


def parse_check_summary(output: str, returncode: int | None = None) -> CheckSummary | None:
    """
    Parses aide --check's own "Summary:" block. AIDE only prints that block
    when it found differences (see print_report_summary_plain in AIDE's
    report_plain.c) - a clean run prints "AIDE found NO differences ...
    Looks okay!!" and exits 0 instead, so either of those means 0/0/0.
    Returns None if none of that is present (e.g. AIDE errored before
    producing a report) rather than guessing at zeros - a missing summary
    is a different, worse situation than a genuinely clean run, and the two
    must never look the same to a caller.
    """
    match = _SUMMARY_RE.search(output)
    if match:
        return CheckSummary(added=int(match.group(1)), removed=int(match.group(2)), changed=int(match.group(3)))
    if _NO_DIFFERENCES_RE.search(output) or returncode == 0:
        return CheckSummary(added=0, removed=0, changed=0)
    return None


# --------------------------------------------------------------- report --


@dataclass
class CheckEntry:
    """One path AIDE reported, with the change category the report put it in."""

    kind: str  # "added" | "removed" | "changed"
    path: str
    detail: str = ""  # AIDE's marker column ("f++++++++++++++++", "f > ...")


@dataclass
class CheckRecord:
    checked_at: str  # ISO 8601, local timezone
    summary: CheckSummary | None
    entries: list[CheckEntry] = field(default_factory=list)

    @property
    def clean(self) -> bool | None:
        return None if self.summary is None else self.summary.clean


_SECTION_HEADERS = {
    "added entries:": "added",
    "removed entries:": "removed",
    "changed entries:": "changed",
}

# AIDE prints one line per changed object in the list sections:
#   f++++++++++++++++: /etc/new.conf
#   f > ... : /etc/passwd
# The first character is the file type; the path starts at the "/" after the
# colon. Everything before it is the marker column worth showing as detail.
_ENTRY_RE = re.compile(r"^(?P<flag>[a-zA-Z])(?P<detail>[^:]*):\s*(?P<path>/\S.*)$")


def parse_check_entries(output: str) -> list[CheckEntry]:
    """
    The added/removed/changed *paths* from aide --check's report, in the
    order AIDE printed them.

    Deliberately section-aware: the summary block repeats the words "Added
    entries:" with a count, and the "Detailed information about changes"
    section lists attributes (not paths). Inside a list section a blank line
    or the next header ends it, so neither the summary nor the detailed
    block is mistaken for a path.
    """
    entries: list[CheckEntry] = []
    kind: str | None = None
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line:
            kind = None  # list sections are separated from the next by a blank line
            continue
        lowered = line.lower()
        if lowered in _SECTION_HEADERS:
            kind = _SECTION_HEADERS[lowered]
            continue
        if line.endswith(":"):
            # "Summary:", "Detailed information about changes:", ...
            kind = None
            continue
        if kind is None:
            continue
        match = _ENTRY_RE.match(line)
        if match is None:
            continue
        entries.append(
            CheckEntry(kind=kind, path=match.group("path").strip(), detail=match.group("detail").strip())
        )
    return entries


def build_check_record(output: str, returncode: int | None = None, when: str | None = None) -> CheckRecord:
    """Everything the page keeps from one check: counts, paths, and when it ran."""
    return CheckRecord(
        checked_at=when or datetime.now().astimezone().isoformat(timespec="seconds"),
        summary=parse_check_summary(output, returncode),
        entries=parse_check_entries(output),
    )


def save_check_record(record: CheckRecord) -> None:
    """Write the last check's state; a UI convenience, never authoritative."""
    payload = {
        "checked_at": record.checked_at,
        "summary": None
        if record.summary is None
        else {
            "added": record.summary.added,
            "removed": record.summary.removed,
            "changed": record.summary.changed,
        },
        "entries": [
            {"kind": entry.kind, "path": entry.path, "detail": entry.detail}
            for entry in record.entries
        ],
    }
    LAST_CHECK_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = LAST_CHECK_FILE.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    temporary.replace(LAST_CHECK_FILE)


def load_check_record() -> CheckRecord | None:
    """The saved last check, or None when there isn't a usable one."""
    try:
        data = json.loads(LAST_CHECK_FILE.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    checked_at = data.get("checked_at")
    if not isinstance(checked_at, str) or not checked_at:
        return None

    summary = None
    raw_summary = data.get("summary")
    if isinstance(raw_summary, dict):
        try:
            summary = CheckSummary(
                added=int(raw_summary["added"]),
                removed=int(raw_summary["removed"]),
                changed=int(raw_summary["changed"]),
            )
        except (KeyError, TypeError, ValueError):
            summary = None

    entries = []
    raw_entries = data.get("entries")
    if isinstance(raw_entries, list):
        for item in raw_entries[:5000]:
            if not isinstance(item, dict):
                continue
            kind = item.get("kind")
            path = item.get("path")
            if kind not in {"added", "removed", "changed"} or not isinstance(path, str) or not path:
                continue
            detail = item.get("detail")
            entries.append(CheckEntry(kind, path, detail if isinstance(detail, str) else ""))

    return CheckRecord(checked_at=checked_at, summary=summary, entries=entries)


def clear_check_record() -> None:
    """Forget the last check (used after re-baselining makes it stale)."""
    try:
        LAST_CHECK_FILE.unlink(missing_ok=True)
    except OSError:
        pass


# --------------------------------------------------------- configuration --


def check_config() -> CommandResult:
    """
    `aide --config-check` validates the config (including every Include)
    without walking the filesystem. Root because included files can be
    root-only; it is fast, so the page runs it as a normal action rather
    than a streaming one.
    """
    return run_privileged(["aide", "--config-check"], timeout=120)


# ------------------------------------------------------------ timer info --


@dataclass
class TimerDetails:
    next_run: str = ""
    last_run: str = ""
    result: str = ""


def timer_details(unit: str) -> TimerDetails:
    """
    systemd's own next/last trigger timestamps for the package's timer.

    `systemctl list-timers` is column-aligned and awkward to parse; the
    property interface returns key=value lines that don't move around
    between systemd releases. Unset properties come back empty, which the
    page shows as "not scheduled" rather than a fabricated date.
    """
    result = run_unprivileged(
        [
            "systemctl", "show", unit,
            "--property=NextElapseUSecRealtime",
            "--property=LastTriggerUSec",
            "--property=Result",
        ],
        timeout=20,
    )
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"systemctl show {unit} exited with status {result.returncode}")

    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    return TimerDetails(
        next_run=values.get("NextElapseUSecRealtime", ""),
        last_run=values.get("LastTriggerUSec", ""),
        result=values.get("Result", ""),
    )


def enable_timer(unit: str) -> CommandResult:
    return run_privileged(["systemctl", "enable", "--now", unit])


def disable_timer(unit: str) -> CommandResult:
    return run_privileged(["systemctl", "disable", "--now", unit])
