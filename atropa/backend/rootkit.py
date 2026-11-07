"""
atropa.backend.rootkit
--------------------------
Rootkit scanning through rkhunter, which is in Arch's **extra** repository
(unlike most "security scanner" tooling): installable with pacman, no AUR
trust question, and the package ships no timer, so Atropa only ever runs it
on request.

Framing matters more here than anywhere else in this app. rkhunter is a
heuristic scanner: it compares known rootkit signatures and file properties
and reports warnings that are frequently false positives (a package update
changes a binary, a hidden file is legitimate, ...). This module therefore
never returns "clean" or "infected" as a verdict - it returns the warning
lines and rkhunter's exit status, and the UI shows "N warnings, review the
log". Nothing is ever removed or "fixed" automatically: on a system that
really is compromised, the useful response is reinstalling from known-good
media, not deleting files a scanner guessed at.

The scan itself runs through the privileged helper's fixed-argv operations
(`rootkit-scan` / `rootkit-update` / `rootkit-baseline`). rkhunter is
deliberately NOT in the helper's command allowlist: running it with
caller-supplied flags would allow `--propupd` (rewrite the baseline) or
arbitrary config overrides through a cached root authorization.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from .privilege import CommandResult, run_privileged, run_privileged_streaming

DB_DIR = Path("/var/lib/rkhunter/db")
STANDARD_BIN = Path("/usr/bin")
LOG_FILE = Path("/var/log/rkhunter.log")

# Last scan's warnings, kept between launches (the scan output itself can be
# long; the log file has the full report).
LAST_SCAN_FILE = Path.home() / ".local" / "share" / "atropa" / "rootkit_last_scan.json"

_WARNING_RE = re.compile(r"\[\s*warning\s*\]", re.IGNORECASE)

# rkhunter is a shell script that calls egrep dozens of times. GNU grep 3.12
# prints a deprecation warning on every egrep call, and its extended-regex
# parser warns about the escaped "+" rkhunter's own patterns use. Both go to
# stderr, which the streaming runner merges into the log; without filtering,
# the progress dialog is nothing but tool noise. These prefixes are cosmetic
# and never part of a scan result - real findings start with "[ Warning ]"
# or "Warning:" and are kept.
_NOISE_PREFIXES = (
    "egrep: warning: egrep is obsolescent",
    "grep: warning: stray \\ before ",
)


@dataclass
class RootkitStatus:
    installed: bool
    database_updated: str = ""  # ISO timestamp; "" when unknown


@dataclass
class RootkitScanRecord:
    checked_at: str  # ISO 8601, local timezone
    returncode: int
    warnings: list[str] = field(default_factory=list)

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)


def _binary_path() -> str | None:
    """
    Locate rkhunter without requiring the *user* to be able to execute it.

    Arch installs /usr/bin/rkhunter as 0700 root-only (it runs as root and
    reads the whole filesystem), so shutil.which() - which checks X_OK for
    the current user - reports it missing on a machine where pacman says it
    is installed. Detection therefore falls back to a plain existence check
    in the PATH; execution still happens through pkexec/the helper as root,
    where the mode is sufficient.
    """
    found = shutil.which("rkhunter")
    if found:
        return found
    candidates = [Path(directory) / "rkhunter" for directory in os.environ.get("PATH", "").split(os.pathsep)]
    candidates.append(STANDARD_BIN / "rkhunter")
    for candidate in candidates:
        try:
            if candidate.is_file():
                return str(candidate)
        except OSError:
            continue
    return None


def is_installed() -> bool:
    return _binary_path() is not None


def _database_timestamp() -> str:
    """
    When the signature database last changed, from the files rkhunter
    actually replaces (`--update` writes into db/ and db/signatures/). The
    directory mtime alone misses an in-place rewrite, hence the glob.
    """
    stamps: list[float] = []
    try:
        stamps.append(DB_DIR.stat().st_mtime)
        for pattern in ("*.dat", "signatures/*.ldb"):
            for path in DB_DIR.glob(pattern):
                try:
                    stamps.append(path.stat().st_mtime)
                except OSError:
                    continue
    except OSError:
        return ""
    if not stamps:
        return ""
    return datetime.fromtimestamp(max(stamps)).astimezone().isoformat(timespec="seconds")


def status() -> RootkitStatus:
    return RootkitStatus(installed=is_installed(), database_updated=_database_timestamp())


def _require_installed() -> None:
    if not is_installed():
        raise RuntimeError("rkhunter isn't installed - install it with: pacman -S rkhunter")


def _visible(line: str) -> bool:
    return not line.startswith(_NOISE_PREFIXES)


def scan(on_line: Callable[[str], None]) -> CommandResult:
    """
    Run `rkhunter --check` (warnings only) and stream it. Non-zero is not an
    error here: rkhunter exits 1 when it has warnings, which is the normal
    "something needs review" result.

    The GNU grep deprecation/escaping noise from rkhunter's internal egrep
    calls is filtered out; see _NOISE_PREFIXES.
    """
    _require_installed()
    return run_privileged_streaming(
        ["rootkit-scan"], lambda line: on_line(line) if _visible(line) else None, timeout=3600
    )


def update_signatures() -> CommandResult:
    """Download fresh rootkit signatures into /var/lib/rkhunter/db."""
    _require_installed()
    return run_privileged(["rootkit-update"], timeout=600)


def update_baseline() -> CommandResult:
    """
    `rkhunter --propupd`: record current file properties as the trusted
    baseline. Exactly as sensitive as AIDE's re-baseline - doing it on a
    compromised machine blesses the compromise - so the UI gates it behind
    an explicit confirmation.
    """
    _require_installed()
    return run_privileged(["rootkit-baseline"], timeout=300)


def parse_warnings(output: str) -> list[str]:
    """
    The warning lines from rkhunter's report.

    Both output shapes are covered: the interactive report's `[ Warning ]`
    marker and the plain `Warning: ...` lines that `--rwo` prints. Other
    lines (including "Rootkit checks", "Info" and the summary) are not
    warnings and are ignored.
    """
    warnings: list[str] = []
    seen: set[str] = set()
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        is_warning = line.lower().startswith("warning:") or bool(_WARNING_RE.search(line))
        if not is_warning or line in seen:
            continue
        seen.add(line)
        warnings.append(line)
    return warnings


def build_scan_record(output: str, returncode: int, when: str | None = None) -> RootkitScanRecord:
    return RootkitScanRecord(
        checked_at=when or datetime.now().astimezone().isoformat(timespec="seconds"),
        returncode=returncode,
        warnings=parse_warnings(output)[:500],
    )


def save_scan_record(record: RootkitScanRecord) -> None:
    payload = {
        "checked_at": record.checked_at,
        "returncode": record.returncode,
        "warnings": record.warnings,
    }
    LAST_SCAN_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = LAST_SCAN_FILE.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    temporary.replace(LAST_SCAN_FILE)


def load_scan_record() -> RootkitScanRecord | None:
    try:
        data = json.loads(LAST_SCAN_FILE.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    checked_at = data.get("checked_at")
    if not isinstance(checked_at, str) or not checked_at:
        return None
    try:
        returncode = int(data.get("returncode", 0))
    except (TypeError, ValueError):
        returncode = 0
    warnings = data.get("warnings")
    return RootkitScanRecord(
        checked_at=checked_at,
        returncode=returncode,
        warnings=[w for w in warnings if isinstance(w, str)][:500] if isinstance(warnings, list) else [],
    )


def clear_scan_record() -> None:
    try:
        LAST_SCAN_FILE.unlink(missing_ok=True)
    except OSError:
        pass
