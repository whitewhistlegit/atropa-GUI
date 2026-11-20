"""
atropa.backend.rollback
--------------------------
Undo a recent pacman transaction from the package cache.

Works on any filesystem: pacman.log says what each transaction changed,
and /var/cache/pacman/pkg usually still holds the versions it replaced. A
rollback reinstalls exactly those versions in one `pacman -U`, so the
packages that moved together go back together - the usual way an upgrade
that broke something is undone on Arch.

What it deliberately doesn't do:
- remove packages a transaction *installed*: something else may depend on
  them by now, and leaving them is harmless;
- roll back a transaction whose packages changed again since (a newer
  upgrade, a manual downgrade) - the plan would be about a state the
  system isn't in, so it's reported as stale instead. A package removed
  since is only skipped: it's gone, so there is nothing of it to undo;
- run with a cache file missing: half a rollback is a partial upgrade.

The pacman -U is privileged and asks for the password every time (helper
tier ASK): installing older versions is a downgrade, and that must never
happen on a remembered authorization.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .privilege import CommandResult, run_privileged_streaming, run_unprivileged

PACMAN_LOG = Path("/var/log/pacman.log")
CACHE_DIR = Path("/var/cache/pacman/pkg")

_LINE_RE = re.compile(r"^\[(?P<time>[^\]]+)\] \[(?P<source>[A-Z-]+)\] (?P<text>.*)$")
_RUNNING_RE = re.compile(r"^Running '(?P<command>.*)'$")
_CHANGE_RE = re.compile(
    r"^(?P<action>upgraded|downgraded|installed|removed|reinstalled) "
    r"(?P<name>\S+) \((?P<versions>[^)]*)\)$"
)


@dataclass
class Change:
    action: str  # upgraded | downgraded | installed | removed | reinstalled
    name: str
    old: str | None  # version before the transaction (None for installed)
    new: str | None  # version after it (None for removed)


@dataclass
class Transaction:
    time: str
    command: str
    changes: list[Change] = field(default_factory=list)

    def count(self, action: str) -> int:
        return sum(1 for change in self.changes if change.action == action)


def parse_log(text: str) -> list[Transaction]:
    """Completed transactions in log order. Failed or interrupted ones changed nothing worth undoing."""
    found: list[Transaction] = []
    command = ""
    current: Transaction | None = None
    for raw in text.splitlines():
        match = _LINE_RE.match(raw)
        if not match:
            continue
        source, line = match["source"], match["text"]
        if source != "ALPM":
            running = _RUNNING_RE.match(line)
            if running:
                command = running["command"]
            continue
        if line == "transaction started":
            current = Transaction(time=match["time"], command=command)
            command = ""
            continue
        if current is None:
            continue
        if line == "transaction completed":
            if current.changes:
                found.append(current)
            current = None
            continue
        if line.startswith("transaction "):  # failed / interrupted
            current = None
            continue
        change = _CHANGE_RE.match(line)
        if not change:
            continue
        versions = change["versions"]
        if " -> " in versions:
            old, new = (part.strip() for part in versions.split(" -> ", 1))
        elif change["action"] == "removed":
            old, new = versions.strip(), None
        else:
            old, new = None, versions.strip()
        if change["action"] == "reinstalled":
            old = new
        current.changes.append(Change(change["action"], change["name"], old, new))
    return found


def transactions(limit: int = 15, log_text: str | None = None) -> list[Transaction]:
    """The newest completed transactions, newest first."""
    if log_text is None:
        try:
            log_text = PACMAN_LOG.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise RuntimeError(f"Couldn't read {PACMAN_LOG}: {exc.strerror or exc}") from exc
    return list(reversed(parse_log(log_text)))[:limit]


def installed_versions() -> dict[str, str]:
    result = run_unprivileged(["pacman", "-Q"])
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or "pacman -Q failed")
    versions = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2:
            versions[parts[0]] = parts[1]
    return versions


def _cached_file(name: str, version: str) -> str | None:
    """The cache file for exactly name-version, whatever its architecture or compression."""
    for arch in (os.uname().machine, "any"):
        for ext in ("zst", "xz"):
            candidate = CACHE_DIR / f"{name}-{version}-{arch}.pkg.tar.{ext}"
            if candidate.is_file() and not candidate.is_symlink():
                return str(candidate)
    return None


@dataclass
class RollbackPlan:
    transaction: Transaction
    files: list[str] = field(default_factory=list)  # what pacman -U gets
    restores: list[Change] = field(default_factory=list)  # the changes those files undo
    missing: list[str] = field(default_factory=list)  # name-version not in the cache
    stale: list[str] = field(default_factory=list)  # changed again since: name (now version)
    kept: list[str] = field(default_factory=list)  # installed by the transaction, left in place
    gone: list[str] = field(default_factory=list)  # upgraded then, removed since: nothing to undo

    @property
    def possible(self) -> bool:
        return bool(self.files) and not self.missing and not self.stale

    @property
    def reason(self) -> str:
        """Why the rollback can't run, for the page; empty when it can."""
        if self.stale:
            return "Changed again since: " + ", ".join(self.stale[:5]) + ("…" if len(self.stale) > 5 else "")
        if self.missing:
            return "Not in the package cache: " + ", ".join(self.missing[:5]) + ("…" if len(self.missing) > 5 else "")
        if not self.files:
            return "Nothing to undo: this transaction only installed packages"
        return ""


def plan(transaction: Transaction, installed: dict[str, str] | None = None) -> RollbackPlan:
    """What undoing `transaction` takes, and whether it still can be done."""
    if installed is None:
        installed = installed_versions()
    result = RollbackPlan(transaction)
    for change in transaction.changes:
        if change.action == "reinstalled":
            continue
        if change.action == "installed":
            result.kept.append(change.name)
            continue
        now = installed.get(change.name)
        if now is None and change.new is not None:
            result.gone.append(change.name)
            continue
        if now != change.new:  # upgraded/downgraded: must still be at .new; removed: must still be gone
            result.stale.append(f"{change.name} (now {now or 'not installed'})")
            continue
        cached = _cached_file(change.name, change.old) if change.old else None
        if cached is None:
            result.missing.append(f"{change.name}-{change.old}")
            continue
        result.files.append(cached)
        result.restores.append(change)
    return result


def apply(rollback: RollbackPlan, on_line: Callable[[str], None]) -> CommandResult:
    """Reinstall the earlier versions in one transaction, streaming pacman's output."""
    if not rollback.possible:
        raise RuntimeError(rollback.reason or "This rollback can't run")
    return run_privileged_streaming(["pacman", "-U", "--noconfirm", *rollback.files], on_line, timeout=3600)
