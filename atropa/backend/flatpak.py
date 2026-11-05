"""
atropa.backend.flatpak
-------------------------
Flatpak apps, their pending updates, and the runtimes nothing needs anymore.

Flatpak can be installed either per-user or system-wide. Which one a command
has to touch decides whether Atropa needs root, so ``system_wide()`` is asked
once per operation instead of guessing from the presence of the binary.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass

from .privilege import (
    CommandResult,
    run_privileged_streaming,
    run_unprivileged,
    run_unprivileged_streaming,
)

_NOT_INSTALLED = "flatpak isn't installed - install it with: pacman -S flatpak"


def flatpak_installed() -> bool:
    """True when the flatpak binary is on PATH."""
    return shutil.which("flatpak") is not None


@dataclass
class InstalledApp:
    app_id: str
    version: str
    origin: str
    branch: str


@dataclass
class AppUpdate:
    app_id: str
    version: str
    branch: str
    origin: str


def _require_flatpak() -> None:
    if not flatpak_installed():
        raise RuntimeError(_NOT_INSTALLED)


def _rows(stdout: str) -> list[list[str]]:
    """Split tab-separated flatpak output into rows, dropping blank lines."""
    rows: list[list[str]] = []
    for raw in stdout.splitlines():
        if not raw.strip():
            continue
        rows.append([field.strip() for field in raw.split("\t")])
    return rows


def installed_apps() -> list[InstalledApp]:
    """Every installed Flatpak application (not runtimes)."""
    _require_flatpak()
    result = run_unprivileged(
        ["flatpak", "list", "--app", "--columns=application,version,origin,branch"],
        timeout=60,
    )
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"flatpak list exited with status {result.returncode}")

    apps: list[InstalledApp] = []
    for fields in _rows(result.stdout):
        app_id = fields[0]
        if not app_id:
            continue
        # Trailing empty columns are dropped by flatpak in some versions, so
        # a short row is still a row; only the app id is genuinely required.
        apps.append(
            InstalledApp(
                app_id,
                fields[1] if len(fields) > 1 else "",
                fields[2] if len(fields) > 2 else "",
                fields[3] if len(fields) > 3 else "",
            )
        )
    return apps


def available_updates() -> list[AppUpdate]:
    """Pending updates from the configured remotes; empty when up to date."""
    _require_flatpak()
    result = run_unprivileged(
        ["flatpak", "remote-ls", "--updates", "--columns=application,version,branch,origin"],
        timeout=120,
    )
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"flatpak remote-ls exited with status {result.returncode}")

    stripped = result.stdout.strip()
    # With no updates, flatpak prints a sentence rather than nothing. Its
    # locale is pinned to C.UTF-8 by the privilege helpers, so this is stable.
    if not stripped or stripped.lower().startswith("no updates"):
        return []

    updates: list[AppUpdate] = []
    for fields in _rows(result.stdout):
        app_id = fields[0]
        if not app_id:
            continue
        updates.append(
            AppUpdate(
                app_id,
                fields[1] if len(fields) > 1 else "",
                fields[2] if len(fields) > 2 else "",
                fields[3] if len(fields) > 3 else "",
            )
        )
    return updates


def system_wide() -> bool:
    """
    True when at least one app is installed system-wide, which means
    update/uninstall need root. A non-zero exit is treated as "no" rather
    than an error: the following streaming call reports the real problem.
    """
    if not flatpak_installed():
        return False
    result = run_unprivileged(["flatpak", "list", "--system", "--columns=application"], timeout=60)
    if not result.ok:
        return False
    return bool(result.stdout.strip())


def update_all(on_line: Callable[[str], None]) -> CommandResult:
    """Update every Flatpak app and runtime, streaming progress to on_line."""
    runner = run_privileged_streaming if system_wide() else run_unprivileged_streaming
    # --noninteractive keeps flatpak from waiting on a prompt no GUI has
    # answered; privilege escalation is pkexec's job, not flatpak's.
    return runner(["flatpak", "update", "-y", "--noninteractive"], on_line, timeout=3600)


def remove_unused(on_line: Callable[[str], None]) -> CommandResult:
    """Delete runtimes no installed app depends on, streaming to on_line."""
    runner = run_privileged_streaming if system_wide() else run_unprivileged_streaming
    return runner(
        ["flatpak", "uninstall", "--unused", "-y", "--noninteractive"],
        on_line,
        timeout=1800,
    )
