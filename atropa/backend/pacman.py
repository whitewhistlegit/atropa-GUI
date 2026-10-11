"""
atropa.backend.pacman
------------------------
Wraps pacman (and, if present, an AUR helper) for the Package Management
module. Read operations run unprivileged; installs/removals/upgrades go
through the privilege layer.

Nothing here refreshes the real package database without upgrading
(`pacman -Sy`): once the database is newer than the installed packages,
every later `pacman -S` is a partial upgrade, which Arch doesn't support.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass

from .privilege import CommandResult, run_privileged, run_privileged_streaming, run_unprivileged

AUR_HELPERS = ["paru", "yay"]  # checked in priority order


class PartialUpgradeError(RuntimeError):
    """Installing now would be a partial upgrade - upgrade the system first."""


@dataclass
class Package:
    name: str
    version: str
    installed: bool = True
    description: str = ""
    repo: str = ""  # "core", "extra", ... or "aur"; empty when pacman didn't say


@dataclass
class PendingUpdate:
    name: str
    old_version: str
    new_version: str


def live_update_check_available() -> bool:
    """
    True if check_updates() asks the mirrors: checkupdates (pacman-contrib)
    refuses to run without fakeroot, which isn't part of base.
    """
    return shutil.which("checkupdates") is not None and shutil.which("fakeroot") is not None


def check_updates() -> list[PendingUpdate]:
    """
    List packages with a pending update (empty list if fully up to date).

    Uses checkupdates (pacman-contrib) when it can run: it syncs a private
    copy of the database, so it needs no root and leaves the real one alone - the old "Refresh database" button ran `pacman -Sy`
    instead, which turned the next install into a partial upgrade.
    Without it this falls back to `pacman -Qu`, which only knows what the
    last full upgrade's sync saw.

    Lines look like 'firefox 120.0-1 -> 121.0-1', occasionally with an
    '[ignored]' suffix for packages held back by IgnorePkg.
    """
    if live_update_check_available():
        result = run_unprivileged(["checkupdates"])
        if result.returncode == 2:  # checkupdates' "no updates available"
            return []
        if not result.ok:
            raise RuntimeError(f"checkupdates failed: {result.stderr.strip() or f'exit code {result.returncode}'}")
        return _parse_updates(result.stdout)
    # -Qu exits 1 with empty stdout when nothing to update, which is not an error for us.
    return _parse_updates(run_unprivileged(["pacman", "-Qu"]).stdout)


def _parse_updates(text: str) -> list[PendingUpdate]:
    updates = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^(\S+)\s+(\S+)\s*->\s*(\S+)", line)
        if m:
            updates.append(PendingUpdate(name=m.group(1), old_version=m.group(2), new_version=m.group(3)))
        else:
            # Unexpected format (e.g. a future pacman version changes it) - still
            # surface the package name rather than silently dropping the line.
            name = line.split(" ", 1)[0]
            updates.append(PendingUpdate(name=name, old_version="", new_version=""))
    return updates


def _behind_local_database() -> list[str]:
    """
    Installed packages the local sync database already has newer versions
    of (IgnorePkg holds aside). Non-empty means something refreshed the
    database without upgrading.
    """
    result = run_unprivileged(["pacman", "-Qu"])
    return [line.split()[0] for line in result.stdout.splitlines() if line.strip() and "[ignored]" not in line]


def _detect_aur_helper() -> str | None:
    for helper in AUR_HELPERS:
        if shutil.which(helper):
            return helper
    return None


def list_installed() -> list[Package]:
    """Return all explicitly + dependency installed packages."""
    result = run_unprivileged(["pacman", "-Q"])
    packages = []
    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        name, _, version = line.partition(" ")
        packages.append(Package(name=name, version=version, installed=True))
    return packages


def list_explicit() -> list[Package]:
    """Packages the user explicitly installed (not pulled in as a dependency)."""
    result = run_unprivileged(["pacman", "-Qe"])
    packages = []
    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        name, _, version = line.partition(" ")
        packages.append(Package(name=name, version=version, installed=True))
    return packages


def list_orphans() -> list[Package]:
    """Dependencies no longer required by anything (safe cleanup candidates)."""
    result = run_unprivileged(["pacman", "-Qdt"])
    packages = []
    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        name, _, version = line.partition(" ")
        packages.append(Package(name=name, version=version, installed=True))
    return packages


def search(query: str, include_aur: bool = True) -> list[Package]:
    """Search official repos, optionally merged with AUR helper results (repo == "aur")."""
    results: list[Package] = []

    repo = run_unprivileged(["pacman", "-Ss", query])
    results.extend(_parse_ss_output(repo.stdout))

    if include_aur:
        helper = _detect_aur_helper()
        if helper:
            aur = run_unprivileged([helper, "-Ss", "--aur", query])
            results.extend(_parse_ss_output(aur.stdout))

    return results


def _parse_ss_output(text: str) -> list[Package]:
    """pacman -Ss output alternates a header line and an indented description line."""
    packages: list[Package] = []
    lines = text.strip().splitlines()
    i = 0
    while i < len(lines):
        header = lines[i]
        if "/" in header:
            repo_name, _, rest = header.partition(" ")
            repo, name = repo_name.split("/", 1)
            version = rest.split(" ")[0] if rest else ""
            installed = "[installed" in header
            desc = ""
            if i + 1 < len(lines) and lines[i + 1].startswith(" "):
                desc = lines[i + 1].strip()
                i += 1
            packages.append(Package(name=name, version=version, installed=installed, description=desc, repo=repo))
        i += 1
    return packages


def upgrade_system() -> CommandResult:
    """pacman -Syu : full system upgrade."""
    return run_privileged(["pacman", "-Syu", "--noconfirm"])


def upgrade_system_streaming(on_line) -> CommandResult:
    """
    Same as upgrade_system(), but streams pacman's own progress output
    (download percentages, package-by-package install lines) to on_line as
    it happens - a full upgrade can take minutes, and a single toast at the
    end leaves the user staring at a frozen-looking UI in the meantime.
    """
    return run_privileged_streaming(["pacman", "-Syu", "--noconfirm"], on_line)


def install(package_names: list[str]) -> CommandResult:
    """
    pacman -S --needed. Refuses (PartialUpgradeError) while the package
    database is newer than what's installed: a package from that database
    can need newer libraries than the installed ones - the partial upgrade
    Arch doesn't support. upgrade_and_install_streaming() is the way then.
    """
    if not package_names:
        raise ValueError("No packages specified")
    behind = _behind_local_database()
    if behind:
        shown = ", ".join(behind[:5]) + (f" and {len(behind) - 5} more" if len(behind) > 5 else "")
        raise PartialUpgradeError(
            f"The package database is newer than {len(behind)} installed package(s) ({shown}), so "
            "installing now would be a partial upgrade. Upgrade the system first."
        )
    return run_privileged(["pacman", "-S", "--needed", "--noconfirm", *package_names])


def upgrade_and_install_streaming(package_names: list[str], on_line) -> CommandResult:
    """pacman -Syu --needed <names>: the Arch wiki's way to install on an out-of-date system."""
    if not package_names:
        raise ValueError("No packages specified")
    return run_privileged_streaming(["pacman", "-Syu", "--needed", "--noconfirm", *package_names], on_line)


def remove(package_names: list[str], purge_config: bool = False) -> CommandResult:
    if not package_names:
        raise ValueError("No packages specified")
    flag = "-Rns" if purge_config else "-Rs"
    return run_privileged(["pacman", flag, "--noconfirm", *package_names])


def clean_cache() -> CommandResult:
    """pacman -Sc : remove uninstalled/old packages from the cache."""
    return run_privileged(["pacman", "-Sc", "--noconfirm"])
