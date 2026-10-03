"""
atropa.backend.pacman
------------------------
Wraps pacman (and, if present, an AUR helper) for the Package Management
module. Read operations run unprivileged; installs/removals/upgrades go
through the privilege layer.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass

from .privilege import CommandResult, run_privileged, run_privileged_streaming, run_unprivileged

AUR_HELPERS = ["paru", "yay"]  # checked in priority order


@dataclass
class Package:
    name: str
    version: str
    installed: bool = True
    description: str = ""


@dataclass
class PendingUpdate:
    name: str
    old_version: str
    new_version: str


def check_updates() -> list[PendingUpdate]:
    """
    List packages with a pending update (empty list if fully up to date).
    pacman -Qu prints lines like 'firefox 120.0-1 -> 121.0-1', occasionally
    with an '[ignored]' suffix for packages held back by IgnorePkg.
    """
    # -Qu exits 1 with empty stdout when nothing to update, which is not an error for us.
    result = run_unprivileged(["pacman", "-Qu"])
    updates = []
    for line in result.stdout.strip().splitlines():
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


def update_single_package(name: str) -> CommandResult:
    """
    Upgrades a single package via `pacman -S <name>`.

    Arch explicitly discourages partial upgrades: updating one package while
    leaving others on old library versions can break anything that depended
    on the old ABI, and pacman gives no safety net for this the way it does
    for a full -Syu's dependency resolution. This exists for cases like an
    urgent single-package security fix - the UI should warn accordingly and
    default to recommending a full system upgrade instead.
    """
    if not name:
        raise ValueError("No package specified")
    return run_privileged(["pacman", "-S", "--noconfirm", name])


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
    """Search official repos, optionally merged with AUR helper results."""
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
            name = repo_name.split("/", 1)[1]
            version = rest.split(" ")[0] if rest else ""
            installed = "[installed" in header
            desc = ""
            if i + 1 < len(lines) and lines[i + 1].startswith(" "):
                desc = lines[i + 1].strip()
                i += 1
            packages.append(Package(name=name, version=version, installed=installed, description=desc))
        i += 1
    return packages


def sync_database() -> CommandResult:
    """pacman -Sy : refresh package database."""
    return run_privileged(["pacman", "-Sy", "--noconfirm"])


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
    if not package_names:
        raise ValueError("No packages specified")
    return run_privileged(["pacman", "-S", "--noconfirm", *package_names])


def remove(package_names: list[str], purge_config: bool = False) -> CommandResult:
    if not package_names:
        raise ValueError("No packages specified")
    flag = "-Rns" if purge_config else "-Rs"
    return run_privileged(["pacman", flag, "--noconfirm", *package_names])


def clean_cache() -> CommandResult:
    """pacman -Sc : remove uninstalled/old packages from the cache."""
    return run_privileged(["pacman", "-Sc", "--noconfirm"])
