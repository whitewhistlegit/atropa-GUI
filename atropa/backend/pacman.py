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
from pathlib import Path

from .privilege import (
    CommandResult,
    PrivilegeError,
    backup_file,
    run_privileged,
    run_privileged_streaming,
    run_unprivileged,
)

AUR_HELPERS = ["paru", "yay"]  # checked in priority order

PACMAN_CONF = Path("/etc/pacman.conf")

# The archlinuxhardened project's binary repository: SELinux's userspace
# tools, policies, and SELinux-enabled builds of core packages. Neither the
# repository nor its packages are signed, so pacman can only use it with
# signature checking off - their README says the same. Enabling it means
# pacman installs whatever that URL serves, as root, unverified.
SELINUX_REPO_NAME = "selinux"
SELINUX_REPO_SERVER = "https://github.com/archlinuxhardened/selinux/releases/download/ArchLinux-SELinux"
_SELINUX_REPO_COMMENTS = (
    "# Added by Atropa: SELinux packages from https://github.com/archlinuxhardened/selinux",
    "# The repository is unsigned, so pacman does not verify what it installs from it.",
)


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


# ------------------------------------------------------- repositories --

_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")


def _sections_in(conf_text: str) -> list[str]:
    """Repository section names in pacman.conf text, in order ([options] isn't one)."""
    names = [m.group(1) for m in map(_SECTION_RE.match, conf_text.splitlines()) if m]
    return [name for name in names if name != "options"]


def configured_repos() -> list[str]:
    """
    The repositories pacman uses, in order. Asks pacman itself
    (pacman-conf follows Include lines); falls back to the section names
    in pacman.conf when that can't be run.
    """
    try:
        result = run_unprivileged(["pacman-conf", "--repo-list"])
    except PrivilegeError:
        result = None
    if result is not None and result.ok:
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    try:
        return _sections_in(PACMAN_CONF.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return []


def selinux_repo_enabled() -> bool:
    return SELINUX_REPO_NAME in configured_repos()


def _selinux_repo_block() -> str:
    return "\n".join(
        [*_SELINUX_REPO_COMMENTS, f"[{SELINUX_REPO_NAME}]", f"Server = {SELINUX_REPO_SERVER}", "SigLevel = Never"]
    ) + "\n"


def _without_section(conf_text: str, name: str) -> str:
    """
    conf_text without the [name] section: its header, everything up to the
    next section, and the comment lines Atropa put above it.
    """
    lines = conf_text.splitlines()
    kept: list[str] = []
    skipping = False
    for line in lines:
        section = _SECTION_RE.match(line)
        if section:
            skipping = section.group(1) == name
            if skipping:
                while kept and (kept[-1].strip() in _SELINUX_REPO_COMMENTS or not kept[-1].strip()):
                    kept.pop()
        if not skipping:
            kept.append(line)
    return "\n".join(kept) + "\n"


def enable_selinux_repo() -> CommandResult:
    """
    Adds the [selinux] repository at the end of pacman.conf - after the
    official repositories, so those keep precedence for any package both
    have. pacman.conf is backed up first, and if pacman can't read the new
    file the previous content goes back: a pacman.conf that doesn't parse
    stops every install and upgrade.

    Nothing is downloaded or installed here. pacman first sees the
    repository at its next sync - which in Atropa is always a full upgrade.
    """
    if selinux_repo_enabled():
        return CommandResult(0, "already enabled", "")
    original = PACMAN_CONF.read_text(encoding="utf-8")
    updated = original.rstrip("\n") + "\n\n" + _selinux_repo_block()

    backup_file(str(PACMAN_CONF))
    result = run_privileged(["tee", str(PACMAN_CONF)], input_text=updated)
    if not result.ok:
        return result
    try:
        check = run_unprivileged(["pacman-conf", "--repo-list"])
    except PrivilegeError:
        return result  # no pacman-conf to ask
    if check.ok and SELINUX_REPO_NAME in check.stdout.split():
        return result

    problem = check.stderr.strip() or f"it doesn't list [{SELINUX_REPO_NAME}]"
    restore = run_privileged(["tee", str(PACMAN_CONF)], input_text=original)
    if restore.ok:
        raise RuntimeError(f"pacman couldn't use the new pacman.conf ({problem}). Restored the previous one.")
    raise RuntimeError(
        f"pacman couldn't use the new pacman.conf ({problem}), and restoring the previous one ALSO failed "
        f"({restore.stderr.strip() or 'unknown error'}) - restore it from Activity & Backups before using pacman."
    )


def disable_selinux_repo() -> CommandResult:
    """
    Takes the [selinux] section back out of pacman.conf. Packages already
    installed from it stay installed; pacman just stops looking there.
    """
    original = PACMAN_CONF.read_text(encoding="utf-8")
    if SELINUX_REPO_NAME not in _sections_in(original):
        return CommandResult(0, "not enabled in pacman.conf", "")
    backup_file(str(PACMAN_CONF))
    return run_privileged(["tee", str(PACMAN_CONF)], input_text=_without_section(original, SELINUX_REPO_NAME))
