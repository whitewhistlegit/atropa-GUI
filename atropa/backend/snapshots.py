"""
atropa.backend.snapshots
---------------------------
Btrfs snapshots with snapper: setup, automatic pacman snapshots (snap-pac),
listing, comparing, restoring files, and booting a snapshot (grub-btrfs).

Where `/` lives decides what a "rollback" can be, so layout() names it:

- top-level: `/` is the filesystem's top-level subvolume (Arch's VM images).
  Snapshots work; the running root can't be swapped for one, so recovery is
  restoring files, or booting a snapshot read-only from GRUB.
- subvolume: `/` is a subvolume named in fstab/rootflags (`@` from
  archinstall). Same, plus archinstall usually mounts `@.snapshots` on
  /.snapshots already - snapper's create-config refuses that, so setup()
  writes the config from snapper's own template instead.
- default-subvolume: `/` is the subvolume the filesystem boots by default and
  nothing pins it (openSUSE-style). `snapper rollback` works there; Atropa
  explains it but doesn't run it.

Atropa never swaps the root subvolume of a running system: one wrong step
there leaves a machine that doesn't boot.

Privilege tiers (see atropa/helper.py): listing, comparing and creating are
keep-tier. Setup (snapper's config is root-equivalent: ALLOW_USERS lets a
user drive snapper), restoring files (writes anything as root), and
deleting a snapshot (removes a way back) ask every time.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import bootloader
from .privilege import CommandResult, run_privileged, run_privileged_streaming, run_unprivileged

SNAPPER_CONFIG = Path("/etc/snapper/configs/root")
SNAPPER_CONFD = Path("/etc/conf.d/snapper")
TEMPLATE = Path("/usr/share/snapper/config-templates/default")
FSTAB = Path("/etc/fstab")
CMDLINE = Path("/proc/cmdline")
SNAPSHOTS_DIR = Path("/.snapshots")

_STATUS_FLAGS = {
    "+": "created", "-": "deleted", "c": "content changed", "t": "type changed",
    "p": "permissions changed", "u": "owner changed", "g": "group changed",
    "x": "extended attributes changed", "a": "ACL changed",
}


# ---------------------------------------------------------------- layout --


@dataclass
class Layout:
    btrfs: bool
    device: str
    subvol: str  # "/" for the top-level subvolume
    kind: str  # not-btrfs | top-level | subvolume | default-subvolume
    snapshots_exists: bool
    snapshots_mounted: bool

    @property
    def rollback(self) -> str:
        """How a whole-system rollback works on this layout, in one sentence."""
        if self.kind == "default-subvolume":
            return ("`snapper rollback N` makes a snapshot the default subvolume; after a reboot the system runs "
                    "from it. Atropa doesn't run that for you.")
        if self.kind in {"top-level", "subvolume"}:
            return ("The running root can't be swapped for a snapshot here. Restore the files that broke, or boot "
                    "a snapshot read-only from the GRUB menu (grub-btrfs) to get a working system and repair "
                    "from there.")
        return "Snapshots need a Btrfs root filesystem."


def _mount_options(path: str) -> tuple[str, str, str] | None:
    result = run_unprivileged(["findmnt", "-n", "-o", "FSTYPE,SOURCE,OPTIONS", path], timeout=20)
    if not result.ok or not result.stdout.split():
        return None
    parts = result.stdout.split()
    return parts[0], parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else ""


def _option(options: str, name: str) -> str | None:
    for item in options.split(","):
        key, sep, value = item.partition("=")
        if sep and key == name:
            return value
    return None


def _root_pinned_to_subvol() -> bool:
    """Does fstab or the kernel command line name the root subvolume?"""
    try:
        for line in FSTAB.read_text(encoding="utf-8", errors="replace").splitlines():
            fields = line.split()
            if len(fields) >= 4 and not fields[0].startswith("#") and fields[1] == "/":
                if _option(fields[3], "subvol") is not None or _option(fields[3], "subvolid") is not None:
                    return True
    except OSError:
        pass
    try:
        for word in CMDLINE.read_text(encoding="utf-8").split():
            if word.startswith("rootflags=") and ("subvol=" in word or "subvolid=" in word):
                return True
    except OSError:
        pass
    return False


def layout() -> Layout:
    mounted = _mount_options("/")
    if mounted is None:
        raise RuntimeError("Couldn't read how / is mounted (findmnt)")
    fstype, source, options = mounted
    device = source.split("[", 1)[0]
    snapshots_exists = SNAPSHOTS_DIR.exists()
    snapshots_mounted = _mount_options(str(SNAPSHOTS_DIR)) is not None if snapshots_exists else False
    if fstype != "btrfs":
        return Layout(False, device, "", "not-btrfs", snapshots_exists, snapshots_mounted)
    subvol = _option(options, "subvol") or "/"
    if subvol in {"/", ""}:
        kind = "top-level"
    elif _root_pinned_to_subvol():
        kind = "subvolume"
    else:
        kind = "default-subvolume"
    return Layout(True, device, subvol, kind, snapshots_exists, snapshots_mounted)


# ---------------------------------------------------------------- status --


def _package_installed(name: str) -> bool:
    return run_unprivileged(["pacman", "-Q", name], timeout=20).ok


@dataclass
class SnapperStatus:
    snapper: bool
    snap_pac: bool
    configured: bool
    cleanup_timer: bool
    grub_btrfs: bool
    grub: bool


def snapper_status() -> SnapperStatus:
    cleanup = run_unprivileged(["systemctl", "is-enabled", "snapper-cleanup.timer"], timeout=20)
    try:
        grub = bootloader.detect() == "grub"
    except Exception:  # noqa: BLE001 - "can't tell" only hides the grub-btrfs offer
        grub = False
    return SnapperStatus(
        snapper=shutil.which("snapper") is not None,
        snap_pac=_package_installed("snap-pac"),
        configured=SNAPPER_CONFIG.exists(),
        cleanup_timer=cleanup.stdout.strip() == "enabled",
        grub_btrfs=_package_installed("grub-btrfs"),
        grub=grub,
    )


# ----------------------------------------------------------------- setup --


def _with_snapper_configs(text: str) -> str:
    """/etc/conf.d/snapper with "root" in SNAPPER_CONFIGS, everything else kept."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("SNAPPER_CONFIGS="):
            names = line.split("=", 1)[1].strip().strip('"').split()
            if "root" not in names:
                names.append("root")
            lines[index] = f'SNAPPER_CONFIGS="{" ".join(names)}"'
            return "\n".join(lines) + "\n"
    return "\n".join([*lines, 'SNAPPER_CONFIGS="root"']).lstrip("\n") + "\n"


def _write_config_from_template() -> CommandResult:
    """create-config without creating /.snapshots: for an @.snapshots already mounted there."""
    template = TEMPLATE.read_text(encoding="utf-8")
    lines = [
        'SUBVOLUME="/"' if line.startswith("SUBVOLUME=") else 'FSTYPE="btrfs"' if line.startswith("FSTYPE=") else line
        for line in template.splitlines()
    ]
    written = run_privileged(["install", "-m", "0640", "/dev/stdin", str(SNAPPER_CONFIG)], input_text="\n".join(lines) + "\n")
    if not written.ok:
        return written
    try:
        current = SNAPPER_CONFD.read_text(encoding="utf-8")
    except FileNotFoundError:
        current = ""
    return run_privileged(["tee", str(SNAPPER_CONFD)], input_text=_with_snapper_configs(current))


def setup(on_line: Callable[[str], None]) -> CommandResult:
    """Install snapper and snap-pac, create the root config, enable the cleanup timer."""
    current = layout()
    if not current.btrfs:
        raise RuntimeError("/ isn't on Btrfs, so snapper can't snapshot it")

    on_line("Installing snapper and snap-pac (snap-pac snapshots every pacman transaction)...")
    installed = run_privileged_streaming(["pacman", "-S", "--needed", "--noconfirm", "snapper", "snap-pac"], on_line)
    if not installed.ok:
        return installed

    if SNAPPER_CONFIG.exists():
        on_line("snapper already has a root config - keeping it.")
    elif not current.snapshots_exists:
        on_line("Creating snapper's root config (and the /.snapshots subvolume)...")
        created = run_privileged(["snapper", "-c", "root", "create-config", "/"])
        if not created.ok:
            return created
    elif current.snapshots_mounted:
        on_line("/.snapshots is already a mounted subvolume - writing snapper's root config from its template...")
        written = _write_config_from_template()
        if not written.ok:
            return written
    else:
        raise RuntimeError(
            "/.snapshots exists but isn't a mounted subvolume; move it aside or mount your snapshots subvolume "
            "there, then run setup again"
        )

    on_line("Enabling snapper-cleanup.timer (removes old snapshots by number)...")
    return run_privileged(["systemctl", "enable", "--now", "snapper-cleanup.timer"])


def install_grub_btrfs(on_line: Callable[[str], None]) -> CommandResult:
    """grub-btrfs lists snapshots in the GRUB menu; grub-btrfsd keeps the menu in step."""
    installed = run_privileged_streaming(
        ["pacman", "-S", "--needed", "--noconfirm", "grub-btrfs", "inotify-tools"], on_line
    )
    if not installed.ok:
        return installed
    enabled = run_privileged(["systemctl", "enable", "--now", "grub-btrfsd.service"])
    if not enabled.ok:
        return enabled
    on_line("Regenerating grub.cfg with the snapshot submenu...")
    return run_privileged_streaming(["grub-mkconfig", "-o", str(bootloader.GRUB_CFG_PATH)], on_line)


# ------------------------------------------------------------- snapshots --


@dataclass
class Snapshot:
    number: int
    type: str  # single | pre | post
    pre_number: int | None
    date: str
    description: str
    cleanup: str


def snapshots() -> list[Snapshot]:
    """Every snapshot of the root config, newest first (0, the live system, left out)."""
    result = run_privileged(["snapper", "--jsonout", "-c", "root", "list"])
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or "snapper list failed")
    try:
        entries = json.loads(result.stdout).get("root", [])
    except (json.JSONDecodeError, AttributeError) as exc:
        raise RuntimeError("snapper didn't return the expected JSON") from exc
    found = [
        Snapshot(
            number=int(entry["number"]),
            type=str(entry.get("type", "single")),
            pre_number=entry.get("pre-number"),
            date=str(entry.get("date") or ""),
            description=str(entry.get("description") or ""),
            cleanup=str(entry.get("cleanup") or ""),
        )
        for entry in entries
        if isinstance(entry, dict) and int(entry.get("number", 0)) > 0
    ]
    return sorted(found, key=lambda snapshot: -snapshot.number)


def create(description: str) -> CommandResult:
    text = " ".join(description.split())[:200] or "Atropa"
    if text.startswith("-"):
        text = text.lstrip("-").strip() or "Atropa"
    return run_privileged(["snapper", "-c", "root", "create", "-d", text, "--cleanup-algorithm", "number"])


def delete(number: int) -> CommandResult:
    if not isinstance(number, int) or number < 1:
        raise ValueError("Not a snapshot number")
    return run_privileged(["snapper", "-c", "root", "delete", str(number)])


@dataclass
class FileChange:
    path: str
    kind: str  # human-readable, from snapper's status flags


def changes(number: int) -> list[FileChange]:
    """Files that differ between snapshot `number` and the live system."""
    if not isinstance(number, int) or number < 1:
        raise ValueError("Not a snapshot number")
    result = run_privileged(["snapper", "-c", "root", "status", f"{number}..0"], timeout=600)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or "snapper status failed")
    found = []
    for line in result.stdout.splitlines():
        flags, _sep, path = line.partition(" ")
        if not path.startswith("/"):
            continue
        kinds = [_STATUS_FLAGS[flag] for flag in flags if flag in _STATUS_FLAGS]
        found.append(FileChange(path, ", ".join(dict.fromkeys(kinds)) or "changed"))
    return found


def restore(number: int, paths: list[str]) -> CommandResult:
    """Put files back as they were in snapshot `number` (created ones are removed again)."""
    if not isinstance(number, int) or number < 1:
        raise ValueError("Not a snapshot number")
    if not paths or any(not path.startswith("/") for path in paths):
        raise ValueError("Restore needs absolute paths")
    return run_privileged(["snapper", "-c", "root", "undochange", f"{number}..0", *paths])
