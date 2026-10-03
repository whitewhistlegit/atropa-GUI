"""
atropa.backend.bootloader
------------------------------
Detects and manages GRUB or systemd-boot, the two common Arch bootloaders.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .privilege import CommandResult, backup_file, restore_file, run_privileged, run_unprivileged

GRUB_DEFAULT_PATH = Path("/etc/default/grub")
SYSTEMD_BOOT_LOADER_CONF = Path("/boot/loader/loader.conf")
SYSTEMD_BOOT_ENTRIES_DIR = Path("/boot/loader/entries")


@dataclass
class BootEntry:
    title: str
    identifier: str
    is_default: bool = False


@dataclass
class BootloaderInfo:
    kind: str  # "grub", "systemd-boot", "unknown"
    entries: list[BootEntry] = field(default_factory=list)
    default_timeout: str = ""


def detect() -> str:
    if shutil.which("bootctl") and SYSTEMD_BOOT_LOADER_CONF.exists():
        return "systemd-boot"
    if GRUB_DEFAULT_PATH.exists() and shutil.which("grub-mkconfig"):
        return "grub"
    return "unknown"


def get_info() -> BootloaderInfo:
    kind = detect()
    if kind == "systemd-boot":
        return _systemd_boot_info()
    if kind == "grub":
        return _grub_info()
    return BootloaderInfo(kind="unknown")


def _systemd_boot_info() -> BootloaderInfo:
    entries = []
    timeout = ""
    if SYSTEMD_BOOT_LOADER_CONF.exists():
        for line in SYSTEMD_BOOT_LOADER_CONF.read_text().splitlines():
            if line.startswith("timeout"):
                timeout = line.split(maxsplit=1)[1] if len(line.split()) > 1 else ""

    if SYSTEMD_BOOT_ENTRIES_DIR.exists():
        for entry_file in sorted(SYSTEMD_BOOT_ENTRIES_DIR.glob("*.conf")):
            title = entry_file.stem
            for line in entry_file.read_text().splitlines():
                if line.startswith("title"):
                    title = line.split(maxsplit=1)[1] if len(line.split()) > 1 else title
            entries.append(BootEntry(title=title, identifier=entry_file.name))

    return BootloaderInfo(kind="systemd-boot", entries=entries, default_timeout=timeout)


def _grub_info() -> BootloaderInfo:
    timeout = ""
    if GRUB_DEFAULT_PATH.exists():
        for line in GRUB_DEFAULT_PATH.read_text().splitlines():
            if line.startswith("GRUB_TIMEOUT="):
                timeout = line.split("=", 1)[1].strip()

    entries = []
    result = run_unprivileged(["grep", "-E", "^menuentry", "/boot/grub/grub.cfg"])
    for line in result.stdout.strip().splitlines():
        # menuentry 'Arch Linux' --class arch ...
        if "'" in line:
            title = line.split("'")[1]
            entries.append(BootEntry(title=title, identifier=title))

    return BootloaderInfo(kind="grub", entries=entries, default_timeout=timeout)


def set_timeout(seconds: int) -> CommandResult:
    kind = detect()
    if kind == "grub":
        # sed-edit /etc/default/grub then regenerate config. If regeneration
        # fails, restore the previous /etc/default/grub - a bad edit here
        # can otherwise leave the boot menu unable to regenerate at all.
        backup_name = backup_file(str(GRUB_DEFAULT_PATH))
        sed_expr = f"s/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT={seconds}/"
        result = run_privileged(["sed", "-i", sed_expr, str(GRUB_DEFAULT_PATH)])
        if result.ok:
            result = regenerate_config()
            if not result.ok and backup_name:
                restore_file(backup_name, str(GRUB_DEFAULT_PATH))
        return result
    if kind == "systemd-boot":
        backup_file(str(SYSTEMD_BOOT_LOADER_CONF))
        sed_expr = f"s/^timeout.*/timeout {seconds}/"
        return run_privileged(["sed", "-i", sed_expr, str(SYSTEMD_BOOT_LOADER_CONF)])
    raise RuntimeError("No supported bootloader detected")


def regenerate_config() -> CommandResult:
    kind = detect()
    if kind == "grub":
        return run_privileged(["grub-mkconfig", "-o", "/boot/grub/grub.cfg"])
    if kind == "systemd-boot":
        return run_privileged(["bootctl", "update"])
    raise RuntimeError("No supported bootloader detected")


def reinstall() -> CommandResult:
    """Reinstall the bootloader to the EFI/MBR (for recovery scenarios)."""
    kind = detect()
    if kind == "systemd-boot":
        return run_privileged(["bootctl", "install"])
    raise RuntimeError(
        "Automatic GRUB reinstall needs your boot disk / EFI target; "
        "use a terminal for 'grub-install' to avoid picking the wrong disk."
    )
