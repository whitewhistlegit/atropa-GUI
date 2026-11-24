"""
atropa.backend.kernels
-------------------------
Installed kernels, a fallback kernel, and what old kernels leave behind.

A kernel package is found by the ``pkgbase`` file it installs in its module
directory (``/usr/lib/modules/<release>/pkgbase``), so a kernel from the AUR
counts as much as one from the repos. For each one:

- whether it's the running kernel (``uname -r`` is its directory name);
- whether its ``-headers`` package is installed - only a problem when a
  DKMS package is, since DKMS builds its modules against those headers;
- whether the bootloader has an entry for it. GRUB's ``grub.cfg`` is
  usually root-only, so that check asks the helper for the ``vmlinuz-*``
  file names in it and nothing else (no kernel command lines);
  systemd-boot's entries and unified kernel images are read from the ESP.

Installing adds the headers when DKMS is in use and regenerates GRUB's
menu; on systemd-boot, an entry can be added by copying the running
kernel's one (``add_boot_entry``). Removing the running kernel or the last
one is refused.

``leftover_module_dirs()`` lists module directories that no kernel package
owns any more. DKMS builds its modules into ``updates/dkms`` of every
kernel release, and pacman doesn't remove those when the kernel goes: the
directory of every old kernel stays. The helper removes one only when it
has no ``kernel/`` tree (so it isn't a kernel installed by hand), isn't the
running kernel, and no package owns it.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from . import bootloader, pacman
from .privilege import CommandResult, run_privileged, run_unprivileged

MODULES_DIR = Path("/usr/lib/modules")

# The kernels Arch ships, and what each is for. Any other kernel that is
# installed is shown and can be removed, but only these are offered.
OFFERED = {
    "linux": "The default Arch kernel",
    "linux-lts": "Long-term support - the usual fallback",
    "linux-zen": "Tuned for desktop responsiveness",
    "linux-hardened": "Security-focused patches and defaults",
}

_PKGBASE_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]*$")
_RELEASE_RE = re.compile(r"^[0-9][A-Za-z0-9._+-]*$")


@dataclass
class Kernel:
    pkgbase: str
    release: str  # the module directory's name, what `uname -r` says when it runs
    version: str  # pacman's version, "" when pacman doesn't know the package
    running: bool
    headers: bool
    boot_entry: bool | None  # None: couldn't tell (e.g. grub.cfg not checked yet)


@dataclass
class LeftoverDir:
    release: str
    size_mb: float
    removable: bool  # no kernel/ tree: only DKMS output and similar
    reason: str


@dataclass
class KernelStatus:
    kernels: list[Kernel]
    leftovers: list[LeftoverDir]
    dkms: list[str]  # installed *-dkms packages
    bootloader: str  # bootloader.detect()


def running_release() -> str:
    return os.uname().release


def _pkgbase(directory: Path) -> str | None:
    try:
        name = (directory / "pkgbase").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return name if _PKGBASE_RE.match(name) else None


def _installed_versions() -> dict[str, str]:
    result = run_unprivileged(["pacman", "-Q"], timeout=30)
    versions = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2:
            versions[parts[0]] = parts[1]
    return versions


def _size_mb(directory: Path) -> float:
    total = 0
    for root, _dirs, files in os.walk(directory):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return round(total / (1024 * 1024), 1)


def _boot_names_grub() -> set[str] | None:
    """The vmlinuz-* names in grub.cfg, or None when they can't be read."""
    try:
        text = bootloader.GRUB_CFG_PATH.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return set()
    except OSError:
        return None
    return set(re.findall(r"vmlinuz-([A-Za-z0-9._+-]+)", text))


def check_grub_entries() -> set[str]:
    """
    Reads grub.cfg's kernel names through the helper - for a root-only
    grub.cfg, on request, since it asks for the password. Only the
    `vmlinuz-*` names come back, not the command lines around them.
    """
    result = run_privileged(["grep", "-oE", "vmlinuz-[A-Za-z0-9._+-]+", str(bootloader.GRUB_CFG_PATH)])
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or "Couldn't read grub.cfg")
    return {line.split("-", 1)[1] for line in result.stdout.split() if line.startswith("vmlinuz-")}


def _boot_names_systemd_boot() -> set[str] | None:
    """Kernels named by systemd-boot entries, plus unified kernel images on the ESP."""
    names: set[str] = set()
    try:
        for loader_dir in bootloader._loader_dirs():
            entries = loader_dir / "entries"
            if entries.is_dir():
                for entry in entries.glob("*.conf"):
                    names.update(re.findall(r"vmlinuz-([A-Za-z0-9._+-]+)", entry.read_text(errors="replace")))
            linux = loader_dir.parent / "EFI" / "Linux"
            if linux.is_dir():
                for image in linux.glob("*.efi"):
                    names.add(image.stem)  # matched loosely below: arch-linux-zen.efi
    except OSError:
        return None
    return names


def _has_entry(pkgbase: str, names: set[str] | None, kind: str) -> bool | None:
    if names is None:
        return None
    if pkgbase in names:
        return True
    if kind == "systemd-boot":
        # UKI names vary (arch-linux-zen.efi, linux-zen-fallback.efi): a
        # name ending in, or containing, "-<pkgbase>" counts.
        return any(name == pkgbase or name.endswith(f"-{pkgbase}") or f"-{pkgbase}-" in name or
                   name.startswith(f"{pkgbase}-") for name in names)
    return False


def status(grub_names: set[str] | None = None) -> KernelStatus:
    """
    Installed kernels and leftover module directories. `grub_names` is the
    result of check_grub_entries(), for when grub.cfg is root-only and the
    user asked to check.
    """
    versions = _installed_versions()
    running = running_release()
    kind = bootloader.detect()
    if kind == "grub":
        names = grub_names if grub_names is not None else _boot_names_grub()
    elif kind == "systemd-boot":
        names = _boot_names_systemd_boot()
    else:
        names = None

    kernels: list[Kernel] = []
    leftovers: list[LeftoverDir] = []
    try:
        directories = sorted(p for p in MODULES_DIR.iterdir() if p.is_dir() and not p.is_symlink())
    except OSError:
        directories = []
    for directory in directories:
        pkgbase = _pkgbase(directory)
        if pkgbase is not None:
            kernels.append(Kernel(
                pkgbase=pkgbase,
                release=directory.name,
                version=versions.get(pkgbase, ""),
                running=directory.name == running,
                headers=f"{pkgbase}-headers" in versions,
                boot_entry=_has_entry(pkgbase, names, kind),
            ))
        elif directory.name != running and _RELEASE_RE.match(directory.name):
            has_tree = (directory / "kernel").exists()
            leftovers.append(LeftoverDir(
                release=directory.name,
                size_mb=_size_mb(directory),
                removable=not has_tree,
                reason=("a kernel installed without pacman, maybe by hand - Atropa leaves it alone"
                        if has_tree else "no kernel package owns it any more"),
            ))
    dkms = sorted(name for name in versions if name.endswith("-dkms") or "-dkms-" in name)
    return KernelStatus(kernels=kernels, leftovers=leftovers, dkms=dkms, bootloader=kind)


def warnings(state: KernelStatus) -> list[str]:
    """Things worth fixing, most important first."""
    found = []
    if len(state.kernels) == 1:
        found.append(
            f"Only one kernel is installed ({state.kernels[0].pkgbase}). If an update breaks it, there's "
            "nothing else to boot - linux-lts is the usual fallback."
        )
    if state.dkms:
        for kernel in state.kernels:
            if not kernel.headers:
                found.append(
                    f"{kernel.pkgbase}-headers isn't installed, so DKMS ({', '.join(state.dkms)}) can't build "
                    f"its modules for {kernel.pkgbase}."
                )
    for kernel in state.kernels:
        if kernel.boot_entry is False:
            found.append(f"The bootloader has no entry for {kernel.pkgbase}, so it can't be booted.")
    return found


def _regenerate_menu(kind: str) -> CommandResult | None:
    if kind == "grub":
        return run_privileged(["grub-mkconfig", "-o", str(bootloader.GRUB_CFG_PATH)])
    return None


def install(pkgbase: str, upgrade: bool = False) -> CommandResult:
    """
    Install one of the OFFERED kernels, with headers when DKMS is in use.
    pacman.PartialUpgradeError when the system is behind its package
    database; upgrade=True then installs it as part of a full upgrade
    (`pacman -Syu --needed`), the way Arch supports.
    """
    if pkgbase not in OFFERED:
        raise ValueError(f"{pkgbase!r} isn't one of: {', '.join(OFFERED)}")
    state = status()
    packages = [pkgbase]
    if state.dkms:
        packages.append(f"{pkgbase}-headers")
    if upgrade:
        result = pacman.upgrade_and_install_streaming(packages, lambda _line: None)
    else:
        result = pacman.install(packages)
    if not result.ok:
        return result
    return _regenerate_menu(state.bootloader) or result


def install_headers(pkgbase: str) -> CommandResult:
    if not _PKGBASE_RE.match(pkgbase):
        raise ValueError(f"{pkgbase!r} isn't a kernel package name")
    return pacman.install([f"{pkgbase}-headers"])


def remove(pkgbase: str) -> CommandResult:
    """Remove a kernel (and its headers); never the running one or the last one."""
    state = status()
    kernel = next((k for k in state.kernels if k.pkgbase == pkgbase), None)
    if kernel is None:
        raise ValueError(f"{pkgbase} isn't an installed kernel")
    if kernel.running:
        raise RuntimeError(f"{pkgbase} is the running kernel. Boot another one first, then remove it.")
    if len(state.kernels) == 1:
        raise RuntimeError(f"{pkgbase} is the only kernel installed; removing it would leave nothing to boot.")
    packages = [pkgbase] + ([f"{pkgbase}-headers"] if kernel.headers else [])
    result = run_privileged(["pacman", "-Rns", "--noconfirm", *packages])
    if not result.ok:
        return result
    return _regenerate_menu(state.bootloader) or result


def remove_leftover(release: str) -> CommandResult:
    """Remove a leftover module directory; the helper re-checks everything."""
    if not _RELEASE_RE.match(release) or release == running_release():
        raise ValueError(f"{release!r} isn't a leftover module directory")
    return run_privileged(["modules-leftover-remove", release])


# ---------------------------------------------------- systemd-boot entries --


def entry_for(pkgbase: str) -> tuple[Path, str]:
    """
    (path, content) of a systemd-boot entry for `pkgbase`, copied from the
    running kernel's entry with the kernel and initramfs names swapped.
    RuntimeError when there's no entry to copy from.
    """
    if not _PKGBASE_RE.match(pkgbase):
        raise ValueError(f"{pkgbase!r} isn't a kernel package name")
    running = next((k for k in status().kernels if k.running), None)
    if running is None:
        raise RuntimeError("The running kernel isn't a kernel package, so there's no entry to copy.")
    for loader_dir in bootloader._loader_dirs():
        entries = loader_dir / "entries"
        if not entries.is_dir():
            continue
        for entry in sorted(entries.glob("*.conf")):
            text = entry.read_text(errors="replace")
            if not re.search(rf"^linux\s+\S*/vmlinuz-{re.escape(running.pkgbase)}\s*$", text, re.MULTILINE):
                continue
            new = re.sub(rf"vmlinuz-{re.escape(running.pkgbase)}\b", f"vmlinuz-{pkgbase}", text)
            new = re.sub(rf"initramfs-{re.escape(running.pkgbase)}(?=[.-])", f"initramfs-{pkgbase}", new)
            new = re.sub(r"^title\s+.*$", f"title   Arch Linux ({pkgbase})", new, count=1, flags=re.MULTILINE)
            return entries / f"atropa-{pkgbase}.conf", new
    raise RuntimeError(f"No systemd-boot entry boots {running.pkgbase}, so there's nothing to copy.")


def add_boot_entry(pkgbase: str) -> CommandResult:
    path, content = entry_for(pkgbase)
    return run_privileged(["tee", str(path)], input_text=content)
