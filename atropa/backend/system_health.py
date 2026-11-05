"""
atropa.backend.system_health
--------------------------------
Read-only checks worth running after an upgrade:

- failed systemd units (``systemctl --failed``)
- whether the running kernel's package now installs a different kernel
  (identified through ``pacman -Qo`` / ``pacman -Ql``, so an intentionally
  installed fallback kernel doesn't produce a permanent "reboot" hint)
- whether the matching CPU microcode package is installed

Nothing here writes, escalates, or needs root. ``check_all()`` isolates the
three checks so one missing tool (systemctl, pacman) or an unowned custom
kernel only blanks that one row instead of hiding the other two.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .privilege import run_unprivileged

MODULES_DIR = Path("/usr/lib/modules")
CPUINFO_PATH = Path("/proc/cpuinfo")

# /proc/cpuinfo vendor_id -> (short name, Arch package)
CPU_VENDORS = {
    "GenuineIntel": ("intel", "intel-ucode"),
    "AuthenticAMD": ("amd", "amd-ucode"),
}


@dataclass
class FailedUnit:
    name: str
    description: str = ""


@dataclass
class KernelStatus:
    running: str
    package: str | None = None
    package_release: str | None = None
    # None means "couldn't tell" (e.g. a custom or unowned kernel), which the
    # UI must show differently from a confident "no reboot needed".
    reboot_required: bool | None = None


@dataclass
class MicrocodeStatus:
    vendor: str | None = None
    package: str | None = None
    installed: bool = False


@dataclass
class HealthReport:
    failed_units: list[FailedUnit] = field(default_factory=list)
    failed_units_error: str = ""
    kernel: KernelStatus | None = None
    kernel_error: str = ""
    microcode: MicrocodeStatus | None = None
    microcode_error: str = ""


def failed_units() -> list[FailedUnit]:
    """Parse ``systemctl --failed``; raises when systemd can't answer."""
    result = run_unprivileged(
        ["systemctl", "--failed", "--no-legend", "--no-pager", "--plain"],
        timeout=20,
    )
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"systemctl exited with status {result.returncode}")

    units = []
    for raw in result.stdout.splitlines():
        line = raw.strip()
        # Older systemd versions prefix each line with a bullet even with
        # --no-legend; --plain removes colour but not necessarily the bullet.
        if line.startswith("●"):
            line = line[1:].strip()
        if not line:
            continue
        # unit load active sub description
        parts = line.split(None, 4)
        if len(parts) < 2:
            continue
        units.append(FailedUnit(parts[0], parts[4] if len(parts) >= 5 else ""))
    return units


def _module_releases_owned_by(package: str) -> set[str]:
    """Kernel release directories ``pacman -Ql <package>`` says it provides."""
    result = run_unprivileged(["pacman", "-Ql", package], timeout=30)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"pacman -Ql {package} exited with status {result.returncode}")

    releases = set()
    for line in result.stdout.splitlines():
        _package, _space, path = line.partition(" ")
        parts = PurePosixPath(path).parts
        if len(parts) >= 6 and parts[1:4] == ("usr", "lib", "modules"):
            releases.add(parts[4])
    return releases


def kernel_status() -> KernelStatus:
    """
    Compare the running kernel with the files its owning package currently
    provides. This deliberately identifies the package instead of assuming
    "newest module directory wins": a machine with linux and linux-lts both
    installed should not report a reboot just because the fallback kernel
    was updated last.
    """
    running = platform.release()
    running_path = MODULES_DIR / running

    result = run_unprivileged(["pacman", "-Qo", str(running_path)], timeout=30)
    if not result.ok:
        raise RuntimeError(
            result.stderr.strip() or f"Couldn't identify the package providing {running_path}"
        )

    packages = []
    for line in result.stdout.splitlines():
        _path, separator, owner = line.partition(" is owned by ")
        if separator:
            package = owner.split()[0]
            if package not in packages:
                packages.append(package)
    if not packages:
        raise RuntimeError(f"Couldn't identify the package providing {running_path}")

    status = KernelStatus(running=running)
    # pacman -Qo can name several owners (the kernel package and its headers).
    # Prefer one that still contains the running release; otherwise the first
    # package that answers tells us what the installed kernel now looks like.
    for package in packages:
        try:
            releases = _module_releases_owned_by(package)
        except RuntimeError:
            continue
        if not releases:
            continue
        status.package = package
        if running in releases:
            status.package_release = running
            status.reboot_required = False
            return status
        status.package_release = sorted(releases)[-1]
        status.reboot_required = True

    if status.reboot_required is None:
        raise RuntimeError(f"Couldn't read the module files for {running_path}")
    return status


def _cpu_vendor_id() -> str:
    try:
        text = CPUINFO_PATH.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() == "vendor_id":
            return value.strip()
    return ""


def microcode_status() -> MicrocodeStatus:
    vendor, package = CPU_VENDORS.get(_cpu_vendor_id(), (None, None))
    if package is None:
        return MicrocodeStatus()

    result = run_unprivileged(["pacman", "-Q", package], timeout=20)
    if result.returncode == 0:
        return MicrocodeStatus(vendor, package, installed=True)
    if result.returncode == 1:  # pacman -Q: not installed
        return MicrocodeStatus(vendor, package, installed=False)
    raise RuntimeError(result.stderr.strip() or f"pacman -Q {package} exited with status {result.returncode}")


def check_all() -> HealthReport:
    """Run all three checks, keeping each one's failure local to its row."""
    report = HealthReport()

    try:
        report.failed_units = failed_units()
    except Exception as exc:  # noqa: BLE001 - one unavailable tool must not blank the whole group
        report.failed_units_error = str(exc)

    try:
        report.kernel = kernel_status()
    except Exception as exc:  # noqa: BLE001
        report.kernel_error = str(exc)

    try:
        report.microcode = microcode_status()
    except Exception as exc:  # noqa: BLE001
        report.microcode_error = str(exc)

    return report
