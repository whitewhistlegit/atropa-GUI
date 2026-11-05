"""
atropa.backend.boot_security
--------------------------------
The two things that decide how exposed a stolen or tampered-with machine
is, and that no other module reports:

- **Root filesystem encryption**: whether ``/`` sits above a LUKS device.
  Read through ``findmnt`` (what is / mounted from) and ``lsblk -s`` (the
  device stack below it), which handles LUKS directly on a partition, LUKS
  under LVM, and root on a subvolume. ``/etc/crypttab`` is the fallback
  when lsblk can't answer (a name in it is decent evidence even then).
- **Secure Boot**: the firmware's state through ``bootctl`` or
  ``mokutil``, plus ``sbctl``'s own view and the key/signing actions.

Nothing here writes unless the caller asks for an sbctl action, and every
one of those goes through pkexec. ``overview()`` keeps each of the three
checks independent, so a machine without an ESP or with an old systemd
still reports the other two instead of one blank page.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .privilege import CommandResult, run_privileged, run_unprivileged

EFI_DIR = Path("/sys/firmware/efi")
CRYPTTAB = Path("/etc/crypttab")


@dataclass
class CrypttabEntry:
    name: str
    device: str
    keyfile: str = "none"
    options: str = ""


@dataclass
class EncryptionStatus:
    # None means "couldn't tell" - deliberately distinct from False (a plain
    # partition), because the report must not claim a machine is unencrypted
    # just because lsblk wasn't available.
    encrypted: bool | None
    source: str
    detail: str
    crypttab: list[CrypttabEntry] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)


@dataclass
class SecureBootStatus:
    supported: bool | None
    enabled: bool | None
    source: str = ""
    detail: str = ""


@dataclass
class SbctlStatus:
    installed: bool
    setup_mode: bool | None = None
    secure_boot: bool | None = None
    vendor_keys: str = ""
    detail: str = ""


@dataclass
class BootSecurityReport:
    encryption: EncryptionStatus | None = None
    encryption_error: str = ""
    secure_boot: SecureBootStatus | None = None
    secure_boot_error: str = ""
    sbctl: SbctlStatus | None = None
    sbctl_error: str = ""


def root_source() -> str:
    """What ``/`` is mounted from, e.g. ``/dev/mapper/root`` or ``/dev/nvme0n1p3``."""
    result = run_unprivileged(["findmnt", "-n", "-o", "SOURCE", "/"], timeout=20)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"findmnt exited with status {result.returncode}")
    source = result.stdout.strip().splitlines()[0].strip() if result.stdout.strip() else ""
    if not source:
        raise RuntimeError("findmnt returned no source for /")
    return source


def _block_device(source: str) -> str:
    """``/dev/nvme0n1p2[/@]`` -> ``/dev/nvme0n1p2`` (btrfs subvolumes name it this way)."""
    return source.split("[", 1)[0]


def read_crypttab() -> list[CrypttabEntry]:
    """Parsed /etc/crypttab; a missing or unreadable file is an empty list."""
    try:
        text = CRYPTTAB.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    entries = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        entries.append(
            CrypttabEntry(
                name=parts[0],
                device=parts[1],
                keyfile=parts[2] if len(parts) >= 3 else "none",
                options=parts[3] if len(parts) >= 4 else "",
            )
        )
    return entries


def _device_stack(device: str) -> list[tuple[str, str]]:
    """``lsblk -s`` for `device`: itself plus its parents, nearest first."""
    result = run_unprivileged(["lsblk", "-s", "-n", "-o", "NAME,TYPE", device], timeout=20)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"lsblk exited with status {result.returncode}")

    chain = []
    for raw in result.stdout.splitlines():
        parts = raw.split()
        if len(parts) >= 2:
            chain.append((parts[0], parts[1]))
    return chain


def encryption_status() -> EncryptionStatus:
    """
    Whether root is above a LUKS device. Falls back to /etc/crypttab when
    lsblk can't be asked, and says so rather than guessing.
    """
    source = root_source()
    device = _block_device(source)
    crypttab = read_crypttab()

    try:
        chain = _device_stack(device)
    except RuntimeError:
        chain = []

    crypt_devices = [name for name, kind in chain if kind == "crypt"]
    if crypt_devices:
        return EncryptionStatus(
            encrypted=True,
            source=source,
            detail=f"Root ({source}) sits above LUKS device '{crypt_devices[0]}'.",
            crypttab=crypttab,
            devices=crypt_devices,
        )

    mapper_name = device.rsplit("/", 1)[-1] if device.startswith("/dev/mapper/") else ""
    if mapper_name and any(entry.name == mapper_name for entry in crypttab):
        return EncryptionStatus(
            encrypted=True,
            source=source,
            detail=(
                f"Root ({source}) is a device-mapper volume named '{mapper_name}', which is listed in "
                "/etc/crypttab - the block-device stack itself couldn't be read."
            ),
            crypttab=crypttab,
            devices=[mapper_name],
        )

    if chain:
        kind = chain[0][1]
        return EncryptionStatus(
            encrypted=False,
            source=source,
            detail=f"Root ({source}) is on a plain '{kind}' device - there is no LUKS layer in its stack.",
            crypttab=crypttab,
        )

    return EncryptionStatus(
        encrypted=None,
        source=source,
        detail=f"Couldn't read the block-device stack for {device}, so encryption can't be confirmed either way.",
        crypttab=crypttab,
    )


def _parse_on_off(value: str) -> bool | None:
    lowered = value.strip().lower()
    if lowered.startswith("enabled") or lowered.startswith("on") or lowered.startswith("true"):
        return True
    if lowered.startswith("disabled") or lowered.startswith("off") or lowered.startswith("false"):
        return False
    return None


def _bootctl_secure_boot() -> SecureBootStatus | None:
    result = run_unprivileged(["bootctl", "status"], timeout=20)
    if not result.ok:
        return None
    for raw in result.stdout.splitlines():
        key, separator, value = raw.partition(":")
        if separator and key.strip().lower() == "secure boot":
            enabled = _parse_on_off(value)
            if enabled is None:
                return None
            return SecureBootStatus(
                supported=True,
                enabled=enabled,
                source="bootctl",
                detail=f"Firmware reports Secure Boot {'enabled' if enabled else 'disabled'}.",
            )
    return None


def _mokutil_secure_boot() -> SecureBootStatus | None:
    result = run_unprivileged(["mokutil", "--sb-state"], timeout=20)
    if not result.ok:
        return None
    text = f"{result.stdout}\n{result.stderr}".lower()
    if "secureboot enabled" in text:
        enabled: bool | None = True
    elif "secureboot disabled" in text:
        enabled = False
    else:
        return None
    return SecureBootStatus(
        supported=True,
        enabled=enabled,
        source="mokutil",
        detail=f"Firmware reports Secure Boot {'enabled' if enabled else 'disabled'}.",
    )


def secure_boot_status() -> SecureBootStatus:
    """Firmware Secure Boot state, via bootctl (preferred) or mokutil."""
    if not EFI_DIR.exists():
        return SecureBootStatus(
            supported=False,
            enabled=None,
            detail="This system booted in legacy BIOS mode, so Secure Boot doesn't apply.",
        )

    # bootctl first: it's part of systemd, so it's present on every Arch
    # install, whereas mokutil is an optional package.
    if shutil.which("bootctl"):
        status = _bootctl_secure_boot()
        if status is not None:
            return status
    if shutil.which("mokutil"):
        status = _mokutil_secure_boot()
        if status is not None:
            return status

    return SecureBootStatus(
        supported=True,
        enabled=None,
        detail="Couldn't read the firmware's Secure Boot state (neither bootctl nor mokutil answered usefully).",
    )


def sbctl_status() -> SbctlStatus:
    """What sbctl says about this machine's keys and signing state."""
    if shutil.which("sbctl") is None:
        return SbctlStatus(
            installed=False,
            detail="sbctl isn't installed - install it with: pacman -S sbctl",
        )

    result = run_unprivileged(["sbctl", "status"], timeout=20)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"sbctl exited with status {result.returncode}")

    status = SbctlStatus(installed=True)
    for raw in result.stdout.splitlines():
        key, separator, value = raw.partition(":")
        if not separator:
            continue
        label = key.strip().lower()
        value = value.strip().lstrip("✓✗xX ").strip()
        if label == "setup mode":
            status.setup_mode = _parse_on_off(value)
        elif label == "secure boot":
            status.secure_boot = _parse_on_off(value)
        elif label == "vendor keys":
            status.vendor_keys = value

    if status.setup_mode is True:
        status.detail = "Setup mode is enabled - the firmware will accept new keys."
    elif status.setup_mode is False and status.secure_boot is True:
        status.detail = "Keys are enrolled and Secure Boot is on."
    elif status.setup_mode is False:
        status.detail = "Setup mode is off (keys are enrolled), but Secure Boot isn't on."
    else:
        status.detail = "sbctl couldn't report the setup-mode state."
    return status


# ------------------------------------------------------------- sbctl actions --
#
# These are the "set up and sign" half of the feature. They are boot-level
# changes, so the UI confirms each one, and enrolling deliberately keeps
# Microsoft's keys (--microsoft): without them, option ROMs and some
# peripherals can stop working on a dual-boot or discrete-GPU machine.


#
# The order matters: create keys, sign, *then* enroll. Many firmwares start
# enforcing as soon as keys are enrolled, and an unsigned kernel or
# bootloader then doesn't boot.


def create_keys() -> CommandResult:
    """Create sbctl's own Secure Boot key pair (idempotent)."""
    return run_privileged(["sbctl", "create-keys"])


def unsigned_boot_files() -> list[str]:
    """
    EFI files sbctl finds unsigned: its file database plus every EFI binary
    on the ESP (`sbctl verify --json`; is_signed is 1, 0, or -1 for a
    database entry whose file is gone - only 0 needs signing).

    Raises RuntimeError when sbctl can't answer, e.g. no keys yet or no ESP.
    """
    result = run_privileged(["sbctl", "verify", "--json"], timeout=120)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"sbctl verify exited with status {result.returncode}")
    try:
        entries = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"sbctl verify didn't return JSON: {result.stdout.strip()[:160]}") from exc
    if not isinstance(entries, list):
        raise RuntimeError("sbctl verify returned unexpected JSON")
    return [
        entry["file_name"]
        for entry in entries
        if isinstance(entry, dict) and entry.get("is_signed") == 0 and isinstance(entry.get("file_name"), str)
    ]


def sign_boot_files() -> CommandResult:
    """
    Sign every unsigned EFI file and save it in sbctl's database (`sign -s`).

    `sbctl sign-all` alone isn't enough: it only re-signs files already in
    the database, which is empty right after create-keys. Saving them is
    also what lets sbctl's pacman hook re-sign them after kernel and
    bootloader updates.
    """
    unsigned = unsigned_boot_files()
    if not unsigned:
        return CommandResult(0, "Every boot file sbctl found is already signed.", "")
    for path in unsigned:
        result = run_privileged(["sbctl", "sign", "-s", path], timeout=120)
        if not result.ok:
            return result
    return CommandResult(0, "Signed and saved: " + ", ".join(unsigned), "")


def enroll_keys(microsoft: bool = True) -> CommandResult:
    """
    Enroll the keys in the firmware. Only works while the firmware is in
    setup mode; sbctl asks for confirmation on stdin, so answer it.

    Refuses while any boot file is unsigned: enrolling first is how a
    machine ends up refusing to boot its own kernel.
    """
    unsigned = unsigned_boot_files()
    if unsigned:
        raise RuntimeError(
            "Sign the boot files first - these are still unsigned: " + ", ".join(unsigned)
        )
    argv = ["sbctl", "enroll-keys"]
    argv.append("--microsoft" if microsoft else "--no-microsoft")
    return run_privileged(argv, input_text="y\n")


def sign_all() -> CommandResult:
    """Re-sign every file already in sbctl's database (what its pacman hook runs)."""
    return run_privileged(["sbctl", "sign-all"], timeout=300)


# --------------------------------------------------------------- compliance --
#
# Shaped for compliance.generate_report() but kept free of a hardening
# import so this module stays independent of the audit's check registry.


@dataclass
class SecurityCheck:
    name: str
    status: str  # "pass" | "warn" | "fail" | "info"
    detail: str


def security_checks() -> list[SecurityCheck]:
    """The two checks that let the exposure score see disk and boot tampering."""
    checks = []
    try:
        encryption = encryption_status()
        if encryption.encrypted is True:
            checks.append(SecurityCheck("Disk encryption", "pass", encryption.detail))
        elif encryption.encrypted is False:
            checks.append(SecurityCheck("Disk encryption", "fail", encryption.detail))
        else:
            checks.append(SecurityCheck("Disk encryption", "info", encryption.detail))
    except Exception as exc:  # noqa: BLE001 - reported as its own row
        checks.append(SecurityCheck("Disk encryption", "info", f"Couldn't check: {exc}"))

    try:
        secure_boot = secure_boot_status()
        if secure_boot.supported is False:
            checks.append(SecurityCheck("Secure Boot", "info", secure_boot.detail))
        elif secure_boot.enabled is True:
            checks.append(SecurityCheck("Secure Boot", "pass", secure_boot.detail))
        elif secure_boot.enabled is False:
            checks.append(SecurityCheck("Secure Boot", "warn", secure_boot.detail))
        else:
            checks.append(SecurityCheck("Secure Boot", "info", secure_boot.detail))
    except Exception as exc:  # noqa: BLE001
        checks.append(SecurityCheck("Secure Boot", "info", f"Couldn't check: {exc}"))

    return checks


def overview() -> BootSecurityReport:
    """All three checks, each failing only in its own row."""
    report = BootSecurityReport()

    try:
        report.encryption = encryption_status()
    except Exception as exc:  # noqa: BLE001
        report.encryption_error = str(exc)

    try:
        report.secure_boot = secure_boot_status()
    except Exception as exc:  # noqa: BLE001
        report.secure_boot_error = str(exc)

    try:
        report.sbctl = sbctl_status()
    except Exception as exc:  # noqa: BLE001
        report.sbctl_error = str(exc)

    return report
