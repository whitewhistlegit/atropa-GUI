"""
atropa.backend.quicksetup
------------------------------
Orchestrates a "recommended security baseline" across every
security-related module (firewall, fail2ban, sysctl, faillock, AppArmor,
auditd, USBGuard, SELinux) as a single batch or one step at a time.

Each step installs its tool from scratch via pacman if it isn't present
yet, then applies a conservative default configuration - conservative
meaning: never flips SELinux straight to enforcing, never disables SSH
access while enabling a firewall, and is upfront (via on_line messages)
about the two things this deliberately does NOT automate because they
need a reboot and carry real risk of a bad boot if done wrong: adding
AppArmor/SELinux kernel parameters, and wiring pam_faillock into PAM.
Those stay manual, cross-referenced from the messages this module prints.

This module composes existing backend functions rather than duplicating
their logic - it is an orchestrator, not a new source of truth for how
any single tool gets configured.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Callable

from . import hardening, pacman, security, selinux
from .privilege import CommandResult


@dataclass
class SetupItem:
    key: str
    title: str
    description: str
    default_selected: bool = True
    risk_note: str = ""  # shown as a warning in the UI if non-empty


CATALOG: list[SetupItem] = [
    SetupItem(
        "firewall", "Firewall",
        "Installs ufw if missing, makes sure SSH stays reachable, then enables it.",
    ),
    SetupItem(
        "fail2ban", "fail2ban",
        "Installs fail2ban if missing, enables it, and configures an SSH jail.",
    ),
    SetupItem(
        "sysctl", "Kernel sysctl hardening",
        "Applies the curated set of hardened kernel parameters (no install needed).",
    ),
    SetupItem(
        "faillock", "Login lockout (faillock)",
        "Applies a 5-attempt / 15-minute lockout policy - only if PAM is already wired "
        "for pam_faillock; wiring it in isn't automated, since a mistake there can lock "
        "out logins entirely.",
    ),
    SetupItem(
        "apparmor", "AppArmor",
        "Installs and enables the AppArmor service. Actual enforcement also needs an "
        "'apparmor=1 security=apparmor' kernel parameter and a reboot - not automated here.",
    ),
    SetupItem(
        "auditd", "auditd",
        "Installs and enables kernel audit logging.",
    ),
    SetupItem(
        "usbguard", "USBGuard",
        "Installs USBGuard and generates an allow policy from currently-connected devices.",
        default_selected=False,
        risk_note=(
            "Blocks any USB device plugged in after setup until you explicitly allow it "
            "in the USBGuard policy. Convenient for a server, surprising on a laptop you "
            "plug new peripherals into often - left unchecked by default."
        ),
    ),
    SetupItem(
        "selinux", "SELinux",
        "Installs SELinux userspace tools (policycoreutils, checkpolicy, audit). Enabling "
        "enforcement also needs a policy package (e.g. refpolicy-arch from the AUR), a "
        "kernel parameter, and a reboot - not automated here.",
    ),
]

# Fixed, safety-conscious order regardless of what the caller passes in:
# firewall always runs first (and pre-allows SSH before enabling deny-by-default),
# so nothing later runs against a freshly-locked-down network stack before SSH
# access is confirmed preserved.
_ORDER = ["firewall", "fail2ban", "sysctl", "faillock", "apparmor", "auditd", "usbguard", "selinux"]


def _apply_firewall(on_line: Callable[[str], None]) -> CommandResult:
    on_line("=== Firewall ===")
    if security.firewall_backend() == "none":
        on_line("Installing ufw...")
        result = pacman.install(["ufw"])
        if not result.ok:
            on_line(f"Failed to install ufw: {result.stderr.strip()}")
            return result

    status = security.firewall_status()
    if status.active:
        on_line("Firewall already active - nothing to do.")
        return CommandResult(0, "already active", "")

    ssh = security.ssh_status()
    port = ssh.port if ssh.installed else "22"
    on_line(f"Allowing SSH (port {port}) before enabling the firewall, so this doesn't lock you out...")
    security.firewall_allow_port(port)

    on_line("Enabling firewall...")
    result = security.firewall_enable()
    on_line("Firewall enabled." if result.ok else f"Failed to enable firewall: {result.stderr.strip()}")
    return result


def _apply_fail2ban(on_line: Callable[[str], None]) -> CommandResult:
    on_line("=== fail2ban ===")
    if shutil.which("fail2ban-client") is None:
        on_line("Installing fail2ban...")
        result = pacman.install(["fail2ban"])
        if not result.ok:
            on_line(f"Failed to install fail2ban: {result.stderr.strip()}")
            return result

    status = hardening.fail2ban_status()
    if not status.active:
        on_line("Enabling fail2ban...")
        hardening.fail2ban_enable()

    on_line("Configuring the SSH jail...")
    result = hardening.fail2ban_protect_ssh()
    on_line("fail2ban configured." if result.ok else f"Failed: {result.stderr.strip()}")
    return result


def _apply_sysctl(on_line: Callable[[str], None]) -> CommandResult:
    on_line("=== Kernel sysctl hardening ===")
    keys = [setting.key for setting in hardening.get_sysctl_status()]
    result = hardening.apply_sysctl_hardening(keys)
    on_line("Applied recommended sysctl settings." if result.ok else f"Failed: {result.stderr.strip()}")
    return result


def _apply_faillock(on_line: Callable[[str], None]) -> CommandResult:
    on_line("=== Login lockout (faillock) ===")
    if not hardening.faillock_wired_into_pam():
        on_line(
            "faillock isn't wired into PAM on this system - skipping. Wiring it in needs a "
            "manual PAM config edit (see the Hardening page); a mistake there can lock out "
            "logins, so it isn't automated."
        )
        return CommandResult(0, "skipped: not wired into PAM", "")

    result = hardening.set_faillock_policy(deny=5, unlock_time=900)
    on_line("Applied faillock policy (5 attempts, 15 minute lockout)." if result.ok else f"Failed: {result.stderr.strip()}")
    return result


def _apply_apparmor(on_line: Callable[[str], None]) -> CommandResult:
    on_line("=== AppArmor ===")
    if shutil.which("aa-status") is None:
        on_line("Installing apparmor...")
        result = pacman.install(["apparmor"])
        if not result.ok:
            on_line(f"Failed to install apparmor: {result.stderr.strip()}")
            return result

    status = hardening.apparmor_status()
    if not status.extra.get("kernel_enabled"):
        on_line(
            "AppArmor isn't enabled at the kernel level yet - that needs "
            "'apparmor=1 security=apparmor' added to your kernel parameters and a reboot, "
            "which isn't automated here. Installing/enabling the service now so it's ready "
            "once that's done."
        )

    result = hardening.apparmor_enable_service()
    on_line("AppArmor service enabled." if result.ok else f"Failed: {result.stderr.strip()}")
    return result


def _apply_auditd(on_line: Callable[[str], None]) -> CommandResult:
    on_line("=== auditd ===")
    if shutil.which("auditctl") is None:
        on_line("Installing audit...")
        result = pacman.install(["audit"])
        if not result.ok:
            on_line(f"Failed to install audit: {result.stderr.strip()}")
            return result

    result = hardening.auditd_enable()
    on_line("auditd enabled." if result.ok else f"Failed: {result.stderr.strip()}")
    return result


def _apply_usbguard(on_line: Callable[[str], None]) -> CommandResult:
    on_line("=== USBGuard ===")
    if shutil.which("usbguard") is None:
        on_line("Installing usbguard...")
        result = pacman.install(["usbguard"])
        if not result.ok:
            on_line(f"Failed to install usbguard: {result.stderr.strip()}")
            return result

    on_line("Generating an allow policy from currently-connected devices, then enabling...")
    result = hardening.usbguard_generate_and_enable()
    on_line("USBGuard enabled." if result.ok else f"Failed: {result.stderr.strip()}")
    return result


def _apply_selinux(on_line: Callable[[str], None]) -> CommandResult:
    on_line("=== SELinux ===")
    if shutil.which("sestatus") is None:
        on_line("Installing SELinux userspace tools (policycoreutils, checkpolicy, audit)...")
        result = pacman.install(["policycoreutils", "checkpolicy", "audit"])
        if not result.ok:
            on_line(f"Failed to install SELinux tools: {result.stderr.strip()}")
            return result

    status = selinux.get_status()
    if not status.available:
        on_line(
            "SELinux isn't enabled at the kernel level. That needs a policy package (e.g. "
            "refpolicy-arch from the AUR), a kernel parameter, and a reboot - none of which "
            "is automated here. Tools are installed and ready for when you do this manually."
        )
        return CommandResult(0, "tools installed; kernel enablement is a manual step", "")

    if status.mode.lower() not in ("permissive", "enforcing"):
        on_line("Setting SELinux to permissive mode (a safe default - review denials before enforcing)...")
        result = selinux.set_mode(enforcing=False, persistent=True)
        on_line("Set to permissive." if result.ok else f"Failed: {result.stderr.strip()}")
        return result

    on_line(f"SELinux is already {status.mode} - nothing to do.")
    return CommandResult(0, "already configured", "")


_APPLIERS: dict[str, Callable[[Callable[[str], None]], CommandResult]] = {
    "firewall": _apply_firewall,
    "fail2ban": _apply_fail2ban,
    "sysctl": _apply_sysctl,
    "faillock": _apply_faillock,
    "apparmor": _apply_apparmor,
    "auditd": _apply_auditd,
    "usbguard": _apply_usbguard,
    "selinux": _apply_selinux,
}


def status_summary() -> dict[str, str]:
    """One human-readable status line per catalog key, for display before applying."""
    summary: dict[str, str] = {}

    fw = security.firewall_status()
    summary["firewall"] = "Active" if fw.active else ("Installed, inactive" if fw.backend != "none" else "Not installed")

    f2b = hardening.fail2ban_status()
    summary["fail2ban"] = "Active" if f2b.active else ("Installed, inactive" if f2b.installed else "Not installed")

    summary["sysctl"] = "Configured" if hardening.sysctl_hardening_file_exists() else "Not configured"

    if hardening.faillock_wired_into_pam():
        fl = hardening.faillock_status()
        summary["faillock"] = f"Wired in - deny={fl.get('deny', '?')}, unlock_time={fl.get('unlock_time', '?')}"
    else:
        summary["faillock"] = "Not wired into PAM (manual step required)"

    aa = hardening.apparmor_status()
    if aa.active:
        summary["apparmor"] = "Active"
    elif aa.installed:
        summary["apparmor"] = "Installed, inactive"
    else:
        summary["apparmor"] = "Not installed"

    ad = hardening.auditd_status()
    summary["auditd"] = "Active" if ad.active else ("Installed, inactive" if ad.installed else "Not installed")

    ug = hardening.usbguard_status()
    summary["usbguard"] = "Active" if ug.active else ("Installed, inactive" if ug.installed else "Not installed")

    sl = selinux.get_status()
    summary["selinux"] = sl.mode.capitalize() if sl.available else "Not enabled at kernel level"

    return summary


def apply_single(key: str, on_line: Callable[[str], None]) -> CommandResult:
    """Applies exactly one catalog item by key - used by the step-by-step
    wizard, where each step is confirmed and run individually rather than
    as part of a batch. Raises KeyError for an unknown key rather than
    silently doing nothing."""
    return _APPLIERS[key](on_line)


def apply_items(keys: list[str], on_line: Callable[[str], None]) -> dict[str, CommandResult]:
    """
    Applies each selected catalog item in a fixed, safety-conscious order
    (see _ORDER) regardless of the order `keys` was given in, streaming a
    human-readable progress line to on_line before/after each step.
    Returns a per-key CommandResult so the caller can report exactly what
    succeeded, failed, or was intentionally skipped.
    """
    results: dict[str, CommandResult] = {}
    ordered_keys = [key for key in _ORDER if key in keys]
    for key in ordered_keys:
        results[key] = _APPLIERS[key](on_line)
        on_line("")
    return results
