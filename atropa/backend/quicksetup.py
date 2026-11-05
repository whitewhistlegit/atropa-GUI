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

One item is not part of the baseline and is locked in the UI: adding the
unsigned SELinux package repository to pacman.conf. It only lets the
SELinux step install SELinux's tools; swapping the base packages for their
SELinux builds stays manual too.

This module composes existing backend functions rather than duplicating
their logic - it is an orchestrator, not a new source of truth for how
any single tool gets configured.
"""

from __future__ import annotations

import shutil
from collections.abc import Collection
from dataclasses import dataclass
from typing import Callable

from . import boot_security, hardening, pacman, security, selinux
from .privilege import CommandResult, run_unprivileged


@dataclass
class SetupItem:
    key: str
    title: str
    description: str
    default_selected: bool = True
    risk_note: str = ""  # shown as a warning in the UI if non-empty
    locked: bool = False  # can't be selected until the administrator password has unlocked it


@dataclass
class BaselineCheck:
    """One read-only fact in the desktop baseline - nothing here is applied."""

    title: str
    status: str  # "pass" | "warn" | "fail" | "info"
    detail: str


@dataclass
class DesktopBaseline:
    applies: bool  # True when sshd isn't installed: the server-shaped steps don't fit
    sshd_installed: bool
    checks: list[BaselineCheck]


CATALOG: list[SetupItem] = [
    SetupItem(
        "firewall", "Firewall",
        "Installs ufw if missing, makes sure SSH stays reachable, then enables it.",
    ),
    SetupItem(
        "fail2ban", "fail2ban",
        "Installs fail2ban if missing, enables it, and configures an SSH jail. Skipped on a "
        "desktop with no SSH server - there's no remote login to protect.",
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
        "Installs and enables the AppArmor service. Actual enforcement also needs AppArmor in "
        f"the kernel's LSM list ('{hardening.APPARMOR_KERNEL_PARAMETER}') and a reboot - not "
        "automated here.",
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
        "selinux_repo", "SELinux package repository",
        "Adds the archlinuxhardened project's [selinux] repository to pacman.conf, so the "
        "SELinux step below can install SELinux's tools with pacman instead of from the AUR. "
        "Locked until you unlock it with the administrator password.",
        default_selected=False,
        risk_note=(
            "The repository and its packages are unsigned, so it is added with SigLevel = Never: "
            f"pacman installs whatever {pacman.SELINUX_REPO_SERVER} serves, as root, without "
            "verifying it. Enable it only if you trust that project."
        ),
        locked=True,
    ),
    SetupItem(
        "selinux", "SELinux",
        "Installs audit (for reviewing denials) and puts an enabled SELinux into permissive "
        "mode. SELinux's own tools aren't in Arch's official repositories: with the SELinux "
        "package repository above enabled they're installed from it, otherwise install them "
        "from the AUR first (policycoreutils, checkpolicy, semodule-utils, selinux-python). "
        "Turning SELinux on also needs SELinux-enabled base packages, a policy (see SELinux: "
        "Build Policy), a kernel parameter and a reboot - not automated here.",
    ),
]

# Fixed, safety-conscious order regardless of what the caller passes in:
# firewall always runs first (and pre-allows SSH before enabling deny-by-default),
# so nothing later runs against a freshly-locked-down network stack before SSH
# access is confirmed preserved. The SELinux repository goes in right before
# the SELinux step that installs from it.
_ORDER = ["firewall", "fail2ban", "sysctl", "faillock", "apparmor", "auditd", "usbguard", "selinux_repo", "selinux"]


def _sshd_will_listen(ssh: security.SshStatus) -> bool:
    """
    Whether sshd accepts connections now *or after the next boot*.

    "Running right now" isn't enough: an enabled sshd that happens to be
    stopped comes back at boot, and with socket activation (sshd.socket)
    sshd.service is only active while a connection is open. Either way a
    deny-by-default firewall without the SSH rule locks remote logins out.
    """
    if not ssh.installed:
        return False
    if ssh.running:
        return True
    units = ["sshd.service", "sshd.socket"]
    active = run_unprivileged(["systemctl", "is-active", *units])
    enabled = run_unprivileged(["systemctl", "is-enabled", *units])
    states = set(active.stdout.split()) | set(enabled.stdout.split())
    return bool(states & {"active", "activating", "enabled", "enabled-runtime"})


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
    if _sshd_will_listen(ssh):
        # Every port sshd listens on - Port lines accumulate, and
        # ListenAddress can name its own - not just the first one.
        ports = ssh.ports or ["22"]
        for port in ports:
            on_line(f"Allowing SSH (port {port}) before enabling the firewall, so this doesn't lock you out...")
            allow_result = security.firewall_allow_port(port)
            if not allow_result.ok:
                # Enabling deny-by-default without the SSH rule in place is
                # exactly the remote lockout this ordering exists to prevent -
                # stop here.
                on_line(
                    f"Couldn't allow SSH port {port}: {allow_result.stderr.strip() or 'unknown error'}. "
                    "Not enabling the firewall, so SSH access isn't cut off."
                )
                return allow_result
    else:
        # A desktop with no SSH server needs no hole punched in its firewall.
        # Opening 22 here anyway was a server-shaped default leaking into a
        # single-user machine: an unnecessary listening surface, on the port
        # every scanner tries first.
        on_line(
            "No SSH server is running or enabled - enabling the firewall with no incoming ports opened."
        )

    on_line("Enabling firewall...")
    result = security.firewall_enable()
    on_line("Firewall enabled." if result.ok else f"Failed to enable firewall: {result.stderr.strip()}")
    return result


def _apply_fail2ban(on_line: Callable[[str], None]) -> CommandResult:
    on_line("=== fail2ban ===")
    # fail2ban's value here is the SSH jail. On a desktop without sshd there
    # is nothing it could ban, so don't install a daemon that can only sit
    # idle - the user can still add it deliberately from the Security page.
    if not security.ssh_status().installed:
        on_line(
            "No SSH server is installed - skipping fail2ban, since there's no remote login to protect. "
            "Install OpenSSH first if you want SSH access."
        )
        return CommandResult(0, "skipped: no SSH server", "")
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
            f"'{hardening.APPARMOR_KERNEL_PARAMETER}' added to your kernel parameters and a "
            "reboot, which isn't automated here. Installing/enabling the service now so it's "
            "ready once that's done."
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


def _apply_selinux_repo(on_line: Callable[[str], None]) -> CommandResult:
    on_line("=== SELinux package repository ===")
    if pacman.selinux_repo_enabled():
        on_line("Already enabled - nothing to do.")
        return CommandResult(0, "already enabled", "")
    on_line(
        f"Adding [{pacman.SELINUX_REPO_NAME}] to {pacman.PACMAN_CONF} with SigLevel = Never - "
        "pacman won't verify the packages it installs from it..."
    )
    result = pacman.enable_selinux_repo()
    on_line(
        "Repository added. pacman reads it at the next full upgrade."
        if result.ok
        else f"Failed to add the repository: {result.stderr.strip()}"
    )
    return result


def _apply_selinux(on_line: Callable[[str], None]) -> CommandResult:
    on_line("=== SELinux ===")
    if shutil.which("ausearch") is None:
        on_line("Installing audit (ausearch, for reviewing denials)...")
        result = pacman.install(["audit"])
        if not result.ok:
            on_line(f"Failed to install audit: {result.stderr.strip()}")
            return result

    if shutil.which("sestatus") is None:
        packages = sorted(set(selinux.SELINUX_TOOL_PACKAGES.values()))
        if not pacman.selinux_repo_enabled():
            # A plain `pacman -S policycoreutils checkpolicy` can only fail:
            # the SELinux userspace isn't in Arch's official repositories.
            on_line(
                "SELinux's userspace tools aren't in Arch's official repositories - install them from the "
                f"AUR ({', '.join(packages)}) with your AUR helper, or enable 'SELinux package repository' "
                "in this list to have pacman install them, then run this step again."
            )
            return CommandResult(
                0, "skipped: SELinux's tools need the AUR or the SELinux repository - a manual step", ""
            )
        on_line(
            f"Installing SELinux's tools from the [{pacman.SELINUX_REPO_NAME}] repository "
            f"({', '.join(packages)}). pacman only reads a new repository as part of a full upgrade, "
            "so this upgrades the system as well..."
        )
        result = pacman.upgrade_and_install_streaming(packages, on_line)
        if not result.ok:
            on_line("Failed to install SELinux's tools - see pacman's output above.")
            return result

    status = selinux.get_status()
    if not status.available:
        on_line(
            "SELinux isn't enabled at the kernel level. That needs SELinux-enabled base packages "
            "(base-selinux, from the SELinux repository or the AUR), a policy (Atropa's own can be "
            "fetched and built on the 'SELinux: Build Policy' page), a kernel parameter, and a "
            "reboot - none of which is automated here. The tools are installed and ready for when "
            "you do this manually."
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
    "selinux_repo": _apply_selinux_repo,
    "selinux": _apply_selinux,
}


def _service_line(status: hardening.ServiceHardeningStatus) -> str:
    return "Active" if status.active else ("Installed, inactive" if status.installed else "Not installed")


def _firewall_line() -> str:
    fw = security.firewall_status()
    return "Active" if fw.active else ("Installed, inactive" if fw.backend != "none" else "Not installed")


def _sysctl_line() -> str:
    gaps, available = hardening.sysctl_hardening_gaps()
    if not available:
        return "Couldn't read sysctl values"
    if not gaps:
        return "All recommended settings in effect"
    return f"{len(gaps)} of {available} recommended settings not in effect"


def _faillock_line() -> str:
    if not hardening.faillock_wired_into_pam():
        return "Not wired into PAM (manual step required)"
    fl = hardening.faillock_status()
    return f"Wired in - deny={fl.get('deny', '?')}, unlock_time={fl.get('unlock_time', '?')}"


def _selinux_line() -> str:
    sl = selinux.get_status()
    return sl.mode.capitalize() if sl.available else "Not enabled at kernel level"


def _fail2ban_line() -> str:
    if not security.ssh_status().installed:
        return "Skipped - no SSH server installed"
    return _service_line(hardening.fail2ban_status())


_STATUS_LINES: dict[str, Callable[[], str]] = {
    "firewall": _firewall_line,
    "fail2ban": _fail2ban_line,
    "sysctl": _sysctl_line,
    "faillock": _faillock_line,
    "apparmor": lambda: _service_line(hardening.apparmor_status()),
    "auditd": lambda: _service_line(hardening.auditd_status()),
    "usbguard": lambda: _service_line(hardening.usbguard_status()),
    "selinux_repo": lambda: "Enabled (unsigned)" if pacman.selinux_repo_enabled() else "Not enabled",
    "selinux": _selinux_line,
}


def desktop_baseline() -> DesktopBaseline:
    """
    The laptop/desktop-shaped counterpart to the server baseline above.

    It is deliberately read-only: it states what is already true (firewall,
    encryption, Secure Boot) instead of adding another set of apply steps.
    The one thing it changes elsewhere is that the checklist stops opening
    SSH and stops offering fail2ban when no SSH server is installed.
    """
    try:
        ssh_installed = security.ssh_status().installed
    except Exception:  # noqa: BLE001 - can't tell means "don't claim desktop-only"
        ssh_installed = True

    checks: list[BaselineCheck] = []

    try:
        firewall = security.firewall_status()
        if firewall.backend == "none":
            checks.append(BaselineCheck(
                "Firewall", "fail",
                "No firewall is installed - every listening socket is reachable from the network.",
            ))
        elif firewall.active:
            checks.append(BaselineCheck(
                "Firewall", "pass", f"{firewall.backend} is active, blocking unsolicited incoming connections.",
            ))
        else:
            checks.append(BaselineCheck(
                "Firewall", "warn", f"{firewall.backend} is installed but inactive.",
            ))
    except Exception as exc:  # noqa: BLE001
        checks.append(BaselineCheck("Firewall", "info", f"Couldn't check: {exc}"))

    try:
        encryption = boot_security.encryption_status()
        if encryption.encrypted is True:
            checks.append(BaselineCheck("Disk encryption", "pass", encryption.detail))
        elif encryption.encrypted is False:
            checks.append(BaselineCheck("Disk encryption", "fail", encryption.detail))
        else:
            checks.append(BaselineCheck("Disk encryption", "info", encryption.detail))
    except Exception as exc:  # noqa: BLE001
        checks.append(BaselineCheck("Disk encryption", "info", f"Couldn't check: {exc}"))

    try:
        secure_boot = boot_security.secure_boot_status()
        if secure_boot.supported is False:
            checks.append(BaselineCheck("Secure Boot", "info", secure_boot.detail))
        elif secure_boot.enabled is True:
            checks.append(BaselineCheck("Secure Boot", "pass", secure_boot.detail))
        elif secure_boot.enabled is False:
            checks.append(BaselineCheck("Secure Boot", "warn", secure_boot.detail))
        else:
            checks.append(BaselineCheck("Secure Boot", "info", secure_boot.detail))
    except Exception as exc:  # noqa: BLE001
        checks.append(BaselineCheck("Secure Boot", "info", f"Couldn't check: {exc}"))

    if ssh_installed:
        checks.append(BaselineCheck(
            "SSH hardening", "warn",
            "OpenSSH is installed, so this machine isn't purely a desktop: harden it on the Security page "
            "(root login, password auth, port) instead of relying on the desktop baseline.",
        ))
    else:
        checks.append(BaselineCheck(
            "SSH hardening", "pass",
            "OpenSSH isn't installed, so there is no remote login surface to harden.",
        ))

    return DesktopBaseline(applies=not ssh_installed, sshd_installed=ssh_installed, checks=checks)


def status_summary() -> dict[str, str]:
    """
    One human-readable status line per catalog key, for display before
    applying. Each line is worked out on its own: a check that fails says
    so in its own line instead of taking every other line down with it -
    one missing tool used to leave the whole checklist without a status.
    """
    summary: dict[str, str] = {}
    for key, line in _STATUS_LINES.items():
        try:
            summary[key] = line()
        except Exception as exc:  # noqa: BLE001 - shown in that item's own line
            summary[key] = f"Couldn't check: {exc}"
    return summary


_LOCKED_KEYS = frozenset(item.key for item in CATALOG if item.locked)


def _locked_refusal(key: str, unlocked: Collection[str]) -> str | None:
    """
    Why a locked item won't run, or None. Being in the list of keys isn't
    enough for one: the caller has to say it was unlocked, so a profile
    import or any other batch can't switch it on in passing.
    """
    if key in _LOCKED_KEYS and key not in unlocked:
        return "it is locked - unlock it with the administrator password in Security Quick Setup first"
    return None


def apply_single(key: str, on_line: Callable[[str], None], unlocked: Collection[str] = ()) -> CommandResult:
    """Applies exactly one catalog item by key - used by the step-by-step
    wizard, where each step is confirmed and run individually rather than
    as part of a batch. Raises KeyError for an unknown key rather than
    silently doing nothing, and RuntimeError for a locked item whose key
    isn't in `unlocked`."""
    applier = _APPLIERS[key]
    refusal = _locked_refusal(key, unlocked)
    if refusal:
        raise RuntimeError(f"Not applying '{key}': {refusal}")
    return applier(on_line)


def apply_items(
    keys: list[str], on_line: Callable[[str], None], unlocked: Collection[str] = ()
) -> dict[str, CommandResult]:
    """
    Applies each selected catalog item in a fixed, safety-conscious order
    (see _ORDER) regardless of the order `keys` was given in, streaming a
    human-readable progress line to on_line before/after each step.
    Returns a per-key CommandResult so the caller can report exactly what
    succeeded, failed, or was intentionally skipped. A locked item is
    refused unless its key is also in `unlocked`.
    """
    results: dict[str, CommandResult] = {}
    ordered_keys = [key for key in _ORDER if key in keys]
    for key in ordered_keys:
        try:
            refusal = _locked_refusal(key, unlocked)
            if refusal:
                raise RuntimeError(f"Not applying '{key}': {refusal}")
            results[key] = _APPLIERS[key](on_line)
        except Exception as exc:  # noqa: BLE001 - one step's error (e.g. a refused install) mustn't skip the rest
            on_line(f"Failed: {exc}")
            results[key] = CommandResult(1, "", str(exc))
        on_line("")
    return results
