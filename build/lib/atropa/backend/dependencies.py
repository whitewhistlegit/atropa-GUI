"""
atropa.backend.dependencies
--------------------------------
A single catalog of every external tool Atropa's modules shell out to,
which pacman package provides it, and which module needs it.

Every other backend module already raises a clear "X isn't installed"
error at the point of use - this module exists so there's ALSO one place
that shows the whole picture up front, instead of only discovering gaps
one at a time as you click into each module. Package names here are kept
consistent with the "Install it with: pacman -S ..." hints already
embedded in error messages across apparmor.py/hardening.py/selinux.py,
rather than introducing a second set of names for the same tools.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass


@dataclass
class Dependency:
    name: str  # the binary looked up with shutil.which, e.g. "pkexec"
    module: str  # which Atropa module/page needs it
    description: str  # why it's needed
    package: str | None = None  # pacman package that provides it; None if not installable via `pacman -S` (e.g. AUR-only helpers)
    required: bool = False  # True = Atropa can't do anything useful without it
    note: str = ""  # extra context shown instead of/alongside an Install button


@dataclass
class DependencyStatus:
    dependency: Dependency
    installed: bool


# One entry per external tool, grouped roughly in sidebar module order.
CATALOG: list[Dependency] = [
    Dependency("pkexec", "Core", "Runs every privileged action - Atropa has no other way to gain root", "polkit", required=True),
    Dependency("sudo", "Core", "Fallback privilege escalation if pkexec isn't available", "sudo"),
    Dependency("pacman", "Package Management", "The package manager itself", "pacman", required=True),
    Dependency(
        "paru", "Package Management", "AUR helper for searching/installing AUR packages", None,
        note="AUR-only - not installable via pacman -S; build it from the AUR or install another AUR helper first",
    ),
    Dependency(
        "yay", "Package Management", "Alternative AUR helper for searching/installing AUR packages", None,
        note="AUR-only - not installable via pacman -S; build it from the AUR or install another AUR helper first",
    ),
    Dependency("systemctl", "Services", "Start/stop/enable/disable systemd services", "systemd", required=True),
    Dependency("nmcli", "Network", "Manage connections, Wi-Fi, static IP via NetworkManager", "networkmanager"),
    Dependency("networkctl", "Network", "Read-only status for systemd-networkd, if used instead of NetworkManager", "systemd"),
    Dependency("grub-mkconfig", "Bootloader", "Regenerate GRUB configuration", "grub"),
    Dependency("bootctl", "Bootloader", "Manage systemd-boot entries and timeout", "systemd"),
    Dependency("ufw", "Security", "Firewall management (alternative to firewalld)", "ufw"),
    Dependency("firewall-cmd", "Security", "Firewall management (alternative to ufw)", "firewalld"),
    Dependency("sshd", "Security", "SSH hardening toggles (root login, password auth, port)", "openssh"),
    Dependency("visudo", "Security", "Sudoers syntax checking", "sudo"),
    Dependency("fail2ban-client", "Hardening", "Bans IPs after repeated failed login attempts", "fail2ban"),
    Dependency("aa-status", "Hardening / AppArmor", "AppArmor profile status and enforcement control", "apparmor"),
    Dependency("apparmor_parser", "AppArmor", "Reloads a profile after a rule change", "apparmor"),
    Dependency("usbguard", "Hardening", "USB device allow-listing (BadUSB protection)", "usbguard"),
    Dependency("auditctl", "Hardening", "Kernel audit logging status", "audit"),
    Dependency("arch-audit", "Hardening", "Scans installed packages against the Arch Security Team's CVE feed", "arch-audit"),
    Dependency("sestatus", "SELinux", "SELinux status reporting", "policycoreutils", note="Arch has no official SELinux policy - most users get this via an AUR policy package (e.g. refpolicy-arch)"),
    Dependency("getsebool", "SELinux", "List SELinux policy booleans", "policycoreutils"),
    Dependency("setsebool", "SELinux", "Persist SELinux boolean changes", "policycoreutils"),
    Dependency("restorecon", "SELinux", "Fix SELinux file contexts", "policycoreutils"),
    Dependency("semodule", "SELinux", "Load/remove/list SELinux policy modules", "policycoreutils"),
    Dependency("checkmodule", "SELinux", "Compile .te policy source into a loadable module", "policycoreutils"),
    Dependency("semodule_package", "SELinux", "Package a compiled module into a .pp file", "policycoreutils"),
    Dependency("audit2why", "SELinux", "Explain why an AVC denial was blocked", "audit"),
    Dependency("audit2allow", "SELinux", "Draft an allow rule from AVC denials", "audit"),
    Dependency("ausearch", "SELinux", "Search /var/log/audit/audit.log for denials", "audit"),
    Dependency(
        "aide", "File Integrity", "Filesystem integrity baseline/checking (CIS 1.3)", None,
        note="AUR-only since it was dropped from Arch's official repos - build it from the AUR first. The plain "
        "'aide' AUR package has had real build failures in the wild (e.g. against newer nettle); if you're "
        "already running SELinux, 'aide-selinux' is a separate AUR package that's been reported to build "
        "cleanly when 'aide' doesn't - either provides the same `aide` binary Atropa looks for.",
    ),
]


def check_all() -> list[DependencyStatus]:
    """Checks every cataloged tool with shutil.which and returns its install status."""
    return [DependencyStatus(dependency=dep, installed=shutil.which(dep.name) is not None) for dep in CATALOG]


def missing_required() -> list[Dependency]:
    """Required tools that are missing - Atropa can't do much useful work without these."""
    return [dep for dep in CATALOG if dep.required and shutil.which(dep.name) is None]


def summary_counts() -> dict:
    """{'installed': n, 'missing': n, 'total': n} across the whole catalog."""
    statuses = check_all()
    installed = sum(1 for s in statuses if s.installed)
    return {"installed": installed, "missing": len(statuses) - installed, "total": len(statuses)}
