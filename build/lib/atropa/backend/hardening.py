"""
atropa.backend.hardening
-----------------------------
Deeper system hardening beyond the basics in security.py: kernel sysctl
tuning, intrusion prevention (fail2ban), mandatory access control
(AppArmor), device whitelisting (USBGuard), audit logging (auditd),
known-CVE scanning (arch-audit), and login lockout policy (pam_faillock).

Two design choices worth flagging:

1. USBGuard is dangerous to enable blind - if you enable it without a
   policy, EVERY USB device (including your keyboard) gets blocked on
   the next replug. `usbguard_generate_and_enable()` always generates a
   policy from currently-connected devices first.

2. We do NOT auto-edit the PAM stack (/etc/pam.d/system-login) to wire in
   pam_faillock if it isn't already there - a bad PAM edit can lock out
   every account, including root, with no easy recovery outside a live
   USB. We only touch /etc/security/faillock.conf, which is inert unless
   pam_faillock is already referenced, and we tell the user clearly which
   case they're in.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import security as security_mod
from . import selinux as selinux_mod
from .privilege import CommandResult, backup_file, run_privileged, run_unprivileged

SYSCTL_HARDENING_FILE = "/etc/sysctl.d/99-atropa-hardening.conf"
FAILLOCK_CONF = Path("/etc/security/faillock.conf")
PAM_SYSTEM_LOGIN = Path("/etc/pam.d/system-login")

# (key, recommended value, human-readable description)
SYSCTL_RECOMMENDATIONS: list[tuple[str, str, str]] = [
    ("kernel.kptr_restrict", "2", "Hide kernel pointers from unprivileged users"),
    ("kernel.dmesg_restrict", "1", "Restrict dmesg to root"),
    ("kernel.yama.ptrace_scope", "1", "Restrict ptrace to parent processes only"),
    ("kernel.randomize_va_space", "2", "Full address space layout randomization"),
    ("kernel.sysrq", "4", "Allow only the secure SysRq attention key combo"),
    ("fs.protected_hardlinks", "1", "Prevent hardlink attacks in world-writable dirs"),
    ("fs.protected_symlinks", "1", "Prevent symlink attacks in world-writable dirs"),
    ("fs.protected_fifos", "2", "Restrict FIFO creation in world-writable sticky dirs"),
    ("fs.suid_dumpable", "0", "Never core-dump setuid programs"),
    ("net.ipv4.conf.all.accept_source_route", "0", "Reject source-routed IPv4 packets"),
    ("net.ipv4.conf.default.accept_source_route", "0", "Reject source-routed IPv4 packets (default)"),
    ("net.ipv4.conf.all.accept_redirects", "0", "Ignore ICMP redirects"),
    ("net.ipv4.conf.default.accept_redirects", "0", "Ignore ICMP redirects (default)"),
    ("net.ipv4.conf.all.secure_redirects", "0", "Ignore ICMP redirects, even from known gateways"),
    ("net.ipv4.conf.all.rp_filter", "1", "Enable strict reverse-path filtering (anti-spoofing)"),
    ("net.ipv4.conf.default.rp_filter", "1", "Enable strict reverse-path filtering (default)"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "Ignore broadcast pings (anti smurf-attack)"),
    ("net.ipv4.tcp_syncookies", "1", "SYN flood protection"),
    ("net.ipv6.conf.all.accept_source_route", "0", "Reject source-routed IPv6 packets"),
    ("net.ipv6.conf.all.accept_redirects", "0", "Ignore IPv6 ICMP redirects"),
]


@dataclass
class SysctlSetting:
    key: str
    recommended: str
    description: str
    current: str | None = None

    @property
    def is_hardened(self) -> bool:
        return self.current == self.recommended


@dataclass
class AuditCheck:
    name: str
    status: str  # "pass" | "warn" | "fail" | "info"
    detail: str


@dataclass
class ServiceHardeningStatus:
    installed: bool
    active: bool
    enabled: bool
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------- sysctl --

def _current_sysctl(key: str) -> str | None:
    result = run_unprivileged(["sysctl", "-n", key])
    value = result.stdout.strip()
    return value if result.ok and value else None


def get_sysctl_status() -> list[SysctlSetting]:
    settings = []
    for key, recommended, desc in SYSCTL_RECOMMENDATIONS:
        settings.append(
            SysctlSetting(key=key, recommended=recommended, description=desc, current=_current_sysctl(key))
        )
    return settings


def apply_sysctl_hardening(keys: list[str]) -> CommandResult:
    """Write the selected recommended settings to a dedicated sysctl.d file and reload."""
    chosen = {k: v for (k, v, _d) in SYSCTL_RECOMMENDATIONS if k in keys}
    if not chosen:
        raise ValueError("No settings selected")

    lines = ["# Managed by Atropa - kernel hardening. Edit freely; this file is only", "# rewritten when you re-apply from the Hardening page.", ""]
    lines += [f"{k} = {v}" for k, v in chosen.items()]
    content = "\n".join(lines) + "\n"

    backup_file(SYSCTL_HARDENING_FILE)
    result = run_privileged(["tee", SYSCTL_HARDENING_FILE], input_text=content)
    if result.ok:
        result = run_privileged(["sysctl", "--system"])
    return result


def sysctl_hardening_file_exists() -> bool:
    return Path(SYSCTL_HARDENING_FILE).exists()


# -------------------------------------------------------------- fail2ban --

def fail2ban_status() -> ServiceHardeningStatus:
    installed = shutil.which("fail2ban-client") is not None
    if not installed:
        return ServiceHardeningStatus(installed=False, active=False, enabled=False)

    active = run_unprivileged(["systemctl", "is-active", "fail2ban"]).stdout.strip() == "active"
    enabled = run_unprivileged(["systemctl", "is-enabled", "fail2ban"]).stdout.strip() == "enabled"

    jails: list[str] = []
    if active:
        status = run_unprivileged(["fail2ban-client", "status"])
        m = re.search(r"Jail list:\s*(.*)", status.stdout)
        if m:
            jails = [j.strip() for j in m.group(1).split(",") if j.strip()]

    return ServiceHardeningStatus(installed=True, active=active, enabled=enabled, extra={"jails": jails})


def fail2ban_enable() -> CommandResult:
    return run_privileged(["systemctl", "enable", "--now", "fail2ban"])


def fail2ban_disable() -> CommandResult:
    return run_privileged(["systemctl", "disable", "--now", "fail2ban"])


def fail2ban_protect_ssh() -> CommandResult:
    """Ensure the sshd jail is enabled, then restart fail2ban to pick it up."""
    content = "[sshd]\nenabled = true\nbackend = systemd\n"
    backup_file("/etc/fail2ban/jail.d/sshd.local")
    result = run_privileged(["tee", "/etc/fail2ban/jail.d/sshd.local"], input_text=content)
    if result.ok:
        result = run_privileged(["systemctl", "restart", "fail2ban"])
    return result


# -------------------------------------------------------------- AppArmor --

def apparmor_status() -> ServiceHardeningStatus:
    installed = shutil.which("aa-status") is not None or Path("/sys/kernel/security/apparmor").exists()
    active = run_unprivileged(["systemctl", "is-active", "apparmor"]).stdout.strip() == "active"

    kernel_enabled = False
    cmdline_path = Path("/proc/cmdline")
    if cmdline_path.exists():
        kernel_enabled = "apparmor=1" in cmdline_path.read_text()

    return ServiceHardeningStatus(
        installed=installed,
        active=active,
        enabled=active,
        extra={"kernel_enabled": kernel_enabled},
    )


def apparmor_enable_service() -> CommandResult:
    """
    Enables the apparmor.service. Note: AppArmor also needs `apparmor=1
    security=apparmor` on the kernel command line to actually enforce
    anything - we don't touch bootloader config automatically since a
    bad kernel parameter can affect bootability. The UI surfaces this.
    """
    return run_privileged(["systemctl", "enable", "--now", "apparmor"])


# -------------------------------------------------------------- USBGuard --

def usbguard_status() -> ServiceHardeningStatus:
    installed = shutil.which("usbguard") is not None
    active = run_unprivileged(["systemctl", "is-active", "usbguard"]).stdout.strip() == "active"
    enabled = run_unprivileged(["systemctl", "is-enabled", "usbguard"]).stdout.strip() == "enabled"
    has_policy = Path("/etc/usbguard/rules.conf").exists() and Path("/etc/usbguard/rules.conf").stat().st_size > 0
    return ServiceHardeningStatus(installed=installed, active=active, enabled=enabled, extra={"has_policy": has_policy})


def usbguard_generate_and_enable() -> CommandResult:
    """
    Generates an allow-list policy from devices plugged in RIGHT NOW, then
    enables enforcement. Anything plugged in later will need approval via
    `usbguard allow-device` (or a GUI applet) - that's the point of the tool.
    """
    generate = run_privileged(["bash", "-c", "usbguard generate-policy > /etc/usbguard/rules.conf"])
    if not generate.ok:
        return generate
    return run_privileged(["systemctl", "enable", "--now", "usbguard"])


def usbguard_disable() -> CommandResult:
    return run_privileged(["systemctl", "disable", "--now", "usbguard"])


# --------------------------------------------------------------- auditd --

def auditd_status() -> ServiceHardeningStatus:
    installed = shutil.which("auditctl") is not None
    active = run_unprivileged(["systemctl", "is-active", "auditd"]).stdout.strip() == "active"
    enabled = run_unprivileged(["systemctl", "is-enabled", "auditd"]).stdout.strip() == "enabled"
    return ServiceHardeningStatus(installed=installed, active=active, enabled=enabled)


def auditd_enable() -> CommandResult:
    return run_privileged(["systemctl", "enable", "--now", "auditd"])


def auditd_disable() -> CommandResult:
    return run_privileged(["systemctl", "disable", "--now", "auditd"])


# ------------------------------------------------------- vulnerability scan --

def vulnerability_scan() -> list[str]:
    """
    Uses `arch-audit` (queries the Arch Security Team's CVE feed against
    your installed packages) if available; raises with an install hint
    otherwise rather than silently returning an empty/misleading result.
    """
    if not shutil.which("arch-audit"):
        raise RuntimeError("arch-audit isn't installed. Install it with: pacman -S arch-audit")

    result = run_unprivileged(["arch-audit"])
    lines = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
    return lines


# -------------------------------------------------------------- faillock --

def faillock_wired_into_pam() -> bool:
    """True if /etc/pam.d/system-login already references pam_faillock."""
    if not PAM_SYSTEM_LOGIN.exists():
        return False
    return "pam_faillock.so" in run_unprivileged(["cat", str(PAM_SYSTEM_LOGIN)]).stdout


def faillock_status() -> dict:
    wired = faillock_wired_into_pam()
    deny, unlock_time = "unknown", "unknown"
    if FAILLOCK_CONF.exists():
        text = run_unprivileged(["cat", str(FAILLOCK_CONF)]).stdout
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("deny"):
                deny = line.split("=")[-1].strip()
            elif line.startswith("unlock_time"):
                unlock_time = line.split("=")[-1].strip()
    return {"wired": wired, "deny": deny, "unlock_time": unlock_time}


def _set_faillock_option(key: str, value: str) -> CommandResult:
    pattern = rf"^#?\s*{re.escape(key)}\s*=.*$"
    replacement = f"{key} = {value}"
    check = run_unprivileged(["grep", "-E", pattern, str(FAILLOCK_CONF)])
    if check.stdout.strip():
        result = run_privileged(["sed", "-i", "-E", f"s/{pattern}/{replacement}/", str(FAILLOCK_CONF)])
    else:
        result = run_privileged(["bash", "-c", f"echo '{replacement}' >> {FAILLOCK_CONF}"])
    return result


def set_faillock_policy(deny: int, unlock_time: int) -> CommandResult:
    """
    Only meaningful if pam_faillock is already referenced in the PAM stack
    (check faillock_wired_into_pam() first and warn the user otherwise).
    """
    backup_file(str(FAILLOCK_CONF))
    result = _set_faillock_option("deny", str(deny))
    if result.ok:
        result = _set_faillock_option("unlock_time", str(unlock_time))
    return result


# ------------------------------------------------------- password complexity --
#
# CIS DIL 5.3.1: password complexity via pam_pwquality (Arch's modern
# default; pam_cracklib is the older equivalent other distros still use).
# Same shape as the faillock functions above - a settings file
# (pwquality.conf) pam_pwquality reads from, rather than arguments baked
# into the PAM stack file itself.

PWQUALITY_CONF = Path("/etc/security/pwquality.conf")


def pwquality_wired_into_pam() -> bool:
    """True if /etc/pam.d/system-login already references pam_pwquality."""
    if not PAM_SYSTEM_LOGIN.exists():
        return False
    return "pam_pwquality.so" in run_unprivileged(["cat", str(PAM_SYSTEM_LOGIN)]).stdout


def pwquality_status() -> dict:
    wired = pwquality_wired_into_pam()
    settings = {"minlen": "unknown", "dcredit": "unknown", "ucredit": "unknown", "lcredit": "unknown", "ocredit": "unknown", "retry": "unknown"}
    if PWQUALITY_CONF.exists():
        text = run_unprivileged(["cat", str(PWQUALITY_CONF)]).stdout
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            for key in settings:
                if line.startswith(key):
                    settings[key] = line.split("=")[-1].strip()
    return {"wired": wired, **settings}


def _set_pwquality_option(key: str, value: str) -> CommandResult:
    pattern = rf"^#?\s*{re.escape(key)}\s*=.*$"
    replacement = f"{key} = {value}"
    check = run_unprivileged(["grep", "-E", pattern, str(PWQUALITY_CONF)])
    if check.stdout.strip():
        return run_privileged(["sed", "-i", "-E", f"s/{pattern}/{replacement}/", str(PWQUALITY_CONF)])
    return run_privileged(["bash", "-c", f"echo '{replacement}' >> {PWQUALITY_CONF}"])


def set_password_complexity_policy(
    minlen: int = 14, dcredit: int = -1, ucredit: int = -1, lcredit: int = -1, ocredit: int = -1, retry: int = 3
) -> CommandResult:
    """
    CIS 5.3.1: minlen >= 14, and at least one digit/uppercase/lowercase/
    special character required. The *credit settings are negative in
    pwquality's own convention - "require at least this many"; a positive
    value there would mean the opposite (a bonus allowance), so this
    isn't validated further here beyond requiring a sane minlen - the
    caller (Compliance Report / CIS page) is expected to only ever offer
    the CIS-recommended values, not an open text field. Only meaningful
    if pam_pwquality is already referenced in the PAM stack (check
    pwquality_wired_into_pam() first and warn the user otherwise, same
    as faillock).
    """
    if minlen < 1:
        raise ValueError("minlen must be at least 1")
    backup_file(str(PWQUALITY_CONF))
    result = CommandResult(0, "", "")
    for key, value in (("minlen", minlen), ("dcredit", dcredit), ("ucredit", ucredit), ("lcredit", lcredit), ("ocredit", ocredit), ("retry", retry)):
        result = _set_pwquality_option(key, str(value))
        if not result.ok:
            return result
    return result


# --------------------------------------------------------- audit rollup --

def run_audit() -> list[AuditCheck]:
    """A rollup security posture check across firewall, SSH, and hardening services."""
    checks: list[AuditCheck] = []

    try:
        fw = security_mod.firewall_status()
        if fw.backend == "none":
            checks.append(AuditCheck("Firewall", "warn", "No firewall installed (ufw or firewalld)"))
        elif fw.active:
            checks.append(AuditCheck("Firewall", "pass", f"{fw.backend} is active"))
        else:
            checks.append(AuditCheck("Firewall", "fail", f"{fw.backend} installed but not active"))
    except Exception as exc:  # noqa: BLE001
        checks.append(AuditCheck("Firewall", "info", str(exc)))

    try:
        ssh = security_mod.ssh_status()
        if not ssh.installed:
            checks.append(AuditCheck("SSH root login", "info", "OpenSSH not installed"))
        else:
            if ssh.root_login.lower() in ("no", "prohibit-password"):
                checks.append(AuditCheck("SSH root login", "pass", f"PermitRootLogin {ssh.root_login}"))
            else:
                checks.append(AuditCheck("SSH root login", "fail", f"PermitRootLogin {ssh.root_login}"))
            if ssh.password_auth.lower() == "no":
                checks.append(AuditCheck("SSH password auth", "pass", "Key-only authentication"))
            else:
                checks.append(AuditCheck("SSH password auth", "warn", "Password authentication is allowed"))
    except Exception as exc:  # noqa: BLE001
        checks.append(AuditCheck("SSH", "info", str(exc)))

    f2b = fail2ban_status()
    if not f2b.installed:
        checks.append(AuditCheck("fail2ban", "warn", "Not installed (pacman -S fail2ban)"))
    elif f2b.active:
        checks.append(AuditCheck("fail2ban", "pass", f"Active, jails: {', '.join(f2b.extra.get('jails', [])) or 'none configured'}"))
    else:
        checks.append(AuditCheck("fail2ban", "fail", "Installed but not running"))

    aa = apparmor_status()
    if not aa.installed:
        checks.append(AuditCheck("AppArmor", "info", "Not installed (optional if you use SELinux instead)"))
    elif aa.extra.get("kernel_enabled") and aa.active:
        checks.append(AuditCheck("AppArmor", "pass", "Enforcing at kernel level"))
    else:
        checks.append(AuditCheck("AppArmor", "warn", "Installed but not fully enabled (service and/or kernel param)"))

    try:
        se = selinux_mod.get_status()
        # Real `sestatus` output is lowercase ("enforcing"/"permissive") -
        # a case-sensitive Title-case comparison here meant this branch
        # never matched on any real system, silently falling through to
        # the generic "warn: Mode: enforcing" case even for a fully
        # enforcing SELinux setup. Confirmed as a real bug on bare metal,
        # not a hypothetical - the same casing mismatch was found (and
        # fixed) in the SELinux page's mode toggle in this same session;
        # this one matters more, since it directly affects a scored,
        # exportable Compliance Report rather than just a UI toggle's
        # visual state.
        mode_lower = (se.mode or "").lower()
        if not se.available:
            checks.append(AuditCheck("SELinux", "info", "Not available (optional if you use AppArmor instead)"))
        elif mode_lower == "enforcing":
            checks.append(AuditCheck("SELinux", "pass", f"Enforcing, policy: {se.policy or 'unknown'}"))
        elif mode_lower == "permissive":
            checks.append(AuditCheck("SELinux", "warn", "Permissive mode - violations are logged but not blocked"))
        else:
            checks.append(AuditCheck("SELinux", "warn", f"Mode: {se.mode}"))
    except Exception as exc:  # noqa: BLE001
        checks.append(AuditCheck("SELinux", "info", str(exc)))

    ug = usbguard_status()
    if not ug.installed:
        checks.append(AuditCheck("USBGuard", "info", "Not installed (optional; pacman -S usbguard)"))
    elif ug.active and ug.extra.get("has_policy"):
        checks.append(AuditCheck("USBGuard", "pass", "Active with a device policy"))
    else:
        checks.append(AuditCheck("USBGuard", "warn", "Not fully active"))

    ad = auditd_status()
    if not ad.installed:
        checks.append(AuditCheck("auditd", "info", "Not installed (optional; pacman -S audit)"))
    elif ad.active:
        checks.append(AuditCheck("auditd", "pass", "Logging kernel audit events"))
    else:
        checks.append(AuditCheck("auditd", "warn", "Installed but not running"))

    if sysctl_hardening_file_exists():
        checks.append(AuditCheck("Kernel sysctl hardening", "pass", "Atropa hardening profile applied"))
    else:
        checks.append(AuditCheck("Kernel sysctl hardening", "warn", "Recommended sysctl settings not applied"))

    try:
        vulns = vulnerability_scan()
        if not vulns:
            checks.append(AuditCheck("Known CVEs (arch-audit)", "pass", "No known vulnerabilities in installed packages"))
        else:
            checks.append(AuditCheck("Known CVEs (arch-audit)", "fail", f"{len(vulns)} advisory line(s) - see Hardening page"))
    except Exception as exc:  # noqa: BLE001
        checks.append(AuditCheck("Known CVEs (arch-audit)", "info", str(exc)))

    return checks
