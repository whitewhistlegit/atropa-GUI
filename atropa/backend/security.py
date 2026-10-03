"""
atropa.backend.security
----------------------------
Firewall (ufw or firewalld, whichever is installed), basic SSH hardening
toggles, and a sudoers sanity check. Deliberately conservative: it edits
well-known, single-purpose settings rather than freeform config files.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .privilege import CommandResult, backup_file, restore_file, run_privileged, run_unprivileged

SSHD_CONFIG = Path("/etc/ssh/sshd_config")


@dataclass
class FirewallStatus:
    backend: str  # "ufw", "firewalld", "none"
    active: bool
    rules: list[str] = field(default_factory=list)


@dataclass
class SshStatus:
    installed: bool
    running: bool
    port: str = "22"
    root_login: str = "unknown"
    password_auth: str = "unknown"
    log_level: str = "unknown"
    x11_forwarding: str = "unknown"
    max_auth_tries: str = "unknown"
    ignore_rhosts: str = "unknown"
    hostbased_authentication: str = "unknown"
    permit_empty_passwords: str = "unknown"
    permit_user_environment: str = "unknown"


def firewall_backend() -> str:
    if shutil.which("ufw"):
        return "ufw"
    if shutil.which("firewall-cmd"):
        return "firewalld"
    return "none"


def firewall_status() -> FirewallStatus:
    """
    Both `ufw status` and `firewall-cmd --list-all` genuinely require root
    on a normal install - without it they don't error loudly, they just
    return limited/empty output, which used to read as "inactive, no
    rules" even when the firewall was actually on. Confirmed on real
    hardware: previously used run_unprivileged() here, which silently
    showed the toggle as off and the rules list as empty regardless of
    the real state. `systemctl is-active firewalld` is the one read here
    that genuinely doesn't need root, so it stays unprivileged.
    """
    backend = firewall_backend()
    if backend == "ufw":
        result = run_privileged(["ufw", "status", "verbose"])
        active = "Status: active" in result.stdout
        rules = [l for l in result.stdout.splitlines() if l.strip() and not l.startswith("Status")]
        return FirewallStatus(backend="ufw", active=active, rules=rules)
    if backend == "firewalld":
        active_result = run_unprivileged(["systemctl", "is-active", "firewalld"])
        active = active_result.stdout.strip() == "active"
        rules_result = run_privileged(["firewall-cmd", "--list-all"])
        rules = rules_result.stdout.strip().splitlines()
        return FirewallStatus(backend="firewalld", active=active, rules=rules)
    return FirewallStatus(backend="none", active=False)


def firewall_enable() -> CommandResult:
    backend = firewall_backend()
    if backend == "ufw":
        return run_privileged(["ufw", "--force", "enable"])
    if backend == "firewalld":
        return run_privileged(["systemctl", "enable", "--now", "firewalld"])
    raise RuntimeError("No firewall backend installed (install 'ufw' or 'firewalld')")


def firewall_disable() -> CommandResult:
    backend = firewall_backend()
    if backend == "ufw":
        return run_privileged(["ufw", "disable"])
    if backend == "firewalld":
        return run_privileged(["systemctl", "disable", "--now", "firewalld"])
    raise RuntimeError("No firewall backend installed")


def firewall_allow_port(port: str, protocol: str = "tcp") -> CommandResult:
    backend = firewall_backend()
    if backend == "ufw":
        return run_privileged(["ufw", "allow", f"{port}/{protocol}"])
    if backend == "firewalld":
        result = run_privileged(["firewall-cmd", "--permanent", "--add-port", f"{port}/{protocol}"])
        if result.ok:
            run_privileged(["firewall-cmd", "--reload"])
        return result
    raise RuntimeError("No firewall backend installed")


def firewall_deny_port(port: str, protocol: str = "tcp") -> CommandResult:
    backend = firewall_backend()
    if backend == "ufw":
        return run_privileged(["ufw", "deny", f"{port}/{protocol}"])
    if backend == "firewalld":
        result = run_privileged(["firewall-cmd", "--permanent", "--remove-port", f"{port}/{protocol}"])
        if result.ok:
            run_privileged(["firewall-cmd", "--reload"])
        return result
    raise RuntimeError("No firewall backend installed")


def ssh_status() -> SshStatus:
    installed = shutil.which("sshd") is not None
    running_result = run_unprivileged(["systemctl", "is-active", "sshd"])
    running = running_result.stdout.strip() == "active"

    fields = {
        "port": "22", "root_login": "unknown", "password_auth": "unknown", "log_level": "unknown",
        "x11_forwarding": "unknown", "max_auth_tries": "unknown", "ignore_rhosts": "unknown",
        "hostbased_authentication": "unknown", "permit_empty_passwords": "unknown", "permit_user_environment": "unknown",
    }
    if SSHD_CONFIG.exists():
        text = run_unprivileged(["cat", str(SSHD_CONFIG)]).stdout
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            lower = line.lower()
            if lower.startswith("port "):
                fields["port"] = line.split(maxsplit=1)[1]
            elif lower.startswith("permitrootlogin"):
                fields["root_login"] = line.split(maxsplit=1)[1]
            elif lower.startswith("passwordauthentication"):
                fields["password_auth"] = line.split(maxsplit=1)[1]
            elif lower.startswith("loglevel"):
                fields["log_level"] = line.split(maxsplit=1)[1]
            elif lower.startswith("x11forwarding"):
                fields["x11_forwarding"] = line.split(maxsplit=1)[1]
            elif lower.startswith("maxauthtries"):
                fields["max_auth_tries"] = line.split(maxsplit=1)[1]
            elif lower.startswith("ignorerhosts"):
                fields["ignore_rhosts"] = line.split(maxsplit=1)[1]
            elif lower.startswith("hostbasedauthentication"):
                fields["hostbased_authentication"] = line.split(maxsplit=1)[1]
            elif lower.startswith("permitemptypasswords"):
                fields["permit_empty_passwords"] = line.split(maxsplit=1)[1]
            elif lower.startswith("permituserenvironment"):
                fields["permit_user_environment"] = line.split(maxsplit=1)[1]

    return SshStatus(installed=installed, running=running, **fields)


def _set_sshd_option(key: str, value: str) -> CommandResult:
    """
    Idempotently set `key value` in sshd_config: replace an existing
    (possibly commented) line, or append if missing. Backs up the file
    first, then validates the result with `sshd -t` BEFORE reloading -
    a syntax error here can lock out remote access, so we check before
    committing rather than reload-and-hope. If validation fails, the
    backup is restored automatically and sshd is never touched.
    """
    backup_name = backup_file(str(SSHD_CONFIG))

    pattern = rf"^#?\s*{re.escape(key)}\s+.*$"
    replacement = f"{key} {value}"

    check = run_unprivileged(["grep", "-Ei", pattern, str(SSHD_CONFIG)])
    if check.stdout.strip():
        sed_expr = f"s/{pattern}/{replacement}/I"
        result = run_privileged(["sed", "-i", "-E", sed_expr, str(SSHD_CONFIG)])
    else:
        result = run_privileged(["bash", "-c", f"echo '{replacement}' >> {SSHD_CONFIG}"])

    if not result.ok:
        return result

    test_result = run_privileged(["sshd", "-t"])
    if not test_result.ok:
        if backup_name:
            restore_file(backup_name, str(SSHD_CONFIG))
        raise RuntimeError(
            f"New sshd_config failed validation (sshd -t): {test_result.stderr.strip()}. "
            "Reverted to the previous config; sshd was NOT reloaded."
        )

    return run_privileged(["systemctl", "reload", "sshd"])


def set_ssh_root_login(allow: bool) -> CommandResult:
    return _set_sshd_option("PermitRootLogin", "yes" if allow else "no")


def set_ssh_password_auth(allow: bool) -> CommandResult:
    return _set_sshd_option("PasswordAuthentication", "yes" if allow else "no")


def set_ssh_port(port: int) -> CommandResult:
    return _set_sshd_option("Port", str(port))


def set_ssh_log_level(level: str) -> CommandResult:
    """CIS 5.2.5: INFO or VERBOSE - either logs enough to investigate an
    incident; sshd's own default (INFO) already satisfies this, but some
    installs get talked down to QUIET/ERROR/FATAL, which lose that."""
    if level not in ("INFO", "VERBOSE"):
        raise ValueError("SSH LogLevel must be INFO or VERBOSE")
    return _set_sshd_option("LogLevel", level)


def set_ssh_x11_forwarding(allow: bool) -> CommandResult:
    return _set_sshd_option("X11Forwarding", "yes" if allow else "no")


def set_ssh_max_auth_tries(count: int) -> CommandResult:
    """CIS 5.2.7: 4 or fewer - raises the cost of an online brute-force
    guessing attempt against this specific SSH daemon."""
    if count < 1:
        raise ValueError("MaxAuthTries must be at least 1")
    return _set_sshd_option("MaxAuthTries", str(count))


def set_ssh_ignore_rhosts(enabled: bool) -> CommandResult:
    return _set_sshd_option("IgnoreRhosts", "yes" if enabled else "no")


def set_ssh_hostbased_authentication(allow: bool) -> CommandResult:
    return _set_sshd_option("HostbasedAuthentication", "yes" if allow else "no")


def set_ssh_permit_empty_passwords(allow: bool) -> CommandResult:
    return _set_sshd_option("PermitEmptyPasswords", "yes" if allow else "no")


def set_ssh_permit_user_environment(allow: bool) -> CommandResult:
    return _set_sshd_option("PermitUserEnvironment", "yes" if allow else "no")


def sudoers_check() -> str:
    """Run visudo's syntax checker (read-only, safe) against /etc/sudoers."""
    result = run_unprivileged(["visudo", "-cf", "/etc/sudoers"])
    return result.stdout or result.stderr
