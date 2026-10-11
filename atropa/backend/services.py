"""
atropa.backend.services
---------------------------
Wraps systemctl for the Services module (start/stop/enable/disable/status).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from .privilege import CommandResult, run_privileged, run_unprivileged

_DBUS = "D-Bus carries the desktop's messages - without it your session ends, Atropa included."
_DISPLAY_MANAGER = "This is the display manager - stopping it ends the graphical session, Atropa included."
_NETWORK = "This machine can lose its network connection - including an SSH session you're using to reach it."
_FIREWALL = "The firewall stops filtering incoming connections."

# Units whose loss breaks Atropa itself, the desktop session, or the way
# into this machine - spelled out before a one-click stop/disable does it.
_IMPACTS = (
    ("polkit.service", "polkit shows Atropa's password prompts - without it no privileged action works, "
     "including starting it again from here."),
    ("dbus.service", _DBUS),
    ("dbus-broker.service", _DBUS),
    ("systemd-logind.service", "logind manages logins and sessions - without it your session can end."),
    ("user@*.service", "This is a user's service manager - stopping it ends that user's whole session."),
    ("gdm.service", _DISPLAY_MANAGER),
    ("sddm.service", _DISPLAY_MANAGER),
    ("lightdm.service", _DISPLAY_MANAGER),
    ("lxdm.service", _DISPLAY_MANAGER),
    ("ly.service", _DISPLAY_MANAGER),
    ("greetd.service", _DISPLAY_MANAGER),
    ("NetworkManager.service", _NETWORK),
    ("systemd-networkd.service", _NETWORK),
    ("iwd.service", _NETWORK),
    ("wpa_supplicant.service", _NETWORK),
    ("dhcpcd.service", _NETWORK),
    ("connman.service", _NETWORK),
    ("sshd.service", "Nobody can log in over SSH without it - if that's how you reach this machine, "
     "you lose the way back in."),
    ("systemd-udevd.service", "udev sets up devices as they're plugged in - new keyboards, drives and "
     "network adapters stop working."),
    ("systemd-resolved.service", "If this machine uses systemd-resolved, name lookups (DNS) stop working."),
    ("bluetooth.service", "Bluetooth keyboards, mice and headsets disconnect."),
    ("firewalld.service", _FIREWALL),
    ("ufw.service", _FIREWALL),
    ("nftables.service", _FIREWALL),
    ("iptables.service", _FIREWALL),
    ("ip6tables.service", _FIREWALL),
    ("auditd.service", "auditd stops recording audit events, including the SELinux/AppArmor denials "
     "Atropa reviews."),
    ("apparmor.service", "apparmor.service loads AppArmor's profiles at boot - without it programs run "
     "unconfined after the next reboot."),
    ("usbguard.service", "USBGuard stops deciding which USB devices are allowed."),
    ("fail2ban.service", "fail2ban stops banning addresses that keep failing to log in."),
)


@dataclass
class Service:
    unit: str
    load: str
    active: str
    sub: str
    description: str
    enabled: str = "unknown"


def list_services(pattern: str = "*.service") -> list[Service]:
    result = run_unprivileged(
        ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", pattern]
    )
    services = []
    for line in result.stdout.strip().splitlines():
        parts = line.split(maxsplit=4)
        if len(parts) < 4:
            continue
        unit, load, active, sub = parts[0], parts[1], parts[2], parts[3]
        desc = parts[4] if len(parts) > 4 else ""
        services.append(Service(unit=unit, load=load, active=active, sub=sub, description=desc))

    states = _unit_file_states([svc.unit for svc in services])
    for svc in services:
        svc.enabled = states.get(svc.unit) or "unknown"

    return services


def _unit_file_states(units: list[str]) -> dict[str, str]:
    """
    {unit: enabled/disabled/static/...} for every unit in one `systemctl
    show` call. It used to be one `systemctl is-enabled` per service:
    hundreds of commands per refresh, each one a line in the Activity log.
    """
    if not units:
        return {}
    result = run_unprivileged(["systemctl", "show", "--property=Id,UnitFileState", "--", *units])
    states = {}
    for block in result.stdout.split("\n\n"):  # one block per unit, blank-line separated
        props = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if props.get("Id"):
            states[props["Id"]] = props.get("UnitFileState", "")
    return states


def stop_impact(unit: str) -> str:
    """What stopping or disabling `unit` breaks, for a confirmation dialog ("" if nothing notable)."""
    return next((impact for pattern, impact in _IMPACTS if fnmatch.fnmatchcase(unit, pattern)), "")


def status(unit: str) -> str:
    result = run_unprivileged(["systemctl", "status", unit, "--no-pager"])
    return result.stdout or result.stderr


def start(unit: str) -> CommandResult:
    return run_privileged(["systemctl", "start", unit])


def stop(unit: str) -> CommandResult:
    return run_privileged(["systemctl", "stop", unit])


def restart(unit: str) -> CommandResult:
    return run_privileged(["systemctl", "restart", unit])


def enable(unit: str, now: bool = False) -> CommandResult:
    argv = ["systemctl", "enable", unit]
    if now:
        argv.append("--now")
    return run_privileged(argv)


def disable(unit: str, now: bool = False) -> CommandResult:
    argv = ["systemctl", "disable", unit]
    if now:
        argv.append("--now")
    return run_privileged(argv)


def journal_tail(unit: str, lines: int = 100) -> str:
    result = run_unprivileged(["journalctl", "-u", unit, "-n", str(lines), "--no-pager"])
    return result.stdout
