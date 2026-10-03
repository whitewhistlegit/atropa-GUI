"""
atropa.backend.network
--------------------------
Wraps `nmcli` (NetworkManager) for the Network module. Falls back to
reporting systemd-networkd status if NetworkManager isn't running, since
plenty of minimal Arch installs use networkd instead.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass

from .privilege import CommandResult, run_privileged, run_unprivileged


@dataclass
class NetworkDevice:
    name: str
    dev_type: str
    state: str
    connection: str


@dataclass
class WifiNetwork:
    ssid: str
    signal: int
    security: str
    in_use: bool


def backend_available() -> str:
    """Returns 'networkmanager', 'networkd', or 'none'."""
    if shutil.which("nmcli"):
        result = run_unprivileged(["systemctl", "is-active", "NetworkManager"])
        if result.stdout.strip() == "active":
            return "networkmanager"
    if shutil.which("networkctl"):
        result = run_unprivileged(["systemctl", "is-active", "systemd-networkd"])
        if result.stdout.strip() == "active":
            return "networkd"
    return "none"


def list_devices() -> list[NetworkDevice]:
    result = run_unprivileged(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"])
    devices = []
    for line in result.stdout.strip().splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            devices.append(NetworkDevice(name=parts[0], dev_type=parts[1], state=parts[2], connection=parts[3]))
    return devices


def list_wifi(rescan: bool = False) -> list[WifiNetwork]:
    if rescan:
        run_unprivileged(["nmcli", "device", "wifi", "rescan"])
    result = run_unprivileged(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,IN-USE", "device", "wifi", "list"])
    networks = []
    for line in result.stdout.strip().splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and parts[0]:
            networks.append(
                WifiNetwork(
                    ssid=parts[0],
                    signal=int(parts[1]) if parts[1].isdigit() else 0,
                    security=parts[2] or "Open",
                    in_use=(parts[3] == "*"),
                )
            )
    return networks


def connect_wifi(ssid: str, password: str | None = None) -> CommandResult:
    """
    Connecting to Wi-Fi requires modifying NetworkManager connection profiles,
    which is a privileged operation via nmcli.
    """
    argv = ["nmcli", "device", "wifi", "connect", ssid]
    if password:
        argv += ["password", password]
    return run_privileged(argv)


def disconnect(device: str) -> CommandResult:
    return run_privileged(["nmcli", "device", "disconnect", device])


def set_static_ip(connection_name: str, ip_cidr: str, gateway: str, dns: list[str]) -> CommandResult:
    """
    ip_cidr example: '192.168.1.50/24'
    """
    argv = [
        "nmcli", "connection", "modify", connection_name,
        "ipv4.addresses", ip_cidr,
        "ipv4.gateway", gateway,
        "ipv4.dns", ",".join(dns),
        "ipv4.method", "manual",
    ]
    result = run_privileged(argv)
    if result.ok:
        run_privileged(["nmcli", "connection", "up", connection_name])
    return result


def set_dhcp(connection_name: str) -> CommandResult:
    result = run_privileged(["nmcli", "connection", "modify", connection_name, "ipv4.method", "auto"])
    if result.ok:
        run_privileged(["nmcli", "connection", "up", connection_name])
    return result


def toggle_networking(enabled: bool) -> CommandResult:
    return run_privileged(["nmcli", "networking", enabled and "on" or "off"])
