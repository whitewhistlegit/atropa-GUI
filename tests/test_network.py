"""Tests for atropa.backend.network."""
from __future__ import annotations

from atropa.backend import network


def test_backend_available_networkmanager(fake_run, fake_which):
    fake_which.add("nmcli")
    fake_run.set_response(["systemctl", "is-active", "NetworkManager"], stdout="active\n")
    assert network.backend_available() == "networkmanager"


def test_backend_available_falls_back_to_networkd(fake_run, fake_which):
    fake_which.add("nmcli")
    fake_which.add("networkctl")
    fake_run.set_response(["systemctl", "is-active", "NetworkManager"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-active", "systemd-networkd"], stdout="active\n")
    assert network.backend_available() == "networkd"


def test_backend_available_none(fake_run, fake_which):
    assert network.backend_available() == "none"


def test_list_devices_parses_colon_separated_output(fake_run):
    fake_run.set_response(
        ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"],
        stdout="eth0:ethernet:connected:Wired connection 1\nlo:loopback:unmanaged:\n",
    )
    devices = network.list_devices()
    assert devices[0] == network.NetworkDevice("eth0", "ethernet", "connected", "Wired connection 1")


def test_list_devices_skips_malformed_lines(fake_run):
    fake_run.set_response(
        ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"],
        stdout="onlytwo:fields\n",
    )
    assert network.list_devices() == []


def test_list_wifi_parses_and_marks_in_use(fake_run):
    fake_run.set_response(
        ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,IN-USE", "device", "wifi", "list"],
        stdout="HomeNet:80:WPA2:*\nGuestNet:45::\n",
    )
    networks = network.list_wifi()
    assert networks[0] == network.WifiNetwork("HomeNet", 80, "WPA2", True)
    assert networks[1] == network.WifiNetwork("GuestNet", 45, "Open", False)


def test_list_wifi_skips_blank_ssid(fake_run):
    fake_run.set_response(
        ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,IN-USE", "device", "wifi", "list"],
        stdout=":80:WPA2:\n",
    )
    assert network.list_wifi() == []


def test_list_wifi_rescan_triggers_extra_call(fake_run):
    fake_run.set_response(
        ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,IN-USE", "device", "wifi", "list"],
        stdout="",
    )
    network.list_wifi(rescan=True)
    assert fake_run.call_containing("rescan") is not None


def test_connect_wifi_with_password(fake_run, fake_which):
    network.connect_wifi("HomeNet", "hunter2")
    assert fake_run.last_call() == [
        "pkexec", "nmcli", "device", "wifi", "connect", "HomeNet", "password", "hunter2",
    ]


def test_connect_wifi_without_password(fake_run, fake_which):
    network.connect_wifi("OpenNet")
    assert fake_run.last_call() == ["pkexec", "nmcli", "device", "wifi", "connect", "OpenNet"]


def test_set_static_ip_brings_connection_up_on_success(fake_run, fake_which):
    fake_run.set_response(["pkexec", "nmcli", "connection", "modify"], returncode=0)
    network.set_static_ip("Wired 1", "192.168.1.50/24", "192.168.1.1", ["1.1.1.1", "8.8.8.8"])
    up_call = fake_run.call_containing("up")
    assert up_call is not None
    modify_call = fake_run.calls[0]
    assert "1.1.1.1,8.8.8.8" in modify_call


def test_set_static_ip_skips_up_on_failure(fake_run, fake_which):
    fake_run.set_response(["pkexec", "nmcli", "connection", "modify"], returncode=1)
    network.set_static_ip("Wired 1", "192.168.1.50/24", "192.168.1.1", ["1.1.1.1"])
    assert fake_run.call_containing("up") is None


def test_set_dhcp(fake_run, fake_which):
    fake_run.set_response(["pkexec", "nmcli", "connection", "modify"], returncode=0)
    network.set_dhcp("Wired 1")
    assert fake_run.call_containing("up") is not None


def test_toggle_networking_on_off(fake_run, fake_which):
    network.toggle_networking(True)
    assert fake_run.last_call() == ["pkexec", "nmcli", "networking", "on"]
    network.toggle_networking(False)
    assert fake_run.last_call() == ["pkexec", "nmcli", "networking", "off"]
