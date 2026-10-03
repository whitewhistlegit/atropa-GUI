"""Tests for atropa.backend.inventory."""
from __future__ import annotations

from atropa.backend import inventory


# --------------------------------------------------------------- catalog sanity --

def test_catalog_keys_are_unique():
    keys = [e.key for e in inventory.CATALOG]
    assert len(keys) == len(set(keys))


def test_every_entry_has_title_description_and_packages():
    for entry in inventory.CATALOG:
        assert entry.title
        assert entry.description
        assert entry.packages


# --------------------------------------------------------------- scan_entry --

def test_scan_entry_not_installed_is_pass(fake_run):
    entry = inventory._CATALOG_BY_KEY["cups"]
    fake_run.set_response(["pacman", "-Q", "cups"], returncode=1)
    finding = inventory.scan_entry(entry)
    assert finding.status == "pass"
    assert "not installed" in finding.detail.lower()


def test_scan_entry_installed_but_inactive_is_warn(fake_run):
    entry = inventory._CATALOG_BY_KEY["cups"]
    fake_run.set_response(["pacman", "-Q", "cups"], returncode=0, stdout="cups 2.4.7-1\n")
    fake_run.set_response(["systemctl", "is-active", "cups"], stdout="inactive\n")
    finding = inventory.scan_entry(entry)
    assert finding.status == "warn"
    assert "not active" in finding.detail


def test_scan_entry_installed_and_active_is_fail(fake_run):
    entry = inventory._CATALOG_BY_KEY["cups"]
    fake_run.set_response(["pacman", "-Q", "cups"], returncode=0, stdout="cups 2.4.7-1\n")
    fake_run.set_response(["systemctl", "is-active", "cups"], stdout="active\n")
    finding = inventory.scan_entry(entry)
    assert finding.status == "fail"
    assert "active" in finding.detail


def test_scan_entry_checks_any_of_multiple_units(fake_run):
    """dhcp-server has two units (dhcpd4, dhcpd6) - either being active should trigger fail."""
    entry = inventory._CATALOG_BY_KEY["dhcp-server"]
    fake_run.set_response(["pacman", "-Q", "dhcp"], returncode=0, stdout="dhcp 4.4.3-1\n")
    fake_run.set_response(["systemctl", "is-active", "dhcpd4"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-active", "dhcpd6"], stdout="active\n")
    finding = inventory.scan_entry(entry)
    assert finding.status == "fail"


def test_scan_entry_client_only_entry_has_no_units_and_never_fails(fake_run):
    """An entry with no service units (pure client tooling) can only ever be pass/warn, never fail."""
    for entry in inventory.CATALOG:
        if not entry.units:
            fake_run.set_response(["pacman", "-Q", entry.packages[0]], returncode=0, stdout="x 1-1\n")
            finding = inventory.scan_entry(entry)
            assert finding.status in ("pass", "warn")


def test_scan_entry_checks_any_of_multiple_packages(fake_run):
    entry = inventory._CATALOG_BY_KEY["legacy-inetutils"]
    fake_run.set_response(["pacman", "-Q", "inetutils"], returncode=0, stdout="inetutils 2.6-1\n")
    fake_run.set_response(["systemctl", "is-active", "telnet.socket"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-active", "rsh.socket"], stdout="inactive\n")
    fake_run.set_response(["systemctl", "is-active", "talk.socket"], stdout="active\n")
    finding = inventory.scan_entry(entry)
    assert finding.status == "fail"


def test_scan_all_returns_one_finding_per_catalog_entry(fake_run):
    fake_run.set_response(["pacman", "-Q"], returncode=1)  # every package "not installed"
    results = inventory.scan_all()
    assert len(results) == len(inventory.CATALOG)
    assert all(f.status == "pass" for f in results)
