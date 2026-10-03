"""Tests for atropa.backend.plugin_registry."""
from __future__ import annotations

from atropa.backend import plugin_registry


def test_registry_keys_match_action_key_field():
    for key, action in plugin_registry.REGISTRY.items():
        assert action.key == key


def test_get_action_known_key():
    action = plugin_registry.get_action("pacman.clean_cache")
    assert action is not None
    assert action.mutating is True


def test_get_action_unknown_key_returns_none():
    assert plugin_registry.get_action("os.system") is None
    assert plugin_registry.get_action("subprocess.run") is None
    assert plugin_registry.get_action("") is None


def test_every_action_has_a_description():
    for action in plugin_registry.REGISTRY.values():
        assert action.description


def test_read_only_actions_are_not_mutating():
    for key in ("dependencies.check_all", "hardening.run_audit", "compliance.generate_report", "pacman.check_updates"):
        action = plugin_registry.get_action(key)
        assert action is not None
        assert action.mutating is False


def test_mutating_actions_flagged_mutating():
    for key in ("pacman.clean_cache", "services.restart", "services.stop"):
        action = plugin_registry.get_action(key)
        assert action is not None
        assert action.mutating is True


def test_higher_risk_domains_are_not_exposed():
    """Users, firewall/SSH, bootloader, SELinux/AppArmor, restorecon, and
    quicksetup/profiles are deliberately excluded - this must stay true
    even as the registry grows, not just be true today."""
    forbidden_prefixes = ("users.", "security.", "bootloader.", "selinux.", "apparmor.", "quicksetup.", "profiles.")
    for key in plugin_registry.REGISTRY:
        assert not key.startswith(forbidden_prefixes), f"{key} should not be exposed to plugins"


def test_describe_call_renders_params():
    text = plugin_registry.describe_call("services.restart", {"unit": "sshd"})
    assert text == "services.restart('sshd')"


def test_describe_call_unknown_key():
    text = plugin_registry.describe_call("not.a.real.action", {})
    assert "unknown action" in text.lower()


def test_describe_call_no_params():
    text = plugin_registry.describe_call("pacman.clean_cache", {})
    assert text == "pacman.clean_cache()"
