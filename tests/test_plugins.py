"""Tests for atropa.backend.plugins."""
from __future__ import annotations

import json

import pytest

from atropa.backend import plugins

VALID_MANIFEST = """
id = "example-plugin"
title = "My Custom Dashboard"
description = "A few shortcuts I check often."
author = "jdoe"
version = "1.0"

[[groups]]
title = "Quick Checks"
description = "Read-only status"

  [[groups.rows]]
  title = "Pending Updates"
  action = "pacman.check_updates"

[[groups]]
title = "Maintenance"

  [[groups.rows]]
  title = "Clean Cache"
  action = "pacman.clean_cache"
  button_label = "Clean now"
"""


@pytest.fixture
def plugin_dirs(monkeypatch, tmp_path):
    plugins_dir = tmp_path / "plugins"
    state_file = tmp_path / "plugins-enabled.json"
    monkeypatch.setattr(plugins, "PLUGINS_DIR", plugins_dir)
    monkeypatch.setattr(plugins, "ENABLED_STATE_FILE", state_file)
    return plugins_dir, state_file


def _write_manifest(plugins_dir, plugin_id: str, content: str) -> None:
    plugin_dir = plugins_dir / plugin_id
    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "manifest.toml").write_text(content)


# --------------------------------------------------------------- discovery/parsing --

def test_discover_plugins_empty_when_dir_missing(plugin_dirs):
    assert plugins.discover_plugins() == []


def test_discover_plugins_parses_valid_manifest(plugin_dirs):
    plugins_dir, _ = plugin_dirs
    _write_manifest(plugins_dir, "example-plugin", VALID_MANIFEST)

    discovered = plugins.discover_plugins()
    assert len(discovered) == 1
    plugin = discovered[0]
    assert plugin.plugin_id == "example-plugin"
    assert plugin.manifest is not None
    assert plugin.manifest.title == "My Custom Dashboard"
    assert plugin.errors == []
    assert len(plugin.manifest.groups) == 2
    assert plugin.manifest.groups[0].rows[0].action_key == "pacman.check_updates"
    assert plugin.manifest.groups[1].rows[0].button_label == "Clean now"


def test_discover_plugins_defaults_to_disabled(plugin_dirs):
    plugins_dir, _ = plugin_dirs
    _write_manifest(plugins_dir, "example-plugin", VALID_MANIFEST)
    discovered = plugins.discover_plugins()
    assert discovered[0].enabled is False


def test_discover_plugins_reflects_enabled_state_file(plugin_dirs):
    plugins_dir, state_file = plugin_dirs
    _write_manifest(plugins_dir, "example-plugin", VALID_MANIFEST)
    state_file.write_text(json.dumps({"example-plugin": True}))

    discovered = plugins.discover_plugins()
    assert discovered[0].enabled is True


def test_discover_plugins_ignores_folders_without_manifest(plugin_dirs):
    plugins_dir, _ = plugin_dirs
    (plugins_dir / "not-a-plugin").mkdir(parents=True)
    assert plugins.discover_plugins() == []


def test_discover_plugins_skips_non_directory_entries(plugin_dirs):
    plugins_dir, _ = plugin_dirs
    plugins_dir.mkdir(parents=True)
    (plugins_dir / "stray-file.txt").write_text("noise")
    assert plugins.discover_plugins() == []


def test_parse_manifest_missing_required_fields(plugin_dirs):
    plugins_dir, _ = plugin_dirs
    _write_manifest(plugins_dir, "broken", "description = \"no id or title\"\n")
    discovered = plugins.discover_plugins()
    assert discovered[0].manifest is None
    assert any("id" in e for e in discovered[0].errors)
    assert any("title" in e for e in discovered[0].errors)


def test_parse_manifest_invalid_toml(plugin_dirs):
    plugins_dir, _ = plugin_dirs
    _write_manifest(plugins_dir, "broken", "this is not [ valid toml")
    discovered = plugins.discover_plugins()
    assert discovered[0].manifest is None
    assert "TOML" in discovered[0].errors[0]


def test_parse_manifest_unknown_action_rejected(plugin_dirs):
    plugins_dir, _ = plugin_dirs
    manifest = """
id = "bad-plugin"
title = "Bad Plugin"

[[groups]]
title = "Danger"

  [[groups.rows]]
  title = "Delete everything"
  action = "os.system"
"""
    _write_manifest(plugins_dir, "bad-plugin", manifest)
    discovered = plugins.discover_plugins()
    assert discovered[0].manifest is None
    assert any("unknown action" in e.lower() for e in discovered[0].errors)


def test_parse_manifest_row_missing_title_or_action(plugin_dirs):
    plugins_dir, _ = plugin_dirs
    manifest = """
id = "bad-plugin"
title = "Bad Plugin"

[[groups]]
title = "Group"

  [[groups.rows]]
  action = "pacman.check_updates"
"""
    _write_manifest(plugins_dir, "bad-plugin", manifest)
    discovered = plugins.discover_plugins()
    assert discovered[0].manifest is None
    assert any("missing a title" in e for e in discovered[0].errors)


def test_parse_manifest_id_must_match_folder_name(plugin_dirs):
    plugins_dir, _ = plugin_dirs
    manifest = 'id = "wrong-id"\ntitle = "X"\n'
    _write_manifest(plugins_dir, "example-plugin", manifest)
    discovered = plugins.discover_plugins()
    assert discovered[0].manifest is None
    assert any("doesn't match" in e for e in discovered[0].errors)


def test_discover_plugins_never_imports_or_execs_manifest_content(plugin_dirs):
    """A manifest containing something that LOOKS like code must be
    treated as inert string data, not executed - this is the core
    security property of the whole system."""
    plugins_dir, _ = plugin_dirs
    manifest = """
id = "sneaky"
title = "__import__('os').system('touch /tmp/pwned')"
description = "eval(compile('1/0', '<string>', 'exec'))"
"""
    _write_manifest(plugins_dir, "sneaky", manifest)
    discovered = plugins.discover_plugins()
    assert discovered[0].manifest is not None
    assert discovered[0].manifest.title == "__import__('os').system('touch /tmp/pwned')"


# --------------------------------------------------------------- enabled_plugins --

def test_enabled_plugins_excludes_disabled(plugin_dirs):
    plugins_dir, _ = plugin_dirs
    _write_manifest(plugins_dir, "example-plugin", VALID_MANIFEST)
    assert plugins.enabled_plugins() == []


def test_enabled_plugins_excludes_invalid_even_if_marked_enabled(plugin_dirs):
    plugins_dir, state_file = plugin_dirs
    _write_manifest(plugins_dir, "broken", "title = \"no id\"\n")
    state_file.write_text(json.dumps({"broken": True}))
    assert plugins.enabled_plugins() == []


def test_enabled_plugins_includes_valid_and_enabled(plugin_dirs):
    plugins_dir, state_file = plugin_dirs
    _write_manifest(plugins_dir, "example-plugin", VALID_MANIFEST)
    state_file.write_text(json.dumps({"example-plugin": True}))
    enabled = plugins.enabled_plugins()
    assert len(enabled) == 1
    assert enabled[0].plugin_id == "example-plugin"


# --------------------------------------------------------------- set_plugin_enabled (privileged gate) --

def test_set_plugin_enabled_requires_privilege(fake_run, fake_which, plugin_dirs):
    _, state_file = plugin_dirs
    fake_run.set_response(["pkexec", "mkdir", "-p", str(state_file.parent)], returncode=0)
    fake_run.set_response(["pkexec", "tee", str(state_file)], returncode=0)

    result = plugins.set_plugin_enabled("example-plugin", True)
    assert result.ok
    assert fake_run.call_containing("pkexec") is not None


def test_set_plugin_enabled_stops_if_mkdir_fails(fake_run, fake_which, plugin_dirs):
    _, state_file = plugin_dirs
    fake_run.set_response(["pkexec", "mkdir", "-p", str(state_file.parent)], returncode=1, stderr="denied")

    result = plugins.set_plugin_enabled("example-plugin", True)
    assert not result.ok
    assert fake_run.call_containing("tee") is None


def test_set_plugin_enabled_preserves_other_plugins_state(fake_run, fake_which, plugin_dirs):
    _, state_file = plugin_dirs
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps({"other-plugin": True}))
    fake_run.set_response(["pkexec", "mkdir", "-p", str(state_file.parent)], returncode=0)
    fake_run.set_response(["pkexec", "tee", str(state_file)], returncode=0)

    plugins.set_plugin_enabled("example-plugin", True)

    tee_call_index = next(i for i, c in enumerate(fake_run.calls) if "tee" in c)
    mkdir_index = next(i for i, c in enumerate(fake_run.calls) if "mkdir" in c)
    assert mkdir_index < tee_call_index


def test_set_plugin_enabled_false_toggles_off(fake_run, fake_which, plugin_dirs):
    _, state_file = plugin_dirs
    fake_run.set_response(["pkexec", "mkdir", "-p", str(state_file.parent)], returncode=0)
    fake_run.set_response(["pkexec", "tee", str(state_file)], returncode=0)

    result = plugins.set_plugin_enabled("example-plugin", False)
    assert result.ok


def test_set_plugin_enabled_raises_privilege_error_without_pkexec_or_sudo(fake_which):
    from atropa.backend.privilege import PrivilegeError
    fake_which.discard("pkexec")
    with pytest.raises(PrivilegeError):
        plugins.set_plugin_enabled("example-plugin", True)


# --------------------------------------------------------------- run_plugin_action --

def test_run_plugin_action_calls_the_real_registry_function(fake_run, fake_which):
    fake_run.set_response(["pacman", "-Qu"], stdout="firefox 1 -> 2\n")
    result = plugins.run_plugin_action("pacman.check_updates", {})
    assert len(result) == 1
    assert result[0].name == "firefox"


def test_run_plugin_action_passes_params_positionally(fake_run, fake_which):
    plugins.run_plugin_action("services.restart", {"unit": "sshd"})
    assert fake_run.last_call() == ["pkexec", "systemctl", "restart", "sshd"]


def test_run_plugin_action_unknown_key_raises():
    with pytest.raises(ValueError, match="Unknown plugin action"):
        plugins.run_plugin_action("os.system", {})


# --------------------------------------------------------------- example manifest --

def test_example_manifest_in_repo_stays_valid():
    """The example manifest shipped in examples/plugins/ is documentation
    someone will copy-paste - if it ever stops parsing (e.g. a registry
    key gets renamed), that's a docs bug worth catching in CI, not
    something a user discovers by trying it."""
    import pathlib

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    example_path = repo_root / "examples" / "plugins" / "example-plugin" / "manifest.toml"
    assert example_path.exists(), "example manifest is missing from examples/plugins/"

    manifest, errors = plugins._parse_manifest(example_path)
    assert errors == [], f"example manifest no longer validates: {errors}"
    assert manifest is not None
    assert manifest.id == "example-plugin"
    assert any(row.action_key == "services.restart" for group in manifest.groups for row in group.rows)
