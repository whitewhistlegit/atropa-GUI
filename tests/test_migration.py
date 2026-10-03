"""Tests for atropa.backend.migration."""
from __future__ import annotations

import json

import pytest

from atropa.backend import migration, privilege
from atropa.backend import selinux as selinux_mod
from atropa.backend import plugins as plugins_mod


@pytest.fixture
def legacy_dirs(monkeypatch, tmp_path):
    old_user_data = tmp_path / "old_home" / ".local" / "share" / "archyast"
    old_plugins = tmp_path / "old_etc" / "archyast"
    monkeypatch.setattr(migration, "OLD_USER_DATA_DIR", old_user_data)
    monkeypatch.setattr(migration, "OLD_PLUGINS_DIR", old_plugins)
    return old_user_data, old_plugins


@pytest.fixture
def new_dirs(monkeypatch, tmp_path):
    """Redirects every *new* Atropa path this module reads/writes to
    under tmp_path, mirroring the fixtures each individual backend
    module's own test file already uses."""
    new_home = tmp_path / "new_home"
    backup_dir = new_home / "backups"
    manifest = backup_dir / "manifest.jsonl"
    log_path = new_home / "actions.log"
    monkeypatch.setattr(privilege, "BACKUP_DIR", backup_dir)
    monkeypatch.setattr(privilege, "BACKUP_MANIFEST", manifest)
    monkeypatch.setattr(privilege, "LOG_PATH", log_path)

    review_base = new_home / "selinux-review"
    monkeypatch.setattr(selinux_mod, "REVIEW_BASE_DIR", review_base)
    monkeypatch.setattr(selinux_mod, "REVIEW_MODULES_DIR", review_base / "modules")
    monkeypatch.setattr(selinux_mod, "APPROVED_MODULES_DIR", review_base / "approved")
    monkeypatch.setattr(selinux_mod, "SETUP_MODE_STATE_FILE", review_base / "setup_mode_state.json")
    monkeypatch.setattr(selinux_mod, "LAST_REVIEW_FILE", review_base / "last_review.json")

    plugins_dir = tmp_path / "new_etc" / "atropa" / "plugins"
    state_file = tmp_path / "new_etc" / "atropa" / "plugins-enabled.json"
    monkeypatch.setattr(plugins_mod, "PLUGINS_DIR", plugins_dir)
    monkeypatch.setattr(plugins_mod, "ENABLED_STATE_FILE", state_file)

    return new_home


# --------------------------------------------------------------- detect_legacy_data --

def test_detect_legacy_data_nothing_found(legacy_dirs):
    status = migration.detect_legacy_data()
    assert status.old_user_data_found is False
    assert status.old_plugins_dir_found is False
    assert status.anything_found is False


def test_detect_legacy_data_finds_user_data(legacy_dirs):
    old_user_data, _ = legacy_dirs
    old_user_data.mkdir(parents=True)
    (old_user_data / "actions.log").write_text("line1\n")
    backups_dir = old_user_data / "backups"
    backups_dir.mkdir()
    (backups_dir / "sshd_config.20260101_000000_000000.bak").write_text("x")
    (backups_dir / "manifest.jsonl").write_text('{"a": 1}\n')
    (old_user_data / "selinux-review").mkdir()

    status = migration.detect_legacy_data()
    assert status.old_user_data_found is True
    assert status.old_actions_log is True
    assert status.old_backup_count == 1
    assert status.old_selinux_review_found is True
    assert status.anything_found is True


def test_detect_legacy_data_finds_plugins(legacy_dirs):
    _, old_plugins = legacy_dirs
    plugin_dir = old_plugins / "plugins" / "example-plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "manifest.toml").write_text("id = 'example-plugin'\n")

    status = migration.detect_legacy_data()
    assert status.old_plugins_dir_found is True
    assert status.old_plugin_count == 1
    assert status.anything_found is True


# --------------------------------------------------------------- migrate_user_data --

def test_migrate_user_data_noop_when_nothing_old(legacy_dirs, new_dirs):
    lines = []
    result = migration.migrate_user_data(lines.append)
    assert result.ok
    assert "nothing to migrate" in result.stdout


def test_migrate_user_data_copies_actions_log(legacy_dirs, new_dirs):
    old_user_data, _ = legacy_dirs
    old_user_data.mkdir(parents=True)
    (old_user_data / "actions.log").write_text("old line 1\nold line 2\n")

    migration.migrate_user_data(lambda _l: None)

    assert privilege.LOG_PATH.read_text() == "old line 1\nold line 2\n"


def test_migrate_user_data_prepends_actions_log_when_new_already_has_entries(legacy_dirs, new_dirs):
    old_user_data, _ = legacy_dirs
    old_user_data.mkdir(parents=True)
    (old_user_data / "actions.log").write_text("old line\n")

    privilege.LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    privilege.LOG_PATH.write_text("new line\n")

    migration.migrate_user_data(lambda _l: None)

    content = privilege.LOG_PATH.read_text()
    assert content.index("old line") < content.index("new line")


def test_migrate_user_data_actions_log_idempotent(legacy_dirs, new_dirs):
    old_user_data, _ = legacy_dirs
    old_user_data.mkdir(parents=True)
    (old_user_data / "actions.log").write_text("old line\n")

    migration.migrate_user_data(lambda _l: None)
    first_content = privilege.LOG_PATH.read_text()
    migration.migrate_user_data(lambda _l: None)
    second_content = privilege.LOG_PATH.read_text()

    assert first_content == second_content
    assert first_content.count("old line") == 1


def test_migrate_user_data_copies_backups_and_manifest(legacy_dirs, new_dirs):
    old_user_data, _ = legacy_dirs
    backups_dir = old_user_data / "backups"
    backups_dir.mkdir(parents=True)
    (backups_dir / "sshd_config.20260101_000000_000000.bak").write_text("old config")
    (backups_dir / "manifest.jsonl").write_text(
        json.dumps({"timestamp": "1", "original_path": "/etc/ssh/sshd_config", "backup_file": "sshd_config.20260101_000000_000000.bak"}) + "\n"
    )

    migration.migrate_user_data(lambda _l: None)

    assert (privilege.BACKUP_DIR / "sshd_config.20260101_000000_000000.bak").read_text() == "old config"
    entries = privilege.list_backups()
    assert len(entries) == 1
    assert entries[0]["original_path"] == "/etc/ssh/sshd_config"


def test_migrate_user_data_does_not_overwrite_existing_backup_file(legacy_dirs, new_dirs):
    old_user_data, _ = legacy_dirs
    backups_dir = old_user_data / "backups"
    backups_dir.mkdir(parents=True)
    (backups_dir / "same_name.bak").write_text("OLD CONTENT")

    privilege.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    (privilege.BACKUP_DIR / "same_name.bak").write_text("NEW CONTENT - DO NOT CLOBBER")

    migration.migrate_user_data(lambda _l: None)

    assert (privilege.BACKUP_DIR / "same_name.bak").read_text() == "NEW CONTENT - DO NOT CLOBBER"


def test_migrate_user_data_copies_selinux_review_artifacts(legacy_dirs, new_dirs):
    old_user_data, _ = legacy_dirs
    review_dir = old_user_data / "selinux-review"
    (review_dir / "modules").mkdir(parents=True)
    (review_dir / "approved").mkdir(parents=True)
    (review_dir / "modules" / "draft.te").write_text("module draft 1.0;")
    (review_dir / "approved" / "fixed.te").write_text("module fixed 1.0;")
    (review_dir / "setup_mode_state.json").write_text('{"started_at": "2026-01-01T00:00:00+00:00"}')
    (review_dir / "last_review.json").write_text("{}")

    migration.migrate_user_data(lambda _l: None)

    assert (selinux_mod.REVIEW_MODULES_DIR / "draft.te").read_text() == "module draft 1.0;"
    assert (selinux_mod.APPROVED_MODULES_DIR / "fixed.te").read_text() == "module fixed 1.0;"
    assert selinux_mod.SETUP_MODE_STATE_FILE.exists()
    assert selinux_mod.LAST_REVIEW_FILE.exists()


def test_migrate_user_data_skips_selinux_state_files_if_already_present(legacy_dirs, new_dirs):
    old_user_data, _ = legacy_dirs
    review_dir = old_user_data / "selinux-review"
    review_dir.mkdir(parents=True)
    (review_dir / "setup_mode_state.json").write_text('{"started_at": "OLD"}')

    selinux_mod.SETUP_MODE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    selinux_mod.SETUP_MODE_STATE_FILE.write_text('{"started_at": "NEW"}')

    migration.migrate_user_data(lambda _l: None)

    assert selinux_mod.SETUP_MODE_STATE_FILE.read_text() == '{"started_at": "NEW"}'


# --------------------------------------------------------------- migrate_plugin_data --

def test_migrate_plugin_data_noop_when_nothing_old(legacy_dirs, new_dirs, fake_run, fake_which):
    lines = []
    result = migration.migrate_plugin_data(lines.append)
    assert result.ok
    assert "nothing to migrate" in result.stdout
    assert fake_run.calls == []


def test_migrate_plugin_data_requires_privilege(legacy_dirs, new_dirs, fake_run, fake_which):
    _, old_plugins = legacy_dirs
    plugin_dir = old_plugins / "plugins" / "example-plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "manifest.toml").write_text("id = 'example-plugin'\n")

    fake_run.set_response(["pkexec", "mkdir", "-p", str(plugins_mod.PLUGINS_DIR)], returncode=0)
    fake_run.set_response(["pkexec", "cp", "-rn"], returncode=0)

    result = migration.migrate_plugin_data(lambda _l: None)
    assert result.ok
    assert fake_run.call_containing("pkexec") is not None
    assert fake_run.call_containing("cp") is not None


def test_migrate_plugin_data_stops_if_mkdir_fails(legacy_dirs, new_dirs, fake_run, fake_which):
    _, old_plugins = legacy_dirs
    old_plugins.mkdir(parents=True)

    fake_run.set_response(["pkexec", "mkdir", "-p", str(plugins_mod.PLUGINS_DIR)], returncode=1, stderr="denied")

    result = migration.migrate_plugin_data(lambda _l: None)
    assert not result.ok
    assert fake_run.call_containing("cp") is None


def test_migrate_plugin_data_skips_enabled_state_if_already_present(legacy_dirs, new_dirs, fake_run, fake_which):
    _, old_plugins = legacy_dirs
    old_plugins.mkdir(parents=True)
    (old_plugins / "plugins-enabled.json").write_text('{"old-plugin": true}')

    plugins_mod.ENABLED_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    plugins_mod.ENABLED_STATE_FILE.write_text('{"new-plugin": true}')

    fake_run.set_response(["pkexec", "mkdir", "-p", str(plugins_mod.PLUGINS_DIR)], returncode=0)

    lines = []
    migration.migrate_plugin_data(lines.append)

    assert any("already exists" in line for line in lines)
    assert plugins_mod.ENABLED_STATE_FILE.read_text() == '{"new-plugin": true}'


def test_migrate_plugin_data_copies_enabled_state_if_missing(legacy_dirs, new_dirs, fake_run, fake_which):
    _, old_plugins = legacy_dirs
    old_plugins.mkdir(parents=True)
    (old_plugins / "plugins-enabled.json").write_text('{"old-plugin": true}')

    fake_run.set_response(["pkexec", "mkdir", "-p", str(plugins_mod.PLUGINS_DIR)], returncode=0)
    fake_run.set_response(
        ["pkexec", "cp", "-n", str(old_plugins / "plugins-enabled.json"), str(plugins_mod.ENABLED_STATE_FILE)],
        returncode=0,
    )

    result = migration.migrate_plugin_data(lambda _l: None)
    assert result.ok
    assert any("plugins-enabled.json" in arg for call in fake_run.calls for arg in call)


# --------------------------------------------------------------- remove_legacy_* --

def test_remove_legacy_user_data_noop_when_missing(legacy_dirs):
    result = migration.remove_legacy_user_data()
    assert result.ok
    assert "nothing to remove" in result.stdout


def test_remove_legacy_user_data_deletes_directory(legacy_dirs):
    old_user_data, _ = legacy_dirs
    old_user_data.mkdir(parents=True)
    (old_user_data / "actions.log").write_text("x")

    result = migration.remove_legacy_user_data()
    assert result.ok
    assert not old_user_data.exists()


def test_remove_legacy_plugin_data_noop_when_missing(legacy_dirs, fake_run, fake_which):
    result = migration.remove_legacy_plugin_data()
    assert result.ok
    assert "nothing to remove" in result.stdout
    assert fake_run.calls == []


def test_remove_legacy_plugin_data_uses_privileged_rm(legacy_dirs, fake_run, fake_which):
    _, old_plugins = legacy_dirs
    old_plugins.mkdir(parents=True)

    fake_run.set_response(["pkexec", "rm", "-rf", str(old_plugins)], returncode=0)

    result = migration.remove_legacy_plugin_data()
    assert result.ok
    assert fake_run.last_call() == ["pkexec", "rm", "-rf", str(old_plugins)]
