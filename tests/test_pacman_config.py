"""Tests for pacman.conf options (Color, ParallelDownloads, multilib)."""

from __future__ import annotations

import pytest

from atropa.backend import pacman, privilege


BASE = """[options]
#Color
#ParallelDownloads = 5
Architecture = x86_64

[core]
Include = /etc/pacman.d/mirrorlist

#[multilib]
#Include = /etc/pacman.d/mirrorlist
"""


def _conf(tmp_path, monkeypatch, text: str):
    path = tmp_path / "pacman.conf"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setattr(pacman, "PACMAN_CONF", path)
    return path


# ------------------------------------------------------------------- parsing --

def test_read_config_parses_active_values(tmp_path, monkeypatch):
    _conf(tmp_path, monkeypatch, "[options]\nColor\nParallelDownloads = 8\n[core]\n[multilib]\n")
    settings = pacman.read_config()
    assert settings.color is True
    assert settings.parallel_downloads == 8
    assert settings.multilib is True


def test_read_config_defaults_for_commented_options(tmp_path, monkeypatch):
    _conf(tmp_path, monkeypatch, BASE)
    settings = pacman.read_config()
    assert settings.color is False
    assert settings.parallel_downloads is None
    assert settings.multilib is False


# -------------------------------------------------------------------- editing --

def test_color_enable_uncomments_and_disable_comments():
    enabled = pacman._with_color(BASE, True)
    disabled = pacman._with_color(enabled, False)
    assert "\nColor\n" in enabled
    assert "\n#Color\n" in disabled


def test_color_inserted_when_no_line_exists():
    text = "[options]\nArchitecture = x86_64\n[core]\n"
    updated = pacman._with_color(text, True)
    assert updated.splitlines()[:3] == ["[options]", "Color", "Architecture = x86_64"]


def test_parallel_downloads_replaces_commented_line_and_validates_range():
    updated = pacman._with_parallel_downloads(BASE, 12)
    assert "ParallelDownloads = 12" in updated
    assert "#ParallelDownloads" not in updated

    with pytest.raises(ValueError):
        pacman._with_parallel_downloads(BASE, 0)
    with pytest.raises(ValueError):
        pacman._with_parallel_downloads(BASE, 21)


def test_multilib_enables_stock_commented_block():
    updated = pacman._with_multilib(BASE, True)
    assert "\n[multilib]\nInclude = /etc/pacman.d/mirrorlist\n" in updated
    assert "#[multilib]" not in updated


def test_multilib_disable_only_comments_that_section():
    text = (
        "[options]\n[core]\nInclude = /etc/pacman.d/mirrorlist\n"
        "[multilib]\nInclude = /etc/pacman.d/mirrorlist\n"
        "[multilib-testing]\nInclude = /etc/pacman.d/mirrorlist\n"
    )
    updated = pacman._with_multilib(text, False)
    assert "#[multilib]\n#Include = /etc/pacman.d/mirrorlist\n" in updated
    assert "[multilib-testing]" in updated
    assert "[core]" in updated


# ------------------------------------------------------------- privileged path --

def test_set_color_backs_up_then_writes_and_validates(tmp_path, monkeypatch, fake_run):
    path = _conf(tmp_path, monkeypatch, BASE)
    fake_run.set_response(["pacman-conf", "Color"], stdout="Color\n")
    fake_run.set_response(["pkexec", "tee", str(path)])

    result = pacman.set_color(True)

    assert result.ok
    write_call = [call for call in fake_run.calls if call[:3] == ["pkexec", "tee", str(path)]]
    assert len(write_call) == 1
    assert "Color" in fake_run.inputs[0]  # first write's stdin is the updated file
    assert list(privilege.BACKUP_DIR.glob(f"{path.name}.*.bak"))


def test_set_multilib_restores_original_when_validation_fails(tmp_path, monkeypatch, fake_run):
    path = _conf(tmp_path, monkeypatch, BASE)
    fake_run.set_response(["pacman-conf", "--repo-list"], stdout="core\nextra\n")
    fake_run.set_response(["pkexec", "tee", str(path)])

    with pytest.raises(RuntimeError, match="Restored the previous one"):
        pacman.set_multilib(True)

    tee_calls = [call for call in fake_run.calls if call[:3] == ["pkexec", "tee", str(path)]]
    assert len(tee_calls) == 2  # the write and the restore
    assert fake_run.inputs[-1] == BASE  # restore writes the original text back
