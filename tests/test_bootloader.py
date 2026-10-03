"""Tests for atropa.backend.bootloader."""
from __future__ import annotations

import pytest

from atropa.backend import bootloader


def test_detect_systemd_boot(monkeypatch, tmp_path, fake_which):
    fake_which.add("bootctl")
    conf = tmp_path / "loader.conf"
    conf.write_text("timeout 5\n")
    monkeypatch.setattr(bootloader, "SYSTEMD_BOOT_LOADER_CONF", conf)
    assert bootloader.detect() == "systemd-boot"


def test_detect_grub(monkeypatch, tmp_path, fake_which):
    fake_which.add("grub-mkconfig")
    grub_default = tmp_path / "grub"
    grub_default.write_text("GRUB_TIMEOUT=5\n")
    monkeypatch.setattr(bootloader, "SYSTEMD_BOOT_LOADER_CONF", tmp_path / "no-such-loader.conf")
    monkeypatch.setattr(bootloader, "GRUB_DEFAULT_PATH", grub_default)
    assert bootloader.detect() == "grub"


def test_detect_unknown_when_neither(monkeypatch, tmp_path, fake_which):
    monkeypatch.setattr(bootloader, "SYSTEMD_BOOT_LOADER_CONF", tmp_path / "nope1")
    monkeypatch.setattr(bootloader, "GRUB_DEFAULT_PATH", tmp_path / "nope2")
    assert bootloader.detect() == "unknown"


def test_systemd_boot_info_parses_timeout_and_entries(monkeypatch, tmp_path, fake_which):
    fake_which.add("bootctl")
    conf = tmp_path / "loader.conf"
    conf.write_text("timeout 5\ndefault arch.conf\n")
    entries_dir = tmp_path / "entries"
    entries_dir.mkdir()
    (entries_dir / "arch.conf").write_text("title Arch Linux\nlinux /vmlinuz\n")
    (entries_dir / "fallback.conf").write_text("linux /vmlinuz-fallback\n")  # no title line

    monkeypatch.setattr(bootloader, "SYSTEMD_BOOT_LOADER_CONF", conf)
    monkeypatch.setattr(bootloader, "SYSTEMD_BOOT_ENTRIES_DIR", entries_dir)

    info = bootloader.get_info()
    assert info.kind == "systemd-boot"
    assert info.default_timeout == "5"
    titles = {e.title for e in info.entries}
    assert "Arch Linux" in titles
    assert "fallback" in titles  # falls back to file stem when no title line


def test_grub_info_parses_timeout_and_menu_entries(monkeypatch, tmp_path, fake_which, fake_run):
    fake_which.add("grub-mkconfig")
    grub_default = tmp_path / "grub"
    grub_default.write_text("GRUB_TIMEOUT=10\nGRUB_DEFAULT=0\n")
    monkeypatch.setattr(bootloader, "SYSTEMD_BOOT_LOADER_CONF", tmp_path / "no-loader")
    monkeypatch.setattr(bootloader, "GRUB_DEFAULT_PATH", grub_default)

    fake_run.set_response(
        ["grep", "-E", "^menuentry"],
        stdout="menuentry 'Arch Linux' --class arch {\nmenuentry 'Windows' --class windows {\n",
    )

    info = bootloader.get_info()
    assert info.kind == "grub"
    assert info.default_timeout == "10"
    assert [e.title for e in info.entries] == ["Arch Linux", "Windows"]


def test_get_info_unknown_kind(monkeypatch, tmp_path, fake_which):
    monkeypatch.setattr(bootloader, "SYSTEMD_BOOT_LOADER_CONF", tmp_path / "nope1")
    monkeypatch.setattr(bootloader, "GRUB_DEFAULT_PATH", tmp_path / "nope2")
    info = bootloader.get_info()
    assert info.kind == "unknown"
    assert info.entries == []


# --------------------------------------------------------------- set_timeout --

def test_set_timeout_grub_success_regenerates_config(
    monkeypatch, tmp_path, fake_which, fake_run, privilege_paths
):
    fake_which.add("grub-mkconfig")
    grub_default = tmp_path / "grub"
    grub_default.write_text("GRUB_TIMEOUT=5\n")
    monkeypatch.setattr(bootloader, "SYSTEMD_BOOT_LOADER_CONF", tmp_path / "no-loader")
    monkeypatch.setattr(bootloader, "GRUB_DEFAULT_PATH", grub_default)

    fake_run.set_response(["pkexec", "sed", "-i"], returncode=0)
    fake_run.set_response(["pkexec", "grub-mkconfig", "-o"], returncode=0)

    result = bootloader.set_timeout(15)
    assert result.ok
    assert fake_run.call_containing("grub-mkconfig") is not None


def test_set_timeout_grub_rolls_back_on_regenerate_failure(
    monkeypatch, tmp_path, fake_which, fake_run, privilege_paths
):
    """If grub-mkconfig fails after the sed edit, the previous
    /etc/default/grub must be restored so the boot menu doesn't break."""
    fake_which.add("grub-mkconfig")
    grub_default = tmp_path / "grub"
    grub_default.write_text("GRUB_TIMEOUT=5\n")
    monkeypatch.setattr(bootloader, "SYSTEMD_BOOT_LOADER_CONF", tmp_path / "no-loader")
    monkeypatch.setattr(bootloader, "GRUB_DEFAULT_PATH", grub_default)

    fake_run.set_response(["pkexec", "sed", "-i"], returncode=0)
    fake_run.set_response(["pkexec", "grub-mkconfig", "-o"], returncode=1, stderr="mkconfig failed")
    fake_run.set_response(["pkexec", "tee", str(grub_default)], returncode=0)

    result = bootloader.set_timeout(15)
    assert not result.ok
    assert fake_run.call_containing("tee") is not None  # restore attempted


def test_set_timeout_no_bootloader_raises(monkeypatch, tmp_path, fake_which):
    monkeypatch.setattr(bootloader, "SYSTEMD_BOOT_LOADER_CONF", tmp_path / "nope1")
    monkeypatch.setattr(bootloader, "GRUB_DEFAULT_PATH", tmp_path / "nope2")
    with pytest.raises(RuntimeError, match="No supported bootloader"):
        bootloader.set_timeout(15)


def test_regenerate_config_systemd_boot(monkeypatch, tmp_path, fake_which, fake_run):
    fake_which.add("bootctl")
    conf = tmp_path / "loader.conf"
    conf.write_text("timeout 5\n")
    monkeypatch.setattr(bootloader, "SYSTEMD_BOOT_LOADER_CONF", conf)
    bootloader.regenerate_config()
    assert fake_run.last_call() == ["pkexec", "bootctl", "update"]


def test_reinstall_systemd_boot(monkeypatch, tmp_path, fake_which, fake_run):
    fake_which.add("bootctl")
    conf = tmp_path / "loader.conf"
    conf.write_text("timeout 5\n")
    monkeypatch.setattr(bootloader, "SYSTEMD_BOOT_LOADER_CONF", conf)
    bootloader.reinstall()
    assert fake_run.last_call() == ["pkexec", "bootctl", "install"]


def test_reinstall_grub_refuses_automation(monkeypatch, tmp_path, fake_which):
    fake_which.add("grub-mkconfig")
    grub_default = tmp_path / "grub"
    grub_default.write_text("GRUB_TIMEOUT=5\n")
    monkeypatch.setattr(bootloader, "SYSTEMD_BOOT_LOADER_CONF", tmp_path / "no-loader")
    monkeypatch.setattr(bootloader, "GRUB_DEFAULT_PATH", grub_default)
    with pytest.raises(RuntimeError, match="grub-install"):
        bootloader.reinstall()
