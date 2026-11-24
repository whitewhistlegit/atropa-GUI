"""Tests for atropa.backend.kernels and the helper's kernel operations."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from atropa import helper
from atropa.backend import bootloader, kernels, pacman


@pytest.fixture
def system(tmp_path, monkeypatch, fake_run, fake_which):
    """Two kernels (zen running, lts), one DKMS leftover, one hand-installed kernel, GRUB."""
    modules = tmp_path / "modules"
    for release, pkgbase in (("7.3.5-zen1-1-zen", "linux-zen"), ("6.12.9-1-lts", "linux-lts")):
        directory = modules / release
        (directory / "kernel").mkdir(parents=True)
        (directory / "pkgbase").write_text(pkgbase + "\n")
    leftover = modules / "7.2.15-zen1-1-zen" / "updates" / "dkms"
    leftover.mkdir(parents=True)
    (leftover / "nvidia.ko.zst").write_bytes(b"x" * 2048)
    (modules / "6.1.0-custom" / "kernel").mkdir(parents=True)
    monkeypatch.setattr(kernels, "MODULES_DIR", modules)
    monkeypatch.setattr(kernels, "running_release", lambda: "7.3.5-zen1-1-zen")
    monkeypatch.setattr(bootloader, "detect", lambda: "grub")
    grub = tmp_path / "grub.cfg"
    grub.write_text("menuentry 'Arch Linux' {\n\tlinux /vmlinuz-linux-zen root=UUID=x rw\n}\n")
    monkeypatch.setattr(bootloader, "GRUB_CFG_PATH", grub)
    fake_run.set_response(
        ["pacman", "-Q"],
        stdout="linux-zen 7.3.5.zen1-1\nlinux-zen-headers 7.3.5.zen1-1\nlinux-lts 6.12.9-1\nnvidia-open-dkms 580-1\n",
    )
    monkeypatch.setattr(pacman, "_behind_local_database", lambda: [])
    return SimpleNamespace(modules=modules, grub=grub, fake_run=fake_run)


def test_status_finds_kernels_by_pkgbase(system):
    state = kernels.status()
    assert [(k.pkgbase, k.running, k.headers, k.boot_entry) for k in state.kernels] == [
        ("linux-lts", False, False, False),
        ("linux-zen", True, True, True),
    ]
    assert state.kernels[1].version == "7.3.5.zen1-1"
    assert state.dkms == ["nvidia-open-dkms"]


def test_leftovers_only_offer_folders_without_a_kernel_tree(system):
    leftovers = {lo.release: lo for lo in kernels.status().leftovers}
    assert leftovers["7.2.15-zen1-1-zen"].removable
    assert leftovers["7.2.15-zen1-1-zen"].size_mb == 0.0  # 2 KiB rounds down
    assert not leftovers["6.1.0-custom"].removable  # a kernel installed by hand


def test_warnings_name_missing_headers_and_boot_entries(system):
    found = kernels.warnings(kernels.status())
    assert any("linux-lts-headers isn't installed" in text for text in found)
    assert any("no entry for linux-lts" in text for text in found)


def test_a_single_kernel_gets_the_fallback_warning(system):
    (system.modules / "6.12.9-1-lts" / "pkgbase").unlink()
    (system.modules / "6.12.9-1-lts" / "kernel").rmdir()
    assert "linux-lts is the usual fallback" in kernels.warnings(kernels.status())[0]


def test_unreadable_grub_cfg_leaves_the_entry_unknown(system, monkeypatch):
    system.grub.chmod(0)
    if os.access(system.grub, os.R_OK):
        pytest.skip("running as root")
    assert {k.boot_entry for k in kernels.status().kernels} == {None}
    assert {k.boot_entry for k in kernels.status({"linux-zen"}).kernels} == {True, False}


def test_check_grub_entries_returns_names_only(system):
    system.fake_run.set_response(["pkexec", "grep"], stdout="vmlinuz-linux-zen\nvmlinuz-linux-lts\n")
    assert kernels.check_grub_entries() == {"linux-zen", "linux-lts"}
    assert system.fake_run.calls[-1][1:4] == ["grep", "-oE", "vmlinuz-[A-Za-z0-9._+-]+"]


def test_install_adds_headers_with_dkms_and_regenerates_grub(system):
    assert kernels.install("linux").ok
    commands = [call[1:] for call in system.fake_run.calls if call[0] == "pkexec"]
    assert commands == [
        ["pacman", "-S", "--needed", "--noconfirm", "linux", "linux-headers"],
        ["grub-mkconfig", "-o", str(system.grub)],
    ]


def test_install_only_offers_arch_kernels(system):
    with pytest.raises(ValueError):
        kernels.install("linux-evil")


def test_remove_refuses_the_running_kernel(system):
    with pytest.raises(RuntimeError, match="running kernel"):
        kernels.remove("linux-zen")


def test_remove_refuses_the_last_kernel(system, monkeypatch):
    monkeypatch.setattr(kernels, "running_release", lambda: "something-else")
    (system.modules / "6.12.9-1-lts" / "pkgbase").unlink()
    with pytest.raises(RuntimeError, match="only kernel"):
        kernels.remove("linux-zen")


def test_remove_takes_the_headers_along(system):
    assert kernels.remove("linux-lts").ok
    pacman_call = next(call for call in system.fake_run.calls if "-Rns" in call)
    assert pacman_call[-1] == "linux-lts"  # no headers installed for it


def test_entry_for_copies_the_running_kernels_entry(system, tmp_path, monkeypatch):
    entries = tmp_path / "esp" / "loader" / "entries"
    entries.mkdir(parents=True)
    (entries / "arch.conf").write_text(
        "title   Arch Linux\nlinux   /vmlinuz-linux-zen\ninitrd  /amd-ucode.img\n"
        "initrd  /initramfs-linux-zen.img\noptions root=UUID=x rw quiet\n"
    )
    monkeypatch.setattr(bootloader, "_loader_dirs", lambda: [entries.parent])
    path, content = kernels.entry_for("linux-lts")
    assert path.name == "atropa-linux-lts.conf"
    assert "linux   /vmlinuz-linux-lts\n" in content
    assert "initrd  /initramfs-linux-lts.img\n" in content
    assert "initrd  /amd-ucode.img\n" in content
    assert "options root=UUID=x rw quiet" in content
    assert content.startswith("title   Arch Linux (linux-lts)\n")


# ------------------------------------------------------------------- helper --

def test_helper_grep_allows_only_kernel_names_from_grub_cfg(monkeypatch):
    monkeypatch.setattr(helper.os.path, "realpath", os.path.normpath)
    assert helper.validate_command(["grep", "-oE", "vmlinuz-[A-Za-z0-9._+-]+", "/boot/grub/grub.cfg"])[0] == helper.KEEP
    with pytest.raises(helper.Refused):
        helper.validate_command(["grep", "-oE", "linux.*", "/boot/grub/grub.cfg"])


@pytest.mark.parametrize("path", [
    "/boot/loader/entries/atropa-linux-lts.conf",
    "/efi/loader/entries/atropa-linux.conf",
    "/boot/efi/loader/entries/atropa-linux-zen.conf",
])
def test_atropa_loader_entries_are_writable_and_ask(path, monkeypatch):
    monkeypatch.setattr(helper.os.path, "realpath", os.path.normpath)
    assert helper.checked_write_path(path) == path
    assert helper.needs_fresh_auth(["tee", path])


@pytest.mark.parametrize("path", [
    "/boot/loader/entries/arch.conf",          # not Atropa's
    "/home/me/loader/entries/atropa-x.conf",   # not a boot directory
    "/etc/loader/loader.conf",                 # loader.conf outside /boot and /efi
    "/home/me/loader/loader.conf",
])
def test_other_loader_paths_are_refused(path, monkeypatch):
    monkeypatch.setattr(helper.os.path, "realpath", os.path.normpath)
    with pytest.raises(helper.Refused):
        helper.checked_write_path(path)


@pytest.fixture
def module_root(tmp_path, monkeypatch):
    root = tmp_path / "modules"
    root.mkdir()
    monkeypatch.setattr(helper, "MODULES_ROOT", str(root))
    monkeypatch.setattr(helper.os, "uname", lambda: SimpleNamespace(release="7.3.5-zen1-1-zen"))
    owner = SimpleNamespace(returncode=1, stdout="")
    monkeypatch.setattr("subprocess.run", lambda *a, **k: owner)
    monkeypatch.setattr(helper, "_system_binary", lambda name: f"/usr/bin/{name}")
    return SimpleNamespace(root=root, owner=owner)


def test_modules_leftover_remove_deletes_a_dkms_leftover(module_root):
    leftover = module_root.root / "7.2.15-zen1-1-zen" / "updates" / "dkms"
    leftover.mkdir(parents=True)
    (leftover / "nvidia.ko.zst").write_text("x")
    assert helper.handle(["modules-leftover-remove", "7.2.15-zen1-1-zen"], tier=helper.KEEP) == 0
    assert not (module_root.root / "7.2.15-zen1-1-zen").exists()


@pytest.mark.parametrize("setup, release, message", [
    (lambda d: (d / "kernel").mkdir(), "6.1.0-custom", "belongs to an installed kernel"),
    (lambda d: (d / "pkgbase").write_text("linux"), "6.12.9-1-lts", "belongs to an installed kernel"),
    (lambda d: None, "7.3.5-zen1-1-zen", "running kernel"),
])
def test_modules_leftover_remove_refuses_real_kernels(module_root, setup, release, message):
    directory = module_root.root / release
    directory.mkdir()
    setup(directory)
    with pytest.raises(helper.Refused, match=message):
        helper.handle(["modules-leftover-remove", release], tier=helper.KEEP)
    assert directory.exists()


def test_modules_leftover_remove_refuses_an_owned_folder(module_root):
    (module_root.root / "7.2.0-1").mkdir()
    module_root.owner.returncode = 0
    module_root.owner.stdout = "some-package\n"
    with pytest.raises(helper.Refused, match="owned by some-package"):
        helper.handle(["modules-leftover-remove", "7.2.0-1"], tier=helper.KEEP)


@pytest.mark.parametrize("release", ["../../etc", "", "x/y", "-rf"])
def test_modules_leftover_remove_refuses_odd_names(module_root, release):
    with pytest.raises(helper.Refused):
        helper.handle(["modules-leftover-remove", release], tier=helper.KEEP)


def test_modules_leftover_remove_refuses_a_symlink(module_root, tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    (module_root.root / "7.2.0-1").symlink_to(target)
    with pytest.raises(helper.Refused, match="isn't a module directory"):
        helper.handle(["modules-leftover-remove", "7.2.0-1"], tier=helper.KEEP)
    assert target.exists()


def test_install_with_upgrade_uses_a_full_upgrade(system, monkeypatch):
    calls = []
    monkeypatch.setattr(pacman, "upgrade_and_install_streaming", lambda packages, on_line: calls.append(packages) or
                        SimpleNamespace(ok=True, returncode=0))
    kernels.install("linux-lts", upgrade=True)
    assert calls == [["linux-lts", "linux-lts-headers"]]


def test_install_passes_on_the_partial_upgrade_refusal(system, monkeypatch):
    monkeypatch.setattr(pacman, "_behind_local_database", lambda: ["glibc"])
    with pytest.raises(pacman.PartialUpgradeError):
        kernels.install("linux-lts")
