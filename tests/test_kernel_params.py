"""Tests for kernel parameters (kernel_params.py), the helper's previous-entry
operations, and wiring pam_pwquality into system-auth."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from atropa import helper
from atropa.backend import bootloader, hardening, kernel_params, kernels

STOCK_SYSTEM_AUTH = (Path(__file__).parent / "fixtures" / "stock" / "pam.d-system-auth").read_text()

# What grub-mkconfig's 10_linux writes for two kernels (shortened).
GRUB_CFG = """\
### BEGIN /etc/grub.d/10_linux ###
menuentry 'Arch Linux' --class arch --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-simple-abc' {
\tload_video
\tsearch --no-floppy --fs-uuid --set=root abc
\techo\t'Loading Linux linux ...'
\tlinux\t/vmlinuz-linux root=UUID=abc rw rootflags=subvol=@ loglevel=3 quiet
\tinitrd\t/initramfs-linux.img
}
submenu 'Advanced options for Arch Linux' $menuentry_id_option 'gnulinux-advanced-abc' {
\tmenuentry 'Arch Linux, with Linux linux-lts' --class arch $menuentry_id_option 'gnulinux-linux-lts-advanced-abc' {
\t\tsearch --no-floppy --fs-uuid --set=root abc
\t\tlinux\t/vmlinuz-linux-lts root=UUID=abc rw rootflags=subvol=@ loglevel=3 quiet
\t\tinitrd\t/initramfs-linux-lts.img
\t}
\tmenuentry 'Arch Linux, with Linux linux-lts (fallback initramfs)' --class arch $menuentry_id_option 'gnulinux-linux-lts-fallback-abc' {
\t\tlinux\t/vmlinuz-linux-lts root=UUID=abc rw rootflags=subvol=@ loglevel=3 quiet
\t\tinitrd\t/initramfs-linux-lts-fallback.img
\t}
}
### END /etc/grub.d/10_linux ###
"""


# ------------------------------------------------------------- with_changes --

def test_with_changes_adds_and_removes():
    assert kernel_params.with_changes(["quiet", "loglevel=3"], ["slab_nomerge"], ["quiet"]) == ["loglevel=3", "slab_nomerge"]


def test_a_new_lsm_list_replaces_the_old_one():
    assert kernel_params.with_changes(["quiet", kernel_params.LSM_APPARMOR], [kernel_params.LSM_SELINUX], []) == [
        "quiet", kernel_params.LSM_SELINUX,
    ]


def test_removing_by_name_drops_every_value():
    assert kernel_params.with_changes(["lsm=a,b", "quiet"], [], ["lsm"]) == ["quiet"]


@pytest.mark.parametrize("param", ["init=/bin/sh quiet", "a\"b", "$(x)", "", "-x", "a;b", "a\nb"])
def test_parameters_are_one_plain_word(param):
    with pytest.raises(ValueError):
        kernel_params.with_changes([], [param], [])


# ------------------------------------------------------------------- GRUB --

DEFAULT_GRUB = """GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_CMDLINE_LINUX_DEFAULT="loglevel=3 quiet"
GRUB_CMDLINE_LINUX="rootflags=subvol=@"
"""


def test_grub_text_puts_additions_in_default_and_removes_from_both():
    configured = ["rootflags=subvol=@", "loglevel=3", "quiet"]
    new = ["rootflags=subvol=@", "loglevel=3", kernel_params.LSM_APPARMOR]
    text = kernel_params._grub_text_with(DEFAULT_GRUB, configured, new)
    assert f'GRUB_CMDLINE_LINUX_DEFAULT="loglevel=3 {kernel_params.LSM_APPARMOR}"' in text
    assert 'GRUB_CMDLINE_LINUX="rootflags=subvol=@"' in text
    assert "GRUB_TIMEOUT=5" in text


@pytest.fixture
def grub(tmp_path, monkeypatch, fake_run, fake_which):
    default = tmp_path / "grub"
    default.write_text(DEFAULT_GRUB)
    monkeypatch.setattr(bootloader, "GRUB_DEFAULT_PATH", default)
    monkeypatch.setattr(bootloader, "detect", lambda: "grub")
    monkeypatch.setattr(kernel_params, "GRUB_CUSTOM_CFG", tmp_path / "custom.cfg")
    monkeypatch.setattr(kernel_params, "running", lambda: ["BOOT_IMAGE=/vmlinuz-linux", "root=UUID=abc"])
    running = kernels.Kernel("linux", "7.3.5-arch1-1", "7.3.5", True, False, True)
    monkeypatch.setattr(kernels, "status", lambda *a: SimpleNamespace(kernels=[running]))
    return SimpleNamespace(default=default, fake_run=fake_run)


def test_read_grub_lists_both_variables(grub):
    state = kernel_params.read()
    assert state.supported and state.configured == ["rootflags=subvol=@", "loglevel=3", "quiet"]


def test_apply_on_grub_keeps_the_entry_first_then_edits_and_regenerates(grub):
    assert kernel_params.apply([kernel_params.LSM_APPARMOR], []).ok
    commands = [call[1:3] for call in grub.fake_run.calls if call[0] == "pkexec"]
    assert commands[0][0] == "grub-keep-previous" and grub.fake_run.calls[0][-1] == "linux"
    assert commands[1] == ["tee", str(grub.default)]
    assert commands[2] == ["grub-mkconfig", "-o"]


def test_apply_on_grub_puts_the_file_back_when_regeneration_fails(grub):
    grub.fake_run.set_response(["pkexec", "grub-mkconfig"], stderr="syntax error", returncode=1)
    result = kernel_params.apply(["slab_nomerge"], [])
    assert not result.ok and "restored the previous" in result.stderr
    assert grub.fake_run.inputs[-1] == DEFAULT_GRUB


def test_apply_with_nothing_to_change_runs_nothing(grub):
    assert kernel_params.apply(["quiet"], []).ok
    assert grub.fake_run.calls == []


# ----------------------------------------------------------- systemd-boot --

def test_apply_on_systemd_boot_copies_the_entry_then_edits_options(tmp_path, monkeypatch, fake_run, fake_which):
    entries = tmp_path / "esp" / "loader" / "entries"
    entries.mkdir(parents=True)
    entry = entries / "arch.conf"
    entry.write_text("title   Arch Linux\nlinux   /vmlinuz-linux\ninitrd  /initramfs-linux.img\noptions root=UUID=x rw quiet\n")
    monkeypatch.setattr(bootloader, "detect", lambda: "systemd-boot")
    monkeypatch.setattr(bootloader, "_loader_dirs", lambda: [entries.parent])
    running = kernels.Kernel("linux", "7.3.5-arch1-1", "7.3.5", True, False, True)
    monkeypatch.setattr(kernels, "status", lambda *a: SimpleNamespace(kernels=[running]))

    state = kernel_params.read()
    assert state.configured == ["root=UUID=x", "rw", "quiet"]
    assert kernel_params.apply(["slab_nomerge"], ["quiet"]).ok

    previous, edited = fake_run.calls[0], fake_run.calls[1]
    assert previous[1:] == ["tee", str(entries / "atropa-previous-arch.conf")]
    assert fake_run.inputs[0].startswith("title   Arch Linux (kernel parameters before ")
    assert "options root=UUID=x rw quiet" in fake_run.inputs[0]
    assert edited[1:] == ["tee", str(entry)]
    assert fake_run.inputs[1].endswith("options root=UUID=x rw slab_nomerge\n")


# ------------------------------------------------------------------ helper --

@pytest.fixture
def grub_files(tmp_path, monkeypatch):
    cfg = tmp_path / "grub.cfg"
    cfg.write_text(GRUB_CFG)
    custom = tmp_path / "custom.cfg"
    monkeypatch.setattr(helper, "GRUB_CFG", str(cfg))
    monkeypatch.setattr(helper, "GRUB_CUSTOM_CFG", str(custom))
    return custom


def test_grub_keep_previous_copies_the_running_kernels_entry(grub_files):
    assert helper.handle(["grub-keep-previous", "2026-11-24", "linux-lts"], tier=helper.ASK) == 0
    text = grub_files.read_text()
    assert text.startswith(helper.ATROPA_MARKER)
    assert "menuentry 'Arch Linux, with Linux linux-lts (kernel parameters before 2026-11-24)'" in text
    assert "'gnulinux-linux-lts-advanced-abc-atropa-previous'" in text
    assert "linux\t/vmlinuz-linux-lts root=UUID=abc rw rootflags=subvol=@ loglevel=3 quiet" in text
    assert "fallback" not in text
    assert text.rstrip().endswith("}") and not text.splitlines()[-1].startswith("\t")
    assert oct(os.stat(grub_files).st_mode & 0o777) == "0o600"


def test_grub_keep_previous_finds_the_top_level_entry(grub_files):
    helper.handle(["grub-keep-previous", "2026-11-24", "linux"], tier=helper.ASK)
    assert "menuentry 'Arch Linux (kernel parameters before 2026-11-24)'" in grub_files.read_text()


def test_grub_keep_previous_leaves_a_users_custom_cfg_alone(grub_files):
    grub_files.write_text("menuentry 'Windows' { chainloader /EFI/Microsoft/Boot/bootmgfw.efi }\n")
    with pytest.raises(helper.Refused, match="wasn't written by Atropa"):
        helper.handle(["grub-keep-previous", "2026-11-24", "linux"], tier=helper.ASK)
    with pytest.raises(helper.Refused):
        helper.handle(["grub-keep-previous", "--clear"], tier=helper.ASK)
    assert "Windows" in grub_files.read_text()


def test_grub_keep_previous_clear_removes_atropas(grub_files):
    helper.handle(["grub-keep-previous", "2026-11-24", "linux"], tier=helper.ASK)
    helper.handle(["grub-keep-previous", "--clear"], tier=helper.ASK)
    assert not grub_files.exists()


@pytest.mark.parametrize("argv", [
    ["grub-keep-previous", "today", "linux"],
    ["grub-keep-previous", "2026-11-24", "../x"],
    ["grub-keep-previous", "2026-11-24", "linux-zen"],  # no entry boots it
])
def test_grub_keep_previous_refuses(grub_files, argv):
    with pytest.raises(helper.Refused):
        helper.handle(argv, tier=helper.ASK)


def test_boot_entry_operations_ask_every_time():
    assert helper.needs_fresh_auth(["grub-keep-previous", "2026-11-24", "linux"])
    assert helper.needs_fresh_auth(["loader-entry-remove", "/boot/loader/entries/atropa-previous-arch.conf"])
    with pytest.raises(helper.Refused, match="asks for a password every time"):
        helper.handle(["grub-keep-previous", "--clear"], tier=helper.KEEP)


def test_loader_entries_existing_ones_editable_new_ones_only_atropas(tmp_path, monkeypatch):
    monkeypatch.setattr(helper, "BOOT_DIRS", (str(tmp_path) + "/",))
    entries = tmp_path / "loader" / "entries"
    entries.mkdir(parents=True)
    (entries / "arch.conf").write_text("x")
    assert helper.checked_write_path(str(entries / "arch.conf"))
    assert helper.checked_write_path(str(entries / "atropa-previous-arch.conf"))
    with pytest.raises(helper.Refused):
        helper.checked_write_path(str(entries / "new-entry.conf"))
    with pytest.raises(helper.Refused, match="isn't one of Atropa's"):
        helper.handle(["loader-entry-remove", str(entries / "arch.conf")], tier=helper.ASK)
    assert (entries / "arch.conf").exists()


# ------------------------------------------------------------- pwquality --

@pytest.fixture
def system_auth(tmp_path, monkeypatch, fake_run, fake_which):
    path = tmp_path / "system-auth"
    path.write_text(STOCK_SYSTEM_AUTH)
    module = tmp_path / "pam_pwquality.so"
    module.write_text("")
    monkeypatch.setattr(hardening, "PAM_SYSTEM_AUTH", path)
    monkeypatch.setattr(hardening, "PWQUALITY_MODULE", module)
    return SimpleNamespace(path=path, fake_run=fake_run)


def test_wire_pwquality_goes_above_the_homed_line(system_auth):
    assert hardening.wire_pwquality().ok
    written = system_auth.fake_run.inputs[-1].splitlines()
    password = [line for line in written if line.lstrip("-").startswith("password")]
    assert password[0] == hardening._PWQUALITY_LINE
    assert "pam_systemd_home.so" in password[1]
    assert password[2].split() == ["password", "required", "pam_unix.so", "try_first_pass", "nullok", "shadow", "use_authtok"]
    # Nothing outside the password section moved.
    assert [line for line in written if not line.lstrip("-").startswith("password")] == [
        line for line in STOCK_SYSTEM_AUTH.splitlines() if not line.lstrip("-").startswith("password")
    ]


def test_unwire_pwquality_restores_the_stock_file(system_auth):
    hardening.wire_pwquality()
    system_auth.path.write_text(system_auth.fake_run.inputs[-1])
    hardening.unwire_pwquality()
    assert system_auth.fake_run.inputs[-1] == STOCK_SYSTEM_AUTH


def test_wire_pwquality_refuses_a_hand_edited_file(system_auth):
    system_auth.path.write_text(STOCK_SYSTEM_AUTH.replace("try_first_pass nullok shadow", "sha512 shadow"))
    with pytest.raises(RuntimeError, match="isn't laid out"):
        hardening.wire_pwquality()
    assert system_auth.fake_run.calls == []


def test_wire_pwquality_needs_the_module(system_auth, tmp_path, monkeypatch):
    monkeypatch.setattr(hardening, "PWQUALITY_MODULE", tmp_path / "missing.so")
    with pytest.raises(RuntimeError, match="libpwquality"):
        hardening.wire_pwquality()


def test_system_auth_writes_ask():
    assert helper.needs_fresh_auth(["tee", "/etc/pam.d/system-auth"])
