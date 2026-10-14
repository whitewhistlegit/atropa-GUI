"""Tests for atropa.backend.bootloader."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from atropa.backend import bootloader


@pytest.fixture
def boot_env(tmp_path, monkeypatch):
    """Nothing installed until a test creates it: ESP candidates, EFI variables, /etc/default/grub and grub.cfg."""
    env = SimpleNamespace(
        efi=tmp_path / "efi", boot=tmp_path / "boot", boot_efi=tmp_path / "boot-efi",
        efivars=tmp_path / "efivars", grub=tmp_path / "default-grub", grub_cfg=tmp_path / "grub.cfg",
    )
    monkeypatch.setattr(bootloader, "ESP_CANDIDATES", (env.efi, env.boot, env.boot_efi))
    monkeypatch.setattr(bootloader, "EFIVARS_DIR", env.efivars)
    monkeypatch.setattr(bootloader, "GRUB_DEFAULT_PATH", env.grub)
    monkeypatch.setattr(bootloader, "GRUB_CFG_PATH", env.grub_cfg)
    return env


def make_esp(root: Path, loader_conf: str | None = "timeout 5\n", entries: dict[str, str] | None = None) -> Path:
    (root / "loader" / "entries").mkdir(parents=True)
    if loader_conf is not None:
        (root / "loader" / "loader.conf").write_text(loader_conf)
    for name, text in (entries or {}).items():
        (root / "loader" / "entries" / name).write_text(text)
    return root


def set_efivar(env, name: str, value: str = "") -> None:
    """An EFI variable the way efivarfs shows it: 4 attribute bytes, then a NUL-terminated UTF-16 string."""
    env.efivars.mkdir(exist_ok=True)
    data = (value + "\0").encode("utf-16-le") if value else b""
    (env.efivars / f"{name}-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f").write_bytes(b"\x06\x00\x00\x00" + data)


def make_grub(env, fake_which) -> None:
    fake_which.add("grub-mkconfig")
    env.grub.write_text("GRUB_TIMEOUT=5\n")


def unreadable(monkeypatch, path: Path) -> None:
    """Reading `path` raises PermissionError, as a root-only file does for a normal user."""
    read_text = Path.read_text

    def guarded(self, *args, **kwargs):
        if self == path:
            raise PermissionError(13, "Permission denied", str(path))
        return read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded)


def written(fake_run, path: Path) -> list[str]:
    return [text for call, text in zip(fake_run.calls, fake_run.inputs) if call == ["pkexec", "tee", str(path)]]


# --------------------------------------------------------------- detect --

def test_detect_systemd_boot_on_an_esp_at_efi(boot_env, fake_which, fake_run):
    # The ESP isn't necessarily /boot - /efi is what the Arch wiki suggests first.
    fake_which.add("bootctl")
    make_esp(boot_env.efi)
    assert bootloader.detect() == "systemd-boot"


def test_detect_systemd_boot_from_its_efi_variable(boot_env, fake_which, fake_run):
    # A root-only ESP can't even be looked into - systemd-boot's LoaderInfo still says it booted us.
    fake_which.add("bootctl")
    set_efivar(boot_env, "LoaderInfo", "systemd-boot 257.5-2-arch")
    assert bootloader.detect() == "systemd-boot"


def test_detect_grub(boot_env, fake_which, fake_run):
    make_grub(boot_env, fake_which)
    assert bootloader.detect() == "grub"


def test_detect_grub_on_a_uefi_machine(boot_env, fake_which, fake_run):
    # Every UEFI machine has an ESP and bootctl comes with systemd, so
    # neither says systemd-boot: this one boots GRUB from /boot/efi.
    fake_which.add("bootctl")
    make_grub(boot_env, fake_which)
    (boot_env.boot_efi / "EFI" / "GRUB").mkdir(parents=True)
    fake_run.set_response(["bootctl", "--print-esp-path"], stdout=f"{boot_env.boot_efi}\n")
    assert bootloader.detect() == "grub"


def test_detect_grub_that_sets_loaderinfo_itself(boot_env, fake_which, fake_run):
    # GRUB 2.12's bli module sets LoaderInfo too, so the variable existing
    # doesn't mean systemd-boot - not even with its files left on the ESP.
    fake_which.add("bootctl")
    make_grub(boot_env, fake_which)
    make_esp(boot_env.efi)
    set_efivar(boot_env, "LoaderInfo", "GRUB 2.12")
    assert bootloader.detect() == "grub"


def test_detect_goes_by_the_loader_that_booted_when_both_are_installed(boot_env, fake_which, fake_run):
    fake_which.add("bootctl")
    make_grub(boot_env, fake_which)  # the grub package is still installed
    make_esp(boot_env.efi)
    set_efivar(boot_env, "LoaderInfo", "systemd-boot 257.5-2-arch")
    assert bootloader.detect() == "systemd-boot"


def test_detect_prefers_grub_when_no_loader_says(boot_env, fake_which, fake_run):
    # systemd-boot always sets LoaderInfo, so without it GRUB is the likelier one.
    fake_which.add("bootctl")
    make_grub(boot_env, fake_which)
    make_esp(boot_env.efi)
    assert bootloader.detect() == "grub"


def test_detect_unknown_when_the_loader_that_booted_cant_be_managed(boot_env, fake_which, fake_run):
    # GRUB booted this machine but grub-mkconfig isn't there: systemd-boot's
    # leftover files don't make it the bootloader.
    fake_which.add("bootctl")
    make_esp(boot_env.efi)
    set_efivar(boot_env, "LoaderInfo", "GRUB 2.12")
    assert bootloader.detect() == "unknown"


def test_detect_unknown_when_neither(boot_env, fake_which, fake_run):
    assert bootloader.detect() == "unknown"


def test_detect_unknown_for_a_bare_esp(boot_env, fake_which, fake_run):
    fake_which.add("bootctl")
    boot_env.efi.mkdir()
    fake_run.set_response(["bootctl", "--print-esp-path"], stdout=f"{boot_env.efi}\n")
    assert bootloader.detect() == "unknown"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"\x06\x00\x00\x00" + "systemd-boot 257.5-2-arch\0".encode("utf-16-le"), "systemd-boot 257.5-2-arch"),
        (b"\x06\x00\x00\x00" + "GRUB 2.12".encode("utf-16-le"), "GRUB 2.12"),  # no terminator
        (b"\x06\x00\x00\x00", ""),  # set, but empty
        (None, ""),  # not set at all: a BIOS boot, or a loader that doesn't say
    ],
    ids=["systemd-boot", "grub-unterminated", "empty", "not-set"],
)
def test_loader_info_reads_the_efi_variable(boot_env, raw, expected):
    if raw is not None:
        boot_env.efivars.mkdir()
        (boot_env.efivars / "LoaderInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f").write_bytes(raw)
    assert bootloader._loader_info() == expected


def test_esp_path_asks_bootctl_first(boot_env, fake_which, fake_run, tmp_path):
    fake_which.add("bootctl")
    elsewhere = make_esp(tmp_path / "custom-esp")
    make_esp(boot_env.boot)
    fake_run.set_response(["bootctl", "--print-esp-path"], stdout=f"{elsewhere}\n")
    assert bootloader.esp_path() == elsewhere


# --------------------------------------------------------------- get_info --

def test_systemd_boot_info_parses_timeout_and_entries(boot_env, fake_which, fake_run):
    fake_which.add("bootctl")
    make_esp(
        boot_env.efi,
        loader_conf="timeout 5\ndefault arch.conf\n",
        entries={"arch.conf": "title Arch Linux\nlinux /vmlinuz\n", "fallback.conf": "linux /vmlinuz-fallback\n"},
    )
    info = bootloader.get_info()
    assert info.kind == "systemd-boot"
    assert info.default_timeout == "5"
    titles = {e.title for e in info.entries}
    assert "Arch Linux" in titles
    assert "fallback" in titles  # falls back to file stem when no title line


def test_systemd_boot_info_last_timeout_line_wins(boot_env, fake_which, fake_run):
    fake_which.add("bootctl")
    make_esp(boot_env.efi, loader_conf="timeout 5\n#timeout 9\ntimeout 2\n")
    assert bootloader.get_info().default_timeout == "2"


def test_systemd_boot_info_reads_a_root_only_esp_in_one_privileged_call(boot_env, fake_which, fake_run, monkeypatch):
    fake_which.add("bootctl")
    loader = make_esp(boot_env.efi) / "loader"
    real_is_file = Path.is_file

    def is_file(self):
        if str(self).startswith(str(loader)):
            raise PermissionError(13, "Permission denied")
        return real_is_file(self)

    monkeypatch.setattr(Path, "is_file", is_file)
    fake_run.set_response(
        ["pkexec", "grep", "-rH", "--include=*.conf", "", str(loader)],
        stdout=(
            f"{loader}/loader.conf:timeout 3\n"
            f"{loader}/entries/arch.conf:title Arch Linux\n"
            f"{loader}/entries/arch.conf:linux /vmlinuz-linux\n"
        ),
    )
    info = bootloader.get_info()
    assert info.default_timeout == "3"
    assert [e.title for e in info.entries] == ["Arch Linux"]
    assert [c for c in fake_run.calls if c[0] == "pkexec"] == [
        ["pkexec", "grep", "-rH", "--include=*.conf", "", str(loader)]
    ]


def test_grub_info_parses_timeout_and_menu_entries(boot_env, fake_which, fake_run):
    fake_which.add("grub-mkconfig")
    boot_env.grub.write_text("GRUB_TIMEOUT=10\nGRUB_DEFAULT=0\n")
    boot_env.grub_cfg.write_text(
        "menuentry 'Arch Linux' --class arch {\n"
        "submenu 'Advanced options for Arch Linux' {\n"
        "\tmenuentry 'Arch Linux, with Linux linux' --class arch {\n"
        "}\n"
        "menuentry 'Windows' --class windows {\n"
    )

    info = bootloader.get_info()
    assert info.kind == "grub"
    assert info.default_timeout == "10"
    assert [e.title for e in info.entries] == ["Arch Linux", "Windows"]  # top level only, as before
    assert info.entries_error == ""


def test_grub_info_unquotes_titles_and_timeout_the_way_the_shell_does(boot_env, fake_which, fake_run):
    # Grub Customizer double-quotes titles, which used to give no entries at all;
    # grub-mkconfig writes an apostrophe as '\''; a hand-written entry may have no
    # space before its brace. A quoted timeout used to read as '"5"'.
    fake_which.add("grub-mkconfig")
    boot_env.grub.write_text('GRUB_TIMEOUT="5"\nGRUB_TIMEOUT_STYLE="menu"\n')
    boot_env.grub_cfg.write_text(
        "menuentry \"Arch Linux, with Linux linux-zen\" --class arch $menuentry_id_option 'gnulinux-zen' {\n"
        "menuentry 'Bob'\\''s Arch' --class arch {\n"
        'menuentry "Custom entry"{\n'
        "menuentry 'Braces { inside' {\n"
    )

    info = bootloader.get_info()

    assert info.default_timeout == "5"
    assert [e.title for e in info.entries] == [
        "Arch Linux, with Linux linux-zen", "Bob's Arch", "Custom entry", "Braces { inside",
    ]


def test_grub_info_reads_a_root_only_grub_cfg_with_one_privileged_grep(boot_env, fake_which, fake_run, monkeypatch):
    # grub-mkconfig writes grub.cfg with umask 077: read as the user, the entries were always empty.
    make_grub(boot_env, fake_which)
    boot_env.grub_cfg.write_text("")
    unreadable(monkeypatch, boot_env.grub_cfg)
    fake_run.set_response(["pkexec", "grep"], stdout='menuentry "Arch Linux" --class arch {\n')

    info = bootloader.get_info()

    assert [e.title for e in info.entries] == ["Arch Linux"]
    assert fake_run.last_call() == ["pkexec", "grep", "-E", "^menuentry", str(boot_env.grub_cfg)]


def test_grub_info_keeps_the_rest_when_the_entries_cant_be_read(boot_env, fake_which, fake_run, monkeypatch):
    make_grub(boot_env, fake_which)
    boot_env.grub_cfg.write_text("")
    unreadable(monkeypatch, boot_env.grub_cfg)
    fake_run.set_response(
        ["pkexec", "grep"], stderr="Error executing command as another user: Request dismissed", returncode=126
    )

    info = bootloader.get_info()

    assert info.kind == "grub"
    assert info.default_timeout == "5"
    assert info.entries == []
    assert "Request dismissed" in info.entries_error


def test_grub_info_without_a_grub_cfg_has_no_entries_and_no_error(boot_env, fake_which, fake_run):
    make_grub(boot_env, fake_which)

    info = bootloader.get_info()

    assert info.entries == []
    assert info.entries_error == ""
    assert fake_run.calls == []


def test_get_info_unknown_kind(boot_env, fake_which, fake_run):
    info = bootloader.get_info()
    assert info.kind == "unknown"
    assert info.entries == []


# --------------------------------------------------------------- set_timeout --

def test_set_timeout_grub_success_regenerates_config(boot_env, fake_which, fake_run, privilege_paths):
    fake_which.add("grub-mkconfig")
    boot_env.grub.write_text("GRUB_TIMEOUT=5\n")
    result = bootloader.set_timeout(15)
    assert result.ok
    assert fake_run.call_containing("grub-mkconfig") is not None


def test_set_timeout_grub_rolls_back_on_regenerate_failure(boot_env, fake_which, fake_run, privilege_paths):
    """If grub-mkconfig fails after the edit, the previous
    /etc/default/grub must be restored so the boot menu doesn't break."""
    fake_which.add("grub-mkconfig")
    boot_env.grub.write_text("GRUB_TIMEOUT=5\n")
    fake_run.set_response(["pkexec", "grub-mkconfig", "-o"], returncode=1, stderr="mkconfig failed")

    result = bootloader.set_timeout(15)
    assert not result.ok
    assert "restored the previous" in result.stderr
    assert written(fake_run, boot_env.grub) == ["GRUB_TIMEOUT=15\n", "GRUB_TIMEOUT=5\n"]


def test_set_timeout_grub_restores_a_commented_out_timeout(boot_env, fake_which, fake_run, privilege_paths):
    fake_which.add("grub-mkconfig")
    boot_env.grub.write_text('GRUB_DEFAULT=0\n#GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX=""\n')
    assert bootloader.set_timeout(15).ok
    assert written(fake_run, boot_env.grub) == ['GRUB_DEFAULT=0\nGRUB_TIMEOUT=15\nGRUB_CMDLINE_LINUX=""\n']


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("timeout 5\ndefault arch.conf\n", "timeout 15\ndefault arch.conf\n"),
        # The stock example ships it commented out - the old edit changed nothing then.
        ("#timeout 3\ndefault arch.conf\n", "timeout 15\ndefault arch.conf\n"),
        ("default arch.conf\n", "default arch.conf\ntimeout 15\n"),
        ("timeout 5\ntimeout 2\n", "timeout 15\ntimeout 15\n"),  # the last one is the one that counts
    ],
)
def test_set_timeout_systemd_boot_edits_loader_conf_on_the_esp(
    boot_env, fake_which, fake_run, privilege_paths, before, after
):
    fake_which.add("bootctl")
    esp = make_esp(boot_env.efi, loader_conf=before)
    assert bootloader.set_timeout(15).ok
    assert written(fake_run, esp / "loader" / "loader.conf") == [after]


def test_set_timeout_systemd_boot_drops_a_timeout_chosen_in_the_boot_menu(
    boot_env, fake_which, fake_run, privilege_paths
):
    # LoaderConfigTimeout overrides loader.conf: without clearing it the edit changes nothing.
    fake_which.add("bootctl")
    make_esp(boot_env.efi)
    set_efivar(boot_env, "LoaderConfigTimeout")
    assert bootloader.set_timeout(15).ok
    assert fake_run.last_call() == ["pkexec", "bootctl", "set-timeout", ""]


def test_set_timeout_systemd_boot_leaves_efi_variables_alone_otherwise(boot_env, fake_which, fake_run, privilege_paths):
    fake_which.add("bootctl")
    make_esp(boot_env.efi)
    bootloader.set_timeout(15)
    assert fake_run.call_containing("set-timeout") is None


def test_set_timeout_no_bootloader_raises(boot_env, fake_which, fake_run):
    with pytest.raises(RuntimeError, match="No supported bootloader"):
        bootloader.set_timeout(15)


def test_regenerate_config_systemd_boot(boot_env, fake_which, fake_run):
    fake_which.add("bootctl")
    make_esp(boot_env.boot)
    bootloader.regenerate_config()
    assert fake_run.last_call() == ["pkexec", "bootctl", "update"]


def test_reinstall_systemd_boot(boot_env, fake_which, fake_run):
    fake_which.add("bootctl")
    make_esp(boot_env.boot)
    bootloader.reinstall()
    assert fake_run.last_call() == ["pkexec", "bootctl", "install"]


def test_reinstall_grub_refuses_automation(boot_env, fake_which, fake_run):
    fake_which.add("grub-mkconfig")
    boot_env.grub.write_text("GRUB_TIMEOUT=5\n")
    with pytest.raises(RuntimeError, match="grub-install"):
        bootloader.reinstall()
