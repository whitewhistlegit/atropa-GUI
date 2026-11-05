"""Tests for atropa.backend.boot_security."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from atropa.backend import boot_security


@pytest.fixture
def boot_paths(monkeypatch, tmp_path):
    """Every file this module reads lives under tmp_path unless a test says otherwise."""
    state = SimpleNamespace(crypttab=tmp_path / "crypttab", efi=tmp_path / "efi")
    monkeypatch.setattr(boot_security, "CRYPTTAB", state.crypttab)
    monkeypatch.setattr(boot_security, "EFI_DIR", state.efi)
    return state


# ------------------------------------------------------------ root source --

def test_root_source_reads_findmnt(fake_run):
    fake_run.set_response(["findmnt"], stdout="/dev/mapper/root\n")
    assert boot_security.root_source() == "/dev/mapper/root"


def test_root_source_failure_is_an_error(fake_run):
    fake_run.set_response(["findmnt"], stderr="findmnt: /: not mounted", returncode=1)
    with pytest.raises(RuntimeError, match="not mounted"):
        boot_security.root_source()


def test_root_source_refuses_empty_output(fake_run):
    fake_run.set_response(["findmnt"], stdout="\n")
    with pytest.raises(RuntimeError, match="no source"):
        boot_security.root_source()


# ---------------------------------------------------------------- crypttab --

def test_read_crypttab_parses_comments_and_optional_fields(boot_paths):
    boot_paths.crypttab.write_text(
        "# name device keyfile options\n"
        "root UUID=1234 none luks,discard\n"
        "\n"
        "swap /dev/nvme0n1p9 none\n"
        "broken\n",
        encoding="utf-8",
    )
    entries = boot_security.read_crypttab()
    assert [entry.name for entry in entries] == ["root", "swap"]
    assert entries[0].device == "UUID=1234"
    assert entries[0].options == "luks,discard"
    assert entries[1].keyfile == "none"
    assert entries[1].options == ""


def test_read_crypttab_missing_file_is_empty(boot_paths):
    assert boot_security.read_crypttab() == []


# -------------------------------------------------------------- encryption --

def test_encryption_detected_through_lsblk_stack(fake_run, boot_paths):
    boot_paths.crypttab.write_text("root UUID=1234 none luks\n", encoding="utf-8")
    fake_run.set_response(["findmnt"], stdout="/dev/mapper/root\n")
    fake_run.set_response(["lsblk", "-s"], stdout="root crypt\nnvme0n1p3 part\nnvme0n1 disk\n")

    status = boot_security.encryption_status()

    assert status.encrypted is True
    assert status.devices == ["root"]
    assert "LUKS device 'root'" in status.detail
    assert status.crypttab[0].device == "UUID=1234"


def test_encryption_falls_back_to_crypttab_when_lsblk_fails(fake_run, boot_paths):
    boot_paths.crypttab.write_text("root UUID=1234 none luks\n", encoding="utf-8")
    fake_run.set_response(["findmnt"], stdout="/dev/mapper/root\n")
    fake_run.set_response(["lsblk"], stderr="lsblk: not found", returncode=1)

    status = boot_security.encryption_status()

    assert status.encrypted is True
    assert "listed in /etc/crypttab" in status.detail


def test_encryption_plain_partition_is_false(fake_run, boot_paths):
    fake_run.set_response(["findmnt"], stdout="/dev/nvme0n1p3\n")
    fake_run.set_response(["lsblk", "-s"], stdout="nvme0n1p3 part\nnvme0n1 disk\n")

    status = boot_security.encryption_status()

    assert status.encrypted is False
    assert "plain" in status.detail


def test_encryption_is_unknown_when_nothing_can_be_read(fake_run, boot_paths):
    fake_run.set_response(["findmnt"], stdout="/dev/nvme0n1p3\n")
    fake_run.set_response(["lsblk"], returncode=1)

    status = boot_security.encryption_status()

    # Not False: "can't tell" must never render as "unencrypted".
    assert status.encrypted is None
    assert "can't be confirmed" in status.detail


def test_encryption_strips_btrfs_subvolume_suffix(fake_run, boot_paths):
    fake_run.set_response(["findmnt"], stdout="/dev/nvme0n1p2[/@]\n")
    fake_run.set_response(["lsblk"], stdout="nvme0n1p2 part\n")

    boot_security.encryption_status()

    assert fake_run.call_containing("/dev/nvme0n1p2") is not None
    assert fake_run.call_containing("/dev/nvme0n1p2[/@]") is None


# ------------------------------------------------------------- secure boot --

def test_legacy_bios_means_secure_boot_does_not_apply(fake_run, boot_paths):
    status = boot_security.secure_boot_status()
    assert status.supported is False
    assert status.enabled is None
    assert "legacy BIOS" in status.detail
    assert fake_run.calls == []


def test_bootctl_reports_enabled(fake_run, fake_which, boot_paths):
    boot_paths.efi.mkdir()
    fake_which.add("bootctl")
    fake_run.set_response(["bootctl", "status"], stdout="System:\n      Secure Boot: enabled (user)\n")

    status = boot_security.secure_boot_status()

    assert status.enabled is True
    assert status.source == "bootctl"


def test_bootctl_reports_disabled(fake_run, fake_which, boot_paths):
    boot_paths.efi.mkdir()
    fake_which.add("bootctl")
    fake_run.set_response(["bootctl", "status"], stdout="      Secure Boot: disabled (setup)\n")

    assert boot_security.secure_boot_status().enabled is False


def test_mokutil_is_the_fallback(fake_run, fake_which, boot_paths):
    boot_paths.efi.mkdir()
    fake_which.add("mokutil")
    fake_run.set_response(["mokutil", "--sb-state"], stdout="SecureBoot enabled\n")

    status = boot_security.secure_boot_status()

    assert status.enabled is True
    assert status.source == "mokutil"


def test_unreadable_secure_boot_is_unknown_not_disabled(fake_run, fake_which, boot_paths):
    boot_paths.efi.mkdir()
    fake_which.add("bootctl")
    fake_run.set_response(["bootctl", "status"], returncode=1)

    status = boot_security.secure_boot_status()

    assert status.supported is True
    assert status.enabled is None


# ------------------------------------------------------------------ sbctl --

def test_sbctl_missing_says_how_to_install(fake_which, boot_paths):
    status = boot_security.sbctl_status()
    assert status.installed is False
    assert "pacman -S sbctl" in status.detail


def test_sbctl_status_parses_setup_mode_and_vendor_keys(fake_run, fake_which, boot_paths):
    fake_which.add("sbctl")
    fake_run.set_response(
        ["sbctl", "status"],
        stdout=(
            "Installed:      ✓ sbctl is installed\n"
            "Owner GUID:     1234\n"
            "Setup Mode:     ✗ Enabled\n"
            "Secure Boot:    ✓ Disabled\n"
            "Vendor Keys:    microsoft\n"
        ),
    )

    status = boot_security.sbctl_status()

    assert status.installed is True
    assert status.setup_mode is True
    assert status.secure_boot is False
    assert status.vendor_keys == "microsoft"
    assert "Setup mode" in status.detail


def test_sbctl_status_failure_is_an_error(fake_run, fake_which, boot_paths):
    fake_which.add("sbctl")
    fake_run.set_response(["sbctl", "status"], stderr="permission denied", returncode=1)
    with pytest.raises(RuntimeError, match="permission denied"):
        boot_security.sbctl_status()


def test_create_keys_goes_through_pkexec(fake_run, fake_which):
    fake_which.add("sbctl")
    boot_security.create_keys()
    assert fake_run.last_call() == ["pkexec", "sbctl", "create-keys"]


def test_enroll_keys_keeps_microsoft_keys_and_answers_the_prompt(fake_run, fake_which):
    fake_which.add("sbctl")
    boot_security.enroll_keys()
    assert fake_run.last_call() == ["pkexec", "sbctl", "enroll-keys", "--microsoft"]
    assert fake_run.inputs[-1] == "y\n"


def test_sign_all_goes_through_pkexec(fake_run, fake_which):
    fake_which.add("sbctl")
    boot_security.sign_all()
    assert fake_run.last_call() == ["pkexec", "sbctl", "sign-all"]


# ------------------------------------------------------------ compliance ---

def test_security_checks_score_encryption_and_secure_boot(fake_run, fake_which, boot_paths):
    boot_paths.efi.mkdir()
    fake_which.add("bootctl")
    fake_run.set_response(["findmnt"], stdout="/dev/mapper/root\n")
    fake_run.set_response(["lsblk"], stdout="root crypt\n")
    fake_run.set_response(["bootctl", "status"], stdout="Secure Boot: enabled (user)\n")

    checks = boot_security.security_checks()

    by_name = {check.name: check for check in checks}
    assert by_name["Disk encryption"].status == "pass"
    assert by_name["Secure Boot"].status == "pass"


def test_security_checks_do_not_hide_a_failure_behind_another(fake_run, boot_paths):
    fake_run.set_response(["findmnt"], returncode=1, stderr="findmnt broke")

    checks = boot_security.security_checks()

    by_name = {check.name: check for check in checks}
    assert by_name["Disk encryption"].status == "info"
    assert "Couldn't check" in by_name["Disk encryption"].detail
    # Secure Boot still gets a real answer even though encryption failed.
    assert by_name["Secure Boot"].status == "info"


def test_overview_isolates_each_check(fake_run, fake_which, boot_paths):
    boot_paths.efi.mkdir()
    fake_which.add("bootctl")
    fake_run.set_response(["findmnt"], returncode=1, stderr="findmnt broke")
    fake_run.set_response(["bootctl", "status"], stdout="Secure Boot: disabled\n")

    report = boot_security.overview()

    assert report.encryption is None
    assert "findmnt broke" in report.encryption_error
    assert report.secure_boot.enabled is False
    assert report.sbctl.installed is False
