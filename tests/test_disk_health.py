"""Tests for atropa.backend.disk_health."""

from __future__ import annotations

import pytest

from atropa.backend import disk_health


# ------------------------------------------------------------------ lsblk --

def test_list_disks_keeps_only_whole_disks(fake_run):
    fake_run.set_response(
        ["lsblk", "-dn", "-o", "NAME,TYPE"],
        stdout="sda disk\nsda1 part\nsr0 rom\nnvme0n1 disk\n",
    )

    assert disk_health.list_disks() == ["/dev/sda", "/dev/nvme0n1"]
    assert fake_run.calls == [["lsblk", "-dn", "-o", "NAME,TYPE"]]


def test_list_disks_skips_malformed_rows(fake_run):
    fake_run.set_response(["lsblk", "-dn", "-o", "NAME,TYPE"], stdout="sda\n\ndisk\nsdb disk extra\n")
    assert disk_health.list_disks() == ["/dev/sdb"]


def test_list_disks_nonzero_exit_raises(fake_run):
    fake_run.set_response(
        ["lsblk", "-dn", "-o", "NAME,TYPE"],
        stderr="lsblk: failed to access sysfs",
        returncode=1,
    )
    with pytest.raises(RuntimeError, match="failed to access sysfs"):
        disk_health.list_disks()


# ------------------------------------------------------------------ smart --

def test_smart_status_passed_reports_verdict_and_runs_exact_command(fake_run):
    verdict = "SMART overall-health self-assessment test result: PASSED"
    fake_run.set_response(
        ["smartctl", "-H", "/dev/sda"],
        stdout=f"smartctl 7.4 2023-08-01 r5530\n\n=== START OF READ SMART DATA SECTION ===\n{verdict}\n",
    )

    status = disk_health.smart_status("/dev/sda")
    assert status == disk_health.SmartStatus("/dev/sda", True, verdict)
    assert fake_run.calls == [["smartctl", "-H", "/dev/sda"]]


def test_smart_status_failed_reports_false(fake_run):
    fake_run.set_response(
        ["smartctl", "-H", "/dev/sdb"],
        stdout="SMART overall-health self-assessment test result: FAILED!\n",
    )
    status = disk_health.smart_status("/dev/sdb")
    assert status.passed is False
    assert status.detail == "SMART overall-health self-assessment test result: FAILED!"


def test_smart_status_accepts_scsi_health_status_ok(fake_run):
    fake_run.set_response(["smartctl", "-H", "/dev/sdc"], stdout="SMART Health Status: OK\n")
    status = disk_health.smart_status("/dev/sdc")
    assert status.passed is True
    assert status.detail == "SMART Health Status: OK"


def test_smart_status_without_verdict_is_unknown_with_first_line(fake_run):
    fake_run.set_response(
        ["smartctl", "-H", "/dev/sdd"],
        stdout="smartctl 7.4 2023-08-01 r5530\nVendor: ACME\n",
    )
    status = disk_health.smart_status("/dev/sdd")
    assert status.passed is None
    assert status.detail == "smartctl 7.4 2023-08-01 r5530"


def test_smart_status_prefail_exit_bit_overrides_passed_text(fake_run):
    fake_run.set_response(
        ["smartctl", "-H", "/dev/sde"],
        stdout="SMART overall-health self-assessment test result: PASSED\n",
        returncode=0x10,  # bit 4: a pre-fail attribute is at/below its threshold
    )
    assert disk_health.smart_status("/dev/sde").passed is False


def test_smart_status_failed_probe_shows_stderr_reason(fake_run):
    fake_run.set_response(
        ["smartctl", "-H", "/dev/sdf"],
        stdout="smartctl 7.4 2023-08-01 r5530\n",
        stderr="Smartctl open device: /dev/sdf failed: Permission denied",
        returncode=2,
    )
    status = disk_health.smart_status("/dev/sdf")
    assert status.passed is None
    assert status.detail == "Smartctl open device: /dev/sdf failed: Permission denied"


# --------------------------------------------------------------------- df --

def test_filesystems_parses_rows_and_skips_malformed_ones(fake_run):
    fake_run.set_response(
        ["df", "-B1", "--output=target,size,used,avail,pcent", "-x", "tmpfs", "-x", "devtmpfs", "-x", "efivarfs"],
        stdout=(
            "Mounted on         Size        Used       Avail Use%\n"
            "/             1000000000   123000000   877000000   12%\n"
            "/boot          512000000   100000000   412000000   20%\n"
            "broken row\n"
            "/data          not-a-size           1           2    3%\n"
        ),
    )

    assert disk_health.filesystems() == [
        disk_health.Usage("/", 1000000000, 123000000, 877000000, 12),
        disk_health.Usage("/boot", 512000000, 100000000, 412000000, 20),
    ]
    assert fake_run.calls == [
        ["df", "-B1", "--output=target,size,used,avail,pcent", "-x", "tmpfs", "-x", "devtmpfs", "-x", "efivarfs"]
    ]


def test_filesystems_nonzero_exit_raises(fake_run):
    fake_run.set_response(
        ["df", "-B1", "--output=target,size,used,avail,pcent", "-x", "tmpfs", "-x", "devtmpfs", "-x", "efivarfs"],
        stderr="df: cannot read table of mounted file systems",
        returncode=1,
    )
    with pytest.raises(RuntimeError, match="cannot read table"):
        disk_health.filesystems()


# ----------------------------------------------------------------- fstrim --

def test_fstrim_status_enabled_and_active(fake_run, fake_which):
    fake_which.add("fstrim")
    fake_run.set_response(["systemctl", "is-enabled", "fstrim.timer"], stdout="enabled\n")
    fake_run.set_response(["systemctl", "is-active", "fstrim.timer"], stdout="active\n")

    assert disk_health.fstrim_status() == disk_health.FstrimStatus(True, True, True)
    assert fake_run.calls == [
        ["systemctl", "is-enabled", "fstrim.timer"],
        ["systemctl", "is-active", "fstrim.timer"],
    ]


def test_fstrim_status_disabled_is_not_an_error(fake_run, fake_which):
    fake_which.add("fstrim")
    fake_run.set_response(["systemctl", "is-enabled", "fstrim.timer"], stdout="disabled\n", returncode=1)
    fake_run.set_response(["systemctl", "is-active", "fstrim.timer"], stdout="inactive\n", returncode=3)

    assert disk_health.fstrim_status() == disk_health.FstrimStatus(True, False, False)


def test_fstrim_status_not_found_means_not_installed(fake_run, fake_which):
    fake_which.add("fstrim")
    fake_run.set_response(["systemctl", "is-enabled", "fstrim.timer"], stderr="not-found\n", returncode=4)
    fake_run.set_response(["systemctl", "is-active", "fstrim.timer"], stderr="not-found\n", returncode=4)

    assert disk_health.fstrim_status() == disk_health.FstrimStatus(False, False, False)


def test_enable_fstrim_runs_privileged_enable_now(fake_run, fake_which):
    fake_run.set_response(["pkexec", "systemctl", "enable", "--now", "fstrim.timer"])

    assert disk_health.enable_fstrim().ok
    assert fake_run.calls == [["pkexec", "systemctl", "enable", "--now", "fstrim.timer"]]


# ---------------------------------------------------------------- journal --

def test_journal_usage_parses_gigabytes(fake_run):
    fake_run.set_response(
        ["journalctl", "--disk-usage"],
        stdout="Archived and active journals take up 2.5G in the file system.\n",
    )

    assert disk_health.journal_usage() == 2684354560
    assert fake_run.calls == [["journalctl", "--disk-usage"]]


def test_journal_usage_parses_plain_bytes(fake_run):
    fake_run.set_response(
        ["journalctl", "--disk-usage"],
        stdout="Archived and active journals take up 4096B in the file system.\n",
    )
    assert disk_health.journal_usage() == 4096


def test_journal_usage_unparsable_output_raises(fake_run):
    fake_run.set_response(["journalctl", "--disk-usage"], stdout="Journals are using some space.\n")
    with pytest.raises(RuntimeError, match="Couldn't parse journalctl --disk-usage"):
        disk_health.journal_usage()


def test_journal_usage_nonzero_exit_raises(fake_run):
    fake_run.set_response(
        ["journalctl", "--disk-usage"],
        stderr="Failed to open journal: Permission denied",
        returncode=1,
    )
    with pytest.raises(RuntimeError, match="Permission denied"):
        disk_health.journal_usage()


def test_vacuum_journal_runs_privileged_vacuum_with_the_requested_size(fake_run, fake_which):
    fake_run.set_response(["pkexec", "journalctl", "--vacuum-size=200M"])

    assert disk_health.vacuum_journal("200M").ok
    assert fake_run.calls == [["pkexec", "journalctl", "--vacuum-size=200M"]]


@pytest.mark.parametrize("bad_size", ["200", "200MB", "200m", "abc", " 200M", "200M "])
def test_vacuum_journal_rejects_sizes_it_cannot_safely_pass(fake_run, bad_size):
    with pytest.raises(ValueError):
        disk_health.vacuum_journal(bad_size)
    assert fake_run.calls == []


# ------------------------------------------------------------------ cache --

def test_cache_size_reads_du_bytes(fake_run, tmp_path, monkeypatch):
    cache = tmp_path / ".cache"
    cache.mkdir()
    monkeypatch.setattr(disk_health, "CACHE_DIR", cache)
    fake_run.set_response(["du", "-sb", str(cache)], stdout=f"2048\t{cache}\n")

    assert disk_health.cache_size() == 2048
    assert fake_run.calls == [["du", "-sb", str(cache)]]


def test_cache_size_missing_directory_is_none_without_running_du(fake_run, tmp_path, monkeypatch):
    monkeypatch.setattr(disk_health, "CACHE_DIR", tmp_path / "nope")
    assert disk_health.cache_size() is None
    assert fake_run.calls == []


def test_cache_size_nonzero_exit_is_none(fake_run, tmp_path, monkeypatch):
    cache = tmp_path / ".cache"
    cache.mkdir()
    monkeypatch.setattr(disk_health, "CACHE_DIR", cache)
    fake_run.set_response(["du", "-sb", str(cache)], stderr="du: cannot read directory", returncode=1)

    assert disk_health.cache_size() is None


def test_clean_coredumps_runs_privileged_tmpfiles(fake_run, fake_which):
    fake_run.set_response(["pkexec", "systemd-tmpfiles", "--clean"])

    assert disk_health.clean_coredumps().ok
    assert fake_run.calls == [["pkexec", "systemd-tmpfiles", "--clean"]]


def test_clear_user_cache_removes_children_but_not_symlink_targets(tmp_path, monkeypatch):
    cache = tmp_path / ".cache"
    cache.mkdir()
    (cache / "file.txt").write_text("x", encoding="utf-8")
    nested = cache / "someapp"
    nested.mkdir()
    (nested / "deep.txt").write_text("x", encoding="utf-8")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    (cache / "linked").symlink_to(outside)

    monkeypatch.setattr(disk_health, "CACHE_DIR", cache)

    assert disk_health.clear_user_cache() == 3
    assert list(cache.iterdir()) == []
    assert (outside / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_clear_user_cache_missing_directory_returns_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(disk_health, "CACHE_DIR", tmp_path / "nope")
    assert disk_health.clear_user_cache() == 0


def test_clear_user_cache_empty_directory_returns_zero(tmp_path, monkeypatch):
    cache = tmp_path / ".cache"
    cache.mkdir()
    monkeypatch.setattr(disk_health, "CACHE_DIR", cache)
    assert disk_health.clear_user_cache() == 0


def test_smart_probe_failure_is_unknown_not_a_failing_disk(fake_run):
    # smartctl says "failed" about opening the device, not about its health.
    # Once that substring set passed=False, an unreadable disk looked dying.
    fake_run.set_response(
        ["smartctl", "-H", "/dev/sda"],
        stdout="smartctl 7.5 2025-04-30 r5714 [x86_64-linux] (local build)\n",
        stderr="Smartctl open device: /dev/sda failed: No such device\n",
        returncode=2,
    )

    status = disk_health.smart_status("/dev/sda")

    assert status.passed is None
    assert "No such device" in status.detail


# ------------------------------------------------------- smartctl (errors) --

def test_smart_error_on_stdout_is_the_detail_not_the_version_banner(fake_run):
    # Real smartctl prints an open failure on *stdout*:
    #   Smartctl open device: /dev/nvme0n1 failed: Permission denied
    # The old fallback showed the version banner, so every unreadable disk
    # looked like an unexplained "unknown".
    fake_run.set_response(
        ["smartctl", "-H", "/dev/nvme0n1"],
        stdout=(
            "smartctl 7.5 2025-04-30 r5714 [x86_64-linux] (local build)\n"
            "Smartctl open device: /dev/nvme0n1 failed: Permission denied\n"
        ),
        returncode=2,
    )

    status = disk_health.smart_status("/dev/nvme0n1")

    assert status.passed is None
    assert "Permission denied" in status.detail


# ---------------------------------------------------- smartctl (privileged) --

def _privileged_json(**overrides):
    import json

    data = {
        "json_format_version": [1, 0],
        "smartctl": {
            "version": [7, 5],
            "messages": [],
            "exit_status": 0,
        },
        "device": {"name": "/dev/nvme0n1", "type": "nvme"},
        "smart_status": {"passed": True},
    }
    data.update(overrides)
    return json.dumps(data)


def test_smart_status_privileged_parses_passed(fake_run):
    fake_run.set_response(["pkexec", "smartctl"], stdout=_privileged_json())

    status = disk_health.smart_status_privileged("/dev/nvme0n1")

    assert status.passed is True
    assert status.detail == "SMART overall-health: PASSED"


def test_smart_status_privileged_reports_failure(fake_run):
    fake_run.set_response(["pkexec", "smartctl"], stdout=_privileged_json(smart_status={"passed": False}))

    status = disk_health.smart_status_privileged("/dev/nvme0n1")

    assert status.passed is False
    assert "FAILED" in status.detail


def test_smart_status_privileged_surfaces_the_open_error(fake_run):
    fake_run.set_response(
        ["pkexec", "smartctl"],
        stdout=_privileged_json(
            smart_status=None,
            smartctl={
                "version": [7, 5],
                "messages": [{"string": "Smartctl open device: /dev/sda failed: Permission denied"}],
                "exit_status": 2,
            },
        ),
        returncode=2,
    )

    status = disk_health.smart_status_privileged("/dev/sda")

    assert status.passed is None
    assert "Permission denied" in status.detail


def test_smart_status_privileged_ignores_non_json_output(fake_run):
    fake_run.set_response(["pkexec", "smartctl"], stdout="not json", stderr="boom", returncode=2)

    with pytest.raises(RuntimeError, match="didn't return JSON"):
        disk_health.smart_status_privileged("/dev/sda")


def test_smart_status_privileged_treats_exit_bit_3_as_failing(fake_run):
    fake_run.set_response(
        ["pkexec", "smartctl"],
        stdout=_privileged_json(smartctl={"version": [7, 5], "messages": [], "exit_status": 8}),
    )

    assert disk_health.smart_status_privileged("/dev/sda").passed is False


def test_smart_status_privileged_goes_through_pkexec(fake_run):
    fake_run.set_response(["pkexec", "smartctl"], stdout=_privileged_json())

    disk_health.smart_status_privileged("/dev/nvme0n1")

    assert fake_run.last_call() == ["pkexec", "smartctl", "-H", "--json", "/dev/nvme0n1"]
