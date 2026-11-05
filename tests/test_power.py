"""Tests for atropa.backend.power."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from atropa.backend import power


@pytest.fixture(autouse=True)
def power_paths(monkeypatch, tmp_path):
    """
    Redirect every live path the module reads into tmp_path, for every test.
    Autouse so a test that forgets one still can't read the real /proc, /sys
    or /etc of the machine running the suite.
    """
    paths = SimpleNamespace(
        power_supply=tmp_path / "power_supply",
        proc_swaps=tmp_path / "swaps",
        proc_meminfo=tmp_path / "meminfo",
        sys_power_state=tmp_path / "power_state",
        zram_conf=tmp_path / "zram-generator.conf",
    )
    monkeypatch.setattr(power, "POWER_SUPPLY", paths.power_supply)
    monkeypatch.setattr(power, "PROC_SWAPS", paths.proc_swaps)
    monkeypatch.setattr(power, "PROC_MEMINFO", paths.proc_meminfo)
    monkeypatch.setattr(power, "SYS_POWER_STATE", paths.sys_power_state)
    monkeypatch.setattr(power, "ZRAM_GENERATOR_CONF", paths.zram_conf)
    return paths


def _write_battery(root, name, capacity=None, status=None, limit=None):
    base = root / name
    base.mkdir(parents=True)
    if capacity is not None:
        (base / "capacity").write_text(f"{capacity}\n", encoding="utf-8")
    if status is not None:
        (base / "status").write_text(f"{status}\n", encoding="utf-8")
    if limit is not None:
        (base / "charge_control_end_threshold").write_text(f"{limit}\n", encoding="utf-8")
    return base


# ------------------------------------------------------------------ profiles --


def test_profiles_parses_daemon_output_in_order(fake_run, fake_which):
    fake_which.add("powerprofilesctl")
    fake_run.set_response(
        ["powerprofilesctl", "list"],
        stdout=(
            "* performance:\n"
            "    Driver:\tpower-profiles-daemon\n"
            "    Degraded:\tno\n"
            "\n"
            "  balanced:\n"
            "    Driver:\tpower-profiles-daemon\n"
            "\n"
            "  power-saver:\n"
            "    Driver:\tpower-profiles-daemon\n"
        ),
    )

    assert power.profiles() == ["performance", "balanced", "power-saver"]
    assert fake_run.calls == [["powerprofilesctl", "list"]]


def test_profiles_ignores_a_bare_driver_line(fake_run, fake_which):
    fake_which.add("powerprofilesctl")
    fake_run.set_response(["powerprofilesctl", "list"], stdout="* balanced:\n  Driver:\n")

    assert power.profiles() == ["balanced"]


def test_profiles_is_empty_when_tool_is_missing(fake_run, fake_which):
    assert power.profiles() == []
    assert fake_run.calls == []


def test_profiles_is_empty_when_command_fails(fake_run, fake_which):
    fake_which.add("powerprofilesctl")
    fake_run.set_response(["powerprofilesctl", "list"], stderr="Failed to connect", returncode=1)

    assert power.profiles() == []


def test_profiles_ignores_empty_output(fake_run, fake_which):
    fake_which.add("powerprofilesctl")
    fake_run.set_response(["powerprofilesctl", "list"], stdout="\n\n")

    assert power.profiles() == []


def test_current_profile_strips_output(fake_run, fake_which):
    fake_which.add("powerprofilesctl")
    fake_run.set_response(["powerprofilesctl", "get"], stdout="performance\n")

    assert power.current_profile() == "performance"
    assert fake_run.calls == [["powerprofilesctl", "get"]]


def test_current_profile_is_none_when_tool_is_missing(fake_run, fake_which):
    assert power.current_profile() is None
    assert fake_run.calls == []


def test_current_profile_is_none_when_command_fails(fake_run, fake_which):
    fake_which.add("powerprofilesctl")
    fake_run.set_response(["powerprofilesctl", "get"], stderr="No daemon", returncode=1)

    assert power.current_profile() is None


def test_current_profile_is_none_on_empty_output(fake_run, fake_which):
    fake_which.add("powerprofilesctl")
    fake_run.set_response(["powerprofilesctl", "get"], stdout="\n")

    assert power.current_profile() is None


def test_set_profile_rejects_unknown_names(fake_run, fake_which):
    with pytest.raises(ValueError, match="Unknown power profile"):
        power.set_profile("overdrive")
    assert fake_run.calls == []


def test_set_profile_runs_unprivileged_so_polkit_can_prompt(fake_run, fake_which):
    fake_which.add("powerprofilesctl")
    result = power.set_profile("balanced")

    assert result.ok
    assert fake_run.calls == [["powerprofilesctl", "set", "balanced"]]


def test_tlp_active_reads_systemctl_state(fake_run):
    fake_run.set_response(["systemctl", "is-active", "tlp"], stdout="active\n")

    assert power.tlp_active() is True
    assert fake_run.calls == [["systemctl", "is-active", "tlp"]]


def test_tlp_inactive_is_false(fake_run):
    fake_run.set_response(["systemctl", "is-active", "tlp"], stdout="inactive\n")

    assert power.tlp_active() is False


# ------------------------------------------------------------------- battery --


def test_batteries_are_sorted_and_read_from_sysfs(fake_run, power_paths):
    bat0 = _write_battery(power_paths.power_supply, "BAT0", capacity=87, status="Discharging", limit=80)
    bat1 = _write_battery(power_paths.power_supply, "BAT1", capacity=55, status="Charging")

    assert power.batteries() == [
        power.Battery("BAT0", 87, "Discharging", 80, bat0 / "charge_control_end_threshold"),
        power.Battery("BAT1", 55, "Charging", None, bat1 / "charge_control_end_threshold"),
    ]
    assert fake_run.calls == []


def test_batteries_treat_missing_and_malformed_values_as_none(power_paths):
    base = _write_battery(power_paths.power_supply, "BAT0", capacity="full", limit="eighty")

    (battery,) = power.batteries()
    assert battery.capacity is None
    assert battery.charge_limit is None
    assert battery.status == ""
    assert battery.charge_limit_path == base / "charge_control_end_threshold"


def test_batteries_empty_without_power_supply(power_paths):
    assert power.batteries() == []


def test_set_charge_limit_rejects_bad_names_and_limits(fake_run):
    for name in ("BATX", "../BAT0", "BAT0/../../etc"):
        with pytest.raises(ValueError, match="battery name"):
            power.set_charge_limit(name, 80)
    for limit in (-1, 101):
        with pytest.raises(ValueError, match="charge limit"):
            power.set_charge_limit("BAT0", limit)
    assert fake_run.calls == []


def test_set_charge_limit_requires_the_threshold_file(fake_run, power_paths):
    power_paths.power_supply.mkdir()

    with pytest.raises(RuntimeError, match="charge limit control"):
        power.set_charge_limit("BAT0", 80)
    assert fake_run.calls == []


def test_set_charge_limit_writes_through_privileged_tee(fake_run, fake_which, power_paths):
    base = _write_battery(power_paths.power_supply, "BAT0", capacity=87, status="Charging", limit=100)
    path = base / "charge_control_end_threshold"

    result = power.set_charge_limit("BAT0", 85)

    assert result.ok
    assert fake_run.calls == [["pkexec", "tee", str(path)]]
    assert fake_run.inputs == ["85\n"]


# ---------------------------------------------------------------------- zram --


def test_zram_devices_parses_two_and_three_column_rows(fake_run, fake_which):
    fake_which.add("zramctl")
    fake_run.set_response(
        ["zramctl", "--noheadings", "--output", "NAME,DISKSIZE,DATA"],
        stdout="zram0 8G 1.2G\nzram1 4G\n",
    )

    assert power.zram_devices() == [
        power.ZramDevice("zram0", "8G", "1.2G"),
        power.ZramDevice("zram1", "4G", ""),
    ]
    assert fake_run.calls == [["zramctl", "--noheadings", "--output", "NAME,DISKSIZE,DATA"]]


def test_zram_devices_empty_on_nonzero_exit(fake_run, fake_which):
    fake_which.add("zramctl")
    fake_run.set_response(["zramctl"], stderr="zramctl: not supported", returncode=1)

    assert power.zram_devices() == []


def test_zram_devices_empty_when_tool_is_missing(fake_run, fake_which):
    assert power.zram_devices() == []
    assert fake_run.calls == []


def test_swap_total_mb_sums_the_kib_column(power_paths):
    power_paths.proc_swaps.write_text(
        "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
        "/dev/zram0                              partition\t8388608\t1024\t100\n"
        "/dev/sda2                               partition\t4194304\t0\t-2\n",
        encoding="utf-8",
    )

    assert power.swap_total_mb() == 12288


def test_swap_total_mb_is_zero_without_proc_swaps(power_paths):
    assert power.swap_total_mb() == 0


def test_hibernate_supported_with_enough_swap(power_paths):
    power_paths.sys_power_state.write_text("freeze mem disk\n", encoding="utf-8")
    power_paths.proc_meminfo.write_text("MemTotal:       16777216 kB\n", encoding="utf-8")
    power_paths.proc_swaps.write_text(
        "Filename Type Size Used Priority\n/dev/zram0 partition 16777216 0 100\n",
        encoding="utf-8",
    )

    status = power.hibernate_status()
    assert status == power.HibernateStatus(True, 16384, 16384, "swap and RAM look sufficient")


def test_hibernate_warns_when_swap_is_smaller_than_ram(power_paths):
    power_paths.sys_power_state.write_text("freeze mem disk\n", encoding="utf-8")
    power_paths.proc_meminfo.write_text("MemTotal:       16777216 kB\n", encoding="utf-8")
    power_paths.proc_swaps.write_text(
        "Filename Type Size Used Priority\n/dev/sda2 partition 4194304 0 -2\n",
        encoding="utf-8",
    )

    status = power.hibernate_status()
    assert status.supported is True
    assert status.swap_mb == 4096
    assert status.ram_mb == 16384
    assert status.detail == "swap 4 GB vs RAM 16 GB - hibernate may fail"


def test_hibernate_without_files_reports_no_swap(power_paths):
    status = power.hibernate_status()

    assert status.supported is False
    assert status.swap_mb == 0
    assert status.ram_mb == 0
    assert status.detail == "no swap - hibernation needs at least RAM-size swap"


def test_hibernate_without_disk_in_power_state_is_unsupported(power_paths):
    power_paths.sys_power_state.write_text("freeze mem\n", encoding="utf-8")
    power_paths.proc_meminfo.write_text("MemTotal:       16777216 kB\n", encoding="utf-8")
    power_paths.proc_swaps.write_text(
        "Filename Type Size Used Priority\n/dev/zram0 partition 16777216 0 100\n",
        encoding="utf-8",
    )

    status = power.hibernate_status()
    assert status.supported is False
    assert status.detail == "swap and RAM look sufficient"


# ---------------------------------------------------------------- zram config --


def test_zram_config_reads_the_file(power_paths):
    power_paths.zram_conf.write_text("[zram0]\nzram-size = 4096\n", encoding="utf-8")

    config = power.zram_config()
    assert config.exists is True
    assert config.content == "[zram0]\nzram-size = 4096\n"
    assert config.path == power_paths.zram_conf


def test_zram_config_missing_file_is_not_configured(power_paths):
    config = power.zram_config()
    assert config.exists is False
    assert config.content == ""


def test_zram_config_unreadable_path_does_not_crash(power_paths):
    power_paths.zram_conf.mkdir()  # read_text() on a directory raises OSError

    config = power.zram_config()
    assert config.exists is True
    assert config.content == ""


def test_enable_zram_rejects_out_of_range_sizes(fake_run):
    for size in (255, 65537, 0):
        with pytest.raises(ValueError, match="256 to 65536"):
            power.enable_zram(size)
    assert fake_run.calls == []


def test_enable_zram_requires_the_generator_package(fake_run, power_paths):
    fake_run.set_response(["pacman", "-Q", "zram-generator"], stderr="error: package not found", returncode=1)

    with pytest.raises(RuntimeError, match="pacman -S zram-generator"):
        power.enable_zram(4096)
    assert fake_run.calls == [["pacman", "-Q", "zram-generator"]]


def test_enable_zram_writes_config_backs_up_and_starts_unit(
    fake_run, fake_which, power_paths, privilege_paths
):
    power_paths.zram_conf.write_text("[zram0]\nzram-size = 2048\n", encoding="utf-8")
    fake_run.set_response(["pacman", "-Q", "zram-generator"], stdout="zram-generator 1.2.1-1\n")

    result = power.enable_zram(4096)

    assert result.ok
    assert fake_run.calls == [
        ["pacman", "-Q", "zram-generator"],
        ["pkexec", "tee", str(power_paths.zram_conf)],
        ["pkexec", "systemctl", "daemon-reload"],
        ["pkexec", "systemctl", "start", "systemd-zram-setup@zram0.service"],
    ]
    assert fake_run.inputs[1] == "[zram0]\nzram-size = 4096\n"
    backups = list(privilege_paths.backup_dir.glob("*.bak"))
    assert len(backups) == 1
    assert backups[0].name.startswith("zram-generator.conf.")
    assert backups[0].read_text(encoding="utf-8") == "[zram0]\nzram-size = 2048\n"


def test_enable_zram_returns_the_failing_write_and_stops(fake_run, fake_which, power_paths):
    fake_run.set_response(["pacman", "-Q", "zram-generator"], returncode=0)
    fake_run.set_response(["pkexec", "tee"], stderr="tee: Permission denied", returncode=1)

    result = power.enable_zram(2048)

    assert result.returncode == 1
    assert fake_run.calls == [
        ["pacman", "-Q", "zram-generator"],
        ["pkexec", "tee", str(power_paths.zram_conf)],
    ]


def test_enable_zram_returns_the_failing_daemon_reload(fake_run, fake_which, power_paths):
    fake_run.set_response(["pacman", "-Q", "zram-generator"], returncode=0)
    fake_run.set_response(["pkexec", "systemctl", "daemon-reload"], stderr="reload failed", returncode=3)

    result = power.enable_zram(2048)

    assert result.returncode == 3
    assert fake_run.calls[-1] == ["pkexec", "systemctl", "daemon-reload"]
    assert ["pkexec", "systemctl", "start", "systemd-zram-setup@zram0.service"] not in fake_run.calls
