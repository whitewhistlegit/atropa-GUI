"""Tests for atropa.backend.system_health."""

from __future__ import annotations

import pytest

from atropa.backend import system_health


# --------------------------------------------------------------- failed units --

def test_failed_units_parses_bulleted_systemctl_lines(fake_run):
    fake_run.set_response(
        ["systemctl", "--failed"],
        stdout="● sshd.service loaded failed failed OpenSSH Daemon\n"
        "● backup.service loaded failed failed Nightly backup\n",
    )
    assert system_health.failed_units() == [
        system_health.FailedUnit("sshd.service", "OpenSSH Daemon"),
        system_health.FailedUnit("backup.service", "Nightly backup"),
    ]


def test_failed_units_accepts_unbulleted_lines_and_skips_blank_ones(fake_run):
    fake_run.set_response(
        ["systemctl", "--failed"],
        stdout="\nsshd.service loaded failed failed OpenSSH Daemon\n",
    )
    assert system_health.failed_units() == [system_health.FailedUnit("sshd.service", "OpenSSH Daemon")]


def test_failed_units_empty_output_means_no_failed_units(fake_run):
    fake_run.set_response(["systemctl", "--failed"], stdout="")
    assert system_health.failed_units() == []


def test_failed_units_failure_is_an_error_not_an_empty_list(fake_run):
    fake_run.set_response(["systemctl", "--failed"], stderr="Access denied", returncode=1)
    with pytest.raises(RuntimeError, match="Access denied"):
        system_health.failed_units()


# -------------------------------------------------------------------- kernel --

def _fake_kernel(fake_run: object, running: str, package: str, releases: list[str], owners: list[str] | None = None) -> None:
    owner_lines = "".join(
        f"/usr/lib/modules/{running}/ is owned by {owner} {running}\n" for owner in (owners or [package])
    )
    fake_run.set_response(["pacman", "-Qo"], stdout=owner_lines)
    fake_run.set_response(
        ["pacman", "-Ql", package],
        stdout="".join(f"{package} /usr/lib/modules/{release}/vmlinuz\n" for release in releases),
    )


def test_kernel_status_current_when_package_still_owns_running_release(fake_run, monkeypatch):
    monkeypatch.setattr(system_health.platform, "release", lambda: "6.12.1-arch1-1")
    _fake_kernel(fake_run, "6.12.1-arch1-1", "linux", ["6.12.1-arch1-1"])

    status = system_health.kernel_status()
    assert status.running == "6.12.1-arch1-1"
    assert status.package == "linux"
    assert status.reboot_required is False


def test_kernel_status_reboot_when_package_now_installs_another_release(fake_run, monkeypatch):
    monkeypatch.setattr(system_health.platform, "release", lambda: "6.12.1-arch1-1")
    _fake_kernel(fake_run, "6.12.1-arch1-1", "linux", ["6.12.2-arch1-1"])

    status = system_health.kernel_status()
    assert status.reboot_required is True
    assert status.package_release == "6.12.2-arch1-1"


def test_kernel_status_prefers_a_package_that_owns_the_running_release(fake_run, monkeypatch):
    monkeypatch.setattr(system_health.platform, "release", lambda: "6.12.1-arch1-1")
    # Headers can be listed first by pacman -Qo; the kernel package still
    # owning the running release decides that no reboot is needed.
    fake_run.set_response(
        ["pacman", "-Qo"],
        stdout="/usr/lib/modules/6.12.1-arch1-1/ is owned by linux-headers 6.12.2.arch1-1\n"
        "/usr/lib/modules/6.12.1-arch1-1/ is owned by linux 6.12.2.arch1-1\n",
    )
    fake_run.set_response(["pacman", "-Ql", "linux-headers"], stdout="linux-headers /usr/lib/modules/6.12.2-arch1-1/vmlinuz\n")
    fake_run.set_response(["pacman", "-Ql", "linux"], stdout="linux /usr/lib/modules/6.12.1-arch1-1/vmlinuz\n")

    assert system_health.kernel_status().reboot_required is False


def test_kernel_status_unowned_kernel_is_an_error(fake_run, monkeypatch):
    monkeypatch.setattr(system_health.platform, "release", lambda: "custom-6.1")
    fake_run.set_response(["pacman", "-Qo"], stderr="error: No package owns /usr/lib/modules/custom-6.1", returncode=1)
    with pytest.raises(RuntimeError, match="No package owns"):
        system_health.kernel_status()


# ----------------------------------------------------------------- microcode --

def _write_cpuinfo(tmp_path, monkeypatch, vendor: str) -> None:
    path = tmp_path / "cpuinfo"
    path.write_text(f"processor\t: 0\nvendor_id\t: {vendor}\n", encoding="utf-8")
    monkeypatch.setattr(system_health, "CPUINFO_PATH", path)


def test_microcode_installed_for_intel(fake_run, tmp_path, monkeypatch):
    _write_cpuinfo(tmp_path, monkeypatch, "GenuineIntel")
    fake_run.set_response(["pacman", "-Q", "intel-ucode"], returncode=0)

    assert system_health.microcode_status() == system_health.MicrocodeStatus("intel", "intel-ucode", True)


def test_microcode_missing_for_amd(fake_run, tmp_path, monkeypatch):
    _write_cpuinfo(tmp_path, monkeypatch, "AuthenticAMD")
    fake_run.set_response(["pacman", "-Q", "amd-ucode"], returncode=1)

    assert system_health.microcode_status() == system_health.MicrocodeStatus("amd", "amd-ucode", False)


def test_microcode_unknown_vendor_does_not_call_pacman(fake_run, tmp_path, monkeypatch):
    _write_cpuinfo(tmp_path, monkeypatch, "SomeOtherCPU")

    assert system_health.microcode_status() == system_health.MicrocodeStatus()
    assert fake_run.calls == []


# ------------------------------------------------------------------ check_all --

def test_check_all_keeps_other_results_when_one_check_fails(monkeypatch):
    monkeypatch.setattr(
        system_health, "failed_units", lambda: (_ for _ in ()).throw(RuntimeError("systemd unavailable"))
    )
    monkeypatch.setattr(
        system_health, "kernel_status", lambda: system_health.KernelStatus("6.12.1", reboot_required=False)
    )
    monkeypatch.setattr(
        system_health, "microcode_status", lambda: system_health.MicrocodeStatus("intel", "intel-ucode", True)
    )

    report = system_health.check_all()
    assert report.failed_units_error == "systemd unavailable"
    assert report.kernel is not None and report.kernel.reboot_required is False
    assert report.microcode is not None and report.microcode.installed is True
