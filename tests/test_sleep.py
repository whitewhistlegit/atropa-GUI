"""Tests for atropa.backend.sleep - lid, power button and hibernate delay."""

from __future__ import annotations

import pytest

from atropa.backend import sleep


@pytest.fixture
def roots(tmp_path, monkeypatch):
    etc, run, usr = (tmp_path / name for name in ("etc", "run", "usr"))
    for root in (etc, run, usr):
        root.mkdir()
    monkeypatch.setattr(sleep, "CONFIG_ROOTS", (etc, run, usr))
    monkeypatch.setattr(sleep, "LID_DIR", tmp_path / "lid")
    return etc, run, usr


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_defaults_when_nothing_is_configured(roots):
    settings = sleep.read_settings()
    assert settings.lid.value == "suspend" and settings.lid.source == "systemd default"
    assert settings.lid_external_power.value == "suspend"
    assert settings.lid_external_power.source == "same as on battery"
    assert settings.power_key.value == "poweroff"
    assert settings.hibernate_delay.value is None
    assert not settings.has_lid


def test_external_power_follows_the_lid_setting(roots):
    etc, _run, _usr = roots
    write(etc / "logind.conf", "[Login]\nHandleLidSwitch=lock\n")
    settings = sleep.read_settings()
    assert settings.lid_external_power.value == "lock"


def test_drop_ins_override_the_main_file_in_name_order(roots):
    etc, run, usr = roots
    write(etc / "logind.conf", "[Login]\nHandleLidSwitch=ignore\nHandlePowerKey=lock\n")
    write(usr / "logind.conf.d" / "10-vendor.conf", "[Login]\nHandleLidSwitch=hibernate\n")
    write(etc / "logind.conf.d" / "50-atropa.conf", "[Login]\nHandleLidSwitch=suspend\n")
    write(run / "logind.conf.d" / "60-later.conf", "[Login]\nHandlePowerKey=ignore\n")

    settings = sleep.read_settings()

    assert (settings.lid.value, settings.lid.source) == ("suspend", str(etc / "logind.conf.d" / "50-atropa.conf"))
    assert (settings.power_key.value, settings.power_key.source) == (
        "ignore", str(run / "logind.conf.d" / "60-later.conf"),
    )


def test_a_drop_in_in_etc_hides_the_same_name_further_down(roots):
    etc, _run, usr = roots
    write(usr / "logind.conf.d" / "50-x.conf", "[Login]\nHandlePowerKey=ignore\n")
    write(etc / "logind.conf.d" / "50-x.conf", "[Login]\n")
    assert sleep.read_settings().power_key.value == "poweroff"


def test_only_the_first_main_file_counts(roots):
    etc, _run, usr = roots
    write(usr / "logind.conf", "[Login]\nHandlePowerKey=ignore\n")
    write(etc / "logind.conf", "[Login]\n#HandlePowerKey=lock\n")
    assert sleep.read_settings().power_key.source == "systemd default"


def test_an_empty_assignment_resets_to_the_default(roots):
    etc, _run, _usr = roots
    write(etc / "logind.conf", "[Login]\nHandlePowerKey=ignore\n")
    write(etc / "logind.conf.d" / "50-atropa.conf", "[Login]\nHandlePowerKey=\n")
    assert sleep.read_settings().power_key.value == "poweroff"


def test_keys_in_other_sections_are_ignored():
    assert sleep.parse("[Other]\nHandleLidSwitch=ignore\n[Login]\n; c\nHandlePowerKey = lock \n", "Login") == {
        "HandlePowerKey": "lock",
    }


def test_hibernate_delay_and_lid_detection(roots, tmp_path):
    etc, _run, _usr = roots
    write(etc / "sleep.conf.d" / "50-atropa.conf", "[Sleep]\nHibernateDelaySec=2h\n")
    (tmp_path / "lid").mkdir()
    settings = sleep.read_settings()
    assert settings.hibernate_delay.value == "2h"
    assert settings.has_lid


def test_logind_content_refuses_unknown_actions():
    assert "HandlePowerKey=lock\n" in sleep.logind_content("suspend", "ignore", "lock")
    with pytest.raises(ValueError):
        sleep.logind_content("suspend\nKillUserProcesses=yes", "ignore", "lock")


@pytest.mark.parametrize("delay", ["2h", "90min", "1h 30min", "45m", "3600s"])
def test_sleep_content_takes_time_spans(delay):
    assert f"HibernateDelaySec={delay}\n" in sleep.sleep_content(delay)


@pytest.mark.parametrize("delay", ["", "2", "2h\nAllowSuspend=no", "forever", "-1h"])
def test_sleep_content_refuses_anything_else(delay):
    with pytest.raises(ValueError):
        sleep.sleep_content(delay)


def test_automatic_delay_writes_no_key():
    assert "HibernateDelaySec" not in sleep.sleep_content(None)


def test_apply_logind_writes_the_drop_in_and_reloads(fake_run, fake_which):
    assert sleep.apply_logind("lock", "ignore", "poweroff").ok
    calls = [call[1:] for call in fake_run.calls]
    assert calls == [
        ["mkdir", "-p", "/etc/systemd/logind.conf.d"],
        ["tee", "/etc/systemd/logind.conf.d/50-atropa.conf"],
        ["systemctl", "reload", "systemd-logind.service"],
    ]
    assert "HandleLidSwitch=lock" in fake_run.inputs[1]


def test_apply_logind_stops_at_the_first_failure(fake_run, fake_which):
    fake_run.set_response(["pkexec", "tee"], stderr="denied", returncode=1)
    assert not sleep.apply_logind("lock", "ignore", "poweroff").ok
    assert not any("reload" in call for call in fake_run.calls)


def test_apply_sleep_writes_the_drop_in(fake_run, fake_which):
    assert sleep.apply_sleep("1h").ok
    assert fake_run.calls[-1][1:] == ["tee", "/etc/systemd/sleep.conf.d/50-atropa.conf"]
    assert "HibernateDelaySec=1h" in fake_run.inputs[-1]
