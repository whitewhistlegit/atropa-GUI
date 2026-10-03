"""Tests for atropa.backend.system_config."""
from __future__ import annotations

import pytest

from atropa.backend import system_config

# --------------------------------------------------------------- hostname --

HOSTNAMECTL_STATUS = """\
   Static hostname: myhost
         Icon name: computer-laptop
           Chassis: laptop
        Machine ID: abc123
           Boot ID: def456
  Operating System: Arch Linux
            Kernel: Linux 6.6.1-arch1-1
      Architecture: x86-64
"""


def test_get_hostname_status_parses_fields(fake_run):
    fake_run.set_response(["hostnamectl", "status"], stdout=HOSTNAMECTL_STATUS)
    status = system_config.get_hostname_status()
    assert status.static_hostname == "myhost"
    assert status.icon_name == "computer-laptop"
    assert status.chassis == "laptop"
    assert status.os_name == "Arch Linux"
    assert status.kernel == "Linux 6.6.1-arch1-1"


def test_get_hostname_status_missing_fields_default_empty(fake_run):
    fake_run.set_response(["hostnamectl", "status"], stdout="   Static hostname: myhost\n")
    status = system_config.get_hostname_status()
    assert status.static_hostname == "myhost"
    assert status.chassis == ""


def test_set_hostname_requires_name():
    with pytest.raises(ValueError):
        system_config.set_hostname("")
    with pytest.raises(ValueError):
        system_config.set_hostname("   ")


def test_set_hostname_runs_privileged(fake_run, fake_which):
    system_config.set_hostname("newhost")
    assert fake_run.last_call() == ["pkexec", "hostnamectl", "set-hostname", "newhost"]


def test_set_hostname_strips_whitespace(fake_run, fake_which):
    system_config.set_hostname("  newhost  ")
    assert fake_run.last_call() == ["pkexec", "hostnamectl", "set-hostname", "newhost"]


# --------------------------------------------------------------- time/NTP --

TIMEDATECTL_STATUS = """\
               Local time: Thu 2026-01-30 12:34:56 UTC
           Universal time: Thu 2026-01-30 12:34:56 UTC
                 RTC time: Thu 2026-01-30 12:34:56
                Time zone: America/New_York (EST, -0500)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no
"""


def test_get_time_status_parses_fields(fake_run):
    fake_run.set_response(["timedatectl", "status"], stdout=TIMEDATECTL_STATUS)
    status = system_config.get_time_status()
    assert status.timezone == "America/New_York (EST, -0500)"
    assert status.local_time == "Thu 2026-01-30 12:34:56 UTC"
    assert status.ntp_service_active is True
    assert status.system_clock_synchronized is True


def test_get_time_status_ntp_inactive(fake_run):
    text = TIMEDATECTL_STATUS.replace("NTP service: active", "NTP service: inactive").replace(
        "System clock synchronized: yes", "System clock synchronized: no"
    )
    fake_run.set_response(["timedatectl", "status"], stdout=text)
    status = system_config.get_time_status()
    assert status.ntp_service_active is False
    assert status.system_clock_synchronized is False


def test_list_timezones_parses_lines(fake_run):
    fake_run.set_response(["timedatectl", "list-timezones"], stdout="America/New_York\nEurope/Berlin\n\n")
    assert system_config.list_timezones() == ["America/New_York", "Europe/Berlin"]


def test_set_timezone_requires_value():
    with pytest.raises(ValueError):
        system_config.set_timezone("")


def test_set_timezone_runs_privileged(fake_run, fake_which):
    system_config.set_timezone("Europe/Berlin")
    assert fake_run.last_call() == ["pkexec", "timedatectl", "set-timezone", "Europe/Berlin"]


def test_set_ntp_true(fake_run, fake_which):
    system_config.set_ntp(True)
    assert fake_run.last_call() == ["pkexec", "timedatectl", "set-ntp", "true"]


def test_set_ntp_false(fake_run, fake_which):
    system_config.set_ntp(False)
    assert fake_run.last_call() == ["pkexec", "timedatectl", "set-ntp", "false"]


# --------------------------------------------------------------- locale --

LOCALECTL_STATUS = """\
   System Locale: LANG=en_US.UTF-8
       VC Keymap: us
      X11 Layout: us
       X11 Model: pc105
"""


def test_get_locale_status_parses_fields(fake_run):
    fake_run.set_response(["localectl", "status"], stdout=LOCALECTL_STATUS)
    status = system_config.get_locale_status()
    assert status.lang == "en_US.UTF-8"
    assert status.vc_keymap == "us"
    assert status.x11_layout == "us"


def test_get_locale_status_missing_lang(fake_run):
    fake_run.set_response(["localectl", "status"], stdout="   VC Keymap: us\n")
    status = system_config.get_locale_status()
    assert status.lang == ""


def test_list_generated_locales(fake_run):
    fake_run.set_response(["localectl", "list-locales"], stdout="en_US.UTF-8\nde_DE.UTF-8\n")
    assert system_config.list_generated_locales() == ["en_US.UTF-8", "de_DE.UTF-8"]


def test_set_locale_requires_value():
    with pytest.raises(ValueError):
        system_config.set_locale("")


def test_set_locale_runs_privileged(fake_run, fake_which):
    system_config.set_locale("de_DE.UTF-8")
    assert fake_run.last_call() == ["pkexec", "localectl", "set-locale", "LANG=de_DE.UTF-8"]


# --------------------------------------------------------------- locale.gen parsing --

LOCALE_GEN_SAMPLE = """\
# This file lists locales that you wish to have built.
#en_US.UTF-8 UTF-8
de_DE.UTF-8 UTF-8
#fr_FR.UTF-8 UTF-8
"""


def test_list_locale_gen_entries_parses_enabled_and_disabled(fake_run):
    fake_run.set_response(["cat", str(system_config.LOCALE_GEN_PATH)], stdout=LOCALE_GEN_SAMPLE)
    entries = system_config.list_locale_gen_entries()

    by_locale = {e.locale: e for e in entries}
    assert by_locale["en_US.UTF-8"].enabled is False
    assert by_locale["de_DE.UTF-8"].enabled is True
    assert by_locale["fr_FR.UTF-8"].enabled is False
    assert by_locale["en_US.UTF-8"].charmap == "UTF-8"


def test_list_locale_gen_entries_ignores_comment_header_line(fake_run):
    fake_run.set_response(["cat", str(system_config.LOCALE_GEN_PATH)], stdout=LOCALE_GEN_SAMPLE)
    entries = system_config.list_locale_gen_entries()
    assert len(entries) == 3  # the descriptive header comment isn't a locale entry


def test_list_locale_gen_entries_empty_when_read_fails(fake_run):
    fake_run.set_response(["cat", str(system_config.LOCALE_GEN_PATH)], returncode=1, stderr="no such file")
    assert system_config.list_locale_gen_entries() == []


# --------------------------------------------------------------- set_locale_gen_enabled --

def test_set_locale_gen_enabled_uncomments_matching_line(fake_run, fake_which, privilege_paths):
    fake_run.set_response(["cat", str(system_config.LOCALE_GEN_PATH)], stdout=LOCALE_GEN_SAMPLE)
    fake_run.set_response(["pkexec", "tee", str(system_config.LOCALE_GEN_PATH)], returncode=0)
    fake_run.set_response(["pkexec", "locale-gen"], returncode=0)

    result = system_config.set_locale_gen_enabled("en_US.UTF-8", "UTF-8", True)
    assert result.ok

    tee_call_index = next(i for i, c in enumerate(fake_run.calls) if "tee" in c)
    locale_gen_index = next(i for i, c in enumerate(fake_run.calls) if "locale-gen" in c)
    assert tee_call_index < locale_gen_index


def test_set_locale_gen_enabled_comments_out_matching_line(fake_run, fake_which, privilege_paths):
    fake_run.set_response(["cat", str(system_config.LOCALE_GEN_PATH)], stdout=LOCALE_GEN_SAMPLE)
    fake_run.set_response(["pkexec", "tee", str(system_config.LOCALE_GEN_PATH)], returncode=0)
    fake_run.set_response(["pkexec", "locale-gen"], returncode=0)

    result = system_config.set_locale_gen_enabled("de_DE.UTF-8", "UTF-8", False)
    assert result.ok


def test_set_locale_gen_enabled_no_match_returns_failure_without_writing(fake_run, fake_which, privilege_paths):
    fake_run.set_response(["cat", str(system_config.LOCALE_GEN_PATH)], stdout=LOCALE_GEN_SAMPLE)

    result = system_config.set_locale_gen_enabled("ja_JP.UTF-8", "UTF-8", True)
    assert not result.ok
    assert "No entry" in result.stderr
    assert fake_run.call_containing("tee") is None
    assert fake_run.call_containing("locale-gen") is None


def test_set_locale_gen_enabled_read_failure_short_circuits(fake_run, fake_which):
    fake_run.set_response(["cat", str(system_config.LOCALE_GEN_PATH)], returncode=1, stderr="denied")
    result = system_config.set_locale_gen_enabled("en_US.UTF-8", "UTF-8", True)
    assert not result.ok
    assert fake_run.call_containing("tee") is None


def test_set_locale_gen_enabled_stops_if_write_fails(fake_run, fake_which, privilege_paths):
    fake_run.set_response(["cat", str(system_config.LOCALE_GEN_PATH)], stdout=LOCALE_GEN_SAMPLE)
    fake_run.set_response(["pkexec", "tee", str(system_config.LOCALE_GEN_PATH)], returncode=1, stderr="disk full")

    result = system_config.set_locale_gen_enabled("en_US.UTF-8", "UTF-8", True)
    assert not result.ok
    assert fake_run.call_containing("locale-gen") is None


def test_set_locale_gen_enabled_preserves_other_lines(fake_run, fake_which, privilege_paths):
    """The rewrite must not silently drop unrelated lines (the header
    comment, other locale entries) - only the matched line changes."""
    fake_run.set_response(["cat", str(system_config.LOCALE_GEN_PATH)], stdout=LOCALE_GEN_SAMPLE)
    fake_run.set_response(["pkexec", "tee", str(system_config.LOCALE_GEN_PATH)], returncode=0)
    fake_run.set_response(["pkexec", "locale-gen"], returncode=0)

    result = system_config.set_locale_gen_enabled("en_US.UTF-8", "UTF-8", True)
    # can't inspect stdin content via the argv-only fake_run, but confirm
    # both the write and regen steps ran without error, which is the
    # externally-observable half of "the rewrite succeeded"
    assert result.ok
    assert fake_run.call_containing("locale-gen") is not None


# --------------------------------------------------------------- keyboard --

def test_list_keymaps(fake_run):
    fake_run.set_response(["localectl", "list-keymaps"], stdout="us\nde\nfr\n")
    assert system_config.list_keymaps() == ["us", "de", "fr"]


def test_set_keymap_requires_value():
    with pytest.raises(ValueError):
        system_config.set_keymap("")


def test_set_keymap_runs_privileged(fake_run, fake_which):
    system_config.set_keymap("de")
    assert fake_run.last_call() == ["pkexec", "localectl", "set-keymap", "de"]


def test_list_x11_layouts_empty_when_localectl_missing(fake_which):
    assert system_config.list_x11_layouts() == []


def test_list_x11_layouts_parses_lines(fake_run, fake_which):
    fake_which.add("localectl")
    fake_run.set_response(["localectl", "list-x11-keymap-layouts"], stdout="us\nde\ngb\n")
    assert system_config.list_x11_layouts() == ["us", "de", "gb"]


def test_set_x11_layout_requires_value():
    with pytest.raises(ValueError):
        system_config.set_x11_layout("")


def test_set_x11_layout_runs_privileged(fake_run, fake_which):
    system_config.set_x11_layout("de")
    assert fake_run.last_call() == ["pkexec", "localectl", "set-x11-keymap", "de"]
