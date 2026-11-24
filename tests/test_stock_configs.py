"""
Atropa's parsers and edits against the configuration files Arch actually
ships (tests/fixtures/stock, see its README), rather than hand-written
snippets: a stock file has the comments, commented-out examples and
look-alike keys that a snippet leaves out.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from atropa.backend import bootloader, hardening, mirrors, pacman, security, sleep, snapshots, system_config

STOCK = Path(__file__).parent / "fixtures" / "stock"


def stock(name: str) -> str:
    return (STOCK / name).read_text(encoding="utf-8")


def changed_lines(before: str, after: str) -> list[tuple[str, str]]:
    """(old, new) for each line that differs, for edits that keep the line count."""
    a, b = before.splitlines(), after.splitlines()
    assert len(a) == len(b), "the edit added or removed lines"
    return [(x, y) for x, y in zip(a, b) if x != y]


# ---------------------------------------------------------------- pacman.conf --

@pytest.fixture
def pacman_conf(tmp_path, monkeypatch):
    path = tmp_path / "pacman.conf"
    path.write_text(stock("pacman.conf"))
    monkeypatch.setattr(pacman, "PACMAN_CONF", path)
    return path


def test_pacman_conf_reads_stock_defaults(pacman_conf):
    settings = pacman.read_config()
    assert (settings.color, settings.parallel_downloads, settings.multilib) == (False, 5, False)


def test_pacman_color_uncomments_the_one_stock_line(pacman_conf):
    text = stock("pacman.conf")
    assert changed_lines(text, pacman._with_color(text, True)) == [("#Color", "Color")]
    assert pacman._with_color(pacman._with_color(text, True), False) == text


def test_pacman_parallel_downloads_edits_the_stock_line(pacman_conf):
    text = stock("pacman.conf")
    assert changed_lines(text, pacman._with_parallel_downloads(text, 10)) == [
        ("ParallelDownloads = 5", "ParallelDownloads = 10"),
    ]


def test_pacman_multilib_enables_the_section_and_its_include_only(pacman_conf):
    text = stock("pacman.conf")
    enabled = pacman._with_multilib(text, True)
    assert "multilib" in pacman._sections_in(enabled)
    assert "multilib-testing" not in pacman._sections_in(enabled)
    changes = changed_lines(text, enabled)
    assert [new for _old, new in changes] == ["[multilib]", "Include = /etc/pacman.d/mirrorlist"]
    assert "multilib" not in pacman._sections_in(pacman._with_multilib(enabled, False))


# ------------------------------------------------------------------ mirrorlist --

def test_stock_mirrorlist_has_no_active_server(tmp_path, monkeypatch):
    path = tmp_path / "mirrorlist"
    path.write_text(stock("mirrorlist"))
    monkeypatch.setattr(mirrors, "MIRRORLIST", path)
    # pacman-mirrorlist ships every Server commented out.
    assert mirrors.current_mirrors() == []
    assert len(re.findall(r"^#Server = ", stock("mirrorlist"), re.MULTILINE)) > 50


# ----------------------------------------------------------------- sshd_config --

@pytest.fixture
def sshd(tmp_path, monkeypatch, fake_run, fake_which):
    path = tmp_path / "sshd_config"
    path.write_text(stock("sshd_config"))
    monkeypatch.setattr(security, "SSHD_CONFIG", path)
    # The stock file includes /etc/ssh/sshd_config.d/*.conf: never this machine's.
    monkeypatch.setattr(security, "_include_paths", lambda value: [])
    return path


def test_sshd_stock_file_sets_nothing_so_defaults_apply(sshd):
    status = security.ssh_status()
    assert status.port == "22" and not status.port_explicit
    assert status.root_login == "unknown" and status.password_auth == "unknown"


@pytest.mark.parametrize("key, value", [
    ("PermitRootLogin", "no"), ("PasswordAuthentication", "no"), ("Port", "2222"), ("MaxAuthTries", "3"),
])
def test_sshd_edit_on_the_stock_file_takes_effect(sshd, key, value):
    edited = security._edit_sshd_global_option(stock("sshd_config"), key, value, include_sets=lambda v, k: False)
    sshd.write_text(edited)
    directives = security._sshd_global_directives(sshd, [])
    first = next(v for k, v in directives if k == key.lower())
    assert first == value
    # A commented example became the setting: nothing else moved.
    assert len(changed_lines(stock("sshd_config"), edited)) == 1


def test_sshd_edit_stays_out_of_the_match_example(sshd):
    edited = security._edit_sshd_global_option(stock("sshd_config"), "X11Forwarding", "no", include_sets=lambda v, k: False)
    match_at = next(i for i, line in enumerate(edited.splitlines()) if line.startswith("#Match"))
    changed = [i for i, (a, b) in enumerate(zip(stock("sshd_config").splitlines(), edited.splitlines())) if a != b]
    assert changed and all(i < match_at for i in changed)


# ------------------------------------------------------- GRUB and systemd-boot --

def test_grub_timeout_changes_only_grub_timeout():
    text = stock("default-grub")
    edited = bootloader._with_setting(text, r"GRUB_TIMEOUT=", "GRUB_TIMEOUT=10")
    assert changed_lines(text, edited) == [("GRUB_TIMEOUT=5", "GRUB_TIMEOUT=10")]
    assert "GRUB_TIMEOUT_STYLE=menu" in edited


def test_loader_conf_from_bootctl_gets_a_timeout():
    text = stock("loader.conf")
    assert bootloader._timeout_from(text) == ""
    edited = bootloader._with_timeout(text, 3)
    assert bootloader._timeout_from(edited) == "3"
    assert edited.splitlines()[0] == text.splitlines()[0]  # the default line stays


# ----------------------------------------------------- faillock and pwquality --

@pytest.mark.parametrize("name, key", [
    ("faillock.conf", "deny"), ("faillock.conf", "unlock_time"),
    ("pwquality.conf", "minlen"), ("pwquality.conf", "dcredit"), ("pwquality.conf", "ucredit"),
    ("pwquality.conf", "lcredit"), ("pwquality.conf", "ocredit"), ("pwquality.conf", "retry"),
])
def test_security_option_patterns_match_exactly_one_stock_line(name, key):
    # replace-in-file rewrites every match: on the stock file the pattern must
    # find the one commented example, not root_unlock_time or even_deny_root.
    pattern = rf"^#?\s*{re.escape(key)}\s*=.*$"
    assert len(re.findall(pattern, stock(name), re.MULTILINE)) == 1


def test_stock_faillock_and_pwquality_report_nothing_set(tmp_path, monkeypatch):
    for name, attr in (("faillock.conf", "FAILLOCK_CONF"), ("pwquality.conf", "PWQUALITY_CONF")):
        path = tmp_path / name
        path.write_text(stock(name))
        monkeypatch.setattr(hardening, attr, path)
    monkeypatch.setattr(hardening, "_pam_stack_references", lambda *a, **k: True)
    assert hardening.faillock_status()["deny"] == "unknown"
    assert hardening.pwquality_status()["minlen"] == "unknown"


# --------------------------------------------------------------------- PAM su --

@pytest.mark.parametrize("name", ["pam.d-su", "pam.d-su-l"])
def test_stock_su_is_open_and_restrictable(name):
    text = stock(name)
    assert hardening._su_file_state(text) == ("open", False)
    restricted = re.sub(hardening._SU_WHEEL_COMMENTED, hardening._SU_WHEEL_LINE, text, flags=re.MULTILINE)
    assert hardening._su_file_state(restricted) == ("restricted", False)
    assert len(changed_lines(text, restricted)) == 1


# ------------------------------------------------------------------ locale.gen --

def test_locale_gen_parses_every_locale_and_no_header_line(tmp_path, monkeypatch, fake_run):
    monkeypatch.setattr(system_config, "LOCALE_GEN_PATH", tmp_path / "locale.gen")
    fake_run.set_response(["cat"], stdout=stock("locale.gen"))
    entries = system_config.list_locale_gen_entries()
    names = [(e.locale, e.charmap) for e in entries]
    assert len(entries) > 400
    assert names.count(("en_US.UTF-8", "UTF-8")) == 1
    assert not any(e.enabled for e in entries)
    assert all(re.match(r"^[\w.@-]+$", e.locale) and "<" not in e.locale for e in entries)


# --------------------------------------------------------- logind and sleep --

@pytest.mark.parametrize("name, section", [("logind.conf", "Login"), ("sleep.conf", "Sleep")])
def test_stock_logind_and_sleep_set_nothing(name, section):
    assert sleep.parse(stock(name), section) == {}


def test_stock_logind_with_atropa_drop_in(tmp_path, monkeypatch):
    etc = tmp_path / "etc"
    (etc / "logind.conf.d").mkdir(parents=True)
    (etc / "logind.conf").write_text(stock("logind.conf"))
    (etc / "logind.conf.d" / "50-atropa.conf").write_text(sleep.logind_content("lock", "ignore", "suspend"))
    monkeypatch.setattr(sleep, "CONFIG_ROOTS", (etc,))
    settings = sleep.read_settings()
    assert (settings.lid.value, settings.power_key.value) == ("lock", "suspend")


# ------------------------------------------------------------------- snapper --

def test_snapper_template_has_the_keys_atropa_rewrites():
    lines = stock("snapper-config-template").splitlines()
    assert sum(line.startswith("SUBVOLUME=") for line in lines) == 1
    assert sum(line.startswith("FSTYPE=") for line in lines) == 1


def test_snapper_confd_gets_root_added():
    assert snapshots._with_snapper_configs('## Path: System/Snapper\nSNAPPER_CONFIGS=""\n').endswith(
        'SNAPPER_CONFIGS="root"\n'
    )
