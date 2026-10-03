"""Tests for atropa.backend.pacman."""
from __future__ import annotations

import pytest

from atropa.backend import pacman


# --------------------------------------------------------------- check_updates --

def test_check_updates_empty_when_up_to_date(fake_run):
    fake_run.set_response(["pacman", "-Qu"], stdout="", returncode=1)
    assert pacman.check_updates() == []


def test_check_updates_parses_normal_lines(fake_run):
    fake_run.set_response(
        ["pacman", "-Qu"],
        stdout="firefox 120.0-1 -> 121.0-1\nlinux 6.6.1-1 -> 6.6.2-1\n",
        returncode=0,
    )
    updates = pacman.check_updates()
    assert len(updates) == 2
    assert updates[0] == pacman.PendingUpdate("firefox", "120.0-1", "121.0-1")
    assert updates[1] == pacman.PendingUpdate("linux", "6.6.1-1", "6.6.2-1")


def test_check_updates_handles_ignored_suffix(fake_run):
    fake_run.set_response(
        ["pacman", "-Qu"],
        stdout="glibc 2.38-1 -> 2.39-1 [ignored]\n",
        returncode=0,
    )
    updates = pacman.check_updates()
    assert updates == [pacman.PendingUpdate("glibc", "2.38-1", "2.39-1")]


def test_check_updates_falls_back_to_name_only_on_unexpected_format(fake_run):
    fake_run.set_response(["pacman", "-Qu"], stdout="weirdformat\n", returncode=0)
    updates = pacman.check_updates()
    assert updates == [pacman.PendingUpdate("weirdformat", "", "")]


# --------------------------------------------------------------- update_single_package --

def test_update_single_package_requires_name():
    with pytest.raises(ValueError):
        pacman.update_single_package("")


def test_update_single_package_runs_pacman_s(fake_run, fake_which):
    pacman.update_single_package("firefox")
    assert fake_run.last_call() == ["pkexec", "pacman", "-S", "--noconfirm", "firefox"]


# --------------------------------------------------------------- list_* --

def test_list_installed_parses_name_version(fake_run):
    fake_run.set_response(["pacman", "-Q"], stdout="bash 5.2.021-1\nzlib 1.3-1\n", returncode=0)
    pkgs = pacman.list_installed()
    assert pkgs == [
        pacman.Package(name="bash", version="5.2.021-1", installed=True),
        pacman.Package(name="zlib", version="1.3-1", installed=True),
    ]


def test_list_installed_skips_blank_lines(fake_run):
    fake_run.set_response(["pacman", "-Q"], stdout="bash 5.2.021-1\n\n\n", returncode=0)
    assert len(pacman.list_installed()) == 1


def test_list_explicit_and_orphans_use_same_parse(fake_run):
    fake_run.set_response(["pacman", "-Qe"], stdout="vim 9.0-1\n", returncode=0)
    fake_run.set_response(["pacman", "-Qdt"], stdout="orphan-lib 1.0-1\n", returncode=0)
    assert pacman.list_explicit() == [pacman.Package(name="vim", version="9.0-1")]
    assert pacman.list_orphans() == [pacman.Package(name="orphan-lib", version="1.0-1")]


# --------------------------------------------------------------- search / _parse_ss_output --

SS_OUTPUT = """\
core/bash 5.2.021-1 [installed]
    The GNU Bourne Again shell
extra/htop 3.3.0-1
    Interactive process viewer
"""


def test_parse_ss_output_basic():
    packages = pacman._parse_ss_output(SS_OUTPUT)
    assert packages == [
        pacman.Package(name="bash", version="5.2.021-1", installed=True, description="The GNU Bourne Again shell"),
        pacman.Package(name="htop", version="3.3.0-1", installed=False, description="Interactive process viewer"),
    ]


def test_parse_ss_output_handles_missing_description_line():
    text = "core/bash 5.2.021-1 [installed]\n"
    packages = pacman._parse_ss_output(text)
    assert packages == [pacman.Package(name="bash", version="5.2.021-1", installed=True, description="")]


def test_parse_ss_output_empty_text():
    assert pacman._parse_ss_output("") == []


def test_search_merges_repo_and_aur_when_helper_present(fake_run, fake_which):
    fake_which.add("paru")
    fake_run.set_response(["pacman", "-Ss", "vim"], stdout="core/vim 9.0-1\n    editor\n")
    fake_run.set_response(["paru", "-Ss", "--aur"], stdout="aur/vim-plugin 1.0-1\n    a plugin\n")

    results = pacman.search("vim", include_aur=True)
    names = [p.name for p in results]
    assert names == ["vim", "vim-plugin"]


def test_search_skips_aur_when_no_helper(fake_run, fake_which):
    fake_run.set_response(["pacman", "-Ss", "vim"], stdout="core/vim 9.0-1\n    editor\n")
    results = pacman.search("vim", include_aur=True)
    assert [p.name for p in results] == ["vim"]


def test_search_include_aur_false_never_checks_helper(fake_run, fake_which):
    fake_which.add("paru")
    fake_run.set_response(["pacman", "-Ss", "vim"], stdout="core/vim 9.0-1\n    editor\n")
    pacman.search("vim", include_aur=False)
    assert fake_run.call_containing("paru") is None


# --------------------------------------------------------------- mutating ops --

def test_install_requires_packages():
    with pytest.raises(ValueError):
        pacman.install([])


def test_install_runs_pacman_with_all_names(fake_run, fake_which):
    pacman.install(["vim", "htop"])
    assert fake_run.last_call() == ["pkexec", "pacman", "-S", "--noconfirm", "vim", "htop"]


def test_remove_requires_packages():
    with pytest.raises(ValueError):
        pacman.remove([])


def test_remove_default_flag(fake_run, fake_which):
    pacman.remove(["vim"])
    assert fake_run.last_call() == ["pkexec", "pacman", "-Rs", "--noconfirm", "vim"]


def test_remove_purge_config_flag(fake_run, fake_which):
    pacman.remove(["vim"], purge_config=True)
    assert fake_run.last_call() == ["pkexec", "pacman", "-Rns", "--noconfirm", "vim"]


# --------------------------------------------------------------- streaming --

def test_upgrade_system_streaming_forwards_lines(monkeypatch, fake_which):
    import subprocess

    lines_seen = []

    class FakeStdout:
        def __iter__(self):
            return iter([
                ":: Synchronizing package databases...",
                "core is up to date",
                ":: Starting full system upgrade...",
            ])

    class FakePopen:
        def __init__(self, argv, **kwargs):
            self.args = argv
            self.stdout = FakeStdout()
            self.stdin = None

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    result = pacman.upgrade_system_streaming(lines_seen.append)

    assert result.ok
    assert lines_seen == [
        ":: Synchronizing package databases...",
        "core is up to date",
        ":: Starting full system upgrade...",
    ]
