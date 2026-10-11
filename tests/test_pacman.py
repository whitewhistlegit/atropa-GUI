"""Tests for atropa.backend.pacman."""
from __future__ import annotations

import re

import pytest

from atropa.backend import pacman, privilege


# --------------------------------------------------------------- check_updates --
# fake_which leaves checkupdates "uninstalled" unless a test adds it, so
# these don't depend on whether the machine running them has pacman-contrib.

def test_check_updates_empty_when_up_to_date(fake_run, fake_which):
    fake_run.set_response(["pacman", "-Qu"], stdout="", returncode=1)
    assert pacman.check_updates() == []


def test_check_updates_parses_normal_lines(fake_run, fake_which):
    fake_run.set_response(
        ["pacman", "-Qu"],
        stdout="firefox 120.0-1 -> 121.0-1\nlinux 6.6.1-1 -> 6.6.2-1\n",
        returncode=0,
    )
    updates = pacman.check_updates()
    assert len(updates) == 2
    assert updates[0] == pacman.PendingUpdate("firefox", "120.0-1", "121.0-1")
    assert updates[1] == pacman.PendingUpdate("linux", "6.6.1-1", "6.6.2-1")


def test_check_updates_handles_ignored_suffix(fake_run, fake_which):
    fake_run.set_response(
        ["pacman", "-Qu"],
        stdout="glibc 2.38-1 -> 2.39-1 [ignored]\n",
        returncode=0,
    )
    updates = pacman.check_updates()
    assert updates == [pacman.PendingUpdate("glibc", "2.38-1", "2.39-1")]


def test_check_updates_falls_back_to_name_only_on_unexpected_format(fake_run, fake_which):
    fake_run.set_response(["pacman", "-Qu"], stdout="weirdformat\n", returncode=0)
    updates = pacman.check_updates()
    assert updates == [pacman.PendingUpdate("weirdformat", "", "")]


def test_check_updates_asks_the_mirrors_via_checkupdates_without_root(fake_run, fake_which):
    fake_which.update({"checkupdates", "fakeroot"})
    fake_run.set_response(["checkupdates"], stdout="firefox 120.0-1 -> 121.0-1\n", returncode=0)
    assert pacman.check_updates() == [pacman.PendingUpdate("firefox", "120.0-1", "121.0-1")]
    assert fake_run.calls == [["checkupdates"]]


def test_check_updates_checkupdates_exit_2_means_up_to_date(fake_run, fake_which):
    fake_which.update({"checkupdates", "fakeroot"})
    fake_run.set_response(["checkupdates"], stdout="", returncode=2)
    assert pacman.check_updates() == []


def test_check_updates_checkupdates_failure_is_an_error_not_up_to_date(fake_run, fake_which):
    fake_which.update({"checkupdates", "fakeroot"})
    fake_run.set_response(["checkupdates"], stderr="==> ERROR: Cannot fetch updates", returncode=1)
    with pytest.raises(RuntimeError, match="Cannot fetch updates"):
        pacman.check_updates()


def test_check_updates_falls_back_to_pacman_qu_without_fakeroot(fake_run, fake_which):
    # checkupdates exits 1 ("Cannot find the fakeroot binary") without it.
    fake_which.add("checkupdates")
    fake_run.set_response(["pacman", "-Qu"], stdout="firefox 120.0-1 -> 121.0-1\n")
    assert pacman.check_updates() == [pacman.PendingUpdate("firefox", "120.0-1", "121.0-1")]
    assert fake_run.call_containing("checkupdates") is None


def test_nothing_refreshes_the_real_database_without_upgrading():
    # `pacman -Sy` on its own is what turned a later install into a partial upgrade.
    assert not hasattr(pacman, "sync_database")


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
        pacman.Package(
            name="bash", version="5.2.021-1", installed=True, description="The GNU Bourne Again shell", repo="core"
        ),
        pacman.Package(
            name="htop", version="3.3.0-1", installed=False, description="Interactive process viewer", repo="extra"
        ),
    ]


def test_parse_ss_output_handles_missing_description_line():
    text = "core/bash 5.2.021-1 [installed]\n"
    packages = pacman._parse_ss_output(text)
    assert packages == [pacman.Package(name="bash", version="5.2.021-1", installed=True, description="", repo="core")]


def test_parse_ss_output_empty_text():
    assert pacman._parse_ss_output("") == []


def test_search_merges_repo_and_aur_when_helper_present(fake_run, fake_which):
    fake_which.add("paru")
    fake_run.set_response(["pacman", "-Ss", "vim"], stdout="core/vim 9.0-1\n    editor\n")
    fake_run.set_response(["paru", "-Ss", "--aur"], stdout="aur/vim-plugin 1.0-1\n    a plugin\n")

    results = pacman.search("vim", include_aur=True)
    assert [(p.repo, p.name) for p in results] == [("core", "vim"), ("aur", "vim-plugin")]


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
    assert fake_run.last_call() == ["pkexec", "pacman", "-S", "--needed", "--noconfirm", "vim", "htop"]


def test_install_refuses_while_the_database_is_ahead_of_installed_packages(fake_run, fake_which):
    # Something ran `pacman -Sy`: installing from that database now is a partial upgrade.
    fake_run.set_response(["pacman", "-Qu"], stdout="glibc 2.38-1 -> 2.39-1\nopenssl 3.1-1 -> 3.2-1\n")
    with pytest.raises(pacman.PartialUpgradeError, match="2 installed package.*glibc, openssl"):
        pacman.install(["vim"])
    assert fake_run.call_containing("pkexec") is None


def test_install_ignores_packages_held_back_by_ignorepkg(fake_run, fake_which):
    fake_run.set_response(["pacman", "-Qu"], stdout="linux 6.1-1 -> 6.2-1 [ignored]\n")
    pacman.install(["vim"])
    assert fake_run.last_call() == ["pkexec", "pacman", "-S", "--needed", "--noconfirm", "vim"]


def test_upgrade_and_install_is_one_full_upgrade(monkeypatch):
    seen = []
    monkeypatch.setattr(pacman, "run_privileged_streaming", lambda argv, on_line: seen.append(argv))
    pacman.upgrade_and_install_streaming(["vim"], lambda _line: None)
    assert seen == [["pacman", "-Syu", "--needed", "--noconfirm", "vim"]]


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


# --------------------------------------------------------------- repositories --

STOCK_CONF = (
    "[options]\nArchitecture = auto\nSigLevel = Required DatabaseOptional\n\n"
    "[core]\nInclude = /etc/pacman.d/mirrorlist\n\n"
    "[extra]\nInclude = /etc/pacman.d/mirrorlist\n"
)
UPSTREAM_BLOCK = (
    "[selinux]\n"
    "Server = https://github.com/archlinuxhardened/selinux/releases/download/ArchLinux-SELinux\n"
    "SigLevel = Never\n"
)


@pytest.fixture
def pacman_conf(tmp_path, monkeypatch, fake_run, fake_which):
    """A pacman.conf the fake `tee` really writes and the fake `pacman-conf` really reads back."""
    conf = tmp_path / "pacman.conf"
    conf.write_text(STOCK_CONF)
    monkeypatch.setattr(pacman, "PACMAN_CONF", conf)

    def run(argv, input=None, **kwargs):  # noqa: A002 - subprocess.run's own name for it
        result = fake_run(argv, input=input, **kwargs)
        if list(argv) == ["pkexec", "tee", str(conf)] and result.returncode == 0:
            conf.write_text(input)
        if list(argv) == ["pacman-conf", "--repo-list"] and result.returncode == 0 and not result.stdout:
            names = re.findall(r"^\[(?!options\])([^\]]+)\]$", conf.read_text(), re.MULTILINE)
            result.stdout = "".join(f"{name}\n" for name in names)
        return result

    monkeypatch.setattr(privilege, "_subprocess_run", run)
    return conf


def test_configured_repos_asks_pacman(fake_run):
    fake_run.set_response(["pacman-conf", "--repo-list"], stdout="core\nextra\nmultilib\n")
    assert pacman.configured_repos() == ["core", "extra", "multilib"]


def test_configured_repos_reads_the_file_when_pacman_conf_cant_be_run(tmp_path, monkeypatch):
    conf = tmp_path / "pacman.conf"
    conf.write_text(STOCK_CONF + "\n#[testing]\n[selinux]\nSigLevel = Never\n")
    monkeypatch.setattr(pacman, "PACMAN_CONF", conf)

    def missing(argv, **kwargs):
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(privilege, "_subprocess_run", missing)
    assert pacman.configured_repos() == ["core", "extra", "selinux"]  # not [options], not the commented one
    assert pacman.selinux_repo_enabled()


def test_selinux_repo_is_not_enabled_on_a_stock_pacman_conf(pacman_conf):
    assert not pacman.selinux_repo_enabled()


def test_enable_selinux_repo_appends_what_upstream_documents(pacman_conf, privilege_paths):
    assert pacman.enable_selinux_repo().ok
    text = pacman_conf.read_text()
    assert text.startswith(STOCK_CONF)  # nothing that was there is touched
    assert text.endswith(UPSTREAM_BLOCK)
    # After the official repositories, so they keep precedence for a package both have.
    assert pacman.configured_repos() == ["core", "extra", "selinux"]
    assert pacman.selinux_repo_enabled()
    assert str(pacman_conf) in privilege_paths.manifest.read_text()  # backed up first


def test_enable_selinux_repo_says_in_the_file_that_it_is_unsigned(pacman_conf):
    pacman.enable_selinux_repo()
    assert "unsigned" in pacman_conf.read_text()


def test_enable_selinux_repo_does_nothing_when_already_enabled(pacman_conf, fake_run):
    pacman.enable_selinux_repo()
    once = pacman_conf.read_text()
    result = pacman.enable_selinux_repo()
    assert result.ok and "already" in result.stdout
    assert pacman_conf.read_text() == once
    assert sum(1 for call in fake_run.calls if call[:2] == ["pkexec", "tee"]) == 1


def test_enable_selinux_repo_puts_pacman_conf_back_when_pacman_cant_read_it(pacman_conf, fake_run):
    # A pacman.conf that doesn't parse stops every install and upgrade.
    fake_run.set_response(["pacman-conf", "--repo-list"], returncode=1, stderr="error: config file could not be read")
    with pytest.raises(RuntimeError, match="Restored the previous one"):
        pacman.enable_selinux_repo()
    assert pacman_conf.read_text() == STOCK_CONF


def test_enable_selinux_repo_reports_a_failed_write(pacman_conf, fake_run):
    fake_run.set_response(["pkexec", "tee"], returncode=126, stderr="Request dismissed")
    assert not pacman.enable_selinux_repo().ok
    assert pacman_conf.read_text() == STOCK_CONF


def test_disable_selinux_repo_removes_exactly_what_enable_added(pacman_conf):
    pacman.enable_selinux_repo()
    assert pacman.disable_selinux_repo().ok
    assert pacman_conf.read_text() == STOCK_CONF
    assert not pacman.selinux_repo_enabled()


def test_disable_selinux_repo_leaves_the_sections_around_it_alone(pacman_conf):
    pacman_conf.write_text(STOCK_CONF + "\n" + UPSTREAM_BLOCK + "\n[custom]\nServer = file:///srv/repo\n")
    assert pacman.disable_selinux_repo().ok
    text = pacman_conf.read_text()
    assert "[selinux]" not in text and "ArchLinux-SELinux" not in text and "SigLevel = Never" not in text
    assert text.startswith(STOCK_CONF)
    assert text.endswith("[custom]\nServer = file:///srv/repo\n")


def test_disable_selinux_repo_does_nothing_when_it_isnt_there(pacman_conf, fake_run):
    result = pacman.disable_selinux_repo()
    assert result.ok and "not enabled" in result.stdout
    assert fake_run.call_containing("tee") is None
    assert pacman_conf.read_text() == STOCK_CONF
