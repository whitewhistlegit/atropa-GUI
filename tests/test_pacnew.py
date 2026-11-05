"""Tests for atropa.backend.pacnew.

Every scan runs against a tmp_path tree (pacnew.ETC_DIR is monkeypatched), so
no test depends on the configs the build machine actually has pending. The two
write paths only ever reach the (fake) privileged prefix.
"""

from __future__ import annotations

import os

import pytest

from atropa.backend import pacnew


@pytest.fixture
def etc(tmp_path, monkeypatch):
    """An empty /etc stand-in, already pointed at by pacnew.ETC_DIR."""
    path = tmp_path / "etc"
    path.mkdir()
    monkeypatch.setattr(pacnew, "ETC_DIR", path)
    return path


def _entry(kind: str, candidate, live, live_exists: bool) -> pacnew.PacnewEntry:
    return pacnew.PacnewEntry(kind, str(candidate), str(live), live_exists)


# ------------------------------------------------------------------- scanning --

def test_scan_finds_both_kinds_and_derives_live_paths(etc):
    (etc / "ssh").mkdir()
    (etc / "ssh" / "sshd_config").write_text("old\n", encoding="utf-8")
    (etc / "ssh" / "sshd_config.pacnew").write_text("new\n", encoding="utf-8")
    (etc / "pacman.conf.pacsave").write_text("saved\n", encoding="utf-8")

    entries = {entry.live: entry for entry in pacnew.scan()}

    assert set(entries) == {str(etc / "ssh" / "sshd_config"), str(etc / "pacman.conf")}
    sshd = entries[str(etc / "ssh" / "sshd_config")]
    assert sshd.kind == "pacnew"
    assert sshd.candidate == str(etc / "ssh" / "sshd_config.pacnew")
    assert sshd.live_exists is True

    pacman = entries[str(etc / "pacman.conf")]
    assert pacman.kind == "pacsave"
    assert pacman.candidate == str(etc / "pacman.conf.pacsave")
    # The package (and so the config) is gone - this is the normal .pacsave case.
    assert pacman.live_exists is False


def test_scan_sorts_by_live_path(etc):
    (etc / "zzz.conf.pacnew").write_text("z\n", encoding="utf-8")
    (etc / "sub").mkdir()
    (etc / "sub" / "aaa.conf.pacnew").write_text("a\n", encoding="utf-8")

    lives = [entry.live for entry in pacnew.scan()]
    assert lives == sorted(lives)
    assert lives == [str(etc / "sub" / "aaa.conf"), str(etc / "zzz.conf")]


def test_scan_ignores_unrelated_files_and_directories(etc):
    (etc / "hosts").write_text("127.0.0.1 localhost\n", encoding="utf-8")
    (etc / "notes.txt").write_text("not a config candidate\n", encoding="utf-8")
    (etc / "odd.pacnew").mkdir()  # a directory whose name would match
    (etc / "keep.conf.pacnew").write_text("new\n", encoding="utf-8")

    assert [entry.live for entry in pacnew.scan()] == [str(etc / "keep.conf")]


def test_scan_ignores_a_dangling_symlink_candidate(etc):
    os.symlink(etc / "gone", etc / "dangling.conf.pacnew")

    assert pacnew.scan() == []


def test_scan_does_not_follow_symlinked_directories(etc, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.conf.pacnew").write_text("x\n", encoding="utf-8")
    (etc / "link").symlink_to(outside, target_is_directory=True)
    (etc / "real.conf.pacnew").write_text("x\n", encoding="utf-8")

    # followlinks=False: a symlinked tree (or one pointing outside /etc) is not
    # walked, so only the real file shows up.
    assert [entry.live for entry in pacnew.scan()] == [str(etc / "real.conf")]


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a 000 directory")
def test_scan_skips_an_unreadable_subdirectory(etc):
    locked = etc / "locked"
    locked.mkdir()
    (locked / "hidden.conf.pacnew").write_text("secret\n", encoding="utf-8")
    (etc / "visible.conf.pacnew").write_text("visible\n", encoding="utf-8")
    locked.chmod(0o000)
    try:
        lives = [entry.live for entry in pacnew.scan()]
    finally:
        locked.chmod(0o755)  # so tmp_path cleanup can remove it

    # One root-only directory must not hide the rest of /etc.
    assert lives == [str(etc / "visible.conf")]


def test_scan_empty_etc_returns_nothing(etc):
    assert pacnew.scan() == []


def test_scan_missing_etc_raises_runtime_error(tmp_path, monkeypatch):
    monkeypatch.setattr(pacnew, "ETC_DIR", tmp_path / "no-such-etc")

    with pytest.raises(RuntimeError):
        pacnew.scan()


def test_scan_etc_that_is_a_file_raises_runtime_error(tmp_path, monkeypatch):
    not_a_dir = tmp_path / "etc"
    not_a_dir.write_text("nope\n", encoding="utf-8")
    monkeypatch.setattr(pacnew, "ETC_DIR", not_a_dir)

    with pytest.raises(RuntimeError):
        pacnew.scan()


# -------------------------------------------------------------------- reading --

def test_read_text_replaces_undecodable_bytes(etc):
    path = etc / "latin1.conf"
    path.write_bytes(b"caf\xe9\n")

    text = pacnew.read_text(str(path))
    assert text.startswith("caf")
    assert "\ufffd" in text  # replacement char, not a decode exception


def test_read_text_missing_file_raises_runtime_error(etc):
    with pytest.raises(RuntimeError, match="latin1.conf"):
        pacnew.read_text(str(etc / "latin1.conf"))


def test_read_text_on_a_directory_raises_runtime_error(etc):
    with pytest.raises(RuntimeError):
        pacnew.read_text(str(etc))


# --------------------------------------------------------------------- diffing --

def test_diff_text_labels_sides_and_shows_changes(etc):
    live = etc / "app.conf"
    live.write_text("keep\nold\n", encoding="utf-8")
    candidate = etc / "app.conf.pacnew"
    candidate.write_text("keep\nnew\n", encoding="utf-8")

    text = pacnew.diff_text(_entry("pacnew", candidate, live, True))

    assert str(live) in text
    assert str(candidate) in text
    changes = [line for line in text.splitlines() if line[:1] in "+-" and not line.startswith(("+++", "---"))]
    assert changes == ["-old", "+new"]
    assert "@@" in text


def test_diff_text_missing_live_file_shows_every_line_added(etc):
    live = etc / "new.conf"  # never created
    candidate = etc / "new.conf.pacnew"
    candidate.write_text("one\ntwo\n", encoding="utf-8")

    text = pacnew.diff_text(_entry("pacsave", candidate, live, False))

    changes = [line for line in text.splitlines() if line[:1] in "+-" and not line.startswith(("+++", "---"))]
    assert changes == ["+one", "+two"]
    assert str(live) in text
    assert str(candidate) in text


def test_diff_text_identical_files_is_empty(etc):
    live = etc / "same.conf"
    live.write_text("same\n", encoding="utf-8")
    candidate = etc / "same.conf.pacnew"
    candidate.write_text("same\n", encoding="utf-8")

    assert pacnew.diff_text(_entry("pacnew", candidate, live, True)) == ""


# --------------------------------------------------------------------- actions --

def test_apply_new_backs_up_then_sends_the_helper_argv(etc, fake_run, fake_which, privilege_paths):
    live = etc / "app.conf"
    live.write_text("live version\n", encoding="utf-8")
    candidate = etc / "app.conf.pacnew"
    candidate.write_text("new version\n", encoding="utf-8")

    result = pacnew.apply_new(_entry("pacnew", candidate, live, True))

    assert result.ok
    assert fake_run.calls == [["pkexec", "pacnew-apply", str(candidate)]]

    backups = list(privilege_paths.backup_dir.glob("app.conf.*.bak"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "live version\n"
    assert str(live) in privilege_paths.manifest.read_text(encoding="utf-8")


def test_apply_new_without_a_live_file_still_sends_the_helper_argv(etc, fake_run, fake_which, privilege_paths):
    candidate = etc / "gone.conf.pacsave"
    candidate.write_text("saved version\n", encoding="utf-8")
    live = etc / "gone.conf"  # the package is gone, so there is nothing to back up

    result = pacnew.apply_new(_entry("pacsave", candidate, live, False))

    assert result.ok
    assert fake_run.calls == [["pkexec", "pacnew-apply", str(candidate)]]
    # backup_file() returning None for a missing live file is normal, not an
    # error - and it must not leave an empty backup dir behind either.
    assert not privilege_paths.backup_dir.exists()


def test_apply_new_rejects_a_bad_suffix(etc, fake_run, fake_which):
    candidate = etc / "app.conf.bak"
    live = etc / "app.conf"

    with pytest.raises(ValueError):
        pacnew.apply_new(_entry("pacnew", candidate, live, True))

    assert fake_run.calls == []  # refused before any password prompt


def test_apply_new_refuses_the_account_databases_before_any_prompt(etc, fake_run, fake_which, privilege_paths):
    live = etc / "shadow"
    live.write_text("me:$y$hash:20000::::::\n", encoding="utf-8")
    candidate = etc / "shadow.pacnew"
    candidate.write_text("root:*:14871::::::\n", encoding="utf-8")

    with pytest.raises(ValueError, match="by hand"):
        pacnew.apply_new(_entry("pacnew", candidate, live, True))

    assert fake_run.calls == []
    # Nothing was backed up either - a backup of shadow is itself a copy of
    # every password hash.
    assert not privilege_paths.backup_dir.exists()


def test_discard_sends_the_helper_argv(etc, fake_run, fake_which):
    candidate = etc / "app.conf.pacnew"

    result = pacnew.discard(_entry("pacnew", candidate, etc / "app.conf", True))

    assert result.ok
    assert fake_run.calls == [["pkexec", "pacnew-remove", str(candidate)]]


def test_discard_rejects_a_bad_suffix(etc, fake_run, fake_which):
    candidate = etc / "app.conf"

    with pytest.raises(ValueError):
        pacnew.discard(_entry("pacnew", candidate, etc / "app.conf", True))

    assert fake_run.calls == []
