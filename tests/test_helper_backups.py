"""Tests for the helper's root-owned backup store (helper phase 3)."""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from atropa import helper
from atropa.backend import privilege


@pytest.fixture
def etc(tmp_path, monkeypatch):
    """A fake /etc whose files the helper may write and backs up."""
    directory = tmp_path / "etc"
    directory.mkdir()
    monkeypatch.setattr(helper, "ETC_ROOT", str(directory))
    monkeypatch.setattr(helper, "WRITE_DIRS", (str(directory) + "/",))
    monkeypatch.setattr(helper, "WRITE_FILES", frozenset())
    return directory


def store() -> Path:
    return Path(helper.BACKUP_STORE)


def manifest() -> list[dict]:
    path = store() / helper.BACKUP_MANIFEST_NAME
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def handle(argv, data=b"", tier=helper.KEEP):
    return helper.handle(argv, data, tier=tier)


# ------------------------------------------------------------ made on write --

def test_tee_backs_the_old_content_up_before_overwriting(etc):
    target = etc / "sshd_config"
    target.write_text("old\n")

    assert handle(["tee", str(target)], b"new\n") == 0

    assert target.read_text() == "new\n"
    (entry,) = manifest()
    assert entry["original_path"] == str(target)
    assert (store() / entry["backup_file"]).read_text() == "old\n"


def test_the_store_is_root_only_except_the_manifest(etc):
    target = etc / "pacman.conf"
    target.write_text("old\n")
    handle(["tee", str(target)], b"new\n")

    (entry,) = manifest()
    assert stat.S_IMODE(os.stat(store()).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(store() / entry["backup_file"]).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(store() / helper.BACKUP_MANIFEST_NAME).st_mode) == 0o644


def test_a_new_file_has_nothing_to_back_up(etc):
    handle(["tee", str(etc / "new.conf")], b"x")
    assert manifest() == []


def test_files_outside_etc_are_not_backed_up(tmp_path, etc, monkeypatch):
    state = tmp_path / "state"
    state.write_text("1")
    monkeypatch.setattr(helper, "WRITE_FILES", frozenset({str(state)}))
    handle(["tee", str(state)], b"2")
    assert manifest() == []


def test_install_and_replace_in_file_back_up_too(etc):
    first = etc / "a.conf"
    second = etc / "b.conf"
    first.write_text("one\n")
    second.write_text("enabled=no\n")

    handle(["install", "-m", "0644", "/dev/stdin", str(first)], b"two\n")
    handle(["replace-in-file", str(second), "^enabled=no$", "enabled=yes"])

    backed_up = {entry["original_path"]: (store() / entry["backup_file"]).read_text() for entry in manifest()}
    assert backed_up == {str(first): "one\n", str(second): "enabled=no\n"}


def test_replace_in_file_that_changes_nothing_makes_no_backup(etc):
    target = etc / "c.conf"
    target.write_text("enabled=yes\n")
    handle(["replace-in-file", str(target), "^enabled=no$", "enabled=yes"])
    assert manifest() == []


def test_one_operation_makes_one_backup(etc):
    target = etc / "pacman.conf"
    target.write_text("original\n")
    handle(["tee", str(target)], b"step 1\n")
    handle(["tee", str(target)], b"step 2\n")

    (entry,) = manifest()
    assert (store() / entry["backup_file"]).read_text() == "original\n"


def test_a_later_operation_makes_a_new_backup(etc, monkeypatch):
    target = etc / "pacman.conf"
    target.write_text("original\n")
    handle(["tee", str(target)], b"step 1\n")
    later = datetime.now() + timedelta(seconds=helper.BACKUP_WINDOW_SECONDS + 1)

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return later

    monkeypatch.setattr("datetime.datetime", Later)
    handle(["tee", str(target)], b"step 2\n")

    assert [(store() / e["backup_file"]).read_text() for e in manifest()] == ["original\n", "step 1\n"]


def test_only_the_newest_backups_of_a_file_are_kept(etc, monkeypatch):
    monkeypatch.setattr(helper, "BACKUP_KEEP_PER_FILE", 2)
    monkeypatch.setattr(helper, "BACKUP_WINDOW_SECONDS", 0)
    target = etc / "f.conf"
    other = etc / "g.conf"
    other.write_text("other\n")
    handle(["tee", str(other)], b"other 2\n")
    for number in range(4):
        target.write_text(f"v{number}\n")
        helper.backup_before_write(str(target), str(target), force=True)

    kept = [e for e in manifest() if e["original_path"] == str(target)]
    assert [(store() / e["backup_file"]).read_text() for e in kept] == ["v2\n", "v3\n"]
    assert len([p for p in store().iterdir() if p.suffix == ".bak"]) == 3  # two of f.conf, one of g.conf


def test_a_symlinked_target_is_not_followed_into_the_store(etc, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("secret")
    link = etc / "link.conf"
    link.symlink_to(secret)
    assert helper.backup_before_write(str(link), str(link)) is None
    assert manifest() == []


def test_pacnew_apply_backs_up_the_live_file(etc):
    live = etc / "locale.gen"
    live.write_text("mine\n")
    (etc / "locale.gen.pacnew").write_text("theirs\n")

    handle(["pacnew-apply", str(etc / "locale.gen.pacnew")])

    (entry,) = manifest()
    assert entry["original_path"] == str(live)
    assert (store() / entry["backup_file"]).read_text() == "mine\n"


def test_a_failed_backup_does_not_stop_the_write(etc, monkeypatch, capsys):
    target = etc / "d.conf"
    target.write_text("old")
    monkeypatch.setattr(helper, "BACKUP_STORE", "/proc/nope/backups")
    assert handle(["tee", str(target)], b"new") == 0
    assert target.read_text() == "new"
    assert "couldn't back up" in capsys.readouterr().err


# ------------------------------------------------------------ show/restore --

def _backup(etc, name="sshd_config", old="old\n", new=b"new\n"):
    target = etc / name
    target.write_text(old)
    handle(["tee", str(target)], new)
    return target, manifest()[-1]["backup_file"]


def test_backup_show_prints_the_content(etc, capsysbinary):
    _target, name = _backup(etc)
    assert handle(["backup-show", name]) == 0
    assert capsysbinary.readouterr().out == b"old\n"


def test_backup_restore_writes_it_back_and_keeps_the_replaced_version(etc):
    target, name = _backup(etc)

    assert handle(["backup-restore", name, str(target)]) == 0

    assert target.read_text() == "old\n"
    # The restore backed up "new\n" first, so it can be undone.
    assert [(store() / e["backup_file"]).read_text() for e in manifest()] == ["old\n", "new\n"]


def test_backup_restore_refuses_another_files_path(etc):
    _target, name = _backup(etc)
    other = etc / "other.conf"
    other.write_text("keep me")
    with pytest.raises(helper.Refused, match="is a backup of"):
        handle(["backup-restore", name, str(other)])
    assert other.read_text() == "keep me"


@pytest.mark.parametrize(
    "name",
    ["../../etc/shadow", "manifest.jsonl", "nope.bak", "x.20260101_000000_000000.bak", ""],
)
def test_backup_show_and_restore_refuse_anything_but_a_listed_backup(etc, name):
    _backup(etc)
    with pytest.raises(helper.Refused):
        handle(["backup-show", name])
    with pytest.raises(helper.Refused):
        handle(["backup-restore", name, str(etc / "sshd_config")])


def test_backup_restore_still_goes_through_the_write_policy(etc, monkeypatch):
    target, name = _backup(etc)
    monkeypatch.setattr(helper, "WRITE_DIRS", ())
    with pytest.raises(helper.Refused, match="isn't a file Atropa is allowed to write"):
        handle(["backup-restore", name, str(target)])


def test_restoring_an_ask_tier_file_asks(etc, monkeypatch):
    target, name = _backup(etc, "pacman.conf")
    monkeypatch.setattr(helper, "ASK_WRITE_FILES", frozenset({str(target)}))
    assert helper.needs_fresh_auth(["backup-restore", name, str(target)])
    assert not helper.needs_fresh_auth(["backup-show", name])
    with pytest.raises(helper.Refused, match="asks for a password every time"):
        handle(["backup-restore", name, str(target)])
    assert handle(["backup-restore", name, str(target)], tier=helper.ASK) == 0


# ------------------------------------------------------------- privilege.py --

@pytest.fixture
def with_helper(monkeypatch):
    monkeypatch.setattr(privilege, "helper_available", lambda: True)
    monkeypatch.setattr(privilege, "_installed", lambda _path: True)


def _system_manifest(*entries):
    privilege.SYSTEM_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    privilege.SYSTEM_BACKUP_MANIFEST.write_text("".join(json.dumps(e) + "\n" for e in entries))


def _home_manifest(*entries):
    privilege.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    privilege.BACKUP_MANIFEST.write_text("".join(json.dumps(e) + "\n" for e in entries))


SSHD = "/etc/ssh/sshd_config"


def test_backup_file_leaves_it_to_the_helper(with_helper, tmp_path):
    src = tmp_path / "file"
    src.write_text("x")
    assert privilege.backup_file(str(src)) is None
    assert not privilege.BACKUP_DIR.exists()


def test_list_backups_merges_both_stores_newest_first(with_helper):
    _system_manifest({"timestamp": "20260102_000000_000000", "original_path": SSHD, "backup_file": "s.bak"})
    _home_manifest({"timestamp": "20260101_000000_000000", "original_path": SSHD, "backup_file": "h.bak"})

    entries = privilege.list_backups()

    assert [(e["backup_file"], e["stored"], e["restorable"]) for e in entries] == [
        ("s.bak", "system", True),
        ("h.bak", "home", False),  # anything running as the user could have changed it
    ]


def test_without_the_helper_home_backups_stay_restorable():
    _home_manifest({"timestamp": "20260101_000000_000000", "original_path": SSHD, "backup_file": "h.bak"})
    (entry,) = privilege.list_backups()
    assert entry["stored"] == "home" and entry["restorable"]


def test_restore_of_a_system_backup_goes_through_the_helper(with_helper, fake_run, fake_which):
    privilege.restore_file("s.bak", SSHD, "system")
    assert fake_run.calls[-1][-3:] == ["backup-restore", "s.bak", SSHD]
    assert fake_run.calls[-1][1] == str(privilege.ASK_HELPER_PATH)  # sshd_config asks every time
    assert fake_run.inputs[-1] is None  # the content never passes through the app


def test_restore_of_a_home_backup_is_refused_once_the_helper_exists(with_helper, fake_run):
    _home_manifest({"timestamp": "1", "original_path": SSHD, "backup_file": "h.bak"})
    (privilege.BACKUP_DIR / "h.bak").write_text("planted")
    with pytest.raises(privilege.PrivilegeError, match="home directory"):
        privilege.restore_file("h.bak", SSHD, "home")
    assert fake_run.calls == []


def test_read_backup_of_a_system_backup_uses_backup_show(with_helper, fake_run, fake_which):
    fake_run.set_response(["pkexec"], stdout="content")
    assert privilege.read_backup("s.bak", "system") == "content"
    assert fake_run.calls[-1][-2:] == ["backup-show", "s.bak"]


def test_backup_show_refuses_a_backup_of_a_file_cat_may_not_read(etc, monkeypatch):
    # pacnew-apply replaces any /etc file, e.g. sudoers; its backup must not
    # become a way to read that file on a cached authorization.
    live = etc / "sudoers"
    live.write_text("root-only\n")
    (etc / "sudoers.pacnew").write_text("new\n")
    monkeypatch.setattr(helper, "WRITE_DIRS", ())
    handle(["pacnew-apply", str(etc / "sudoers.pacnew")])
    (entry,) = manifest()

    with pytest.raises(helper.Refused, match="isn't a file Atropa reads"):
        handle(["backup-show", entry["backup_file"]])
