"""Tests for atropa.backend.users."""
from __future__ import annotations

import grp
import pwd
from collections import namedtuple

import pytest

from atropa.backend import users

# Minimal stand-ins for the structs returned by pwd.getpwall()/grp.getgrall(),
# since the real ones are C structs that can't be constructed directly.
FakePwEntry = namedtuple("FakePwEntry", ["pw_name", "pw_uid", "pw_gid", "pw_gecos", "pw_dir", "pw_shell"])
FakeGrEntry = namedtuple("FakeGrEntry", ["gr_name", "gr_gid", "gr_mem"])


@pytest.fixture
def fake_passwd_db(monkeypatch):
    entries = [
        FakePwEntry("root", 0, 0, "root", "/root", "/bin/bash"),
        FakePwEntry("daemon", 1, 1, "daemon", "/", "/usr/bin/nologin"),
        FakePwEntry("alice", 1000, 1000, "Alice Example,,,", "/home/alice", "/bin/zsh"),
        FakePwEntry("bob", 1001, 1001, "Bob Example", "/home/bob", "/bin/bash"),
    ]
    groups = [
        FakeGrEntry("root", 0, []),
        FakeGrEntry("wheel", 10, ["alice"]),
        FakeGrEntry("users", 1000, ["alice", "bob"]),
    ]
    monkeypatch.setattr(pwd, "getpwall", lambda: entries)
    monkeypatch.setattr(grp, "getgrall", lambda: groups)
    return entries, groups


def test_list_users_excludes_system_users_by_default(fake_passwd_db):
    result = users.list_users(include_system=False)
    names = [u.username for u in result]
    # root (uid 0) is always kept even though it's "system"; daemon (uid 1) is excluded
    assert "daemon" not in names
    assert "root" in names
    assert "alice" in names
    assert "bob" in names


def test_list_users_includes_system_when_requested(fake_passwd_db):
    result = users.list_users(include_system=True)
    assert {u.username for u in result} == {"root", "daemon", "alice", "bob"}


def test_list_users_sorted_by_uid(fake_passwd_db):
    result = users.list_users(include_system=True)
    assert [u.uid for u in result] == [0, 1, 1000, 1001]


def test_list_users_full_name_strips_extra_gecos_fields(fake_passwd_db):
    result = users.list_users(include_system=False)
    alice = next(u for u in result if u.username == "alice")
    assert alice.full_name == "Alice Example"


def test_list_users_group_membership(fake_passwd_db):
    result = users.list_users(include_system=False)
    alice = next(u for u in result if u.username == "alice")
    bob = next(u for u in result if u.username == "bob")
    assert set(alice.groups) == {"wheel", "users"}
    assert set(bob.groups) == {"users"}


def test_list_groups_excludes_system_by_default(fake_passwd_db):
    result = users.list_groups(include_system=False)
    names = {g.name for g in result}
    assert "wheel" not in names  # gid 10 < 1000
    assert "users" in names
    assert "root" in names  # gid 0 always kept


def test_list_groups_includes_system_when_requested(fake_passwd_db):
    result = users.list_groups(include_system=True)
    assert {g.name for g in result} == {"root", "wheel", "users"}


# --------------------------------------------------------------- mutating ops --

def test_create_user_minimal(fake_run, fake_which):
    users.create_user("carol")
    assert fake_run.last_call() == ["pkexec", "useradd", "-m", "-s", "/bin/bash", "carol"]


def test_create_user_no_home(fake_run, fake_which):
    users.create_user("carol", create_home=False)
    assert fake_run.last_call() == ["pkexec", "useradd", "-M", "-s", "/bin/bash", "carol"]


def test_create_user_with_full_name_and_groups(fake_run, fake_which):
    users.create_user("carol", full_name="Carol Example", extra_groups=["wheel", "users"])
    assert fake_run.last_call() == [
        "pkexec", "useradd", "-m", "-s", "/bin/bash", "-c", "Carol Example",
        "-G", "wheel,users", "carol",
    ]


def test_set_password_uses_stdin_not_argv(fake_run, fake_which):
    users.set_password("carol", "hunter2")
    call = fake_run.last_call()
    assert call == ["pkexec", "chpasswd"]
    assert "hunter2" not in call  # must never appear on the command line


def test_modify_user_lock(fake_run, fake_which):
    users.modify_user("carol", lock=True)
    assert fake_run.last_call() == ["pkexec", "usermod", "-L", "carol"]


def test_modify_user_unlock(fake_run, fake_which):
    users.modify_user("carol", lock=False)
    assert fake_run.last_call() == ["pkexec", "usermod", "-U", "carol"]


def test_modify_user_no_lock_arg_omits_flag(fake_run, fake_which):
    users.modify_user("carol", shell="/bin/fish")
    assert fake_run.last_call() == ["pkexec", "usermod", "-s", "/bin/fish", "carol"]


def test_delete_user_default_keeps_home(fake_run, fake_which):
    users.delete_user("carol")
    assert fake_run.last_call() == ["pkexec", "userdel", "carol"]


def test_delete_user_remove_home(fake_run, fake_which):
    users.delete_user("carol", remove_home=True)
    assert fake_run.last_call() == ["pkexec", "userdel", "-r", "carol"]


def test_create_and_delete_group(fake_run, fake_which):
    users.create_group("developers")
    assert fake_run.last_call() == ["pkexec", "groupadd", "developers"]
    users.delete_group("developers")
    assert fake_run.last_call() == ["pkexec", "groupdel", "developers"]
