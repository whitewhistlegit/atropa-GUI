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


def test_nobody_is_not_listed_as_a_regular_account(fake_passwd_db):
    # uid/gid 65534 is above login.defs' UID_MAX; it used to show up with a delete button.
    entries, groups = fake_passwd_db
    entries.append(FakePwEntry("nobody", 65534, 65534, "Kernel Overflow User", "/", "/usr/bin/nologin"))
    groups.append(FakeGrEntry("nobody", 65534, []))
    assert "nobody" not in [u.username for u in users.list_users()]
    assert "nobody" not in [g.name for g in users.list_groups()]
    assert "nobody" in [u.username for u in users.list_users(include_system=True)]
    assert "nobody" in [g.name for g in users.list_groups(include_system=True)]


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
    assert fake_run.inputs[-1] == "carol:hunter2\n"


@pytest.mark.parametrize(
    "username, password",
    [
        ("carol", "one\nroot:two"),  # a pasted second line would be a second chpasswd entry
        ("carol", "one\rtwo"),
        ("carol", ""),
        ("", "hunter2"),
        ("carol:x", "hunter2"),
        ("carol\nroot", "hunter2"),
    ],
)
def test_set_password_refuses_what_would_not_stay_one_entry(fake_run, fake_which, username, password):
    with pytest.raises(ValueError):
        users.set_password(username, password)
    assert fake_run.calls == []


def test_set_password_allows_a_colon_in_the_password(fake_run, fake_which):
    users.set_password("carol", "with: colon")
    assert fake_run.inputs[-1] == "carol:with: colon\n"


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


def test_set_groups_replaces_the_whole_list(fake_run, fake_which):
    users.set_groups("carol", ["audio", "wheel"])
    assert fake_run.last_call() == ["pkexec", "usermod", "-G", "audio,wheel", "carol"]
    users.set_groups("carol", [])
    assert fake_run.last_call() == ["pkexec", "usermod", "-G", "", "carol"]


def test_supplementary_groups_lists_memberships(fake_passwd_db):
    assert users.supplementary_groups("alice") == ["users", "wheel"]
    assert users.supplementary_groups("root") == []


def test_groups_warning_when_the_only_admin_leaves_wheel(fake_passwd_db):
    assert "only member" in users.groups_warning("alice", ["users"])
    assert users.groups_warning("alice", ["users", "wheel"]) == ""
    assert users.groups_warning("bob", []) == ""  # was never in it


def test_groups_warning_when_another_admin_remains(fake_passwd_db):
    _entries, groups = fake_passwd_db
    groups[1] = groups[1]._replace(gr_mem=["alice", "bob"])
    assert "stops being an administrator" in users.groups_warning("alice", ["users"])


def test_groups_warning_ignores_admins_through_the_primary_group(fake_passwd_db):
    # usermod -G can't take a primary group away, so nothing is lost.
    entries, groups = fake_passwd_db
    entries.append(FakePwEntry("carol", 1002, 10, "", "/home/carol", "/bin/bash"))
    groups[1] = groups[1]._replace(gr_mem=["alice", "carol"])
    assert users.groups_warning("carol", []) == ""


def test_group_delete_refusal(fake_passwd_db):
    _entries, groups = fake_passwd_db
    groups.append(FakeGrEntry("developers", 1005, ["alice", "bob"]))
    assert "root" in users.group_delete_refusal("root")
    assert "administrator" in users.group_delete_refusal("wheel")
    assert "alice" in users.group_delete_refusal("users")  # gid 1000 is alice's primary group
    assert users.group_delete_refusal("developers") is None
    assert users.group_delete_refusal("nosuchgroup") is None


# ------------------------------------------------------------ lock/delete guards --

@pytest.fixture
def signed_in_as(monkeypatch, fake_passwd_db):
    """Pretend the GUI runs as the given uid (fake_passwd_db: root=0, alice=1000 in wheel, bob=1001)."""
    def _set(uid: int):
        monkeypatch.setattr(users.os, "getuid", lambda: uid)
    return _set


def test_locking_your_own_account_is_refused(signed_in_as):
    signed_in_as(1000)
    assert "signed in with" in users.lock_refusal("alice")
    assert users.lock_refusal("bob") is None


def test_deleting_your_own_account_or_root_is_refused(signed_in_as):
    signed_in_as(1000)
    assert "signed in with" in users.delete_refusal("alice")
    assert "root" in users.delete_refusal("root")
    assert users.delete_refusal("bob") is None


def test_locking_root_is_allowed_while_someone_can_answer_prompts(signed_in_as):
    signed_in_as(1001)  # bob isn't in wheel, but alice is - polkit asks for her password
    assert users.lock_refusal("root") is None


def test_locking_root_is_refused_when_nobody_is_in_wheel(signed_in_as, fake_passwd_db):
    # polkit falls back to root's password when the admin group is empty.
    _entries, groups = fake_passwd_db
    groups[1] = groups[1]._replace(gr_mem=[])
    signed_in_as(1001)
    assert "wheel" in users.lock_refusal("root")


def test_lock_warning_for_the_only_admin(signed_in_as):
    signed_in_as(1001)
    assert "only member" in users.lock_warning("alice")
    assert users.lock_warning("bob") == ""


def test_lock_warning_counts_primary_group_members_as_admins(signed_in_as, fake_passwd_db):
    # Membership through the primary gid never shows up in gr_mem.
    entries, _groups = fake_passwd_db
    entries.append(FakePwEntry("carol", 1002, 10, "", "/home/carol", "/bin/bash"))
    signed_in_as(1001)
    assert "administrator" in users.lock_warning("alice")
    assert "only member" not in users.lock_warning("alice")
