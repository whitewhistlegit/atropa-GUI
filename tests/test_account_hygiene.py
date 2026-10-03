"""Tests for atropa.backend.account_hygiene."""
from __future__ import annotations

import grp
import pwd
import stat
from collections import namedtuple

import pytest

from atropa.backend import account_hygiene as ah

FakePwEntry = namedtuple("FakePwEntry", ["pw_name", "pw_uid", "pw_gid", "pw_gecos", "pw_dir", "pw_shell"])
FakeGrEntry = namedtuple("FakeGrEntry", ["gr_name", "gr_gid", "gr_mem"])


@pytest.fixture
def fake_passwd_db(monkeypatch):
    entries = [
        FakePwEntry("root", 0, 0, "root", "/root", "/bin/bash"),
        FakePwEntry("daemon", 1, 1, "daemon", "/", "/usr/bin/nologin"),
        FakePwEntry("alice", 1000, 1000, "Alice", "/home/alice", "/bin/zsh"),
        FakePwEntry("bob", 1001, 1001, "Bob", "/home/bob", "/bin/bash"),
    ]
    groups = [
        FakeGrEntry("root", 0, []),
        FakeGrEntry("wheel", 10, ["alice"]),
    ]
    monkeypatch.setattr(pwd, "getpwall", lambda: entries)
    monkeypatch.setattr(grp, "getgrall", lambda: groups)
    return entries, groups


# --------------------------------------------------------------- duplicates --

def test_no_duplicates_all_pass(fake_passwd_db):
    findings = {f.key: f for f in ah._check_duplicates()}
    assert findings["dup-uid"].status == "pass"
    assert findings["dup-username"].status == "pass"
    assert findings["dup-gid"].status == "pass"
    assert findings["dup-groupname"].status == "pass"


def test_duplicate_uid_detected(monkeypatch):
    entries = [
        FakePwEntry("root", 0, 0, "root", "/root", "/bin/bash"),
        FakePwEntry("shadowroot", 0, 0, "sneaky", "/home/shadowroot", "/bin/bash"),
    ]
    monkeypatch.setattr(pwd, "getpwall", lambda: entries)
    monkeypatch.setattr(grp, "getgrall", lambda: [])
    findings = {f.key: f for f in ah._check_duplicates()}
    assert findings["dup-uid"].status == "fail"
    assert "0" in findings["dup-uid"].detail


def test_duplicate_groupname_detected(monkeypatch):
    monkeypatch.setattr(pwd, "getpwall", lambda: [])
    monkeypatch.setattr(
        grp, "getgrall",
        lambda: [FakeGrEntry("wheel", 10, []), FakeGrEntry("wheel", 11, [])],
    )
    findings = {f.key: f for f in ah._check_duplicates()}
    assert findings["dup-groupname"].status == "fail"
    assert findings["dup-gid"].status == "pass"  # GIDs 10 and 11 are distinct even though names collide


# --------------------------------------------------------------- uid zero --

def test_only_root_has_uid_zero_passes(fake_passwd_db):
    assert ah._check_uid_zero().status == "pass"


def test_extra_uid_zero_account_fails(monkeypatch):
    entries = [
        FakePwEntry("root", 0, 0, "root", "/root", "/bin/bash"),
        FakePwEntry("backdoor", 0, 0, "x", "/home/backdoor", "/bin/bash"),
    ]
    monkeypatch.setattr(pwd, "getpwall", lambda: entries)
    result = ah._check_uid_zero()
    assert result.status == "fail"
    assert "backdoor" in result.detail


# --------------------------------------------------------------- system account shells --

def test_system_accounts_with_nologin_pass(fake_passwd_db):
    assert ah._check_system_account_shells().status == "pass"


def test_system_account_with_login_shell_warns(monkeypatch):
    entries = [
        FakePwEntry("root", 0, 0, "root", "/root", "/bin/bash"),
        FakePwEntry("sneaky", 33, 33, "x", "/", "/bin/bash"),
    ]
    monkeypatch.setattr(pwd, "getpwall", lambda: entries)
    result = ah._check_system_account_shells()
    assert result.status == "warn"
    assert "sneaky" in result.detail


def test_root_uid_zero_shell_never_flagged(monkeypatch):
    """Root is UID 0, explicitly excluded from the system-account shell check."""
    entries = [FakePwEntry("root", 0, 0, "root", "/root", "/bin/bash")]
    monkeypatch.setattr(pwd, "getpwall", lambda: entries)
    assert ah._check_system_account_shells().status == "pass"


# --------------------------------------------------------------- home directories --

def test_home_directory_missing_fails(monkeypatch, tmp_path):
    missing = tmp_path / "nonexistent_home"
    entries = [FakePwEntry("alice", 1000, 1000, "Alice", str(missing), "/bin/bash")]
    monkeypatch.setattr(pwd, "getpwall", lambda: entries)
    findings = ah._check_home_directories()
    assert len(findings) == 1
    assert findings[0].status == "fail"
    assert "does not exist" in findings[0].detail


def test_home_directory_correct_ownership_and_mode_passes(monkeypatch, tmp_path):
    import os

    home = tmp_path / "alice_home"
    home.mkdir()
    home.chmod(0o700)
    # Use whatever UID this test process actually runs as (root locally, an
    # unprivileged CI runner user in GitHub Actions) rather than a fixed 1000 -
    # we can't chown to an arbitrary UID without being root. Lower the
    # interactive-UID floor to 0 so this test's UID isn't skipped either way.
    monkeypatch.setattr(ah, "MIN_INTERACTIVE_UID", 0)
    entries = [FakePwEntry("alice", os.getuid(), os.getgid(), "Alice", str(home), "/bin/bash")]
    monkeypatch.setattr(pwd, "getpwall", lambda: entries)
    findings = ah._check_home_directories()
    assert findings[0].status == "pass"


def test_home_directory_world_writable_warns(monkeypatch, tmp_path):
    import os

    home = tmp_path / "alice_home"
    home.mkdir()
    home.chmod(0o777)
    monkeypatch.setattr(ah, "MIN_INTERACTIVE_UID", 0)
    entries = [FakePwEntry("alice", os.getuid(), os.getgid(), "Alice", str(home), "/bin/bash")]
    monkeypatch.setattr(pwd, "getpwall", lambda: entries)
    findings = ah._check_home_directories()
    assert findings[0].status == "warn"


def test_home_directory_skips_system_accounts_and_nobody(monkeypatch):
    entries = [
        FakePwEntry("daemon", 1, 1, "daemon", "/", "/usr/bin/nologin"),
        FakePwEntry("nobody", 65534, 65534, "nobody", "/", "/usr/bin/nologin"),
    ]
    monkeypatch.setattr(pwd, "getpwall", lambda: entries)
    assert ah._check_home_directories() == []


# --------------------------------------------------------------- empty passwords --

def test_empty_password_field_detected(fake_run, fake_which):
    fake_run.set_response(
        ["pkexec", "cat", "/etc/shadow"],
        stdout="root:$6$abc:19700:0:99999:7:::\nghost::19700:0:99999:7:::\n",
    )
    result = ah._check_empty_passwords()
    assert result.status == "fail"
    assert "ghost" in result.detail


def test_no_empty_password_fields_passes(fake_run, fake_which):
    fake_run.set_response(
        ["pkexec", "cat", "/etc/shadow"],
        stdout="root:$6$abc:19700:0:99999:7:::\nalice:$6$def:19700:0:99999:7:::\n",
    )
    result = ah._check_empty_passwords()
    assert result.status == "pass"


def test_empty_password_check_handles_unreadable_shadow(fake_run, fake_which):
    fake_run.set_response(["pkexec", "cat", "/etc/shadow"], returncode=1, stderr="permission denied")
    result = ah._check_empty_passwords()
    assert result.status == "info"


# --------------------------------------------------------------- root PATH --

def test_root_path_with_no_assignment_found_is_info(fake_run, fake_which, monkeypatch):
    fake_run.set_response(["pkexec", "cat", "/root/.bash_profile", "/root/.bashrc"], returncode=1)
    monkeypatch.setattr(ah.Path, "exists", lambda self: False)
    result = ah._check_root_path()
    assert result.status == "info"


def test_root_path_flags_dot_component(fake_run, fake_which, monkeypatch):
    fake_run.set_response(["pkexec", "cat", "/root/.bash_profile", "/root/.bashrc"], stdout='PATH="/usr/bin:.:/bin"\n')
    monkeypatch.setattr(ah.Path, "exists", lambda self: False)
    result = ah._check_root_path()
    assert result.status == "fail"
    assert "'.'" in result.detail


def test_root_path_clean_assignment_passes(fake_run, fake_which, monkeypatch):
    fake_run.set_response(["pkexec", "cat", "/root/.bash_profile", "/root/.bashrc"], stdout="PATH=/usr/local/sbin:/usr/bin:/sbin\n")
    monkeypatch.setattr(ah.Path, "exists", lambda self: False)
    result = ah._check_root_path()
    assert result.status == "pass"


# --------------------------------------------------------------- file perms --

def test_file_perms_flags_looser_than_expected(monkeypatch):
    class FakeStat:
        st_mode = 0o100644 | stat.S_IWOTH  # world-writable passwd - should fail

    monkeypatch.setattr(ah.Path, "exists", lambda self: True)
    monkeypatch.setattr(ah.Path, "stat", lambda self: FakeStat())
    findings = {f.key: f for f in ah._check_file_perms()}
    assert findings["perms-passwd"].status == "fail"


def test_file_perms_missing_file_is_info(monkeypatch):
    monkeypatch.setattr(ah.Path, "exists", lambda self: False)
    findings = {f.key: f for f in ah._check_file_perms()}
    assert all(f.status == "info" for f in findings.values())


# --------------------------------------------------------------- scan_all --

def test_scan_all_aggregates_every_check(fake_passwd_db, fake_run, fake_which):
    fake_run.set_response(["pkexec", "cat", "/etc/shadow"], returncode=1)
    fake_run.set_response(["pkexec", "cat", "/root/.bash_profile", "/root/.bashrc"], returncode=1)
    results = ah.scan_all()
    keys = {f.key for f in results}
    assert "dup-uid" in keys
    assert "uid-zero" in keys
    assert "system-shells" in keys
    assert "empty-password" in keys
    assert "root-path" in keys
    assert any(k.startswith("perms-") for k in keys)
    assert any(k.startswith("home-") for k in keys)
