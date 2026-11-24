"""Tests for restricting su to the wheel group (hardening.py)."""

from __future__ import annotations

import pytest

from atropa.backend import hardening, users

STOCK = """#%PAM-1.0
auth            sufficient      pam_rootok.so
# Uncomment the following line to implicitly trust users in the "wheel" group.
#auth           sufficient      pam_wheel.so trust use_uid
# Uncomment the following line to require a user to be in the "wheel" group.
#auth           required        pam_wheel.so use_uid
auth            required        pam_unix.so
account         required        pam_unix.so
session         required        pam_unix.so
"""


@pytest.fixture
def pam(tmp_path, monkeypatch):
    directory = tmp_path / "pam.d"
    directory.mkdir()
    files = (directory / "su", directory / "su-l")
    for path in files:
        path.write_text(STOCK)
    monkeypatch.setattr(hardening, "PAM_SU_FILES", files)
    monkeypatch.setattr(users, "_admin_usernames", lambda: {"me"})
    monkeypatch.setattr("getpass.getuser", lambda: "me")
    return files


def test_stock_files_are_open(pam):
    status = hardening.su_restriction_status()
    assert set(status.files.values()) == {"open"}
    assert not status.restricted and not status.trusting and status.user_in_wheel


def test_restricted_when_every_file_requires_wheel(pam):
    for path in pam:
        path.write_text(STOCK.replace("#auth           required        pam_wheel", "auth required pam_wheel"))
    assert hardening.su_restriction_status().restricted


def test_one_restricted_file_is_not_enough(pam):
    pam[0].write_text(STOCK.replace("#auth           required        pam_wheel", "auth required pam_wheel"))
    status = hardening.su_restriction_status()
    assert not status.restricted
    assert status.files[str(pam[0])] == "restricted" and status.files[str(pam[1])] == "open"


def test_a_trust_line_is_reported(pam):
    pam[0].write_text(STOCK.replace("#auth           sufficient      pam_wheel.so trust", "auth sufficient pam_wheel.so trust"))
    assert hardening.su_restriction_status().trusting


def test_a_hand_edited_file_is_custom(pam):
    pam[1].write_text("auth required pam_unix.so\n")
    assert hardening.su_restriction_status().files[str(pam[1])] == "custom"


def test_a_missing_su_l_is_skipped(pam):
    pam[1].unlink()
    assert list(hardening.su_restriction_status().files) == [str(pam[0])]


def test_restrict_uncomments_the_stock_line_in_both_files(pam, fake_run, fake_which):
    assert hardening.restrict_su_to_wheel().ok
    edits = [call[1:] for call in fake_run.calls]
    assert [edit[:2] for edit in edits] == [["replace-in-file", str(pam[0])], ["replace-in-file", str(pam[1])]]
    pattern, replacement = edits[0][2], edits[0][3]
    # The pattern only ever matches the commented required line, never the trust one.
    import re

    matches = [line for line in STOCK.splitlines() if re.match(pattern, line)]
    assert matches == ["#auth           required        pam_wheel.so use_uid"]
    assert replacement.split() == ["auth", "required", "pam_wheel.so", "use_uid"]


def test_restrict_refuses_when_you_are_not_in_wheel(pam, fake_run, monkeypatch):
    monkeypatch.setattr(users, "_admin_usernames", lambda: {"someone-else"})
    with pytest.raises(RuntimeError, match="aren't in the wheel group"):
        hardening.restrict_su_to_wheel()
    assert fake_run.calls == []


def test_restrict_refuses_a_hand_edited_file(pam, fake_run):
    pam[1].write_text("auth required pam_unix.so\n")
    with pytest.raises(RuntimeError, match="edited by hand"):
        hardening.restrict_su_to_wheel()
    assert fake_run.calls == []


def test_allow_comments_the_line_back_out(pam, fake_run, fake_which):
    pam[0].write_text(STOCK.replace("#auth           required        pam_wheel", "auth           required        pam_wheel"))
    assert hardening.allow_su_for_everyone().ok
    (call,) = fake_run.calls  # su-l was still open: nothing to do there
    assert call[1:3] == ["replace-in-file", str(pam[0])]
    assert call[4].startswith("#auth")


def test_su_writes_are_ask_tier():
    from atropa import helper

    assert helper.needs_fresh_auth(["replace-in-file", "/etc/pam.d/su", "x", "y"])
    assert helper.needs_fresh_auth(["replace-in-file", "/etc/pam.d/su-l", "x", "y"])
    with pytest.raises(helper.Refused):
        helper.checked_write_path("/etc/pam.d/sudo")
