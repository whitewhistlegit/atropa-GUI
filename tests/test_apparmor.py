"""Tests for atropa.backend.apparmor."""
from __future__ import annotations

import pytest

from atropa.backend import apparmor


# --------------------------------------------------------------- list_profiles --

AA_STATUS_OUTPUT = """\
apparmor module is loaded.
15 profiles are loaded.
10 profiles are in enforce mode.
   /usr/bin/firefox
   /usr/sbin/cupsd
5 profiles are in complain mode.
   /usr/bin/evince
3 processes have profiles defined.
2 processes are in enforce mode.
   /usr/bin/firefox (1234)
"""


def test_list_profiles_not_installed_raises(fake_which):
    with pytest.raises(RuntimeError, match="isn't installed"):
        apparmor.list_profiles()


def test_list_profiles_parses_modes(fake_run, fake_which):
    fake_which.add("aa-status")
    fake_run.set_response(["pkexec", "aa-status"], stdout=AA_STATUS_OUTPUT, returncode=0)

    profiles = apparmor.list_profiles()
    by_path = {p.path: p.mode for p in profiles}
    assert by_path["/usr/bin/firefox"] == "enforce"
    assert by_path["/usr/sbin/cupsd"] == "enforce"
    assert by_path["/usr/bin/evince"] == "complain"
    # the "processes" section (with PIDs) must not be included
    assert len(profiles) == 3


def test_list_profiles_raises_on_command_failure(fake_run, fake_which):
    fake_which.add("aa-status")
    fake_run.set_response(["pkexec", "aa-status"], stdout="", stderr="permission denied", returncode=1)
    with pytest.raises(RuntimeError, match="permission denied"):
        apparmor.list_profiles()


def test_set_profile_mode_unknown_mode_raises():
    with pytest.raises(ValueError, match="Unknown mode"):
        apparmor.set_profile_mode("/usr/bin/firefox", "bogus")


def test_set_profile_mode_tool_missing_raises(fake_which):
    with pytest.raises(RuntimeError, match="isn't installed"):
        apparmor.set_profile_mode("/usr/bin/firefox", "enforce")


def test_set_profile_mode_runs_correct_tool(fake_run, fake_which):
    fake_which.add("aa-complain")
    apparmor.set_profile_mode("/usr/bin/firefox", "complain")
    assert fake_run.last_call() == ["pkexec", "aa-complain", "/usr/bin/firefox"]


# --------------------------------------------------------------- resolve_profile_file --

def test_resolve_profile_file_direct_match(tmp_path, monkeypatch):
    monkeypatch.setattr(apparmor, "PROFILES_DIR", tmp_path)
    (tmp_path / "usr.bin.firefox").write_text("profile /usr/bin/firefox {\n}\n")
    assert apparmor.resolve_profile_file("/usr/bin/firefox") == str(tmp_path / "usr.bin.firefox")


def test_resolve_profile_file_falls_back_to_grep(tmp_path, monkeypatch, fake_run):
    monkeypatch.setattr(apparmor, "PROFILES_DIR", tmp_path)
    (tmp_path / "named-profile").write_text("profile my-hat {\n}\n")
    fake_run.set_response(["grep", "-rl"], stdout=str(tmp_path / "named-profile") + "\n")
    assert apparmor.resolve_profile_file("my-hat") == str(tmp_path / "named-profile")


def test_resolve_profile_file_none_when_nothing_found(tmp_path, monkeypatch, fake_run):
    monkeypatch.setattr(apparmor, "PROFILES_DIR", tmp_path)
    fake_run.set_response(["grep", "-rl"], stdout="")
    assert apparmor.resolve_profile_file("nonexistent") is None


# --------------------------------------------------------------- rule insertion --

def test_insert_before_final_brace():
    content = "profile /usr/bin/foo {\n  #include <abstractions/base>\n}\n"
    result = apparmor._insert_before_final_brace(content, "capability net_admin,")
    assert result == "profile /usr/bin/foo {\n  #include <abstractions/base>\n  capability net_admin,\n}\n"


def test_insert_before_final_brace_no_brace_raises():
    with pytest.raises(RuntimeError, match="closing"):
        apparmor._insert_before_final_brace("no braces here", "capability net_admin,")


def test_set_capability_rule_adds_when_missing(fake_run, fake_which, tmp_path, monkeypatch):
    profile = tmp_path / "usr.bin.foo"
    profile.write_text("profile /usr/bin/foo {\n}\n")
    fake_run.set_response(["pkexec", "tee", str(profile)], returncode=0)
    fake_run.set_response(["pkexec", "apparmor_parser", "-r", str(profile)], returncode=0)

    result = apparmor.set_capability_rule(str(profile), "net_admin", True)
    assert result.ok
    tee_call = fake_run.call_containing("tee")
    assert tee_call is not None


def test_set_capability_rule_no_change_when_already_absent(fake_run, fake_which, tmp_path):
    profile = tmp_path / "usr.bin.foo"
    profile.write_text("profile /usr/bin/foo {\n}\n")
    result = apparmor.set_capability_rule(str(profile), "net_admin", False)
    assert result.ok
    assert result.stdout == "no change needed"
    assert fake_run.call_containing("tee") is None


def test_set_capability_rule_removes_when_present(fake_run, fake_which, tmp_path):
    profile = tmp_path / "usr.bin.foo"
    profile.write_text("profile /usr/bin/foo {\n  capability net_admin,\n}\n")
    fake_run.set_response(["pkexec", "tee", str(profile)], returncode=0)
    fake_run.set_response(["pkexec", "apparmor_parser", "-r", str(profile)], returncode=0)

    apparmor.set_capability_rule(str(profile), "net_admin", False)
    written_call = fake_run.call_containing("tee")
    assert written_call is not None


def test_set_network_rule_grammar(fake_run, fake_which, tmp_path):
    profile = tmp_path / "usr.bin.foo"
    profile.write_text("profile /usr/bin/foo {\n}\n")
    fake_run.set_response(["pkexec", "tee", str(profile)], returncode=0)
    fake_run.set_response(["pkexec", "apparmor_parser", "-r", str(profile)], returncode=0)

    apparmor.set_network_rule(str(profile), "inet stream", True)
    # can't directly inspect input_text via fake_run.calls (argv only), but
    # ensure it ran the reload step, implying the tee succeeded
    assert fake_run.call_containing("apparmor_parser") is not None


def test_profile_toggle_states(tmp_path):
    profile = tmp_path / "usr.bin.foo"
    profile.write_text(
        "profile /usr/bin/foo {\n  capability net_admin,\n  network inet stream,\n}\n"
    )
    states = apparmor.profile_toggle_states(str(profile))
    assert states["capabilities"]["net_admin"] is True
    assert states["capabilities"]["sys_admin"] is False
    assert states["network"]["inet stream"] is True
    assert states["network"]["unix dgram"] is False


# --------------------------------------------------------------- denial parsing --

DENIAL_LINE = (
    'apparmor="DENIED" operation="open" profile="/usr/bin/foo" '
    'name="/etc/shadow" comm="foo" requested_mask="r" denied_mask="r"'
)


def test_extract_field_found_and_missing():
    assert apparmor._extract_field(DENIAL_LINE, "operation") == "open"
    assert apparmor._extract_field(DENIAL_LINE, "nonexistent") is None


def test_explain_denial_includes_available_fields():
    explanation = apparmor.explain_denial(DENIAL_LINE)
    assert "Operation: open" in explanation
    assert "Target: /etc/shadow" in explanation
    assert "Process: foo" in explanation
    assert "Capability" not in explanation  # not present in this denial


def test_generate_rule_suggestion_file_access():
    assert apparmor.generate_rule_suggestion(DENIAL_LINE) == "/etc/shadow r,"


def test_generate_rule_suggestion_capability():
    line = 'apparmor="DENIED" operation="capable" capname="net_admin"'
    assert apparmor.generate_rule_suggestion(line) == "capability net_admin,"


def test_generate_rule_suggestion_network():
    line = 'apparmor="DENIED" operation="create" family="inet" sock_type="stream"'
    assert apparmor.generate_rule_suggestion(line) == "network inet stream,"


def test_generate_rule_suggestion_unrecognized_falls_back_to_comment():
    line = 'apparmor="DENIED" operation="mystery"'
    result = apparmor.generate_rule_suggestion(line)
    assert result.startswith("#")
    assert "mystery" in result


def test_list_denials_filters_and_limits(fake_run):
    fake_run.set_response(
        ["journalctl", "-k"],
        stdout="irrelevant kernel line\naudit: type=1400 apparmor=\"DENIED\" ...\n",
    )
    denials = apparmor.list_denials(limit=1)
    assert len(denials) == 1
    assert "DENIED" in denials[0]
