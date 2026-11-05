"""Tests for atropa.helper - the one program pkexec is allowed to run."""

from __future__ import annotations

import ast
import os
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from atropa import helper

REPO = Path(__file__).resolve().parent.parent
POLICY = REPO / "atropa" / "resources" / "org.atropa.pkexec.policy"


def _bin_dir(tmp_path, name="systemctl", mode=0o755):
    directory = tmp_path / "bin"
    directory.mkdir(exist_ok=True)
    program = directory / name
    program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    program.chmod(mode)
    return program, (str(directory),)


# ------------------------------------------------------------- resolution --

def test_resolve_returns_the_real_path_of_an_allowed_command(tmp_path):
    program, directories = _bin_dir(tmp_path)
    assert helper.resolve("systemctl", directories) == str(program)


def test_check_keeps_the_arguments_and_resolves_the_program(tmp_path):
    program, directories = _bin_dir(tmp_path, "tee")
    assert helper.check(["tee", "/etc/hostname"], directories) == [str(program), "/etc/hostname"]


def test_resolve_refuses_a_command_that_is_not_allowlisted(tmp_path):
    _bin_dir(tmp_path, "sh")
    with pytest.raises(helper.Refused, match="allowlist"):
        helper.resolve("sh", (str(tmp_path / "bin"),))


def test_resolve_refuses_a_program_missing_from_the_search_path(tmp_path):
    with pytest.raises(helper.Refused, match="not found"):
        helper.resolve("systemctl", (str(tmp_path / "empty"),))


@pytest.mark.parametrize("name", ["../bin/tee", "/usr/bin/tee", "./tee", "sub/tee", "", ".", ".."])
def test_check_refuses_paths_instead_of_resolving_them(name):
    with pytest.raises(helper.Refused):
        helper.check([name])


def test_check_refuses_an_empty_argv():
    with pytest.raises(helper.Refused, match="no command"):
        helper.check([])


def test_a_non_executable_file_is_not_a_command(tmp_path):
    _bin_dir(tmp_path, "systemctl", mode=0o644)
    with pytest.raises(helper.Refused, match="not found"):
        helper.resolve("systemctl", (str(tmp_path / "bin"),))


# ------------------------------------------------------------------- main --

def test_main_refuses_to_run_without_root(monkeypatch):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 1000)
    assert helper.main(["true"]) == 126


def test_main_execs_the_resolved_command_with_a_clean_environment(monkeypatch):
    calls = []

    def fake_execve(path, argv, env):
        calls.append((path, argv, env))

    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    monkeypatch.setattr(helper.os, "execve", fake_execve)

    helper.main(["true", "extra"])

    path, argv, env = calls[0]
    assert path == os.path.realpath(env["PATH"].split(":")[0] + "/true")
    assert argv == [path, "extra"]
    assert env["LC_ALL"] == "C.UTF-8"
    assert env["HOME"] == "/root"


def test_main_refuses_an_allowlisted_name_that_is_actually_a_shell(monkeypatch):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    assert helper.main(["bash", "-c", "id"]) == 126


# -------------------------------------------------------------- allowlist --
#
# This is the test that keeps ALLOWED honest: any new run_privileged(["...",
# ...]) call with a literal command name must be added to the helper too, or
# the feature silently stops working when the helper is installed.

def _literal_privileged_commands() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in sorted((REPO / "atropa" / "backend").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if name not in {"run_privileged", "run_privileged_streaming"}:
                continue
            first = node.args[0] if node.args else None
            if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
                head = first.elts[0]
                if isinstance(head, ast.Constant) and isinstance(head.value, str):
                    found.setdefault(head.value, set()).add(path.name)
    return found


def test_every_literal_privileged_command_is_in_the_allowlist():
    missing = {command: files for command, files in _literal_privileged_commands().items() if command not in helper.ALLOWED}
    assert missing == {}, f"privileged commands missing from ALLOWED: {missing}"


def test_allowlist_contains_no_shells_or_interpreters():
    forbidden = {"sh", "bash", "dash", "python", "python3", "perl", "env", "xargs", "find", "awk"}
    assert helper.ALLOWED.isdisjoint(forbidden)


# ---------------------------------------------------------------- policy --

def test_policy_annotates_the_helper_path_with_a_keep_action():
    root = ET.parse(POLICY).getroot()
    action = root.find("action")
    assert action is not None
    defaults = action.find("defaults")
    assert defaults.findtext("allow_active") == "auth_admin_keep"
    annotations = {entry.get("key"): (entry.text or "").strip() for entry in action.findall("annotate")}
    assert annotations.get("org.freedesktop.policykit.exec.path") == "/usr/lib/atropa/atropa-helper"


def test_policy_is_valid_xml():
    assert ET.parse(POLICY).getroot().tag == "policyconfig"
