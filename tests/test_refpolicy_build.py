"""Tests for atropa.backend.refpolicy_build."""
from __future__ import annotations

import subprocess

import pytest

from atropa.backend import refpolicy_build


def _install_streaming(monkeypatch, lines, returncode=0):
    """Streaming calls (build()/install()) go through subprocess.Popen
    directly, not subprocess.run - the fake_run fixture (which patches
    subprocess.run) doesn't apply to them at all. Mirrors the same
    pattern test_aide.py uses for its own streaming calls."""
    captured = {}

    class Stdout:
        def __iter__(self):
            return iter(lines)

    class FakePopen:
        def __init__(self, argv, **kwargs):
            captured["argv"] = argv
            self.args = argv
            self.stdout = Stdout()
            self.stdin = None

        def wait(self, timeout=None):
            return returncode

    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    return captured


@pytest.fixture
def source_dir(tmp_path):
    d = tmp_path / "atropa-refpolicy"
    d.mkdir()
    (d / "Makefile").write_text("# refpolicy makefile\n")
    return str(d)


# --------------------------------------------------------------- build --

def test_build_missing_make_raises(fake_which, source_dir):
    with pytest.raises(RuntimeError, match="isn't installed"):
        refpolicy_build.build(source_dir, lambda _l: None)


def test_build_missing_directory_raises(fake_which, tmp_path):
    fake_which.add("make")
    with pytest.raises(RuntimeError, match="isn't a directory"):
        refpolicy_build.build(str(tmp_path / "nonexistent"), lambda _l: None)


def test_build_missing_makefile_raises(fake_which, tmp_path):
    fake_which.add("make")
    empty_dir = tmp_path / "not-a-refpolicy-tree"
    empty_dir.mkdir()
    with pytest.raises(RuntimeError, match="doesn't look like a refpolicy source tree"):
        refpolicy_build.build(str(empty_dir), lambda _l: None)


def test_build_runs_make_conf_all_unprivileged(monkeypatch, fake_which, source_dir):
    fake_which.add("make")
    captured = _install_streaming(monkeypatch, ["Compiling base.pp", "All modules built"], returncode=0)
    lines = []
    result = refpolicy_build.build(source_dir, lines.append)
    assert result.ok
    assert "All modules built" in lines
    # never privileged - no pkexec prefix at all
    assert captured["argv"] == ["make", "-C", source_dir, "conf", "all"]


# --------------------------------------------------------------- install --

def test_install_missing_make_raises(fake_which, source_dir):
    with pytest.raises(RuntimeError, match="isn't installed"):
        refpolicy_build.install(source_dir, lambda _l: None)


def test_install_missing_directory_raises(fake_which, tmp_path):
    fake_which.add("make")
    with pytest.raises(RuntimeError, match="isn't a directory"):
        refpolicy_build.install(str(tmp_path / "nonexistent"), lambda _l: None)


def test_install_runs_make_install_privileged(monkeypatch, fake_which, source_dir):
    fake_which.add("make")
    captured = _install_streaming(monkeypatch, ["Installing base.pp", "Installing modules"], returncode=0)
    lines = []
    result = refpolicy_build.install(source_dir, lines.append)
    assert result.ok
    assert "Installing modules" in lines
    assert captured["argv"] == ["pkexec", "make", "-C", source_dir, "install"]


# --------------------------------------------------------------- activate --

def test_activate_all_steps_succeed(fake_run, fake_which):
    fake_run.set_response(["pkexec", "sed", "-i", "-E"], returncode=0)
    fake_run.set_response(["pkexec", "semanage", "login", "-a", "-s", "unconfined_u", "__default__"], returncode=0)
    fake_run.set_response(["pkexec", "touch", "/.autorelabel"], returncode=0)

    results = refpolicy_build.activate("atropa-refpolicy")

    assert len(results) == 3
    assert all(r.ok for r in results)


def test_activate_uses_the_given_policy_name_in_sed(fake_run, fake_which):
    fake_run.set_response(["pkexec", "sed", "-i", "-E"], returncode=0)
    fake_run.set_response(["pkexec", "semanage", "login", "-a"], returncode=0)
    fake_run.set_response(["pkexec", "touch", "/.autorelabel"], returncode=0)

    refpolicy_build.activate("my-custom-policy")

    sed_calls = [c for c in fake_run.calls if c and c[:2] == ["pkexec", "sed"]]
    assert len(sed_calls) == 1
    assert any("SELINUXTYPE=my-custom-policy" in arg for arg in sed_calls[0])


def test_activate_stops_if_config_edit_fails(fake_run, fake_which):
    fake_run.set_response(["pkexec", "sed", "-i", "-E"], returncode=1, stderr="permission denied")

    results = refpolicy_build.activate("atropa-refpolicy")

    assert len(results) == 1
    assert not results[0].ok
    # neither semanage nor the relabel touch should ever have been attempted
    assert fake_run.call_containing("semanage") is None
    assert fake_run.call_containing("/.autorelabel") is None


def test_activate_falls_back_to_modify_when_login_mapping_already_exists(fake_run, fake_which):
    fake_run.set_response(["pkexec", "sed", "-i", "-E"], returncode=0)
    fake_run.set_response(
        ["pkexec", "semanage", "login", "-a", "-s", "unconfined_u", "__default__"],
        returncode=1,
        stderr="__default__ already defined",
    )
    fake_run.set_response(["pkexec", "semanage", "login", "-m", "-s", "unconfined_u", "__default__"], returncode=0)
    fake_run.set_response(["pkexec", "touch", "/.autorelabel"], returncode=0)

    results = refpolicy_build.activate("atropa-refpolicy")

    assert len(results) == 3
    assert all(r.ok for r in results)
    # both the failed -a attempt AND the successful -m fallback actually ran
    add_calls = [c for c in fake_run.calls if c and "-a" in c and "login" in c]
    modify_calls = [c for c in fake_run.calls if c and "-m" in c and "login" in c]
    assert len(add_calls) == 1
    assert len(modify_calls) == 1


def test_activate_stops_if_both_add_and_modify_login_mapping_fail(fake_run, fake_which):
    fake_run.set_response(["pkexec", "sed", "-i", "-E"], returncode=0)
    fake_run.set_response(["pkexec", "semanage", "login", "-a", "-s", "unconfined_u", "__default__"], returncode=1)
    fake_run.set_response(["pkexec", "semanage", "login", "-m", "-s", "unconfined_u", "__default__"], returncode=1)

    results = refpolicy_build.activate("atropa-refpolicy")

    assert len(results) == 2
    assert not results[-1].ok
    # relabel must never be scheduled if the login mapping never succeeded
    assert fake_run.call_containing("/.autorelabel") is None


def test_activate_never_touches_kernel_or_bootloader_config(fake_run, fake_which):
    """
    Explicit regression guard for the user's own instruction: nothing in
    the activate() sequence may touch kernel command-line parameters or
    bootloader config, however this function evolves in the future.
    """
    fake_run.set_response(["pkexec", "sed", "-i", "-E"], returncode=0)
    fake_run.set_response(["pkexec", "semanage", "login", "-a"], returncode=0)
    fake_run.set_response(["pkexec", "touch", "/.autorelabel"], returncode=0)

    refpolicy_build.activate("atropa-refpolicy")

    forbidden = ("grub", "grub-mkconfig", "loader.conf", "kernelstub", "bootctl", "/boot/", "cmdline")
    for call in fake_run.calls:
        if not call:
            continue
        joined = " ".join(call).lower()
        assert not any(f in joined for f in forbidden), f"unexpected boot/kernel-related call: {call}"


def test_activate_uses_custom_login_seuser_when_given(fake_run, fake_which):
    fake_run.set_response(["pkexec", "sed", "-i", "-E"], returncode=0)
    fake_run.set_response(
        ["pkexec", "semanage", "login", "-a", "-s", "staff_u", "__default__"], returncode=0
    )
    fake_run.set_response(["pkexec", "touch", "/.autorelabel"], returncode=0)

    results = refpolicy_build.activate("atropa-refpolicy", default_login_seuser="staff_u")
    assert all(r.ok for r in results)
    assert fake_run.call_containing("staff_u") is not None
