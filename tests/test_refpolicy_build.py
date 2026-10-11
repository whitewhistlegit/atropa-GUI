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


def test_install_runs_make_install_privileged(monkeypatch, fake_run, fake_which, source_dir):
    fake_which.add("make")
    captured = _install_streaming(monkeypatch, ["Installing base.pp", "Installing modules"], returncode=0)
    lines = []
    result = refpolicy_build.install(source_dir, lines.append)
    assert result.ok
    assert "Installing modules" in lines
    # load is what builds the compiled policy and store; install alone left nothing to boot into
    assert captured["argv"] == ["pkexec", "make", "-C", source_dir, "install", "load"]


def test_install_hands_root_created_files_back(monkeypatch, fake_run, fake_which, source_dir):
    # Root-owned build files left by `make install` broke the next unprivileged Build.
    fake_which.add("make")
    _install_streaming(monkeypatch, ["Installing modules"], returncode=0)
    monkeypatch.setattr(refpolicy_build.os, "getuid", lambda: 1000)
    monkeypatch.setattr(refpolicy_build.os, "getgid", lambda: 1000)
    refpolicy_build.install(source_dir, lambda _l: None)
    assert fake_run.calls == [["pkexec", "chown", "-R", "-h", "--from=0:0", "1000:1000", "--", source_dir]]


def test_install_says_so_when_handing_files_back_fails(monkeypatch, fake_run, fake_which, source_dir):
    fake_which.add("make")
    _install_streaming(monkeypatch, ["Installing modules"], returncode=0)
    monkeypatch.setattr(refpolicy_build.os, "getuid", lambda: 1000)
    fake_run.set_response(["pkexec", "chown"], returncode=126, stderr="Request dismissed")
    lines = []
    assert refpolicy_build.install(source_dir, lines.append).ok
    assert any("Couldn't hand the files" in line and "Request dismissed" in line for line in lines)


# --------------------------------------------------------------- activate --

CONFIG_TEXT = "SELINUX=enforcing\nSELINUXTYPE=targeted\n"


@pytest.fixture
def selinux_tree(tmp_path, monkeypatch):
    """A fake /etc/selinux with an installed, compiled atropa-refpolicy."""
    root = tmp_path / "etc-selinux"
    for name in ("atropa-refpolicy", "my-custom-policy"):
        (root / name / "policy").mkdir(parents=True)
        (root / name / "policy" / "policy.33").write_text("binary")
    config = root / "config"
    config.write_text(CONFIG_TEXT)
    monkeypatch.setattr(refpolicy_build, "SELINUX_ROOT", root)
    monkeypatch.setattr(refpolicy_build, "SELINUX_CONFIG", config)
    return root


def _written_configs(fake_run, selinux_tree):
    target = ["pkexec", "tee", str(selinux_tree / "config")]
    return [text for call, text in zip(fake_run.calls, fake_run.inputs) if call == target]


def test_activate_all_steps_succeed(fake_run, fake_which, selinux_tree):
    results = refpolicy_build.activate("atropa-refpolicy")

    assert len(results) == 3
    assert all(r.ok for r in results)
    assert _written_configs(fake_run, selinux_tree) == ["SELINUX=enforcing\nSELINUXTYPE=atropa-refpolicy\n"]


def test_activate_maps_the_login_in_the_new_policys_store_before_switching(fake_run, fake_which, selinux_tree):
    refpolicy_build.activate("atropa-refpolicy")
    semanage = next(i for i, c in enumerate(fake_run.calls) if "semanage" in c)
    tee = next(i for i, c in enumerate(fake_run.calls) if c[:2] == ["pkexec", "tee"])
    assert semanage < tee
    assert fake_run.calls[semanage][:6] == ["pkexec", "semanage", "login", "-S", "atropa-refpolicy", "-N"]


def test_activate_adds_selinuxtype_when_the_config_has_none(fake_run, fake_which, selinux_tree):
    (selinux_tree / "config").write_text("SELINUX=permissive\n# SELINUXTYPE=targeted\n")
    refpolicy_build.activate("my-custom-policy")
    [written] = _written_configs(fake_run, selinux_tree)
    assert written.splitlines() == ["SELINUX=permissive", "# SELINUXTYPE=targeted", "SELINUXTYPE=my-custom-policy"]


@pytest.mark.parametrize("name", ["", "targeted/e touch /x", "a b", "../targeted", "x" * 65, "-x"])
def test_activate_rejects_anything_but_a_plain_policy_name(fake_run, fake_which, selinux_tree, name):
    # The name used to be pasted straight into a privileged sed expression.
    with pytest.raises(ValueError):
        refpolicy_build.activate(name)
    assert fake_run.calls == []


def test_activate_refuses_a_policy_that_isnt_installed(fake_run, fake_which, selinux_tree):
    # A typo'd SELINUXTYPE leaves an enforcing system unable to boot.
    with pytest.raises(RuntimeError, match="No compiled policy"):
        refpolicy_build.activate("atropa-refpolicyy")
    assert fake_run.calls == []


def test_activate_refuses_a_policy_dir_without_a_compiled_policy(fake_run, fake_which, selinux_tree):
    (selinux_tree / "half-installed" / "policy").mkdir(parents=True)
    with pytest.raises(RuntimeError, match="No compiled policy"):
        refpolicy_build.activate("half-installed")


def test_activate_stops_if_config_edit_fails(fake_run, fake_which, selinux_tree):
    fake_run.set_response(["pkexec", "tee"], returncode=1, stderr="permission denied")

    results = refpolicy_build.activate("atropa-refpolicy")

    assert len(results) == 2
    assert not results[-1].ok
    assert fake_run.call_containing("/.autorelabel") is None


def test_activate_falls_back_to_modify_when_login_mapping_already_exists(fake_run, fake_which, selinux_tree):
    store = ["-S", "atropa-refpolicy", "-N"]
    fake_run.set_response(
        ["pkexec", "semanage", "login", *store, "-a", "-s", "unconfined_u", "__default__"],
        returncode=1,
        stderr="__default__ already defined",
    )

    results = refpolicy_build.activate("atropa-refpolicy")

    assert len(results) == 3
    assert all(r.ok for r in results)
    # both the failed -a attempt AND the successful -m fallback actually ran
    add_calls = [c for c in fake_run.calls if c and "-a" in c and "login" in c]
    modify_calls = [c for c in fake_run.calls if c and "-m" in c and "login" in c]
    assert len(add_calls) == 1
    assert len(modify_calls) == 1


def test_activate_changes_nothing_if_the_login_mapping_fails(fake_run, fake_which, selinux_tree):
    fake_run.set_response(["pkexec", "semanage", "login"], returncode=1, stderr="store not found")

    results = refpolicy_build.activate("atropa-refpolicy")

    assert len(results) == 1
    assert not results[-1].ok
    assert _written_configs(fake_run, selinux_tree) == []
    assert fake_run.call_containing("/.autorelabel") is None


def test_activate_puts_the_config_back_if_the_relabel_cant_be_scheduled(fake_run, fake_which, selinux_tree):
    fake_run.set_response(["pkexec", "touch", "/.autorelabel"], returncode=1, stderr="read-only file system")

    results = refpolicy_build.activate("atropa-refpolicy")

    assert not results[-1].ok
    assert "previous /etc/selinux/config back" in results[-1].stderr
    assert _written_configs(fake_run, selinux_tree)[-1] == CONFIG_TEXT


def test_activate_never_touches_kernel_or_bootloader_config(fake_run, fake_which, selinux_tree):
    """
    Explicit regression guard for the user's own instruction: nothing in
    the activate() sequence may touch kernel command-line parameters or
    bootloader config, however this function evolves in the future.
    """
    refpolicy_build.activate("atropa-refpolicy")

    forbidden = ("grub", "grub-mkconfig", "loader.conf", "kernelstub", "bootctl", "/boot/", "cmdline")
    for call in fake_run.calls:
        if not call:
            continue
        joined = " ".join(call).lower()
        assert not any(f in joined for f in forbidden), f"unexpected boot/kernel-related call: {call}"


def test_activate_uses_custom_login_seuser_when_given(fake_run, fake_which, selinux_tree):
    results = refpolicy_build.activate("atropa-refpolicy", default_login_seuser="staff_u")
    assert all(r.ok for r in results)
    assert fake_run.call_containing("staff_u") is not None
