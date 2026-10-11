"""
Shared pytest fixtures for the atropa.backend test suite.

The backend modules are deliberately GTK-free and funnel every subprocess
call through `backend.privilege.run_privileged` / `run_unprivileged`, both
of which bottom out in `subprocess.run`. That means we only need to fake
one thing (subprocess.run) to unit-test parsing/logic across every module,
without ever touching the real system.

Fixtures:
    fake_run     -- registers canned CompletedProcess-like responses keyed
                     by an argv prefix; records every call made.
    fake_which   -- controls which command-line tools "exist" (shutil.which).
    privilege_paths -- AUTOUSE: redirects HOME and every per-user data path
                        (action log, backups, SELinux review artifacts, the
                        downloaded policy source, the legacy ArchYaST dir)
                        under tmp_path, so no test can
                        touch the real ~/.local/share/atropa - even one that
                        never asks for this fixture by name.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from atropa.backend import apparmor, hardening, migration, privilege, refpolicy_build, selinux


@dataclass
class _FakeResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


class FakeRun:
    """Registers and serves canned subprocess responses; records calls made."""

    def __init__(self):
        self._responses: dict[tuple, _FakeResult] = {}
        self.calls: list[list[str]] = []
        self.inputs: list[str | None] = []  # stdin text passed with each call, parallel to `calls`

    def set_response(self, argv_prefix, stdout="", stderr="", returncode=0):
        """Any call whose argv starts with argv_prefix gets this response.
        More specific (longer) prefixes are matched first."""
        self._responses[tuple(argv_prefix)] = _FakeResult(stdout, stderr, returncode)

    def __call__(self, argv, input=None, capture_output=True, text=True, timeout=None):
        self.calls.append(list(argv))
        self.inputs.append(input)
        best_match = None
        for prefix, resp in self._responses.items():
            if tuple(argv[: len(prefix)]) == prefix:
                if best_match is None or len(prefix) > len(best_match[0]):
                    best_match = (prefix, resp)
        resp = best_match[1] if best_match else _FakeResult()
        return SimpleNamespace(returncode=resp.returncode, stdout=resp.stdout, stderr=resp.stderr)

    def last_call(self) -> list[str] | None:
        return self.calls[-1] if self.calls else None

    def call_containing(self, needle: str) -> list[str] | None:
        for call in self.calls:
            if needle in call:
                return call
        return None


@pytest.fixture
def fake_run(monkeypatch):
    fr = FakeRun()
    # privilege._subprocess_run is the one place commands are started from
    # (subprocess.run's interface, run through Popen); subprocess.run is
    # patched too so nothing slips through to a real command.
    monkeypatch.setattr(privilege, "_subprocess_run", fr)
    monkeypatch.setattr(subprocess, "run", fr)
    return fr


@pytest.fixture
def fake_which(monkeypatch):
    """Default: only 'pkexec' is 'installed'. Tests add more via fake_which.add(...)."""
    available = {"pkexec"}

    def which(name):
        return f"/usr/bin/{name}" if name in available else None

    monkeypatch.setattr(shutil, "which", which)
    return available


@pytest.fixture(autouse=True)
def privilege_paths(monkeypatch, tmp_path):
    """
    Redirects every path Atropa writes per-user data to into tmp_path, for
    every test. Autouse on purpose: when this was opt-in, tests that forgot
    it (AppArmor rule toggles, SELinux Setup Mode) wrote real backups and
    manifest entries into the developer's own ~/.local/share/atropa, which
    then showed up as restorable "backups" in the real Activity page.
    Tests that need the paths can still request this fixture by name.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))

    backup_dir = tmp_path / "backups"
    manifest = backup_dir / "manifest.jsonl"
    log_path = tmp_path / "actions.log"
    monkeypatch.setattr(privilege, "BACKUP_DIR", backup_dir)
    monkeypatch.setattr(privilege, "BACKUP_MANIFEST", manifest)
    monkeypatch.setattr(privilege, "LOG_PATH", log_path)

    review_base = tmp_path / "selinux-review"
    monkeypatch.setattr(selinux, "REVIEW_BASE_DIR", review_base)
    monkeypatch.setattr(selinux, "REVIEW_MODULES_DIR", review_base / "modules")
    monkeypatch.setattr(selinux, "APPROVED_MODULES_DIR", review_base / "approved")
    monkeypatch.setattr(selinux, "SETUP_MODE_STATE_FILE", review_base / "setup_mode_state.json")
    monkeypatch.setattr(selinux, "LAST_REVIEW_FILE", review_base / "last_review.json")

    monkeypatch.setattr(migration, "OLD_USER_DATA_DIR", tmp_path / "archyast")
    monkeypatch.setattr(refpolicy_build, "ATROPA_POLICY_DIR", tmp_path / "refpolicy-atropa")

    return SimpleNamespace(backup_dir=backup_dir, manifest=manifest, log_path=log_path, home=home)


@pytest.fixture(autouse=True)
def kernel_state(monkeypatch, tmp_path):
    """
    Points the checks that read live kernel state (the active LSM list,
    AppArmor's enabled flag and securityfs directory) at paths under
    tmp_path that don't exist unless a test creates them, so no result
    depends on the kernel the tests happen to run on. GitHub's Ubuntu
    runners have AppArmor on, which is how "AppArmor isn't available"
    tests passed locally and failed in CI.
    """
    kernel = tmp_path / "kernel"
    kernel.mkdir()
    state = SimpleNamespace(
        lsm=kernel / "lsm", apparmor_enabled=kernel / "apparmor-enabled", apparmor_securityfs=kernel / "apparmor"
    )
    monkeypatch.setattr(hardening, "LSM_LIST", state.lsm)
    monkeypatch.setattr(hardening, "APPARMOR_ENABLED_PARAM", state.apparmor_enabled)
    monkeypatch.setattr(hardening, "APPARMOR_SECURITYFS", state.apparmor_securityfs)
    monkeypatch.setattr(apparmor, "SECURITYFS_DIR", state.apparmor_securityfs)
    return state
