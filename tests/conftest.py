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
    privilege_paths -- redirects backup/log paths under tmp_path so tests
                        never touch the real ~/.local/share/atropa.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from atropa.backend import privilege


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

    def set_response(self, argv_prefix, stdout="", stderr="", returncode=0):
        """Any call whose argv starts with argv_prefix gets this response.
        More specific (longer) prefixes are matched first."""
        self._responses[tuple(argv_prefix)] = _FakeResult(stdout, stderr, returncode)

    def __call__(self, argv, input=None, capture_output=True, text=True, timeout=None):
        self.calls.append(list(argv))
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


@pytest.fixture
def privilege_paths(monkeypatch, tmp_path):
    """Redirects privilege.py's backup/log locations into tmp_path."""
    backup_dir = tmp_path / "backups"
    manifest = backup_dir / "manifest.jsonl"
    log_path = tmp_path / "actions.log"
    monkeypatch.setattr(privilege, "BACKUP_DIR", backup_dir)
    monkeypatch.setattr(privilege, "BACKUP_MANIFEST", manifest)
    monkeypatch.setattr(privilege, "LOG_PATH", log_path)
    return SimpleNamespace(backup_dir=backup_dir, manifest=manifest, log_path=log_path)
