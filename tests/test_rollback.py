"""Tests for atropa.backend.rollback - undoing a pacman transaction from the cache."""

from __future__ import annotations

import pytest

from atropa import helper
from atropa.backend import pacman, rollback

LOG = """\
[2026-11-12T09:07:01+0100] [PACMAN] Running 'pacman -Syuu'
[2026-11-12T09:07:05+0100] [ALPM] transaction started
[2026-11-12T09:07:06+0100] [ALPM] upgraded zlib (1:1.3.2-4 -> 1:1.4-1)
[2026-11-12T09:07:06+0100] [ALPM] upgraded mesa (1:26.2.5-1 -> 1:26.2.6-1)
[2026-11-12T09:07:06+0100] [ALPM] installed libnew (1.0-1)
[2026-11-12T09:07:06+0100] [ALPM] upgraded kdeconnect (26.08.2-1 -> 26.08.3-1)
[2026-11-12T09:07:07+0100] [ALPM] running '30-systemd-update.hook'...
[2026-11-12T09:07:08+0100] [ALPM] transaction completed
[2026-11-13T10:00:00+0100] [PACMAN] Running 'pacman -S broken'
[2026-11-13T10:00:01+0100] [ALPM] transaction started
[2026-11-13T10:00:01+0100] [ALPM] installed broken (1-1)
[2026-11-13T10:00:02+0100] [ALPM] transaction failed
[2026-11-14T11:00:00+0100] [PACMAN] Running 'pacman -Rns kpeople'
[2026-11-14T11:00:01+0100] [ALPM] transaction started
[2026-11-14T11:00:01+0100] [ALPM] removed kpeople (6.31.0-1)
[2026-11-14T11:00:01+0100] [ALPM] reinstalled bash (5.3-1)
[2026-11-14T11:00:02+0100] [ALPM] transaction completed
"""


@pytest.fixture
def cache(tmp_path, monkeypatch):
    directory = tmp_path / "pkg"
    directory.mkdir()
    monkeypatch.setattr(rollback, "CACHE_DIR", directory)
    monkeypatch.setattr(rollback.os, "uname", lambda: type("U", (), {"machine": "x86_64"})())

    def add(name, version, arch="x86_64", ext="zst"):
        path = directory / f"{name}-{version}-{arch}.pkg.tar.{ext}"
        path.write_bytes(b"pkg")
        return str(path)

    return add


# --------------------------------------------------------------------- parsing --

def test_parse_keeps_completed_transactions_with_their_command():
    transactions = rollback.parse_log(LOG)
    assert [t.command for t in transactions] == ["pacman -Syuu", "pacman -Rns kpeople"]
    first = transactions[0]
    assert [(c.action, c.name, c.old, c.new) for c in first.changes] == [
        ("upgraded", "zlib", "1:1.3.2-4", "1:1.4-1"),
        ("upgraded", "mesa", "1:26.2.5-1", "1:26.2.6-1"),
        ("installed", "libnew", None, "1.0-1"),
        ("upgraded", "kdeconnect", "26.08.2-1", "26.08.3-1"),
    ]


def test_parse_skips_failed_transactions_and_hook_lines():
    assert all(t.command != "pacman -S broken" for t in rollback.parse_log(LOG))


def test_parse_reads_removed_and_reinstalled():
    last = rollback.parse_log(LOG)[-1]
    assert [(c.action, c.name, c.old, c.new) for c in last.changes] == [
        ("removed", "kpeople", "6.31.0-1", None),
        ("reinstalled", "bash", "5.3-1", "5.3-1"),
    ]


def test_transactions_are_newest_first():
    assert [t.command for t in rollback.transactions(log_text=LOG)] == ["pacman -Rns kpeople", "pacman -Syuu"]


# ------------------------------------------------------------------------ plans --

def _upgrade():
    return rollback.parse_log(LOG)[0]


def test_plan_reinstalls_the_replaced_versions(cache):
    zlib = cache("zlib", "1:1.3.2-4")
    mesa = cache("mesa", "1:26.2.5-1")
    plan = rollback.plan(_upgrade(), {"zlib": "1:1.4-1", "mesa": "1:26.2.6-1", "libnew": "1.0-1"})
    assert plan.possible
    assert plan.files == [zlib, mesa]
    assert plan.kept == ["libnew"]
    assert plan.gone == ["kdeconnect"]  # removed since: nothing of it to undo


def test_plan_finds_any_arch_and_xz_packages(cache):
    zlib = cache("zlib", "1:1.3.2-4", arch="any", ext="xz")
    cache("mesa", "1:26.2.5-1")
    plan = rollback.plan(_upgrade(), {"zlib": "1:1.4-1", "mesa": "1:26.2.6-1"})
    assert zlib in plan.files


def test_plan_with_a_missing_cache_file_is_refused(cache):
    cache("zlib", "1:1.3.2-4")
    plan = rollback.plan(_upgrade(), {"zlib": "1:1.4-1", "mesa": "1:26.2.6-1"})
    assert not plan.possible
    assert plan.missing == ["mesa-1:26.2.5-1"]
    assert "Not in the package cache" in plan.reason


def test_plan_for_a_package_changed_again_since_is_stale(cache):
    cache("zlib", "1:1.3.2-4")
    cache("mesa", "1:26.2.5-1")
    plan = rollback.plan(_upgrade(), {"zlib": "1:1.5-1", "mesa": "1:26.2.6-1"})
    assert not plan.possible
    assert plan.stale == ["zlib (now 1:1.5-1)"]


def test_plan_does_not_match_a_package_whose_name_is_a_prefix(cache):
    cache("zlib-ng", "1:1.3.2-4")  # not zlib
    cache("mesa", "1:26.2.5-1")
    plan = rollback.plan(_upgrade(), {"zlib": "1:1.4-1", "mesa": "1:26.2.6-1"})
    assert plan.missing == ["zlib-1:1.3.2-4"]


def test_plan_restores_a_removed_package_still_absent(cache):
    kpeople = cache("kpeople", "6.31.0-1")
    plan = rollback.plan(rollback.parse_log(LOG)[-1], {"bash": "5.3-1"})
    assert plan.possible and plan.files == [kpeople]


def test_plan_for_an_install_only_transaction_has_nothing_to_undo(cache):
    log = (
        "[2026-11-18T03:34:16+0100] [PACMAN] Running 'pacman -S kdialog'\n"
        "[2026-11-18T03:34:17+0100] [ALPM] transaction started\n"
        "[2026-11-18T03:34:17+0100] [ALPM] installed kdialog (26.08.3-1)\n"
        "[2026-11-18T03:34:17+0100] [ALPM] transaction completed\n"
    )
    plan = rollback.plan(rollback.parse_log(log)[0], {"kdialog": "26.08.3-1"})
    assert not plan.possible
    assert "only installed" in plan.reason


# ------------------------------------------------------------------------ apply --

def test_apply_runs_one_pacman_u_with_the_cache_files(cache, monkeypatch):
    cache("zlib", "1:1.3.2-4")
    cache("mesa", "1:26.2.5-1")
    plan = rollback.plan(_upgrade(), {"zlib": "1:1.4-1", "mesa": "1:26.2.6-1"})
    calls = []
    monkeypatch.setattr(rollback, "run_privileged_streaming", lambda argv, on_line, **kw: calls.append(argv))
    rollback.apply(plan, lambda _line: None)
    assert calls == [["pacman", "-U", "--noconfirm", *plan.files]]


def test_apply_refuses_an_impossible_plan(cache, monkeypatch):
    plan = rollback.plan(_upgrade(), {"zlib": "1:1.4-1", "mesa": "1:26.2.6-1"})
    monkeypatch.setattr(rollback, "run_privileged_streaming", lambda *a, **k: pytest.fail("must not run"))
    with pytest.raises(RuntimeError, match="Not in the package cache"):
        rollback.apply(plan, lambda _line: None)


# ----------------------------------------------------------------------- helper --

def test_helper_takes_pacman_u_only_from_the_cache_and_always_asks(tmp_path, monkeypatch):
    cache_dir = tmp_path / "pkg"
    cache_dir.mkdir()
    package = cache_dir / "zlib-1:1.3.2-4-x86_64.pkg.tar.zst"
    package.write_bytes(b"pkg")
    monkeypatch.setattr(helper, "PACKAGE_CACHE", f"{cache_dir}/")

    assert helper.validate_command(["pacman", "-U", "--noconfirm", str(package)]) == (
        helper.ASK, ["-U", "--noconfirm", str(package)]
    )


@pytest.mark.parametrize(
    "path",
    [
        "/home/me/evil.pkg.tar.zst",
        "/var/cache/pacman/pkg/../../../home/me/evil.pkg.tar.zst",
        "/var/cache/pacman/pkg/sub/evil.pkg.tar.zst",
        "/var/cache/pacman/pkg/zlib-1-1-x86_64.pkg.tar.zst.sig",
        "/var/cache/pacman/pkg/download-AbCdEf",
    ],
)
def test_helper_refuses_pacman_u_for_anything_else(path):
    with pytest.raises(helper.Refused):
        helper.validate_command(["pacman", "-U", "--noconfirm", path])


def test_helper_refuses_a_symlink_in_the_cache(tmp_path, monkeypatch):
    cache_dir = tmp_path / "pkg"
    cache_dir.mkdir()
    (tmp_path / "evil.pkg.tar.zst").write_bytes(b"x")
    (cache_dir / "zlib-1-1-x86_64.pkg.tar.zst").symlink_to(tmp_path / "evil.pkg.tar.zst")
    monkeypatch.setattr(helper, "PACKAGE_CACHE", f"{cache_dir}/")
    with pytest.raises(helper.Refused):
        helper.validate_command(["pacman", "-U", "--noconfirm", str(cache_dir / "zlib-1-1-x86_64.pkg.tar.zst")])


# ------------------------------------------------------------------ clean cache --

def test_clean_keeps_the_previous_version_with_paccache(fake_run, fake_which):
    fake_which.add("paccache")
    assert pacman.clean_cache().ok
    sent = [call[1:] for call in fake_run.calls if call[:1] == ["pkexec"]]
    assert sent == [["paccache", "-r", "-k2"], ["paccache", "-r", "-u", "-k0"]]
    for argv in sent:
        assert helper.validate_command(argv)[0] == helper.KEEP


def test_clean_without_paccache_says_rollback_is_gone(fake_run, fake_which):
    fake_which.discard("paccache")
    result = pacman.clean_cache()
    assert fake_run.calls[-1] == ["pkexec", "pacman", "-Sc", "--noconfirm"]
    assert "can't be rolled back" in result.stdout
