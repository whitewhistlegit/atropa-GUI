"""Tests for atropa.backend.mirrors."""

from __future__ import annotations

import pytest

from atropa.backend import mirrors

# The command rank_mirrors() is expected to send, without --country/--print.
REFLECTOR_PREFIX = ["reflector", "--score", "20", "--latest", "30", "--sort", "rate", "--number"]


def _mirrorlist(tmp_path, monkeypatch, text: str | None):
    path = tmp_path / "mirrorlist"
    if text is not None:
        path.write_text(text, encoding="utf-8")
    monkeypatch.setattr(mirrors, "MIRRORLIST", path)
    return path


# ------------------------------------------------------------- current_mirrors --

def test_current_mirrors_returns_active_server_lines_in_order(fake_run, tmp_path, monkeypatch):
    _mirrorlist(
        tmp_path,
        monkeypatch,
        "# Managed by Atropa\n"
        "Server = https://fast.example/$repo/os/$arch\n"
        "\n"
        "Server = http://second.example/$repo/os/$arch\n"
        "#Server = https://disabled.example/$repo/os/$arch\n",
    )

    assert mirrors.current_mirrors() == [
        mirrors.Mirror("https://fast.example/$repo/os/$arch"),
        mirrors.Mirror("http://second.example/$repo/os/$arch"),
    ]
    assert fake_run.calls == []  # the file is read directly, not through cat


def test_current_mirrors_missing_file_is_empty(fake_run, tmp_path, monkeypatch):
    _mirrorlist(tmp_path, monkeypatch, None)
    assert mirrors.current_mirrors() == []


def test_current_mirrors_unreadable_file_is_an_error(fake_run, tmp_path, monkeypatch):
    path = tmp_path / "mirrorlist"
    path.mkdir()  # read_text() raises IsADirectoryError, an OSError
    monkeypatch.setattr(mirrors, "MIRRORLIST", path)

    with pytest.raises(RuntimeError, match="Couldn't read"):
        mirrors.current_mirrors()


def test_current_mirrors_ignores_other_lines(fake_run, tmp_path, monkeypatch):
    _mirrorlist(
        tmp_path,
        monkeypatch,
        "# Server = https://commented.example/$repo/os/$arch\n"
        "Include = /etc/pacman.d/otherlist\n",
    )
    assert mirrors.current_mirrors() == []


# ------------------------------------------------------------------ rank_mirrors --

def test_rank_mirrors_without_reflector_explains_how_to_install(fake_run, fake_which):
    with pytest.raises(RuntimeError, match="pacman -S reflector"):
        mirrors.rank_mirrors()
    assert fake_run.calls == []


def test_rank_mirrors_runs_reflector_and_parses_server_and_bare_urls(fake_run, fake_which):
    fake_which.add("reflector")
    fake_run.set_response(
        ["reflector"],
        stdout="Server = https://fast.example/$repo/os/$arch\n"
        "https://bare.example/$repo/os/$arch\n"
        "Server = https://fast.example/$repo/os/$arch\n"
        "not a mirror line\n",
    )

    assert mirrors.rank_mirrors(5) == [
        "https://fast.example/$repo/os/$arch",
        "https://bare.example/$repo/os/$arch",
    ]
    assert fake_run.calls == [REFLECTOR_PREFIX + ["5", "--print"]]


def test_rank_mirrors_adds_country_before_print(fake_run, fake_which):
    fake_which.add("reflector")
    fake_run.set_response(["reflector"], stdout="Server = https://nl.example/$repo/os/$arch\n")

    assert mirrors.rank_mirrors(3, "Netherlands") == ["https://nl.example/$repo/os/$arch"]
    assert fake_run.last_call() == REFLECTOR_PREFIX + ["3", "--country", "Netherlands", "--print"]


def test_rank_mirrors_empty_output_names_the_output_snippet(fake_run, fake_which):
    fake_which.add("reflector")
    fake_run.set_response(["reflector"], stdout="nothing useful here\n")

    with pytest.raises(RuntimeError, match="nothing useful here"):
        mirrors.rank_mirrors()


def test_rank_mirrors_malformed_output_is_an_error(fake_run, fake_which):
    fake_which.add("reflector")
    fake_run.set_response(["reflector"], stdout="Server = \n")

    with pytest.raises(RuntimeError, match="no usable mirrors"):
        mirrors.rank_mirrors()


def test_rank_mirrors_nonzero_exit_reports_stderr(fake_run, fake_which):
    fake_which.add("reflector")
    fake_run.set_response(["reflector"], stderr="reflector: unknown country 'Narnia'", returncode=1)

    with pytest.raises(RuntimeError, match="unknown country 'Narnia'"):
        mirrors.rank_mirrors(country="Narnia")


def test_rank_mirrors_nonzero_exit_without_stderr_reports_status(fake_run, fake_which):
    fake_which.add("reflector")
    fake_run.set_response(["reflector"], returncode=2)

    with pytest.raises(RuntimeError, match="status 2"):
        mirrors.rank_mirrors()


# ---------------------------------------------------------------- write_mirrorlist --

def test_write_mirrorlist_rejects_an_empty_list(fake_run, fake_which):
    with pytest.raises(ValueError):
        mirrors.write_mirrorlist([])
    assert fake_run.calls == []


@pytest.mark.parametrize("url", ["ftp://example/$repo/os/$arch", "https://example/a b", "https://example/\tx"])
def test_write_mirrorlist_rejects_non_http_or_whitespace_urls(fake_run, fake_which, url):
    with pytest.raises(ValueError):
        mirrors.write_mirrorlist([url])
    assert fake_run.calls == []


def test_write_mirrorlist_backs_up_then_tees_the_new_content(
    fake_run, fake_which, tmp_path, monkeypatch, privilege_paths
):
    path = _mirrorlist(tmp_path, monkeypatch, "Server = https://old.example/$repo/os/$arch\n")
    fake_run.set_response(["pkexec", "tee", str(path)], returncode=0)

    result = mirrors.write_mirrorlist(
        ["https://a.example/$repo/os/$arch", "http://b.example/$repo/os/$arch"]
    )

    assert result.ok
    assert fake_run.calls == [["pkexec", "tee", str(path)]]
    assert fake_run.inputs == [
        "# /etc/pacman.d/mirrorlist - written by Atropa\n\n"
        "Server = https://a.example/$repo/os/$arch\n"
        "Server = http://b.example/$repo/os/$arch\n"
    ]
    backups = list(privilege_paths.backup_dir.glob("mirrorlist.*.bak"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "Server = https://old.example/$repo/os/$arch\n"


def test_write_mirrorlist_works_when_no_old_file_exists(fake_run, fake_which, tmp_path, monkeypatch, privilege_paths):
    path = _mirrorlist(tmp_path, monkeypatch, None)
    fake_run.set_response(["pkexec", "tee", str(path)], returncode=0)

    result = mirrors.write_mirrorlist(["https://a.example/$repo/os/$arch"])

    assert result.ok
    assert fake_run.calls == [["pkexec", "tee", str(path)]]
    assert not privilege_paths.backup_dir.exists()  # nothing to back up


def test_write_mirrorlist_returns_a_failed_result_instead_of_raising(
    fake_run, fake_which, tmp_path, monkeypatch, privilege_paths
):
    path = _mirrorlist(tmp_path, monkeypatch, "Server = https://old.example/\n")
    fake_run.set_response(["pkexec", "tee", str(path)], stderr="tee: No space left on device", returncode=1)

    result = mirrors.write_mirrorlist(["https://a.example/$repo/os/$arch"])

    assert not result.ok
    assert result.returncode == 1
    assert result.stderr == "tee: No space left on device"
