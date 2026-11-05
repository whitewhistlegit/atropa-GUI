"""
atropa.backend.pacnew
------------------------
Review the configuration files pacman leaves behind:

- ``.pacnew``: a package shipped a new version of a config the user had
  modified, so pacman wrote the new one alongside it instead of
  overwriting the local changes.
- ``.pacsave``: a package was removed, but its modified config was kept.

Scanning and diffing are read-only, so the page can be opened without a
password prompt. Only apply_new()/discard() escalate, and they don't copy or
delete anything themselves: /etc isn't writable by the GUI, and the root-owned
helper is the one place that gets to touch it. Both actions hand exactly one
argv to that helper, which re-checks the suffix before acting - so the GUI's
suffix check is a fast rejection, not the security boundary.

Nothing here shells out to ``diff``/``rm``/``cp``: the unified diff is built
in-process (difflib), and the two writes are helper operations.
"""

from __future__ import annotations

import difflib
import os
from dataclasses import dataclass
from pathlib import Path

from .privilege import CommandResult, backup_file, path_exists, run_privileged

# Patched in tests: scanning the developer's real /etc from a unit test would
# make the result depend on that machine's pending configs.
ETC_DIR = Path("/etc")

PACNEW_SUFFIX = ".pacnew"
PACSAVE_SUFFIX = ".pacsave"
_SUFFIXES = (PACNEW_SUFFIX, PACSAVE_SUFFIX)


@dataclass
class PacnewEntry:
    """One candidate file and the live config it would replace (or restore)."""

    kind: str  # "pacnew" or "pacsave"
    candidate: str  # absolute path to the .pacnew/.pacsave file
    live: str  # candidate with the suffix stripped
    live_exists: bool

    # A .pacsave usually has no live file (the package that owned it is gone),
    # so "there is nothing to overwrite" is a normal state, not an error.


def _require_candidate_suffix(candidate: str) -> None:
    """
    Refuse anything the helper won't accept, before prompting for a password.

    The helper takes exactly one path ending in .pacnew or .pacsave; without
    this check a hand-built entry would cost a pkexec prompt just to fail.
    """
    if not candidate.endswith(_SUFFIXES):
        raise ValueError(f"{candidate!r} isn't a .pacnew or .pacsave file")


def scan() -> list[PacnewEntry]:
    """
    Find every .pacnew/.pacsave file under ETC_DIR, sorted by the live path.

    Unreadable subdirectories are skipped rather than aborting the walk: /etc
    has root-only corners, and one of those must not hide every other pending
    config. ETC_DIR itself being missing or unreadable is different - there is
    nothing to review at all - so it raises RuntimeError for the page to show.
    """
    try:
        if not ETC_DIR.is_dir():
            raise RuntimeError(f"{ETC_DIR} isn't a directory, so there's nothing to review")
        # Readability check up front: os.walk() would swallow a PermissionError
        # on the top directory and return an empty walk, which would look like
        # "no pending configs" instead of "couldn't look".
        with os.scandir(ETC_DIR):
            pass
    except OSError as exc:
        raise RuntimeError(f"Couldn't read {ETC_DIR}: {exc.strerror or exc}") from exc

    entries: list[PacnewEntry] = []
    # onerror: os.walk's default already ignores a directory it can't list;
    # passing this makes that deliberate - a root-only /etc subdirectory only
    # blanks itself. followlinks=False keeps symlinks from making the walk
    # leave /etc or loop.
    for dirpath, _dirnames, filenames in os.walk(ETC_DIR, followlinks=False, onerror=lambda _error: None):
        for name in filenames:
            if name.endswith(PACNEW_SUFFIX):
                kind, suffix = "pacnew", PACNEW_SUFFIX
            elif name.endswith(PACSAVE_SUFFIX):
                kind, suffix = "pacsave", PACSAVE_SUFFIX
            else:
                continue  # every other file under /etc is none of our business

            candidate = os.path.abspath(os.path.join(dirpath, name))
            # os.walk also yields symlinks. A dangling one, or a directory
            # whose name happens to end in .pacnew, isn't a candidate file.
            if not os.path.isfile(candidate):
                continue

            live = candidate[: -len(suffix)]
            # path_exists() returns None when it can't tell (an unsearchable
            # parent), which must read as "not there" rather than crash: the
            # page only uses this to say whether a diff has a live side.
            entries.append(PacnewEntry(kind, candidate, live, path_exists(live) is True))

    entries.sort(key=lambda entry: entry.live)
    return entries


def read_text(path: str) -> str:
    """
    Read a config as text, replacing undecodable bytes.

    Configs under /etc are allowed to be non-UTF-8 (or binary-ish); a decode
    error must not stop the user from seeing the rest of the diff, so this
    decodes leniently and only an actual read failure raises.
    """
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise RuntimeError(f"Couldn't read {path}: {exc.strerror or exc}") from exc


def diff_text(entry: PacnewEntry) -> str:
    """
    Unified diff of the live config (old) against the candidate (new).

    A missing live file is diffed as empty, so a .pacnew for a file the
    package newly added (and a .pacsave whose live side is gone) reads as
    "every line is new" instead of raising. An empty string means both sides
    are identical - the page says so rather than showing a blank box.
    """
    live_lines = read_text(entry.live).splitlines() if entry.live_exists else []
    candidate_lines = read_text(entry.candidate).splitlines()
    # lineterm="" + a plain join keeps the output one diff line per output
    # line, including for a file whose last line has no trailing newline
    # (splitlines loses that byte either way, and a keepends join glued
    # "-old" and "+new" together).
    diff = difflib.unified_diff(
        live_lines,
        candidate_lines,
        fromfile=entry.live,
        tofile=entry.candidate,
        lineterm="",
    )
    return "\n".join(diff)


def apply_new(entry: PacnewEntry) -> CommandResult:
    """
    Replace the live config with the candidate.

    backup_file() runs first so there is a one-click way back in Activity.
    It returns None when there is no live file yet - exactly the normal case
    for a .pacsave - and that is not an error. The copy itself is the
    privileged helper's job: the GUI can't write under /etc, and the helper
    re-validates the suffix on its side.
    """
    _require_candidate_suffix(entry.candidate)
    backup_file(entry.live)
    return run_privileged(["pacnew-apply", entry.candidate])


def discard(entry: PacnewEntry) -> CommandResult:
    """Delete the .pacnew/.pacsave file; the live config stays untouched."""
    _require_candidate_suffix(entry.candidate)
    return run_privileged(["pacnew-remove", entry.candidate])
