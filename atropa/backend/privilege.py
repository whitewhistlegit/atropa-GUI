"""
atropa.backend.privilege
---------------------------
Central place for running commands that need root privileges.

Design goals:
 - Never ask the whole app to run as root. The GUI runs as a normal user.
 - Individual privileged actions go through `pkexec`, which pops a native
   polkit auth dialog (password prompt) for just that one command.
 - Every privileged call is logged (path configurable) so users can audit
   exactly what Atropa ran on their system.
 - All subprocess calls use argument lists (never shell=True) to avoid
   shell-injection issues from user-supplied strings (package names, etc).
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

LOG_PATH = Path.home() / ".local" / "share" / "atropa" / "actions.log"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

BACKUP_DIR = Path.home() / ".local" / "share" / "atropa" / "backups"
BACKUP_MANIFEST = BACKUP_DIR / "manifest.jsonl"

logger = logging.getLogger("atropa.privilege")
_handler = logging.FileHandler(LOG_PATH)
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(_handler)
logger.setLevel(logging.INFO)


class PrivilegeError(RuntimeError):
    """Raised when a privileged command fails or pkexec is unavailable."""


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _run(argv: list[str], input_text: str | None = None, timeout: int = 300) -> CommandResult:
    logger.info("RUN: %s", " ".join(argv))
    try:
        proc = subprocess.run(
            argv,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise PrivilegeError(f"Command not found: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise PrivilegeError(f"Command timed out: {' '.join(argv)}") from exc

    result = CommandResult(proc.returncode, proc.stdout, proc.stderr)
    if not result.ok:
        logger.warning("FAILED (%s): %s", result.returncode, result.stderr.strip())
    return result


def run_unprivileged(argv: list[str], input_text: str | None = None, timeout: int = 120) -> CommandResult:
    """Run a read-only / non-destructive command as the current user."""
    return _run(argv, input_text=input_text, timeout=timeout)


def _resolve_privileged_prefix() -> list[str]:
    """
    Picks the pkexec/sudo prefix for a privileged command, or raises if
    neither is available. Shared by run_privileged() and
    run_privileged_streaming() so both stay in sync.
    """
    if shutil.which("pkexec"):
        return ["pkexec"]
    if shutil.which("sudo"):
        return ["sudo", "-A"]
    raise PrivilegeError(
        "Neither pkexec nor sudo is available. Install 'polkit' to use "
        "privileged actions in Atropa."
    )


def run_privileged(argv: list[str], input_text: str | None = None, timeout: int = 600) -> CommandResult:
    """
    Run a command as root via pkexec.

    pkexec shows a native polkit dialog asking the logged-in user to
    authenticate (password or fingerprint), scoped to this one command.
    Falls back to `sudo -A` (askpass) if pkexec isn't present, and raises
    if neither is available rather than silently doing something insecure.
    """
    full_argv = _resolve_privileged_prefix() + argv
    return _run(full_argv, input_text=input_text, timeout=timeout)


def _run_streaming(argv: list[str], on_line: Callable[[str], None], input_text: str | None, timeout: int) -> CommandResult:
    """
    Shared Popen + live-line-streaming implementation. `argv` must already
    include any privilege-escalation prefix the caller needs (or none, for
    an unprivileged call) - this function itself doesn't know or care
    which.
    """
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as exc:
        raise PrivilegeError(f"Command not found: {argv[0]}") from exc

    if input_text is not None and proc.stdin is not None:
        proc.stdin.write(input_text)
        proc.stdin.close()

    lines: list[str] = []
    if proc.stdout is not None:
        for raw_line in proc.stdout:
            line = raw_line.rstrip("\n")
            lines.append(line)
            on_line(line)

    try:
        returncode = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        raise PrivilegeError(f"Command timed out: {' '.join(argv)}") from exc

    output = "\n".join(lines)
    result = CommandResult(returncode, output, "")
    if not result.ok:
        logger.warning("FAILED (%s): %s", result.returncode, output[-500:])
    return result


def run_privileged_streaming(
    argv: list[str],
    on_line: Callable[[str], None],
    input_text: str | None = None,
    timeout: int = 1800,
) -> CommandResult:
    """
    Like run_privileged(), but calls on_line(text) for each line of
    combined stdout/stderr as it's produced, instead of blocking silently
    until the whole command finishes. Meant for genuinely long operations
    (a full system upgrade, a live filesystem relabel) where the UI should
    show real progress rather than one toast then silence.

    stdout and stderr are merged (stderr redirected into stdout) since the
    caller just wants a readable progress log, not a machine-parsed
    CommandResult split the way run_privileged() gives - the returned
    CommandResult.stderr is always empty; .stdout holds everything.
    """
    full_argv = _resolve_privileged_prefix() + argv
    logger.info("RUN (streaming, privileged): %s", " ".join(full_argv))
    return _run_streaming(full_argv, on_line, input_text, timeout)


def run_unprivileged_streaming(
    argv: list[str],
    on_line: Callable[[str], None],
    input_text: str | None = None,
    timeout: int = 1800,
) -> CommandResult:
    """
    Like run_unprivileged(), but streams output line-by-line via on_line()
    instead of blocking silently, for genuinely long *unprivileged*
    operations (e.g. compiling a full SELinux policy source tree, which
    can take several minutes) where the UI should show live progress.
    Never goes through pkexec, unlike run_privileged_streaming() - if a
    caller needs root, use that instead rather than escalating this one.
    """
    logger.info("RUN (streaming, unprivileged): %s", " ".join(argv))
    return _run_streaming(argv, on_line, input_text, timeout)


# ------------------------------------------------------ backups & history --
#
# Every module that edits an existing config file (sshd_config, GRUB
# defaults, faillock.conf, SELinux config, ...) should call backup_file()
# on it first. This is the one place that logic lives, so every module
# gets a one-click way back for free instead of each one reinventing it.


def backup_file(path: str) -> str | None:
    """
    Copies `path` into BACKUP_DIR with a timestamp suffix before a risky
    edit touches it. Returns the backup's filename (not full path - that's
    what restore_file() expects), or None if the source doesn't exist yet
    (nothing to back up, e.g. a config file being created for the first time).
    """
    src = Path(path)
    if not src.exists():
        return None

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_name = f"{src.name}.{timestamp}.bak"
    dest = BACKUP_DIR / backup_name

    try:
        content = src.read_bytes()
    except PermissionError:
        # Some config files (e.g. sshd host key related bits) may not be
        # user-readable; fall back to a privileged read rather than skipping
        # the backup silently.
        result = run_privileged(["cat", str(src)])
        if not result.ok:
            logger.warning("Backup failed for %s: %s", path, result.stderr.strip())
            return None
        content = result.stdout.encode("utf-8")

    dest.write_bytes(content)
    with open(BACKUP_MANIFEST, "a", encoding="utf-8") as f:
        f.write(json.dumps({"timestamp": timestamp, "original_path": str(src), "backup_file": backup_name}) + "\n")
    logger.info("Backed up %s -> %s", path, dest)
    return backup_name


def restore_file(backup_file_name: str, original_path: str) -> CommandResult:
    """
    Writes a previously-made backup back to its original location. Always
    privileged, since everything we back up lives under /etc.
    """
    src = BACKUP_DIR / backup_file_name
    if not src.exists():
        raise PrivilegeError(f"Backup {backup_file_name} no longer exists")
    content = src.read_text(encoding="utf-8", errors="replace")
    result = run_privileged(["tee", original_path], input_text=content)
    if result.ok:
        logger.info("Restored %s from %s", original_path, backup_file_name)
    return result


def list_backups(limit: int = 200) -> list[dict]:
    """Most-recent-first list of {timestamp, original_path, backup_file} entries."""
    if not BACKUP_MANIFEST.exists():
        return []
    entries = []
    for line in BACKUP_MANIFEST.read_text(encoding="utf-8", errors="replace").strip().splitlines():
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(entries))[:limit]


def get_recent_actions(limit: int = 200) -> list[str]:
    """Most-recent-first tail of the action log (every privileged command Atropa has run)."""
    if not LOG_PATH.exists():
        return []
    lines = LOG_PATH.read_text(encoding="utf-8", errors="replace").strip().splitlines()
    return list(reversed(lines[-limit:]))
