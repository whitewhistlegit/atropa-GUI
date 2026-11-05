#!/usr/bin/python3
"""
atropa.helper
----------------
Atropa's single privileged entry point.

Why this exists: pkexec picks a polkit action from the *program it runs*.
Atropa used to run every tool directly (`pkexec tee /etc/...`, `pkexec
systemctl ...`), so each call hit polkit's generic
`org.freedesktop.policykit.exec` action, which always asks - there was no
action to remember authorization against, and a normal configuration change
meant half a dozen password prompts.

This helper is installed at a fixed root-owned path
(``/usr/lib/atropa/atropa-helper``) and the shipped policy annotates that
path with its own action (``auth_admin_keep``). One authentication then
covers further calls for polkit's keep window (five minutes by default), so
a multi-step operation asks once.

What it deliberately does not do: take a shell, run an arbitrary program,
or accept an absolute/relative program path. argv[0] must be a bare command
name from a fixed allowlist of tools Atropa actually uses, resolved through
a fixed PATH to a real binary under /usr/{,s}bin or /{,s}bin. There is no
shell involved, so no argument can turn into a second command.

Security note: the helper is a *command* allowlist, not an operation one.
Anything that can run as the invoking user can, within the keep window, run
those same tools as root without another prompt - the same power pkexec
already granted, just cached. That is the tradeoff `auth_admin_keep` is for;
the allowlist keeps it to programs Atropa itself can run.
"""

from __future__ import annotations

import os
import sys

# Every program Atropa invokes with run_privileged(). Keep this in sync with
# the backend - `tests/test_helper.py` walks the backend's call sites and
# fails when a literal command is missing from this set.
ALLOWED = frozenset(
    {
        "aa-complain", "aa-disable", "aa-enforce", "aa-status",
        "aide", "apparmor_parser", "auditctl", "augenrules", "ausearch",
        "bootctl", "cat", "chown", "chpasswd", "cp",
        "firewall-cmd", "firewall-offline-cmd", "flatpak",
        "fwupdmgr", "grep", "groupadd", "groupdel", "grub-mkconfig",
        "hostnamectl", "install",
        "journalctl", "locale-gen", "localectl",
        "make", "mkdir",
        "nmcli",
        "pacman",
        "restorecon", "rm",
        "sbctl", "sed", "semanage", "semodule", "setenforce", "setsebool",
        "smartctl", "sshd", "systemctl", "systemd-tmpfiles", "sysctl",
        "tee", "timedatectl", "touch", "true",
        "ufw", "usbguard", "useradd", "userdel", "usermod",
        "visudo",
    }
)

# Fixed search path: the caller's PATH is never consulted, so a user-writable
# directory earlier in PATH cannot shadow systemctl with something else.
SAFE_PATH = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")

# A command name is a bare basename; anything with a slash is refused rather
# than resolved, so `../bin/sh` or an absolute path can't slip through.
_BAD_NAME = "/"


class Refused(Exception):
    """The command isn't one the helper is allowed to run."""


def resolve(program: str, directories: tuple[str, ...] = SAFE_PATH) -> str:
    """Absolute path of `program` under `directories`, or Refused."""
    if not program or _BAD_NAME in program or program in {".", ".."}:
        raise Refused(f"{program!r} isn't a bare command name")
    if program not in ALLOWED:
        raise Refused(f"{program!r} isn't in Atropa's privileged allowlist")
    for directory in directories:
        candidate = os.path.join(directory, program)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.realpath(candidate)
    raise Refused(f"{program!r} not found in {'/'.join(directories)}")


def check(argv: list[str], directories: tuple[str, ...] = SAFE_PATH) -> list[str]:
    """The argv to exec (program resolved), or Refused. Never uses a shell."""
    if not argv:
        raise Refused("no command given")
    return [resolve(argv[0], directories), *argv[1:]]


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv

    # pkexec makes the child root; running this directly as a user must not
    # do anything, even if it somehow has a setuid bit it shouldn't.
    if os.geteuid() != 0:
        print("atropa-helper must be run through pkexec", file=sys.stderr)
        return 126

    try:
        command = check(args)
    except Refused as exc:
        print(f"atropa-helper: refused: {exc}", file=sys.stderr)
        return 126

    environment = {
        "PATH": ":".join(SAFE_PATH),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "HOME": "/root",
    }
    try:
        os.execve(command[0], command, environment)
    except OSError as exc:
        print(f"atropa-helper: couldn't run {command[0]}: {exc}", file=sys.stderr)
        return 127
    return 127  # unreachable; execve doesn't return


if __name__ == "__main__":
    sys.exit(main())
