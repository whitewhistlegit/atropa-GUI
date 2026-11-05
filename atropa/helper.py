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

Caching authorization makes the *breadth* of what the helper can do much more
important than it was when every call prompted. This version therefore does
not hand a generic command allowlist to ``exec``: the file-manipulating
commands the app uses (`tee`, `install`, `replace-in-file`, `cp`, `mkdir`,
`touch`, `rm`, `chown`) are implemented or validated here against a fixed
policy of paths Atropa is allowed to manage. In particular:

- `tee`/`install` writes are performed by this process after resolving the
  destination, refusing symlinks, and checking the policy. There is no `tee`
  binary to point at another file.
- `replace-in-file` is a real operation (regex substitution) instead of
  `sed -i`: sed scripts can write arbitrary files (`w /etc/sudoers`), so sed
  is not allowed at all.
- `rm` only removes the legacy plugin directory; `chown` only hands files
  back to the invoking user inside that user's home; `cp` only copies into
  the AIDE database or Atropa's plugin directory; `mkdir`/`touch` only the
  paths Atropa creates.
- Everything else must still be a bare command name from a much smaller
  allowlist (systemctl, pacman, the user/group tools, ...). That list is
  phase 2 of the operation-level migration and is documented in
  DOCUMENTATION.md.

The policy below is deliberately exact-path rather than "anything under
/etc": a cached authorization must not turn into "write any root-owned
file". `tests/test_helper.py` compares it against the backend's own path
constants so a new managed file cannot silently fall outside it.
"""

from __future__ import annotations

import os
import re
import sys

# Bare command names still executed through a fixed PATH. File-manipulating
# commands are absent on purpose: this module handles or validates them.
ALLOWED = frozenset(
    {
        "aa-complain", "aa-disable", "aa-enforce", "aa-status",
        "aide", "apparmor_parser", "auditctl", "augenrules", "ausearch",
        "bootctl", "cat", "chpasswd",
        "firewall-cmd", "firewall-offline-cmd", "flatpak",
        "fwupdmgr", "grep", "groupadd", "groupdel", "grub-mkconfig",
        "hostnamectl", "journalctl", "locale-gen", "localectl",
        "make", "nmcli", "pacman", "restorecon",
        "sbctl", "semanage", "semodule", "setenforce", "setsebool",
        "smartctl", "sshd", "systemctl", "systemd-tmpfiles", "sysctl",
        "timedatectl", "true", "ufw", "usbguard",
        "useradd", "userdel", "usermod", "visudo",
    }
)

# Exact files Atropa writes (and may restore a backup over).
WRITE_FILES = frozenset(
    {
        "/.autorelabel",
        "/etc/atropa/plugins-enabled.json",
        "/etc/default/grub",
        "/etc/fail2ban/jail.d/sshd.local",
        "/etc/locale.gen",
        "/etc/pacman.conf",
        "/etc/pacman.d/mirrorlist",
        "/etc/security/faillock.conf",
        "/etc/security/pwquality.conf",
        "/etc/selinux/config",
        "/etc/ssh/sshd_config",
        "/etc/sysctl.d/99-atropa-hardening.conf",
        "/etc/systemd/zram-generator.conf",
        "/etc/usbguard/rules.conf",
        "/var/lib/aide/aide.db",
        "/var/lib/aide/aide.db.gz",
        "/var/lib/aide/aide.db.new",
        "/var/lib/aide/aide.db.new.gz",
    }
)

# Directories Atropa writes into, with a trailing slash so prefix matching
# cannot be fooled by "/etc/apparmor.d-evil".
WRITE_DIRS = (
    "/etc/apparmor.d/",
    "/etc/archyast/",
    "/etc/atropa/plugins/",
    "/etc/audit/rules.d/",
    "/var/lib/aide/",
)

# Directories mkdir -p may create.
MKDIR_DIRS = frozenset({"/etc/atropa", "/etc/atropa/plugins", "/etc/audit/rules.d"})

# cp: sources are the AIDE database or the legacy plugin tree; destinations
# are the AIDE database, the plugin directory, or the enabled-state file.
COPY_SOURCES = ("/var/lib/aide/", "/etc/archyast/")
COPY_DEST_FILES = frozenset({"/etc/atropa/plugins-enabled.json"})
COPY_DEST_DIRS = ("/var/lib/aide/", "/etc/atropa/plugins/")

SAFE_PATH = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")

# Where pacman leaves .pacnew/.pacsave files. A constant so tests can point
# the two operations at a temporary tree.
ETC_ROOT = "/etc"

# Commands handled by this module rather than executed (or refused): they
# either write content themselves or validate every path before exec.
FILE_COMMANDS = frozenset(
    {
        "tee", "install", "replace-in-file", "cp", "mkdir", "touch", "rm", "chown", "sed",
        "pacnew-apply", "pacnew-remove",
    }
)

_MODE_RE = re.compile(r"^[0-7]{3,4}$")
_OWNER_RE = re.compile(r"^(\d+):(\d+)$")


class Refused(Exception):
    """The command or one of its paths isn't allowed."""


def resolve(program: str, directories: tuple[str, ...] = SAFE_PATH) -> str:
    """Absolute path of `program` under `directories`, or Refused."""
    if not program or "/" in program or program in {".", ".."}:
        raise Refused(f"{program!r} isn't a bare command name")
    if program not in ALLOWED:
        raise Refused(f"{program!r} isn't in Atropa's privileged allowlist")
    for directory in directories:
        candidate = os.path.join(directory, program)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.realpath(candidate)
    raise Refused(f"{program!r} not found in {'/'.join(directories)}")


# --------------------------------------------------------------- path policy --


def check(argv: list[str], directories: tuple[str, ...] = SAFE_PATH) -> list[str]:
    """Resolve an allowlisted command's argv (kept for tests and callers)."""
    if not argv:
        raise Refused("no command given")
    return [resolve(argv[0], directories), *argv[1:]]


def _system_binary(name: str) -> str:
    """Path of one of the binaries this module execs after validating argv."""
    for directory in SAFE_PATH:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.realpath(candidate)
    raise Refused(f"{name!r} not found in {'/'.join(SAFE_PATH)}")


def _normal(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise Refused(f"{path!r} isn't an absolute path")
    return os.path.normpath(path)


def _resolved(path: str) -> str:
    """
    Normalised absolute path, refusing symlinked targets.

    Both halves matter. A relative path or ".." must never reach a write. A
    symlink is how an allowed directory becomes a write into an unrelated
    file (`/etc/apparmor.d/x -> /etc/sudoers`), so the resolved path has to
    be the same as the requested one.
    """
    normal = _normal(path)
    real = os.path.realpath(normal)
    if real != normal:
        raise Refused(f"{path} resolves to {real}; symlinked targets are refused")
    return real


def _is_loader_conf(path: str) -> bool:
    # systemd-boot's timeout lives on whatever ESP was detected (/efi,
    # /boot or /boot/efi); the exact file is what matters, not the ESP.
    return path.endswith("/loader/loader.conf")


def _is_battery_limit(path: str) -> bool:
    return path.startswith("/sys/class/power_supply/") and path.endswith(
        "/charge_control_end_threshold"
    )


def checked_write_path(path: str) -> str:
    normal = _normal(path)
    if _is_battery_limit(normal):
        # /sys/class/power_supply/BAT0 is itself a symlink to the device tree,
        # so resolving it is expected here - the sysfs file is what gets
        # written, and the basename is what makes it the charge threshold.
        real = os.path.realpath(normal)
        if real.startswith("/sys/") and real.endswith("/charge_control_end_threshold"):
            return real
        raise Refused(f"{path} doesn't resolve to a battery charge threshold")
    target = _resolved(path)
    if target in WRITE_FILES or target.startswith(WRITE_DIRS):
        return target
    if _is_loader_conf(target):
        return target
    raise Refused(f"{target} isn't a file Atropa is allowed to write")


def _checked_mkdir(path: str) -> str:
    target = _resolved(path)
    if target not in MKDIR_DIRS:
        raise Refused(f"mkdir {target} isn't allowed")
    return target


def _checked_remove(path: str) -> str:
    target = _resolved(path)
    if target != "/etc/archyast" and not target.startswith("/etc/archyast/"):
        raise Refused(f"rm {target} isn't allowed")
    return target


def _checked_copy(src: str, dst: str) -> tuple[str, str]:
    source, destination = _resolved(src), _resolved(dst)
    if not source.startswith(COPY_SOURCES):
        raise Refused(f"cp source {source} isn't allowed")
    if (
        destination not in COPY_DEST_FILES
        and destination != "/etc/atropa/plugins"
        and not destination.startswith(COPY_DEST_DIRS)
    ):
        raise Refused(f"cp destination {destination} isn't allowed")
    # Return the *original* spellings: `cp -rn src/. dst` means "copy the
    # contents of src into dst", and normalising away the trailing /. turns
    # it into "copy src as a subdirectory of dst". Validation used the
    # resolved forms; cp gets the paths the caller actually meant.
    return src, dst


def _calling_uid() -> int:
    raw = os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID")
    if raw is None or not raw.isdigit():
        raise Refused("can't identify the invoking user")
    return int(raw)


def _checked_chown(argv: list[str]) -> list[str]:
    """
    Only `chown -R -h --from=0:0 <my uid>:<my gid> -- <dir under $HOME>`.

    This exists so a `make install` run as root leaves the build tree usable
    by the user again; as a general chown it would be a way to hand root-owned
    files (including /etc/shadow) to an unprivileged account.
    """
    if len(argv) < 3:
        raise Refused("chown needs an owner and a path")
    owner = argv[-3]
    if argv[-2] != "--":
        raise Refused("chown must separate its path with --")
    path = argv[-1]
    uid = _calling_uid()
    import pwd  # local import: only needed for this operation

    try:
        account = pwd.getpwuid(uid)
    except KeyError:
        raise Refused(f"uid {uid} has no passwd entry") from None
    match = _OWNER_RE.match(owner.replace(",", ":"))
    if not match or int(match.group(1)) != account.pw_uid or int(match.group(2)) != account.pw_gid:
        raise Refused(f"chown owner {owner} isn't {account.pw_uid}:{account.pw_gid}")
    target = _resolved(path)
    home = os.path.realpath(account.pw_dir)
    if target != home and not target.startswith(home.rstrip("/") + "/"):
        raise Refused(f"chown {target} is outside {home}")
    allowed_flags = {"-R", "-h", "--from=0:0"}
    for flag in argv[1:-3]:
        if flag not in allowed_flags:
            raise Refused(f"chown flag {flag} isn't allowed")
    return ["chown", *argv[1:]]


# ------------------------------------------------------------- .pacnew files --


def _pacnew_candidate(path: str) -> str:
    """
    A root-owned file ending .pacnew/.pacsave under /etc that is not itself a
    symlink. These two operations exist instead of a general write because
    pacman leaves them for *any* /etc config, not just the files Atropa
    manages - the capability is bounded by "a .pacnew already exists here",
    which an unprivileged user cannot create in /etc.
    """
    target = _normal(path)
    if not target.startswith(ETC_ROOT.rstrip("/") + "/"):
        raise Refused(f"{target} isn't under {ETC_ROOT}")
    if not target.endswith((".pacnew", ".pacsave")):
        raise Refused(f"{target} isn't a .pacnew/.pacsave file")
    if os.path.islink(target) or not os.path.isfile(target):
        raise Refused(f"{target} isn't a regular file")
    return os.path.realpath(target)


def _pacnew_live(candidate: str) -> str:
    live = candidate[: -len(".pacnew")] if candidate.endswith(".pacnew") else candidate[: -len(".pacsave")]
    if live == ETC_ROOT or not live.startswith(ETC_ROOT.rstrip("/") + "/"):
        raise Refused(f"{live!r} isn't a live file under {ETC_ROOT}")
    if os.path.islink(live):
        raise Refused(f"{live} is a symlink; refusing to replace it")
    return live


def _pacnew_apply(argv: list[str]) -> int:
    if len(argv) != 2:
        raise Refused("pacnew-apply takes exactly one path")
    candidate = _pacnew_candidate(argv[1])
    live = _pacnew_live(candidate)
    with open(candidate, "rb") as handle:
        data = handle.read()
    mode = os.stat(candidate).st_mode & 0o7777
    fd = os.open(live, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.chmod(live, mode)
    return 0


def _pacnew_remove(argv: list[str]) -> int:
    if len(argv) != 2:
        raise Refused("pacnew-remove takes exactly one path")
    candidate = _pacnew_candidate(argv[1])
    os.unlink(candidate)
    return 0


# -------------------------------------------------------------- file writing --


def _write(target: str, data: bytes, append: bool = False, mode: int | None = None) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
    flags |= os.O_APPEND if append else os.O_TRUNC
    fd = os.open(target, flags, 0o644 if mode is None else mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    if mode is not None:
        os.chmod(target, mode)


def _tee(argv: list[str], data: bytes) -> int:
    args = list(argv[1:])
    append = False
    if args and args[0] == "-a":
        append = True
        args = args[1:]
    if args and args[0] == "--":
        args = args[1:]
    if len(args) != 1:
        raise Refused("tee must name exactly one file")
    target = checked_write_path(args[0])
    _write(target, data, append=append)
    return 0


def _install(argv: list[str], data: bytes) -> int:
    # The only install invocation Atropa uses: install -m MODE /dev/stdin FILE
    if len(argv) != 5 or argv[1] != "-m" or argv[3] != "/dev/stdin":
        raise Refused("install must be `install -m MODE /dev/stdin FILE`")
    if not _MODE_RE.match(argv[2]):
        raise Refused(f"install mode {argv[2]!r} isn't a file mode")
    target = checked_write_path(argv[4])
    _write(target, data, mode=int(argv[2], 8))
    return 0


def _replace_in_file(argv: list[str]) -> int:
    """
    `replace-in-file PATH PATTERN REPLACEMENT` - the operation sed -i was
    doing, without sed's ability to write other files from its script.
    """
    if len(argv) != 4:
        raise Refused("replace-in-file needs PATH, PATTERN and REPLACEMENT")
    target = checked_write_path(argv[1])
    pattern, replacement = argv[2], argv[3]
    try:
        regex = re.compile(pattern, re.MULTILINE)
    except re.error as exc:
        raise Refused(f"bad pattern: {exc}") from exc
    with open(target, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    updated = regex.sub(lambda _match: replacement, text)
    _write(target, updated.encode("utf-8"))
    return 0


def _exec(program: str, argv: list[str]) -> int:
    # Keep argv[0] the resolved path, never whatever name the caller used.
    argv = [program, *argv[1:]]
    environment = {
        "PATH": ":".join(SAFE_PATH),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "HOME": "/root",
    }
    try:
        os.execve(program, argv, environment)
    except OSError as exc:
        print(f"atropa-helper: couldn't run {program}: {exc}", file=sys.stderr)
        return 127
    return 127  # unreachable; execve doesn't return


def handle(argv: list[str], data: bytes = b"") -> int | None:
    """
    Perform an allowed file operation (returning its exit code), or return
    None when argv should be exec'd as an allowlisted command.
    """
    if not argv:
        raise Refused("no command given")
    program = argv[0]

    if program == "tee":
        return _tee(argv, data)
    if program == "install":
        return _install(argv, data)
    if program == "replace-in-file":
        return _replace_in_file(argv)
    if program == "mkdir":
        if len(argv) != 3 or argv[1] != "-p":
            raise Refused("mkdir must be `mkdir -p DIR`")
        target = _checked_mkdir(argv[2])
        return _exec(_system_binary("mkdir"), ["mkdir", "-p", target])
    if program == "touch":
        if len(argv) != 2:
            raise Refused("touch takes exactly one path")
        target = _resolved(argv[1])
        if target != "/.autorelabel":
            raise Refused(f"touch {target} isn't allowed")
        return _exec(_system_binary("touch"), ["touch", target])
    if program == "rm":
        if len(argv) != 3 or argv[1] != "-rf":
            raise Refused("rm must be `rm -rf DIR`")
        target = _checked_remove(argv[2])
        return _exec(_system_binary("rm"), ["rm", "-rf", target])
    if program == "cp":
        flags = []
        rest = list(argv[1:])
        while rest and rest[0] in {"-n", "-rn"}:
            flags.append(rest.pop(0))
        if len(rest) != 2:
            raise Refused("cp needs a source and a destination")
        source, destination = _checked_copy(rest[0], rest[1])
        return _exec(_system_binary("cp"), ["cp", *flags, source, destination])
    if program == "chown":
        validated = _checked_chown(argv)
        return _exec(_system_binary("chown"), validated)
    if program == "sed":
        raise Refused("sed isn't allowed; use replace-in-file")
    if program == "pacnew-apply":
        return _pacnew_apply(argv)
    if program == "pacnew-remove":
        return _pacnew_remove(argv)

    return None  # an allowlisted bare command: main() execs it


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv

    # pkexec makes the child root; running this directly as a user must not
    # do anything, even if it somehow has a setuid bit it shouldn't.
    if os.geteuid() != 0:
        print("atropa-helper must be run through pkexec", file=sys.stderr)
        return 126

    data = b""
    if args and args[0] in {"tee", "install"}:
        data = sys.stdin.buffer.read()

    try:
        handled = handle(args, data)
    except Refused as exc:
        print(f"atropa-helper: refused: {exc}", file=sys.stderr)
        return 126

    if handled is not None:
        return handled

    try:
        program = resolve(args[0])
    except Refused as exc:
        print(f"atropa-helper: refused: {exc}", file=sys.stderr)
        return 126
    return _exec(program, args)


if __name__ == "__main__":
    sys.exit(main())
