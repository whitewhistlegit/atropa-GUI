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
- Every other program has its own validator in COMMANDS: the exact
  argument shapes Atropa uses, nothing else (no `pacman -U`, no
  `systemctl link`, no `make` outside `install load`, no `cat /etc/shadow`).
  An unknown program or shape is refused.

Two tiers, because some of Atropa's own operations are root-equivalent by
nature (a password for root, a member for wheel, a policy module, a
pacman.conf HookDir) and no argument check makes them safe to cache:

- KEEP: everything else. Installed as ``atropa-helper``, whose polkit action
  is ``auth_admin_keep``.
- ASK: the root-equivalent operations. The same file installed again as
  ``atropa-helper-ask``, whose action is plain ``auth_admin``: it asks every
  time. The keep helper refuses ASK operations; privilege.py sends them to
  the ask helper (``needs_fresh_auth()`` is the shared answer).

The policy below is deliberately exact-path rather than "anything under
/etc": a cached authorization must not turn into "write any root-owned
file". `tests/test_helper.py` compares it against the backend's own path
constants so a new managed file cannot silently fall outside it.
"""

from __future__ import annotations

import os
import re
import sys

# The two installed copies of this file. Which one is running decides the
# tier: the kernel hands the script the path it was exec'd from, so a caller
# can't make the keep helper believe it is the ask helper.
KEEP_HELPER_PATH = "/usr/lib/atropa/atropa-helper"
ASK_HELPER_PATH = "/usr/lib/atropa/atropa-helper-ask"
KEEP = "keep"
ASK = "ask"

# Exact files Atropa writes (and may restore a backup over).
WRITE_FILES = frozenset(
    {
        "/.autorelabel",
        "/etc/atropa/plugins-enabled.json",
        "/etc/conf.d/snapper",
        "/etc/default/grub",
        "/etc/fail2ban/jail.d/sshd.local",
        "/etc/locale.gen",
        "/etc/pacman.conf",
        "/etc/pam.d/su",
        "/etc/pam.d/su-l",
        "/etc/pacman.d/mirrorlist",
        "/etc/security/faillock.conf",
        "/etc/security/pwquality.conf",
        "/etc/selinux/config",
        "/etc/snapper/configs/root",
        "/etc/ssh/sshd_config",
        "/etc/sysctl.d/99-atropa-hardening.conf",
        "/etc/systemd/logind.conf.d/50-atropa.conf",
        "/etc/systemd/sleep.conf.d/50-atropa.conf",
        "/etc/systemd/zram-generator.conf",
        "/etc/usbguard/rules.conf",
        "/var/lib/aide/aide.db",
        "/var/lib/aide/aide.db.gz",
        "/var/lib/aide/aide.db.new",
        "/var/lib/aide/aide.db.new.gz",
    }
)

# Managed files that may be a symlink to a sibling, mapped to the prefix the
# resolved target must have. selinux-refpolicy-arch's install script links
# /etc/selinux/config -> config.refpolicy-arch when no config exists yet,
# which is exactly the state after setting SELinux up from scratch.
SYMLINKED_FILES = {"/etc/selinux/config": "/etc/selinux/config."}

# Managed files whose content can run code as root or open a login path:
# su's PAM stack (pam_permit), pacman.conf (HookDir, unsigned repos), sshd_config (AuthorizedKeysCommand),
# SELinux mode, the kernel command line (init=), sysctl (core_pattern,
# modprobe), fail2ban actions (shell commands), AppArmor profiles. Writes to
# these go through the ask helper only.
ASK_WRITE_FILES = frozenset(
    {
        "/etc/pam.d/su",
        "/etc/pam.d/su-l",
        "/etc/conf.d/snapper",
        "/etc/snapper/configs/root",
        "/etc/default/grub",
        "/etc/fail2ban/jail.d/sshd.local",
        "/etc/pacman.conf",
        "/etc/selinux/config",
        "/etc/ssh/sshd_config",
        "/etc/sysctl.d/99-atropa-hardening.conf",
    }
)
ASK_WRITE_DIRS = ("/etc/apparmor.d/",)

# Root-only files Atropa reads (besides the ones it manages, which it reads
# to back them up). /etc/shadow is deliberately absent: shadow-status
# answers the only question Atropa asks of it without the hashes.
READ_FILES = frozenset({"/root/.bash_profile", "/root/.bashrc", "/etc/profile"})

# Where boot files live: the ESP is /efi, /boot or /boot/efi.
BOOT_DIRS = ("/boot/", "/efi/")

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
MKDIR_DIRS = frozenset(
    {
        "/etc/atropa", "/etc/atropa/plugins", "/etc/audit/rules.d",
        "/etc/systemd/logind.conf.d", "/etc/systemd/sleep.conf.d",
    }
)

# cp: sources are the AIDE database or the legacy plugin tree; destinations
# are the AIDE database, the plugin directory, or the enabled-state file.
COPY_SOURCES = ("/var/lib/aide/", "/etc/archyast/")
COPY_DEST_FILES = frozenset({"/etc/atropa/plugins-enabled.json"})
COPY_DEST_DIRS = ("/var/lib/aide/", "/etc/atropa/plugins/")

SAFE_PATH = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")

# Where pacman leaves .pacnew/.pacsave files. A constant so tests can point
# the two operations at a temporary tree.
ETC_ROOT = "/etc"

# The account databases. Their .pacnew is the filesystem package's stock
# copy with none of this machine's users in it, so "use new" would delete
# every account (and with shadow, every password). These are merged by hand,
# never replaced. Kept in step with backend/pacnew.py, which can't be
# imported here: this file is installed on its own.
ACCOUNT_FILES = frozenset({"passwd", "group", "shadow", "gshadow"})

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
    if program not in COMMANDS:
        raise Refused(f"{program!r} isn't a program Atropa runs as root")
    for directory in directories:
        candidate = os.path.join(directory, program)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.realpath(candidate)
    raise Refused(f"{program!r} not found in {'/'.join(directories)}")


# --------------------------------------------------------------- path policy --


def check(argv: list[str], directories: tuple[str, ...] = SAFE_PATH) -> list[str]:
    """Validate an executed command's argv and resolve its program."""
    if not argv:
        raise Refused("no command given")
    _tier, args = validate_command(argv)
    return [resolve(argv[0], directories), *args]


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
    # /boot or /boot/efi). Any of those, but only those: matching the file
    # name alone let any directory called "loader" take a root write.
    return path.startswith(BOOT_DIRS) and path.endswith("/loader/loader.conf")


_LOADER_ENTRY_RE = re.compile(r"^atropa-[a-z0-9][a-z0-9._+-]*\.conf$")


def _is_loader_entry(path: str) -> bool:
    # A systemd-boot entry Atropa adds for an installed kernel. Only its own
    # atropa-*.conf names: entries written by hand or by kernel-install stay
    # untouched. An entry carries the kernel command line, so writing one
    # asks every time (see _write_tier).
    parts = path.split("/")
    return (
        path.startswith(BOOT_DIRS)
        and len(parts) >= 4
        and parts[-3:-1] == ["loader", "entries"]
        and bool(_LOADER_ENTRY_RE.match(parts[-1]))
    )


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
    prefix = SYMLINKED_FILES.get(normal)
    if prefix is not None:
        # The write goes to the resolved file, and only when that is a sibling
        # named like the policy's own copy - never somewhere a link could aim.
        real = os.path.realpath(normal)
        rest = real[len(prefix):]
        if real == normal or (real.startswith(prefix) and rest and "/" not in rest):
            return real
        raise Refused(f"{path} resolves to {real}, which isn't its {prefix}* sibling")
    target = _resolved(path)
    if target in WRITE_FILES or target.startswith(WRITE_DIRS):
        return target
    if _is_loader_conf(target) or _is_loader_entry(target):
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
    if os.path.dirname(live) == os.path.normpath(ETC_ROOT) and os.path.basename(live) in ACCOUNT_FILES:
        raise Refused(f"{live} lists this machine's accounts; merge {candidate} by hand instead of replacing it")
    with open(candidate, "rb") as handle:
        data = handle.read()
    mode = os.stat(candidate).st_mode & 0o7777
    backup_before_write(live, live)
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



# ------------------------------------------------------------- command shapes --
#
# One validator per program: it receives argv[1:] and returns (tier, args)
# for a shape Atropa uses, or raises Refused. Names and values that end up
# as separate argv entries can't inject options when they can't start with
# "-", which every free-form value below checks.

_UNIT_RE = re.compile(r"^[A-Za-z0-9@_][A-Za-z0-9@._:\\-]*$")  # a unit *name*: no "/" (no unit files from $HOME)
_PACKAGE_RE = re.compile(r"^(?:[a-z0-9][a-z0-9._-]*/)?[a-z0-9@_+][a-z0-9@._+-]*$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")
_GROUP_LIST_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}(,[a-z_][a-z0-9_-]{0,31})*$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_LOCALE_VALUE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]*$")
_TIMEZONE_RE = re.compile(r"^[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*$")
_PORT_SPEC_RE = re.compile(r"^\d{1,5}(?:[:-]\d{1,5})?/(?:tcp|udp)$")
_BOOLEAN_RE = re.compile(r"^[a-z0-9_]+$")
_MODULE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_SEUSER_RE = re.compile(r"^[a-z_][a-z0-9_]*$")
_SIZE_RE = re.compile(r"^\d+[KMG]?$")
_DEVICE_RE = re.compile(r"^/dev/[A-Za-z0-9_][A-Za-z0-9/_-]*$")


def _value(value: str, pattern: re.Pattern, what: str) -> str:
    if not isinstance(value, str) or not pattern.match(value) or ".." in value:
        raise Refused(f"{value!r} isn't a valid {what}")
    return value


def _free_text(value: str, what: str) -> str:
    """A value that can be anything readable, but not an option or a line break."""
    if not isinstance(value, str) or value.startswith("-") or any(ch in value for ch in "\n\r\0"):
        raise Refused(f"{value!r} isn't a valid {what}")
    return value


def _shapes(args: list[str], *allowed: tuple[str, ...]) -> list[str]:
    if tuple(args) not in allowed:
        raise Refused(f"arguments {args!r} aren't a shape Atropa uses")
    return list(args)


def _keep_exact(*allowed: tuple[str, ...]):
    return lambda args: (KEEP, _shapes(args, *allowed))


def _under(path: str, prefixes: tuple[str, ...], what: str) -> str:
    target = _resolved(path)
    if not target.startswith(prefixes):
        raise Refused(f"{target} isn't a {what}")
    return target


def _apparmor_mode(args):
    if len(args) != 1:
        raise Refused("expected one profile path")
    return KEEP, [_under(args[0], ("/etc/apparmor.d/",), "profile under /etc/apparmor.d")]


def _apparmor_parser(args):
    if len(args) != 2 or args[0] != "-r":
        raise Refused("apparmor_parser must be `-r PROFILE`")
    return KEEP, ["-r", _under(args[1], ("/etc/apparmor.d/",), "profile under /etc/apparmor.d")]


def _ausearch(args):
    if len(args) < 3 or args[0] != "-m" or args[1] not in {"avc", "AVC,APPARMOR_DENIED"} or args[-1] != "--input-logs":
        raise Refused("ausearch must be `-m avc|AVC,APPARMOR_DENIED [-ts boot] --input-logs`")
    if args[2:-1] not in ([], ["-ts", "boot"]):
        raise Refused("ausearch only takes -ts boot")
    return KEEP, list(args)


def _bootctl(args):
    if args in (["update"], ["install"]):
        return KEEP, list(args)
    if len(args) == 2 and args[0] == "set-timeout" and (args[1] == "" or args[1].isdigit()):
        return KEEP, list(args)
    raise Refused("bootctl must be update, install or set-timeout N")


def _checked_read_path(path: str) -> str:
    normal = _normal(path)
    if normal in READ_FILES:
        return _resolved(path)
    # Anything Atropa may write it may also read back (backups, diffs).
    try:
        return checked_write_path(path)
    except Refused:
        raise Refused(f"{normal} isn't a file Atropa reads") from None


def _cat(args):
    paths = args[1:] if args[:1] == ["--"] else args
    if not paths:
        raise Refused("cat needs a path")
    return KEEP, ["--", *(_checked_read_path(path) for path in paths)]


def _grep(args):
    if len(args) == 3 and args[:2] == ["-E", "^menuentry"] and _resolved(args[2]) == "/boot/grub/grub.cfg":
        return KEEP, list(args)
    # Only the kernel file names grub.cfg boots, never the command lines.
    if len(args) == 3 and args[:2] == ["-oE", "vmlinuz-[A-Za-z0-9._+-]+"] and _resolved(args[2]) == "/boot/grub/grub.cfg":
        return KEEP, list(args)
    if len(args) == 4 and args[:3] == ["-rH", "--include=*.conf", ""]:
        loader = _under(args[3], BOOT_DIRS, "boot directory")
        if os.path.basename(loader) == "loader":
            return KEEP, [*args[:3], loader]
    raise Refused("grep only reads grub.cfg's menu entries or kernel names, or a systemd-boot loader directory")


def _firewall_cmd(args):
    if args in (["--list-all"], ["--reload"]):
        return KEEP, list(args)
    if len(args) == 3 and args[0] == "--permanent" and args[1] in {"--add-port", "--remove-port"}:
        return KEEP, ["--permanent", args[1], _value(args[2], _PORT_SPEC_RE, "port")]
    raise Refused("firewall-cmd only lists, reloads, and adds or removes a port")


def _firewall_offline_cmd(args):
    if len(args) == 1:
        flag, sep, spec = args[0].partition("=")
        if sep and flag in {"--add-port", "--remove-port"}:
            return KEEP, [f"{flag}={_value(spec, _PORT_SPEC_RE, 'port')}"]
    raise Refused("firewall-offline-cmd only adds or removes a port")


def _hostnamectl(args):
    if len(args) == 2 and args[0] == "set-hostname":
        return KEEP, ["set-hostname", _value(args[1], _HOSTNAME_RE, "hostname")]
    raise Refused("hostnamectl must be set-hostname NAME")


def _journalctl(args):
    if len(args) == 1 and args[0].startswith("--vacuum-size="):
        _value(args[0].split("=", 1)[1], _SIZE_RE, "size")
        return KEEP, list(args)
    raise Refused("journalctl only vacuums by size")


def _localectl(args):
    if len(args) == 2 and args[0] in {"set-keymap", "set-x11-keymap"}:
        return KEEP, [args[0], _value(args[1], _LOCALE_VALUE_RE, "keymap")]
    if len(args) == 2 and args[0] == "set-locale" and args[1].startswith("LANG="):
        _value(args[1][5:], _LOCALE_VALUE_RE, "locale")
        return KEEP, list(args)
    raise Refused("localectl must be set-locale LANG=..., set-keymap or set-x11-keymap")


def _make(args):
    # The policy build: `make install load` in a source tree. It runs that
    # tree's Makefile as root, so it is root-equivalent by design.
    if len(args) == 4 and args[0] == "-C" and args[2:] == ["install", "load"]:
        source = _resolved(args[1])
        if not os.path.isdir(source):
            raise Refused(f"{source} isn't a directory")
        return ASK, ["-C", source, "install", "load"]
    raise Refused("make must be `-C DIR install load`")


def _ip(value: str, network: bool = False) -> str:
    import ipaddress

    try:
        ipaddress.ip_interface(value) if network else ipaddress.ip_address(value)
    except ValueError:
        raise Refused(f"{value!r} isn't an IP address") from None
    return value


def _nmcli(args):
    if args == ["networking", "on"] or args == ["networking", "off"]:
        return KEEP, list(args)
    head = args[1:] if args[:1] == ["--ask"] else args
    if len(head) == 4 and head[:3] == ["device", "wifi", "connect"]:
        return KEEP, [*args[: len(args) - len(head)], *head[:3], _free_text(head[3], "network name")]
    if len(args) == 3 and args[:2] == ["device", "disconnect"]:
        return KEEP, ["device", "disconnect", _free_text(args[2], "device")]
    if len(args) == 3 and args[:2] == ["connection", "up"]:
        return KEEP, ["connection", "up", _free_text(args[2], "connection")]
    if len(args) == 5 and args[:2] == ["connection", "modify"] and args[3:] == ["ipv4.method", "auto"]:
        return KEEP, ["connection", "modify", _free_text(args[2], "connection"), "ipv4.method", "auto"]
    if (
        len(args) == 11
        and args[:2] == ["connection", "modify"]
        and args[3] == "ipv4.addresses" and args[5] == "ipv4.gateway" and args[7] == "ipv4.dns"
        and args[9:] == ["ipv4.method", "manual"]
    ):
        dns = args[8].split(",") if args[8] else []
        for server in dns:
            _ip(server)
        return KEEP, [
            "connection", "modify", _free_text(args[2], "connection"),
            "ipv4.addresses", _ip(args[4], network=True), "ipv4.gateway", _ip(args[6]),
            "ipv4.dns", args[8], "ipv4.method", "manual",
        ]
    raise Refused("nmcli arguments aren't a shape Atropa uses")


PACKAGE_CACHE = "/var/cache/pacman/pkg/"
_PACKAGE_FILE_RE = re.compile(r"^[^/]+\.pkg\.tar\.(?:zst|xz)$")


def _cached_package(path: str) -> str:
    """A package file directly in pacman's root-owned cache, not a symlink."""
    target = _under(path, (PACKAGE_CACHE,), f"package in {PACKAGE_CACHE}")
    name = target[len(PACKAGE_CACHE):]
    if not _PACKAGE_FILE_RE.match(name) or not os.path.isfile(target):
        raise Refused(f"{target} isn't a package file in {PACKAGE_CACHE}")
    return target


def _pacman(args):
    # Repository operations by package name. -U only takes files that
    # pacman itself downloaded into its root-owned cache (a rollback): any
    # other package file is arbitrary root code. Installing older versions
    # is a downgrade, so that shape always asks. No --config, --root,
    # --dbpath, --hookdir or --cachedir anywhere.
    if len(args) >= 3 and args[:2] == ["-U", "--noconfirm"]:
        return ASK, ["-U", "--noconfirm", *(_cached_package(path) for path in args[2:])]
    shapes = {
        ("-Syu", "--noconfirm"): 0,
        ("-Sc", "--noconfirm"): 0,
        ("-S", "--needed", "--noconfirm"): 1,
        ("-Syu", "--needed", "--noconfirm"): 1,
        ("-Rs", "--noconfirm"): 1,
        ("-Rns", "--noconfirm"): 1,
    }
    for prefix, minimum in shapes.items():
        if tuple(args[: len(prefix)]) == prefix:
            packages = args[len(prefix):]
            if (minimum == 0 and packages) or (minimum and not packages):
                break
            return KEEP, [*prefix, *(_value(name, _PACKAGE_RE, "package name") for name in packages)]
    raise Refused("pacman only syncs, installs, removes or cleans by package name")


def _restorecon(args):
    if len(args) == 2 and args[0] in {"-v", "-Rv"}:
        return KEEP, [args[0], _normal(args[1])]
    raise Refused("restorecon must be -v|-Rv PATH")


def _sbctl(args):
    if args in (["create-keys"], ["verify", "--json"], ["sign-all"]):
        return KEEP, list(args)
    if len(args) == 3 and args[:2] == ["sign", "-s"]:
        # Only boot files: signing a file from $HOME with your own keys
        # would make it bootable under Secure Boot.
        return KEEP, ["sign", "-s", _under(args[2], BOOT_DIRS, "file under /boot or /efi")]
    if args in (["enroll-keys", "--microsoft"], ["enroll-keys", "--no-microsoft"]):
        return ASK, list(args)  # changes the firmware's trusted keys
    raise Refused("sbctl arguments aren't a shape Atropa uses")


_SNAPSHOT_NUMBER_RE = re.compile(r"^[1-9][0-9]{0,8}$")


def _snapper(args):
    # Only the root config. Reading and creating are harmless; restoring
    # files writes anything as root, deleting removes a way back, and the
    # config itself (ALLOW_USERS) is root-equivalent - those always ask.
    if args in (["--jsonout", "-c", "root", "list"], ["--jsonout", "list-configs"]):
        return KEEP, list(args)
    if args[:2] != ["-c", "root"]:
        raise Refused("snapper only works on the root config")
    rest = args[2:]
    if len(rest) == 5 and rest[0] == "create" and rest[1] == "-d" and rest[3:] == ["--cleanup-algorithm", "number"]:
        if len(rest[2]) > 200:
            raise Refused("snapshot description is too long")
        return KEEP, ["-c", "root", "create", "-d", _free_text(rest[2], "description"), *rest[3:]]
    if len(rest) == 2 and rest[0] == "status" and rest[1].endswith("..0"):
        _value(rest[1][:-3], _SNAPSHOT_NUMBER_RE, "snapshot number")
        return KEEP, list(args)
    if len(rest) == 2 and rest[0] == "delete":
        return ASK, ["-c", "root", "delete", _value(rest[1], _SNAPSHOT_NUMBER_RE, "snapshot number")]
    if rest == ["create-config", "/"]:
        return ASK, list(args)
    if len(rest) >= 3 and rest[0] == "undochange" and rest[1].endswith("..0"):
        _value(rest[1][:-3], _SNAPSHOT_NUMBER_RE, "snapshot number")
        return ASK, ["-c", "root", "undochange", rest[1], *(_normal(path) for path in rest[2:])]
    raise Refused("snapper arguments aren't a shape Atropa uses")


def _semanage(args):
    if (
        len(args) == 9 and args[0] == "login" and args[1] == "-S" and args[3] == "-N"
        and args[4] in {"-a", "-m"} and args[5] == "-s" and args[8] == "__default__"
    ):
        _value(args[2], _MODULE_RE, "policy name")
        _value(args[6], _SEUSER_RE, "SELinux user")
        return ASK, list(args)
    raise Refused("semanage only maps __default__ in a named policy store")


def _semodule(args):
    if args == ["-l"]:
        return KEEP, ["-l"]
    if len(args) >= 2 and args[0] == "-i":
        paths = [_resolved(path) for path in args[1:]]
        for path in paths:
            if not path.endswith(".pp") or not os.path.isfile(path):
                raise Refused(f"{path} isn't a compiled .pp module")
        return ASK, ["-i", *paths]
    if len(args) == 2 and args[0] == "-r":
        return ASK, ["-r", _value(args[1], _MODULE_RE, "module name")]
    raise Refused("semodule only lists, installs .pp files or removes a module")


def _setsebool(args):
    rest = args[1:] if args[:1] == ["-P"] else args
    if len(rest) == 2 and rest[1] in {"on", "off"} and "=" not in rest[0]:
        return KEEP, [*args[: len(args) - 2], _value(rest[0], _BOOLEAN_RE, "boolean"), rest[1]]
    if rest and all("=" in item for item in rest):
        for item in rest:
            name, _sep, value = item.partition("=")
            _value(name, _BOOLEAN_RE, "boolean")
            if value not in {"on", "off"}:
                raise Refused(f"{item!r} isn't name=on|off")
        return KEEP, list(args)
    raise Refused("setsebool must be [-P] NAME on|off or [-P] NAME=on|off ...")


def _smartctl(args):
    if len(args) == 3 and args[:2] == ["-H", "--json"]:
        return KEEP, ["-H", "--json", _value(args[2], _DEVICE_RE, "device")]
    raise Refused("smartctl must be -H --json DEVICE")


# Units Atropa itself starts, restarts or enables. Starting an arbitrary
# installed unit is not harmless: debug-shell.service is a root shell on
# tty9 without a password (and enabling it gives one at every boot), and
# emergency/rescue targets are similar. So start/restart/enable of any
# other unit - everything the Services page offers - asks every time;
# stopping or disabling only ever switches something off and stays KEEP.
MANAGED_UNITS = frozenset(
    {
        "aide-check.timer", "aide.timer", "aidecheck.timer",
        "apparmor.service", "auditd.service", "fail2ban.service", "firewalld.service",
        "fstrim.timer", "grub-btrfsd.service", "snapper-cleanup.timer", "sshd.service",
        "systemd-zram-setup@zram0.service",
        "ufw.service", "usbguard.service",
    }
)
_ACTIVATING_VERBS = {"start", "restart", "try-reload-or-restart", "enable"}


def _unit_id(name: str) -> str:
    return name if "." in name else f"{name}.service"


def _systemctl(args):
    if args == ["daemon-reload"]:
        return KEEP, ["daemon-reload"]
    if args == ["reload", "systemd-logind.service"]:
        # Re-reads logind.conf without ending sessions, which a restart would.
        return KEEP, list(args)
    verbs = _ACTIVATING_VERBS | {"stop", "disable"}
    rest = [arg for arg in args[1:] if arg != "--now"]
    now = len(rest) != len(args) - 1
    if args and args[0] in verbs and len(rest) == 1 and (not now or args[0] in {"enable", "disable"}):
        validated = list(args[:1]) + [arg if arg == "--now" else _value(arg, _UNIT_RE, "unit name") for arg in args[1:]]
        activating = args[0] in _ACTIVATING_VERBS
        return (ASK if activating and _unit_id(rest[0]) not in MANAGED_UNITS else KEEP), validated
    raise Refused("systemctl must be daemon-reload, reload systemd-logind.service, or VERB UNIT (enable/disable may add --now)")


def _timedatectl(args):
    if len(args) == 2 and args[0] == "set-timezone":
        return KEEP, ["set-timezone", _value(args[1], _TIMEZONE_RE, "time zone")]
    if args in (["set-ntp", "true"], ["set-ntp", "false"]):
        return KEEP, list(args)
    raise Refused("timedatectl must be set-timezone ZONE or set-ntp true|false")


def _ufw(args):
    if args in (["status", "verbose"], ["--force", "enable"], ["disable"]):
        return KEEP, list(args)
    if len(args) == 2 and args[0] in {"allow", "deny"}:
        return KEEP, [args[0], _value(args[1], _PORT_SPEC_RE, "port")]
    raise Refused("ufw only reports status, enables, disables, and allows or denies a port")


def _shell(value: str) -> str:
    try:
        with open("/etc/shells", encoding="utf-8") as handle:
            shells = {line.strip() for line in handle if line.strip() and not line.startswith("#")}
    except OSError:
        shells = set()
    if value not in shells:
        raise Refused(f"{value!r} isn't listed in /etc/shells")
    return value


def _user_options(args: list[str], allowed: dict[str, int]) -> list[str]:
    """Options as flag/value pairs (value count per flag), validated, user name last."""
    out: list[str] = []
    index = 0
    while index < len(args) - 1:
        flag = args[index]
        if flag not in allowed:
            raise Refused(f"option {flag!r} isn't one Atropa uses")
        out.append(flag)
        if allowed[flag]:
            value = args[index + 1]
            if flag == "-s":
                value = _shell(value)
            elif flag == "-G":
                value = _value(value, _GROUP_LIST_RE, "group list")
            elif flag == "-c":
                value = _free_text(value, "full name")
                if ":" in value:
                    raise Refused("a full name can't contain ':'")
            out.append(value)
        index += 1 + allowed[flag]
    if index != len(args) - 1:
        raise Refused("expected a user name last")
    return [*out, _value(args[-1], _USER_RE, "user name")]


def _useradd(args):
    return ASK, _user_options(args, {"-m": 0, "-M": 0, "-s": 1, "-c": 1, "-G": 1})


def _usermod(args):
    return ASK, _user_options(args, {"-c": 1, "-s": 1, "-G": 1, "-L": 0, "-U": 0})


def _userdel(args):
    validated = _user_options(args, {"-r": 0})
    if validated[-1] == "root":
        raise Refused("root can't be deleted")
    return ASK, validated


def _group(args):
    if len(args) == 1:
        return ASK, [_value(args[0], _USER_RE, "group name")]
    raise Refused("expected one group name")


COMMANDS = {
    "aa-complain": _apparmor_mode,
    "aa-disable": _apparmor_mode,
    "aa-enforce": _apparmor_mode,
    "aa-status": _keep_exact(()),
    "aide": _keep_exact(("--init",), ("--check",), ("--config-check",)),
    "apparmor_parser": _apparmor_parser,
    "auditctl": _keep_exact(("-l",)),
    "augenrules": _keep_exact(("--load",)),
    "ausearch": _ausearch,
    "bootctl": _bootctl,
    "cat": _cat,
    "chpasswd": lambda args: (ASK, _shapes(args, ())),
    "firewall-cmd": _firewall_cmd,
    "firewall-offline-cmd": _firewall_offline_cmd,
    "flatpak": _keep_exact(("update", "-y", "--noninteractive"), ("uninstall", "--unused", "-y", "--noninteractive")),
    "fwupdmgr": _keep_exact(("refresh", "--force"), ("update", "-y")),
    "grep": _grep,
    "groupadd": _group,
    "groupdel": _group,
    "grub-mkconfig": _keep_exact(("-o", "/boot/grub/grub.cfg")),
    "hostnamectl": _hostnamectl,
    "journalctl": _journalctl,
    "locale-gen": _keep_exact(()),
    "localectl": _localectl,
    "make": _make,
    "nmcli": _nmcli,
    "pacman": _pacman,
    # Cache cleanup that keeps the previous version of every installed
    # package (so a rollback stays possible) and drops uninstalled ones.
    "paccache": _keep_exact(("-r", "-k2"), ("-r", "-u", "-k0")),
    "restorecon": _restorecon,
    "sbctl": _sbctl,
    "semanage": _semanage,
    "snapper": _snapper,
    "semodule": _semodule,
    "setenforce": lambda args: (ASK, _shapes(args, ("0",), ("1",))),
    "setsebool": _setsebool,
    "smartctl": _smartctl,
    "sshd": _keep_exact(("-t",)),
    "sysctl": _keep_exact(("--system",)),
    "systemctl": _systemctl,
    "systemd-tmpfiles": _keep_exact(("--clean",)),
    "timedatectl": _timedatectl,
    # privilege.authenticate(): unlocks controls that must not be reachable
    # without a password, so a cached keep authorization mustn't satisfy it.
    "true": lambda args: (ASK, _shapes(args, ())),
    "ufw": _ufw,
    "usbguard": _keep_exact(("generate-policy",)),
    "useradd": _useradd,
    "userdel": _userdel,
    "usermod": _usermod,
    "visudo": _keep_exact(("-cf", "/etc/sudoers")),
}


def validate_command(argv: list[str]) -> tuple[str, list[str]]:
    """(tier, validated args) for an executed program, or Refused."""
    if not argv:
        raise Refused("no command given")
    validator = COMMANDS.get(argv[0])
    if validator is None:
        raise Refused(f"{argv[0]!r} isn't a program Atropa runs as root")
    return validator(list(argv[1:]))


def _write_tier(path: str) -> str:
    normal = _normal(path)
    if normal in ASK_WRITE_FILES or normal.startswith(ASK_WRITE_DIRS) or _is_loader_entry(normal):
        return ASK
    return KEEP


def _file_command_tier(argv: list[str]) -> str:
    program = argv[0]
    if program == "chown":
        return ASK  # only used after the (ask-tier) policy build
    target = None
    if program == "tee":
        rest = [arg for arg in argv[1:] if arg not in {"-a", "--"}]
        target = rest[0] if len(rest) == 1 else None
    elif program == "install" and len(argv) == 5:
        target = argv[4]
    elif program == "replace-in-file" and len(argv) == 4:
        target = argv[1]
    elif program == "backup-restore" and len(argv) == 3:
        target = argv[2]
    if target is None:
        return KEEP  # malformed: the operation itself refuses it
    return _write_tier(target)


def needs_fresh_auth(argv: list[str]) -> bool:
    """
    True when `argv` is an ASK operation, which the keep helper refuses.
    privilege.py asks this to pick the helper; it never raises, so a
    malformed argv goes to the keep helper and is refused there.
    """
    if not argv:
        return False
    try:
        if argv[0] in FILE_COMMANDS or argv[0] in OPERATIONS:
            return _file_command_tier(argv) == ASK
        return validate_command(argv)[0] == ASK
    except Refused:
        return False


# ------------------------------------------------------------ shadow status --


SHADOW = "/etc/shadow"


def _shadow_status(argv: list[str]) -> int:
    """
    `shadow-status`: one `user:empty|locked|set` line per account, never a
    hash. The account-hygiene check only needs to know which password
    fields are empty, and `cat /etc/shadow` would hand every hash to any
    process that can reuse a cached authorization.
    """
    if len(argv) != 1:
        raise Refused("shadow-status takes no arguments")
    with open(SHADOW, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            fields = line.rstrip("\n").split(":")
            if len(fields) < 2 or not fields[0]:
                continue
            field = fields[1]
            status = "empty" if field == "" else "locked" if field.startswith(("!", "*")) else "set"
            print(f"{fields[0]}:{status}")
    return 0


# ---------------------------------------------------- leftover module dirs --


MODULES_ROOT = "/usr/lib/modules"
_RELEASE_RE = re.compile(r"^[0-9][A-Za-z0-9._+-]*$")


def _modules_leftover_remove(argv: list[str]) -> int:
    """
    `modules-leftover-remove RELEASE`: delete /usr/lib/modules/RELEASE when
    an old kernel left it behind - in practice DKMS output in updates/dkms,
    which pacman doesn't remove with the kernel. Refused unless all of:
    not the running kernel, a real directory (no symlink), no pkgbase file
    (no kernel package claims it), no kernel/ tree (so not a kernel
    installed by hand), and no package owns it.
    """
    import shutil
    import subprocess

    if len(argv) != 2 or not _RELEASE_RE.match(argv[1]):
        raise Refused("modules-leftover-remove takes one kernel release")
    release = argv[1]
    if release == os.uname().release:
        raise Refused(f"{release} is the running kernel")
    path = os.path.join(MODULES_ROOT, release)
    if os.path.islink(path) or not os.path.isdir(path) or os.path.realpath(path) != path:
        raise Refused(f"{path} isn't a module directory")
    for name in ("pkgbase", "kernel"):
        if os.path.lexists(os.path.join(path, name)):
            raise Refused(f"{path} has {name}, so it belongs to an installed kernel")
    owner = subprocess.run(
        [_system_binary("pacman"), "-Qqo", path],
        capture_output=True, text=True, env={"PATH": ":".join(SAFE_PATH), "LC_ALL": "C.UTF-8"}, check=False,
    )
    if owner.returncode == 0:
        raise Refused(f"{path} is owned by {owner.stdout.strip()}")
    shutil.rmtree(path)
    return 0


# Operations implemented here that aren't files or programs.
OPERATIONS = frozenset({"shadow-status", "backup-show", "backup-restore", "modules-leftover-remove"})


# ------------------------------------------------------------------ backups --
#
# The helper backs a file up itself, as root, right before it overwrites
# it. Backups used to be copies the app made in ~/.local/share/atropa,
# where anything running as the user could change one and have Restore
# write it back as root. Here the copy is taken from the real file by the
# process doing the write, into storage only root can change:
#
#   /var/lib/atropa/backups/          0755 root
#     manifest.jsonl                  0644 root - names and paths only
#     <name>.<timestamp>.bak          0600 root - the content
#
# The manifest is world-readable so the app can list backups without a
# password; the copies aren't, since some originals are root-only.

BACKUP_STORE = "/var/lib/atropa/backups"
BACKUP_MANIFEST_NAME = "manifest.jsonl"
# One backup per operation, not per write: an operation that edits a file
# in several steps (pacman.conf) would otherwise leave every in-between
# state. A write within this many seconds of the last backup of the same
# file is taken to be part of the same operation.
BACKUP_WINDOW_SECONDS = 60
BACKUP_KEEP_PER_FILE = 30
BACKUP_MAX_BYTES = 1024 * 1024
_BACKUP_NAME_RE = re.compile(r"^[A-Za-z0-9_.@+-]+\.\d{8}_\d{6}_\d{6}(?:-\d+)?\.bak$")


def _backed_up(path: str) -> bool:
    """Files whose overwrite is worth a backup: configuration, not state."""
    return path.startswith(ETC_ROOT.rstrip("/") + "/") or _is_loader_conf(path)


def _manifest_path() -> str:
    return os.path.join(BACKUP_STORE, BACKUP_MANIFEST_NAME)


def _read_manifest() -> list[dict]:
    import json

    try:
        with open(_manifest_path(), encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        return []
    entries = []
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and all(
            isinstance(entry.get(key), str) for key in ("timestamp", "original_path", "backup_file")
        ):
            entries.append(entry)
    return entries


def _write_manifest(entries: list[dict]) -> None:
    import json

    temporary = _manifest_path() + ".new"
    _write(temporary, "".join(json.dumps(entry) + "\n" for entry in entries).encode("utf-8"), mode=0o644)
    os.replace(temporary, _manifest_path())


def _ensure_store() -> None:
    os.makedirs(BACKUP_STORE, mode=0o755, exist_ok=True)
    if os.path.islink(BACKUP_STORE) or not os.path.isdir(BACKUP_STORE):
        raise Refused(f"{BACKUP_STORE} isn't a directory")
    os.chmod(BACKUP_STORE, 0o755)


def backup_before_write(requested: str, target: str, *, force: bool = False) -> str | None:
    """
    Copy `target` (the resolved file about to be overwritten) into the
    store, recorded under `requested` (the path the app asked for, which
    restore writes back through checked_write_path). Returns the backup's
    name, or None when there was nothing to do. Never raises: a full disk
    shouldn't stop a configuration change, and the write happens anyway.
    """
    from datetime import datetime

    try:
        if not _backed_up(target) or os.path.islink(target) or not os.path.isfile(target):
            return None
        if os.path.getsize(target) > BACKUP_MAX_BYTES:
            return None
        _ensure_store()
        entries = _read_manifest()
        now = datetime.now()
        if not force:
            for entry in reversed(entries):
                if entry["original_path"] != requested:
                    continue
                try:
                    made = datetime.strptime(entry["timestamp"], "%Y%m%d_%H%M%S_%f")
                except ValueError:
                    break
                if 0 <= (now - made).total_seconds() < BACKUP_WINDOW_SECONDS:
                    return None
                break
        with open(target, "rb") as handle:
            data = handle.read()
        timestamp = now.strftime("%Y%m%d_%H%M%S_%f")
        base = re.sub(r"[^A-Za-z0-9_.@+-]", "_", os.path.basename(requested)) or "file"
        name = f"{base}.{timestamp}.bak"
        attempt = 0
        while True:
            try:
                fd = os.open(
                    os.path.join(BACKUP_STORE, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                break
            except FileExistsError:
                attempt += 1
                name = f"{base}.{timestamp}-{attempt}.bak"
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        entries.append({"timestamp": timestamp, "original_path": requested, "backup_file": name})

        # Keep the newest BACKUP_KEEP_PER_FILE of each file.
        same = [entry for entry in entries if entry["original_path"] == requested]
        dropped = same[: max(0, len(same) - BACKUP_KEEP_PER_FILE)]
        for entry in dropped:
            if _BACKUP_NAME_RE.match(entry["backup_file"]):
                try:
                    os.unlink(os.path.join(BACKUP_STORE, entry["backup_file"]))
                except FileNotFoundError:
                    pass
        if dropped:
            entries = [entry for entry in entries if entry not in dropped]
        _write_manifest(entries)
        return name
    except (OSError, Refused) as exc:
        print(f"atropa-helper: couldn't back up {requested}: {exc}", file=sys.stderr)
        return None


def _backup_entry(name: str) -> dict:
    if not isinstance(name, str) or not _BACKUP_NAME_RE.match(name):
        raise Refused(f"{name!r} isn't the name of a backup")
    for entry in _read_manifest():
        if entry["backup_file"] == name:
            return entry
    raise Refused(f"there's no backup named {name}")


def _read_backup(name: str) -> bytes:
    path = os.path.join(BACKUP_STORE, name)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        return handle.read()


def _backup_show(argv: list[str]) -> int:
    """
    `backup-show NAME`: print a backup's content - only of a file `cat`
    may read. pacnew-apply backs up whatever /etc file it replaces (a root
    can still restore those by hand), and showing a backup must not read
    more than reading the file itself would.
    """
    if len(argv) != 2:
        raise Refused("backup-show takes one backup name")
    entry = _backup_entry(argv[1])
    _checked_read_path(entry["original_path"])
    sys.stdout.buffer.write(_read_backup(argv[1]))
    sys.stdout.flush()
    return 0


def _backup_restore(argv: list[str]) -> int:
    """
    `backup-restore NAME PATH`: write a backup back where it came from.
    PATH must be the one the manifest recorded - it's in argv so the tier
    (needs_fresh_auth) can be told before anything runs - and the write
    goes through the same policy as any other. The file being replaced is
    backed up first, so a restore can itself be undone.
    """
    if len(argv) != 3:
        raise Refused("backup-restore takes a backup name and its file")
    entry = _backup_entry(argv[1])
    requested = _normal(argv[2])
    if entry["original_path"] != requested:
        raise Refused(f"{argv[1]} is a backup of {entry['original_path']}, not {requested}")
    target = checked_write_path(requested)
    data = _read_backup(argv[1])
    backup_before_write(requested, target, force=True)
    _write(target, data)
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
    backup_before_write(_normal(args[0]), target)
    _write(target, data, append=append)
    return 0


def _install(argv: list[str], data: bytes) -> int:
    # The only install invocation Atropa uses: install -m MODE /dev/stdin FILE
    if len(argv) != 5 or argv[1] != "-m" or argv[3] != "/dev/stdin":
        raise Refused("install must be `install -m MODE /dev/stdin FILE`")
    if not _MODE_RE.match(argv[2]):
        raise Refused(f"install mode {argv[2]!r} isn't a file mode")
    target = checked_write_path(argv[4])
    backup_before_write(_normal(argv[4]), target)
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
    if updated != text:
        backup_before_write(_normal(argv[1]), target)
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


def handle(argv: list[str], data: bytes = b"", *, tier: str) -> int | None:
    """
    Perform an allowed file operation (returning its exit code), or return
    None when argv should be exec'd as a validated command. `tier` is the
    tier of the running helper; an ASK operation in the keep helper is
    refused before anything is touched.
    """
    if not argv:
        raise Refused("no command given")
    program = argv[0]
    if tier != ASK and needs_fresh_auth(argv):
        raise Refused(f"{program} asks for a password every time; it runs through {ASK_HELPER_PATH}")
    if program == "shadow-status":
        return _shadow_status(argv)
    if program == "backup-show":
        return _backup_show(argv)
    if program == "backup-restore":
        return _backup_restore(argv)
    if program == "modules-leftover-remove":
        return _modules_leftover_remove(argv)

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

    validate_command(argv)  # refuse here too, so handle() alone decides
    return None  # a validated command: main() execs it


def running_tier(script: str | None = None) -> str:
    """ASK when this process is the installed ask helper, KEEP otherwise."""
    path = os.path.realpath(script if script is not None else sys.argv[0])
    return ASK if path == os.path.realpath(ASK_HELPER_PATH) else KEEP


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    tier = running_tier()

    # pkexec makes the child root; running this directly as a user must not
    # do anything, even if it somehow has a setuid bit it shouldn't.
    if os.geteuid() != 0:
        print("atropa-helper must be run through pkexec", file=sys.stderr)
        return 126

    data = b""
    if args and args[0] in {"tee", "install"}:
        data = sys.stdin.buffer.read()

    try:
        handled = handle(args, data, tier=tier)
    except Refused as exc:
        print(f"atropa-helper: refused: {exc}", file=sys.stderr)
        return 126

    if handled is not None:
        return handled

    try:
        validated = check(args)
    except Refused as exc:
        print(f"atropa-helper: refused: {exc}", file=sys.stderr)
        return 126
    return _exec(validated[0], validated)


if __name__ == "__main__":
    sys.exit(main())
