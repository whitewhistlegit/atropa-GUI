"""
atropa.backend.security
----------------------------
Firewall (ufw or firewalld, whichever is installed), basic SSH hardening
toggles, and a sudoers sanity check. Deliberately conservative: it edits
well-known, single-purpose settings rather than freeform config files.
"""

from __future__ import annotations

import glob
import os
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .privilege import CommandResult, backup_file, run_privileged, run_unprivileged

SSHD_CONFIG = Path("/etc/ssh/sshd_config")


@dataclass
class FirewallStatus:
    backend: str  # "ufw", "firewalld", "none"
    active: bool
    rules: list[str] = field(default_factory=list)


@dataclass
class SshStatus:
    installed: bool
    running: bool
    port: str = "22"
    root_login: str = "unknown"
    password_auth: str = "unknown"
    log_level: str = "unknown"
    x11_forwarding: str = "unknown"
    max_auth_tries: str = "unknown"
    ignore_rhosts: str = "unknown"
    hostbased_authentication: str = "unknown"
    permit_empty_passwords: str = "unknown"
    permit_user_environment: str = "unknown"
    # `port` falls back to "22" for display when sshd_config has no Port
    # line; this says whether that value was actually configured, so a
    # profile export doesn't record the default as if it were a setting.
    port_explicit: bool = False
    # Every port sshd listens on per its config (Port lines are cumulative,
    # unlike other keywords; ListenAddress host:port adds more). Empty means
    # nothing is configured and sshd uses 22.
    ports: list[str] = field(default_factory=list)
    # Included files that exist but couldn't be read - their settings could
    # override anything reported above, so callers shouldn't call it a pass.
    unreadable_includes: list[str] = field(default_factory=list)

    def effective(self, name: str) -> str:
        """The value sshd actually uses: what's configured, else OpenSSH's own default."""
        value = getattr(self, name)
        return SSHD_DEFAULTS.get(name, value) if value == "unknown" else value


# Every value sshd accepts for PermitRootLogin ("without-password" is the
# deprecated spelling of "prohibit-password").
SSH_PERMIT_ROOT_LOGIN_VALUES = ("yes", "no", "prohibit-password", "without-password", "forced-commands-only")

# sshd_config keyword (lowercase - keywords are case-insensitive) -> SshStatus field.
_SSHD_FIELDS = {
    "permitrootlogin": "root_login",
    "passwordauthentication": "password_auth",
    "loglevel": "log_level",
    "x11forwarding": "x11_forwarding",
    "maxauthtries": "max_auth_tries",
    "ignorerhosts": "ignore_rhosts",
    "hostbasedauthentication": "hostbased_authentication",
    "permitemptypasswords": "permit_empty_passwords",
    "permituserenvironment": "permit_user_environment",
}

# OpenSSH's compiled-in defaults (sshd_config(5)) for the fields above -
# what applies when sshd_config never sets the keyword.
SSHD_DEFAULTS = {
    "root_login": "prohibit-password",
    "password_auth": "yes",
    "log_level": "INFO",
    "x11_forwarding": "no",
    "max_auth_tries": "6",
    "ignore_rhosts": "yes",
    "hostbased_authentication": "no",
    "permit_empty_passwords": "no",
    "permit_user_environment": "no",
}


def firewall_backend() -> str:
    if shutil.which("ufw"):
        return "ufw"
    if shutil.which("firewall-cmd"):
        return "firewalld"
    return "none"


def firewall_status() -> FirewallStatus:
    """
    Both `ufw status` and `firewall-cmd --list-all` genuinely require root
    on a normal install - without it they don't error loudly, they just
    return limited/empty output, which used to read as "inactive, no
    rules" even when the firewall was actually on. Confirmed on real
    hardware: previously used run_unprivileged() here, which silently
    showed the toggle as off and the rules list as empty regardless of
    the real state. `systemctl is-active firewalld` is the one read here
    that genuinely doesn't need root, so it stays unprivileged.
    """
    backend = firewall_backend()
    if backend == "ufw":
        result = run_privileged(["ufw", "status", "verbose"])
        active = "Status: active" in result.stdout
        rules = [l for l in result.stdout.splitlines() if l.strip() and not l.startswith("Status")]
        return FirewallStatus(backend="ufw", active=active, rules=rules)
    if backend == "firewalld":
        active_result = run_unprivileged(["systemctl", "is-active", "firewalld"])
        active = active_result.stdout.strip() == "active"
        rules_result = run_privileged(["firewall-cmd", "--list-all"])
        rules = rules_result.stdout.strip().splitlines()
        return FirewallStatus(backend="firewalld", active=active, rules=rules)
    return FirewallStatus(backend="none", active=False)


def firewall_enable() -> CommandResult:
    backend = firewall_backend()
    if backend == "ufw":
        return run_privileged(["ufw", "--force", "enable"])
    if backend == "firewalld":
        return run_privileged(["systemctl", "enable", "--now", "firewalld"])
    raise RuntimeError("No firewall backend installed (install 'ufw' or 'firewalld')")


def firewall_disable() -> CommandResult:
    backend = firewall_backend()
    if backend == "ufw":
        return run_privileged(["ufw", "disable"])
    if backend == "firewalld":
        return run_privileged(["systemctl", "disable", "--now", "firewalld"])
    raise RuntimeError("No firewall backend installed")


def _firewalld_change_port(flag: str, port: str, protocol: str) -> CommandResult:
    """
    Applies a permanent firewalld port change (`flag` is "--add-port" or
    "--remove-port"). firewall-cmd talks to the running daemon and fails
    outright ("FirewallD is not running") when it's stopped - which is
    exactly the state Quick Setup is in when it pre-allows SSH before
    enabling the firewall for the first time. A stopped firewalld gets the
    same change via firewall-offline-cmd instead, which edits the permanent
    config directly and is picked up when the daemon starts.
    """
    spec = f"{port}/{protocol}"
    if run_unprivileged(["systemctl", "is-active", "firewalld"]).stdout.strip() != "active":
        return run_privileged(["firewall-offline-cmd", f"{flag}={spec}"])

    result = run_privileged(["firewall-cmd", "--permanent", flag, spec])
    if not result.ok:
        return result
    # The permanent rule is written either way, but the running firewall
    # doesn't have it until a reload succeeds - report that as the failure
    # rather than a success that isn't in effect yet.
    reload_result = run_privileged(["firewall-cmd", "--reload"])
    return result if reload_result.ok else reload_result


def firewall_allow_port(port: str, protocol: str = "tcp") -> CommandResult:
    backend = firewall_backend()
    if backend == "ufw":
        return run_privileged(["ufw", "allow", f"{port}/{protocol}"])
    if backend == "firewalld":
        return _firewalld_change_port("--add-port", port, protocol)
    raise RuntimeError("No firewall backend installed")


def firewall_deny_port(port: str, protocol: str = "tcp") -> CommandResult:
    backend = firewall_backend()
    if backend == "ufw":
        return run_privileged(["ufw", "deny", f"{port}/{protocol}"])
    if backend == "firewalld":
        return _firewalld_change_port("--remove-port", port, protocol)
    raise RuntimeError("No firewall backend installed")


# ------------------------------------------------------------ sshd_config --
#
# sshd's own parsing rules, which both reading and editing have to follow:
#  - the FIRST value read for a keyword wins (Port and ListenAddress are the
#    exceptions: they accumulate);
#  - `Include` pulls files in at that point (relative paths are under
#    /etc/ssh, globs in lexical order);
#  - after a `Match` line nothing applies globally until a `Match all`, and a
#    Match inside an included file ends with that file.
# Reading only the main file and letting the last line win reported settings
# sshd wasn't using; editing with a replace-every-line sed (Match blocks
# included) or an append at the end of the file (inside whatever Match block
# came last) could leave the real setting unchanged while reporting success.

_MAX_INCLUDE_DEPTH = 16  # sshd's own limit


def _split_directive(line: str) -> tuple[str, str]:
    """('keyword' lowercased, 'value') for one non-comment sshd_config line.
    Keyword and value may be separated by whitespace or a single '='; a
    trailing '#' comment is dropped."""
    parts = re.split(r"\s*=\s*|\s+", line.strip(), maxsplit=1)
    keyword = parts[0].lower()
    tokens = parts[1].split() if len(parts) > 1 else []
    for i, token in enumerate(tokens):
        if token.startswith("#"):
            tokens = tokens[:i]
            break
    return keyword, " ".join(tokens).strip('"')


def _include_paths(value: str) -> list[Path]:
    paths: list[Path] = []
    for pattern in value.split():
        full = pattern if os.path.isabs(pattern) else str(SSHD_CONFIG.parent / pattern)
        paths.extend(Path(p) for p in sorted(glob.glob(full)))
    return paths


def _sshd_global_directives(path: Path, unreadable: list[str], depth: int = 0) -> list[tuple[str, str]]:
    """Every (keyword, value) sshd applies globally from `path`, in the order it reads them."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        unreadable.append(str(path))
        return []

    directives: list[tuple[str, str]] = []
    active = True
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        keyword, value = _split_directive(line)
        if keyword == "match":
            active = value.lower() == "all"
        elif not active:
            continue
        elif keyword == "include":
            if depth < _MAX_INCLUDE_DEPTH:
                for included in _include_paths(value):
                    directives += _sshd_global_directives(included, unreadable, depth + 1)
        else:
            directives.append((keyword, value))
    return directives


def _listen_ports(directives: list[tuple[str, str]]) -> list[str]:
    ports = [value for keyword, value in directives if keyword == "port"]
    for keyword, value in directives:
        if keyword == "listenaddress":
            # host:port or [v6addr]:port; a bare address uses the Port lines
            m = re.match(r"^(?:\[[^\]]+\]|[^:\s]+):(\d+)", value)
            if m:
                ports.append(m.group(1))
    return list(dict.fromkeys(ports))


def ssh_status() -> SshStatus:
    installed = shutil.which("sshd") is not None
    running_result = run_unprivileged(["systemctl", "is-active", "sshd"])
    running = running_result.stdout.strip() == "active"

    fields = dict.fromkeys(_SSHD_FIELDS.values(), "unknown")
    unreadable: list[str] = []
    directives = _sshd_global_directives(SSHD_CONFIG, unreadable) if SSHD_CONFIG.exists() else []
    for keyword, value in directives:
        name = _SSHD_FIELDS.get(keyword)
        if name and fields[name] == "unknown":  # first value wins
            fields[name] = value

    configured_ports = [value for keyword, value in directives if keyword == "port"]
    return SshStatus(
        installed=installed,
        running=running,
        port=configured_ports[0] if configured_ports else "22",
        port_explicit=bool(configured_ports),
        ports=_listen_ports(directives),
        unreadable_includes=unreadable,
        **fields,
    )


def _include_sets(value: str, keyword: str) -> bool:
    """Whether the files an `Include` line pulls in set `keyword` globally -
    or might: an unreadable included file counts as yes."""
    unreadable: list[str] = []
    found = False
    for included in _include_paths(value):
        found = found or any(k == keyword for k, _v in _sshd_global_directives(included, unreadable, 1))
    return found or bool(unreadable)


def _edit_sshd_global_option(
    text: str, key: str, value: str, include_sets: Callable[[str, str], bool] = _include_sets
) -> str:
    """
    Returns sshd_config `text` with `key value` as the value sshd reads
    first for `key`. Only the global section is edited - lines inside Match
    blocks are never touched. In order of preference: the first active
    global line for `key` is replaced in place; or a commented-out
    `#Key ...` template in the global section is uncommented; or the line
    is inserted before the first Include/Match (so it's read first) or at
    the end. If an Include earlier than the existing line could set `key`,
    the line goes above that Include instead. Later global lines for `key`
    (dead once ours wins) are set to the same value so the file doesn't
    read as if they applied.
    """
    key_lower = key.lower()
    new_line = f"{key} {value}"
    lines = text.splitlines()

    active = True
    occurrences: list[int] = []
    template_index: int | None = None
    first_boundary: int | None = None  # first Include or Match line
    blocking_include: int | None = None
    includes: list[str] = []
    for i, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            body = line.lstrip("#").strip()
            if active and template_index is None and body and _split_directive(body)[0] == key_lower:
                template_index = i
            continue
        keyword, rest = _split_directive(line)
        if keyword == "match":
            first_boundary = i if first_boundary is None else first_boundary
            active = rest.lower() == "all"
        elif not active:
            continue
        elif keyword == "include":
            first_boundary = i if first_boundary is None else first_boundary
            includes.append(rest)
            if not occurrences and blocking_include is None and include_sets(rest, key_lower):
                blocking_include = i
        elif keyword == key_lower:
            occurrences.append(i)

    if key_lower == "port":
        # Port lines accumulate rather than override - "setting the port"
        # can't be done safely by adding or rewriting one of several.
        if len(occurrences) > 1 or any(include_sets(rest, "port") for rest in includes):
            raise ValueError(
                "sshd listens on Port settings from several lines (or an included file) - "
                "change them in sshd_config by hand"
            )

    def indent_of(index: int) -> str:
        return lines[index][: len(lines[index]) - len(lines[index].lstrip())]

    if occurrences and blocking_include is None:
        targets = occurrences
    else:
        targets = occurrences[:]  # dead copies after the Include, kept consistent
        if blocking_include is not None:
            lines.insert(blocking_include, new_line)
            targets = [i + 1 for i in targets]
        elif template_index is not None:
            lines[template_index] = indent_of(template_index) + new_line
        elif first_boundary is not None:
            lines.insert(first_boundary, new_line)
        else:
            lines.append(new_line)
    for i in targets:
        lines[i] = indent_of(i) + new_line
    return "\n".join(lines) + "\n"


def _read_sshd_config() -> str:
    try:
        return SSHD_CONFIG.read_text(encoding="utf-8")
    except PermissionError:
        result = run_privileged(["cat", str(SSHD_CONFIG)])
        if not result.ok:
            raise RuntimeError(f"Couldn't read {SSHD_CONFIG}: {result.stderr.strip()}") from None
        return result.stdout


def _set_sshd_option(key: str, value: str) -> CommandResult:
    """
    Sets `key value` so it's the value sshd actually uses (see the rules
    above), written back in one privileged step. The file is backed up
    first and the result validated with `sshd -t` BEFORE anything is
    reloaded - a bad config can lock out remote access. If validation
    fails, the original content (kept in memory, so this doesn't depend on
    the backup) is written back and sshd is never reloaded; the error says
    plainly if even that failed.
    """
    if not SSHD_CONFIG.exists():
        raise RuntimeError(f"{SSHD_CONFIG} doesn't exist - is OpenSSH installed?")
    original = _read_sshd_config()
    updated = _edit_sshd_global_option(original, key, value)
    if updated == original:
        return CommandResult(0, f"{key} is already {value}", "")

    backup_file(str(SSHD_CONFIG))
    write_result = run_privileged(["tee", str(SSHD_CONFIG)], input_text=updated)
    if not write_result.ok:
        return write_result

    test_result = run_privileged(["sshd", "-t"])
    if not test_result.ok:
        problem = test_result.stderr.strip() or f"sshd -t exited with {test_result.returncode}"
        restore_result = run_privileged(["tee", str(SSHD_CONFIG)], input_text=original)
        if restore_result.ok:
            raise RuntimeError(
                f"New sshd_config failed validation (sshd -t): {problem}. "
                "Restored the previous config; sshd was NOT reloaded."
            )
        raise RuntimeError(
            f"New sshd_config failed validation (sshd -t): {problem}. Restoring the previous config "
            f"ALSO failed ({restore_result.stderr.strip() or 'unknown error'}), so {SSHD_CONFIG} still "
            "contains the rejected change - sshd was NOT reloaded, but fix the file (a backup is under "
            "Activity & Backups) before sshd restarts."
        )

    # try-reload-or-restart: reloads a running sshd, and is a no-op (not an
    # error, unlike `reload`) when sshd isn't running - the new config then
    # simply applies whenever it starts.
    return run_privileged(["systemctl", "try-reload-or-restart", "sshd"])


def set_ssh_root_login(allow: bool) -> CommandResult:
    return set_ssh_permit_root_login("yes" if allow else "no")


def set_ssh_permit_root_login(value: str) -> CommandResult:
    """
    Sets PermitRootLogin to an exact value, for replaying a captured
    profile faithfully - "prohibit-password" (key-only root login) is a
    meaningfully different setting from "no", not a variant of it. Only
    the fixed set of values sshd accepts ever reaches the config file: the
    value comes from a profile file that may have been hand-edited or
    shared, and it's interpolated into a sed expression below.
    """
    normalized = value.strip().lower()
    if normalized not in SSH_PERMIT_ROOT_LOGIN_VALUES:
        raise ValueError(f"Unsupported PermitRootLogin value: {value!r}")
    return _set_sshd_option("PermitRootLogin", normalized)


def set_ssh_password_auth(allow: bool) -> CommandResult:
    return _set_sshd_option("PasswordAuthentication", "yes" if allow else "no")


def set_ssh_port(port: int) -> CommandResult:
    return _set_sshd_option("Port", str(port))


def set_ssh_log_level(level: str) -> CommandResult:
    """CIS 5.2.5: INFO or VERBOSE - either logs enough to investigate an
    incident; sshd's own default (INFO) already satisfies this, but some
    installs get talked down to QUIET/ERROR/FATAL, which lose that."""
    if level not in ("INFO", "VERBOSE"):
        raise ValueError("SSH LogLevel must be INFO or VERBOSE")
    return _set_sshd_option("LogLevel", level)


def set_ssh_x11_forwarding(allow: bool) -> CommandResult:
    return _set_sshd_option("X11Forwarding", "yes" if allow else "no")


def set_ssh_max_auth_tries(count: int) -> CommandResult:
    """CIS 5.2.7: 4 or fewer - raises the cost of an online brute-force
    guessing attempt against this specific SSH daemon."""
    if count < 1:
        raise ValueError("MaxAuthTries must be at least 1")
    return _set_sshd_option("MaxAuthTries", str(count))


def set_ssh_ignore_rhosts(enabled: bool) -> CommandResult:
    return _set_sshd_option("IgnoreRhosts", "yes" if enabled else "no")


def set_ssh_hostbased_authentication(allow: bool) -> CommandResult:
    return _set_sshd_option("HostbasedAuthentication", "yes" if allow else "no")


def set_ssh_permit_empty_passwords(allow: bool) -> CommandResult:
    return _set_sshd_option("PermitEmptyPasswords", "yes" if allow else "no")


def set_ssh_permit_user_environment(allow: bool) -> CommandResult:
    return _set_sshd_option("PermitUserEnvironment", "yes" if allow else "no")


def sudoers_check() -> CommandResult:
    """
    Runs visudo's syntax checker (read-only) against /etc/sudoers and the
    files it includes. Needs root: sudoers is root-only (0440) on Arch, and
    an unprivileged visudo can only print "unable to open /etc/sudoers:
    Permission denied" - which is what this used to report as the result.
    Callers should go by .ok (visudo's exit status), not the output text.
    """
    return run_privileged(["visudo", "-cf", "/etc/sudoers"])
