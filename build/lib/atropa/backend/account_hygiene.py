"""
atropa.backend.account_hygiene
------------------------------
CIS-DIL-inspired file/account hygiene scanning (CIS 6.1 "System File
Permissions" + 6.2 "User and Group Settings") - read-only findings, no
auto-fix. Unlike Phase 1's sysctl/pwquality settings, several of these
(a stray UID-0 account, an unexpected home directory owner) are exactly
the kind of thing that needs a human to look at *why* before anything
touches it - so this module only ever reports, it never changes anything.

/etc/shadow's password-hash field requires a privileged read (it's
root:root 0600, correctly - this module doesn't relax that, it just reads
it once via pkexec to check for a genuinely empty field, and never stores
or displays the hash itself).

"Root PATH integrity" (CIS 6.2.x) is checked against what's actually
findable in root's own profile files (/root/.bash_profile, /root/.bashrc)
plus /etc/profile, rather than pkexec's own sanitized environment - pkexec
sets a fixed secure PATH for the command it runs, which would make this
check trivially pass regardless of what root's real interactive shell
PATH looks like. Reading the profile files directly is a genuine, if
imperfect, proxy: a "." or empty PATH component, or a world-writable
directory, in any PATH= line in those files is the actual finding CIS
cares about (a later program in the search path could be silently
shadowed by something planted in a writable/relative directory).
"""

from __future__ import annotations

import grp
import pwd
import stat
from dataclasses import dataclass
from pathlib import Path

from .privilege import run_privileged

# CIS's default boundary between "system" and "real"/interactive accounts.
MIN_INTERACTIVE_UID = 1000

# (path, expected max mode, description) - "expected max" because a stricter
# mode (e.g. 000 instead of 600) is fine, only "looser than this" is a finding.
_FILE_PERM_CHECKS: list[tuple[str, int, str]] = [
    ("/etc/passwd", 0o644, "world-readable is normal (no secrets in it), but must not be group/world-writable"),
    ("/etc/group", 0o644, "world-readable is normal, but must not be group/world-writable"),
    ("/etc/shadow", 0o600, "holds password hashes - must not be group/world-readable"),
    ("/etc/gshadow", 0o600, "holds group password hashes - must not be group/world-readable"),
]

_ROOT_PROFILE_FILES = ["/root/.bash_profile", "/root/.bashrc", "/etc/profile"]


@dataclass
class HygieneFinding:
    key: str
    title: str
    status: str  # "pass" | "warn" | "fail" | "info"
    detail: str


def _check_file_perms() -> list[HygieneFinding]:
    findings = []
    for path_str, max_mode, note in _FILE_PERM_CHECKS:
        path = Path(path_str)
        key = f"perms-{path.name}"
        if not path.exists():
            findings.append(HygieneFinding(key, f"{path} permissions", "info", "File doesn't exist on this system"))
            continue
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except PermissionError:
            findings.append(HygieneFinding(key, f"{path} permissions", "info", "Couldn't read (permission denied)"))
            continue
        if mode & ~max_mode:
            findings.append(
                HygieneFinding(
                    key, f"{path} permissions", "fail",
                    f"Mode {oct(mode)} is looser than expected {oct(max_mode)} - {note}",
                )
            )
        else:
            findings.append(HygieneFinding(key, f"{path} permissions", "pass", f"Mode {oct(mode)}"))
    return findings


def _check_duplicates() -> list[HygieneFinding]:
    findings = []

    uids = [e.pw_uid for e in pwd.getpwall()]
    dup_uids = sorted({u for u in uids if uids.count(u) > 1})
    findings.append(
        HygieneFinding(
            "dup-uid", "Duplicate UIDs", "fail" if dup_uids else "pass",
            f"Shared by multiple accounts: {dup_uids}" if dup_uids else "No UID is shared by more than one account",
        )
    )

    names = [e.pw_name for e in pwd.getpwall()]
    dup_names = sorted({n for n in names if names.count(n) > 1})
    findings.append(
        HygieneFinding(
            "dup-username", "Duplicate usernames", "fail" if dup_names else "pass",
            f"Appears more than once in /etc/passwd: {dup_names}" if dup_names else "No duplicate usernames",
        )
    )

    gids = [e.gr_gid for e in grp.getgrall()]
    dup_gids = sorted({g for g in gids if gids.count(g) > 1})
    findings.append(
        HygieneFinding(
            "dup-gid", "Duplicate GIDs", "fail" if dup_gids else "pass",
            f"Shared by multiple groups: {dup_gids}" if dup_gids else "No GID is shared by more than one group",
        )
    )

    gnames = [e.gr_name for e in grp.getgrall()]
    dup_gnames = sorted({n for n in gnames if gnames.count(n) > 1})
    findings.append(
        HygieneFinding(
            "dup-groupname", "Duplicate group names", "fail" if dup_gnames else "pass",
            f"Appears more than once in /etc/group: {dup_gnames}" if dup_gnames else "No duplicate group names",
        )
    )

    return findings


def _check_uid_zero() -> HygieneFinding:
    extra_root = sorted(e.pw_name for e in pwd.getpwall() if e.pw_uid == 0 and e.pw_name != "root")
    if extra_root:
        return HygieneFinding(
            "uid-zero", "Accounts with UID 0", "fail",
            f"Only 'root' should have UID 0 - also found: {extra_root}",
        )
    return HygieneFinding("uid-zero", "Accounts with UID 0", "pass", "Only 'root' has UID 0")


def _check_system_account_shells() -> HygieneFinding:
    """System/service accounts (UID < 1000, excluding root) shouldn't have an interactive login shell."""
    nologin_shells = {"/usr/bin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""}
    offenders = sorted(
        e.pw_name
        for e in pwd.getpwall()
        if e.pw_uid != 0 and e.pw_uid < MIN_INTERACTIVE_UID and e.pw_shell not in nologin_shells
    )
    if offenders:
        return HygieneFinding(
            "system-shells", "System accounts with a login shell", "warn",
            f"Service/system accounts that can normally log in: {offenders}",
        )
    return HygieneFinding(
        "system-shells", "System accounts with a login shell", "pass",
        "Every system account (UID < 1000, excluding root) uses a non-login shell",
    )


def _check_home_directories() -> list[HygieneFinding]:
    findings = []
    for entry in pwd.getpwall():
        if entry.pw_uid < MIN_INTERACTIVE_UID or entry.pw_name == "nobody":
            continue
        key = f"home-{entry.pw_name}"
        title = f"Home directory for {entry.pw_name}"
        home = Path(entry.pw_dir)
        if not home.exists():
            findings.append(HygieneFinding(key, title, "fail", f"{home} does not exist"))
            continue
        try:
            st = home.stat()
        except PermissionError:
            findings.append(HygieneFinding(key, title, "info", f"{home} exists but couldn't be stat'd"))
            continue
        if st.st_uid != entry.pw_uid:
            findings.append(
                HygieneFinding(key, title, "fail", f"{home} is owned by UID {st.st_uid}, not {entry.pw_name}'s UID {entry.pw_uid}")
            )
            continue
        mode = stat.S_IMODE(st.st_mode)
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            findings.append(HygieneFinding(key, title, "warn", f"{home} is group/other-writable (mode {oct(mode)})"))
        else:
            findings.append(HygieneFinding(key, title, "pass", f"{home} exists, correctly owned, mode {oct(mode)}"))
    return findings


def _check_empty_passwords() -> HygieneFinding:
    """Requires a privileged read of /etc/shadow - never stores or surfaces the hash itself, only field emptiness."""
    result = run_privileged(["cat", "/etc/shadow"])
    if not result.ok:
        return HygieneFinding("empty-password", "Empty password fields", "info", "Couldn't read /etc/shadow")

    empty = []
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if len(fields) > 1 and fields[1] == "":
            empty.append(fields[0])

    if empty:
        return HygieneFinding("empty-password", "Empty password fields", "fail", f"Accounts with no password set: {empty}")
    return HygieneFinding("empty-password", "Empty password fields", "pass", "No account has an empty password field")


def _check_root_path() -> HygieneFinding:
    lines: list[str] = []

    # /root/.bash_profile and /root/.bashrc both need a privileged read (root-
    # owned, mode 600) - combined into one pkexec call rather than one per
    # file. Two separate privileged reads meant two separate authentication
    # prompts for what's conceptually a single check; cat concatenating both
    # files' output is fine here since this function only ever scans the
    # combined lines for "PATH=" content, never needs to know which file a
    # given line came from.
    root_owned = [p for p in _ROOT_PROFILE_FILES if p.startswith("/root/")]
    if root_owned:
        result = run_privileged(["cat", *root_owned])
        if result.ok:
            lines.extend(result.stdout.splitlines())

    for path_str in _ROOT_PROFILE_FILES:
        if path_str.startswith("/root/"):
            continue
        path = Path(path_str)
        if path.exists():
            try:
                lines.extend(path.read_text(encoding="utf-8", errors="replace").splitlines())
            except PermissionError:
                pass

    path_assignments = [line.strip() for line in lines if "PATH=" in line and not line.strip().startswith("#")]
    if not path_assignments:
        return HygieneFinding(
            "root-path", "Root PATH integrity", "info",
            "No PATH= assignment found in /root/.bash_profile, /root/.bashrc, or /etc/profile",
        )

    problems = []
    for assignment in path_assignments:
        value = assignment.split("PATH=", 1)[1].split()[0].strip("\"'")
        components = value.split(":")
        if "" in components:
            problems.append(f"{assignment!r} contains an empty (current-directory) component")
        if "." in components:
            problems.append(f"{assignment!r} explicitly includes '.'")
        for component in components:
            if not component or component == ".":
                continue
            p = Path(component)
            if p.is_dir():
                mode = stat.S_IMODE(p.stat().st_mode)
                if mode & stat.S_IWOTH:
                    problems.append(f"{component} (from {assignment!r}) is world-writable")

    if problems:
        return HygieneFinding("root-path", "Root PATH integrity", "fail", "; ".join(problems))
    return HygieneFinding("root-path", "Root PATH integrity", "pass", f"Checked {len(path_assignments)} PATH assignment(s), nothing risky found")


def scan_all() -> list[HygieneFinding]:
    findings: list[HygieneFinding] = []
    findings.extend(_check_file_perms())
    findings.extend(_check_duplicates())
    findings.append(_check_uid_zero())
    findings.append(_check_system_account_shells())
    findings.extend(_check_home_directories())
    findings.append(_check_empty_passwords())
    findings.append(_check_root_path())
    return findings
