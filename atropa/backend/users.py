"""
atropa.backend.users
------------------------
Wraps useradd/usermod/userdel/groupadd/passwd for the Users & Groups module.
Reads /etc/passwd and /etc/group directly since that's unprivileged and
always accurate; writes go through privileged commands.
"""

from __future__ import annotations

import grp
import os
import pwd
from dataclasses import dataclass, field

from .privilege import CommandResult, run_privileged

# Arch's minimum UID for "real" (non-system) users, per /etc/login.defs default
DEFAULT_MIN_UID = 1000

# polkit's administrator group on Arch (/usr/share/polkit-1/rules.d/50-default.rules):
# Atropa's password prompts accept a member's password. With nobody in it,
# polkit falls back to asking for root's.
ADMIN_GROUP = "wheel"


@dataclass
class UserAccount:
    username: str
    uid: int
    gid: int
    full_name: str
    home: str
    shell: str
    groups: list[str] = field(default_factory=list)


@dataclass
class Group:
    name: str
    gid: int
    members: list[str] = field(default_factory=list)


def list_users(include_system: bool = False) -> list[UserAccount]:
    users = []
    for entry in pwd.getpwall():
        if not include_system and entry.pw_uid < DEFAULT_MIN_UID and entry.pw_uid != 0:
            continue
        member_groups = [g.gr_name for g in grp.getgrall() if entry.pw_name in g.gr_mem]
        users.append(
            UserAccount(
                username=entry.pw_name,
                uid=entry.pw_uid,
                gid=entry.pw_gid,
                full_name=entry.pw_gecos.split(",")[0],
                home=entry.pw_dir,
                shell=entry.pw_shell,
                groups=member_groups,
            )
        )
    return sorted(users, key=lambda u: u.uid)


def list_groups(include_system: bool = False) -> list[Group]:
    groups = []
    for entry in grp.getgrall():
        if not include_system and entry.gr_gid < DEFAULT_MIN_UID and entry.gr_gid != 0:
            continue
        groups.append(Group(name=entry.gr_name, gid=entry.gr_gid, members=list(entry.gr_mem)))
    return sorted(groups, key=lambda g: g.gid)


def create_user(
    username: str,
    full_name: str = "",
    shell: str = "/bin/bash",
    create_home: bool = True,
    extra_groups: list[str] | None = None,
) -> CommandResult:
    argv = ["useradd", "-m" if create_home else "-M", "-s", shell]
    if full_name:
        argv += ["-c", full_name]
    if extra_groups:
        argv += ["-G", ",".join(extra_groups)]
    argv.append(username)
    return run_privileged(argv)


def set_password(username: str, password: str) -> CommandResult:
    """Sets a user's password via chpasswd, fed through stdin (never argv)."""
    return run_privileged(["chpasswd"], input_text=f"{username}:{password}\n")


def modify_user(
    username: str,
    full_name: str | None = None,
    shell: str | None = None,
    extra_groups: list[str] | None = None,
    lock: bool | None = None,
) -> CommandResult:
    argv = ["usermod"]
    if full_name is not None:
        argv += ["-c", full_name]
    if shell is not None:
        argv += ["-s", shell]
    if extra_groups is not None:
        argv += ["-G", ",".join(extra_groups)]
    if lock is True:
        argv.append("-L")
    elif lock is False:
        argv.append("-U")
    argv.append(username)
    return run_privileged(argv)


def _admin_usernames() -> set[str]:
    for group in grp.getgrall():
        if group.gr_name == ADMIN_GROUP:
            names = set(group.gr_mem)
            names.update(entry.pw_name for entry in pwd.getpwall() if entry.pw_gid == group.gr_gid)
            return names
    return set()


def _uid_of(username: str) -> int | None:
    return next((entry.pw_uid for entry in pwd.getpwall() if entry.pw_name == username), None)


def lock_refusal(username: str) -> str | None:
    """
    Why Atropa won't lock `username`'s password, or None. Both cases take
    away the only password that can answer Atropa's prompts - including
    the one needed to unlock it again - so there'd be no way back short
    of a rescue boot.
    """
    uid = _uid_of(username)
    if uid == os.getuid():
        return (
            "This is the account you're signed in with - locking it would disable the password "
            "Atropa's prompts need, including the one to unlock it again."
        )
    if uid == 0 and not _admin_usernames():
        return (
            f"Nobody is in the {ADMIN_GROUP} group, so password prompts ask for root's password - "
            "locking it would leave no way to run privileged actions."
        )
    return None


def lock_warning(username: str) -> str:
    """What else locking `username` breaks, beyond that user's own logins ("" if nothing)."""
    admins = _admin_usernames()
    if username in admins and not admins - {username}:
        return (
            f"{username} is the only member of the {ADMIN_GROUP} group, so Atropa's password prompts "
            "(and pkexec's) would ask for a password that no longer works."
        )
    if username in admins:
        return f"{username} is an administrator ({ADMIN_GROUP} group) and can no longer answer password prompts."
    return ""


def delete_refusal(username: str) -> str | None:
    """Why Atropa won't delete `username`, or None."""
    uid = _uid_of(username)
    if uid == os.getuid():
        return "This is the account you're signed in with."
    if uid == 0:
        return "The root account can't be deleted."
    return None


def delete_user(username: str, remove_home: bool = False) -> CommandResult:
    argv = ["userdel"]
    if remove_home:
        argv.append("-r")
    argv.append(username)
    return run_privileged(argv)


def create_group(name: str) -> CommandResult:
    return run_privileged(["groupadd", name])


def delete_group(name: str) -> CommandResult:
    return run_privileged(["groupdel", name])
