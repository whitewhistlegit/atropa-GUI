"""
atropa.backend.users
------------------------
Wraps useradd/usermod/userdel/groupadd/passwd for the Users & Groups module.
Reads /etc/passwd and /etc/group directly since that's unprivileged and
always accurate; writes go through privileged commands.
"""

from __future__ import annotations

import grp
import pwd
from dataclasses import dataclass, field

from .privilege import CommandResult, run_privileged

# Arch's minimum UID for "real" (non-system) users, per /etc/login.defs default
DEFAULT_MIN_UID = 1000


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
