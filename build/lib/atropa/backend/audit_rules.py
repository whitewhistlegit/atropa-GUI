"""
atropa.backend.audit_rules
------------------------------
CIS-DIL-inspired auditd rule sets (time-change, identity, network
environment, logins/sessions, sudoers scope) - the actual audit.rules
content, not just "is auditd running" (hardening.py's auditd_status()
already covers that).

Every rule set writes to its own numbered file under /etc/audit/rules.d/,
following the standard augenrules convention (files merged in filename
order, then compiled via `augenrules --load`). A -w (watch) rule for a
path that doesn't exist on this system is skipped rather than written -
several of the paths in the standard CIS rule sets (/var/log/faillog,
/var/log/tallylog, /etc/network) come from RHEL/Debian-era conventions
that a stock Arch install simply doesn't have, and a rules file
referencing a missing path can fail to load entirely on some auditd
versions - silently dropping what doesn't apply here is safer than a
failed load blocking every rule in the set, including the ones that
would have worked fine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .privilege import CommandResult, run_privileged

AUDIT_RULES_DIR = Path("/etc/audit/rules.d")


@dataclass
class AuditRuleSet:
    key: str
    title: str
    description: str
    syscall_rules: list[str] = field(default_factory=list)  # always included, no path dependency
    watch_paths: list[tuple[str, str]] = field(default_factory=list)  # (path, permissions) - skipped if path missing


RULE_SETS: list[AuditRuleSet] = [
    AuditRuleSet(
        key="time-change",
        title="Time change monitoring",
        description="Detects unexpected system clock changes - a common way to confuse log timestamps or cover tracks.",
        syscall_rules=[
            "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change",
            "-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change",
        ],
        watch_paths=[("/etc/localtime", "wa")],
    ),
    AuditRuleSet(
        key="identity",
        title="Identity file monitoring",
        description="Watches the files that define user/group/password identity - unexpected changes can indicate account tampering.",
        watch_paths=[
            ("/etc/group", "wa"),
            ("/etc/passwd", "wa"),
            ("/etc/gshadow", "wa"),
            ("/etc/shadow", "wa"),
            ("/etc/security/opasswd", "wa"),
        ],
    ),
    AuditRuleSet(
        key="system-locale",
        title="Network environment monitoring",
        description="Detects changes to hostname/domainname and the files that configure this host's identity on the network.",
        syscall_rules=[
            "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale",
            "-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale",
        ],
        watch_paths=[("/etc/issue", "wa"), ("/etc/issue.net", "wa"), ("/etc/hosts", "wa")],
    ),
    AuditRuleSet(
        key="logins",
        title="Login/session monitoring",
        description="Watches the files that record login history and active sessions.",
        watch_paths=[
            ("/var/log/lastlog", "wa"),
            ("/var/log/wtmp", "wa"),
            ("/var/log/btmp", "wa"),
            ("/var/run/utmp", "wa"),
        ],
    ),
    AuditRuleSet(
        key="scope",
        title="Sudo scope monitoring",
        description="Watches sudoers configuration - unexpected changes here can indicate unauthorized privilege escalation.",
        watch_paths=[("/etc/sudoers", "wa"), ("/etc/sudoers.d/", "wa")],
    ),
]

_RULE_SETS_BY_KEY = {r.key: r for r in RULE_SETS}


def _applicable_lines(rule_set: AuditRuleSet) -> list[str]:
    lines = list(rule_set.syscall_rules)
    for path, perms in rule_set.watch_paths:
        if Path(path).exists():
            lines.append(f"-w {path} -p {perms} -k {rule_set.key}")
    return lines


def is_audit_rule_set_active(key: str) -> bool:
    """
    Checks whether this rule set's key already appears in the currently
    loaded audit rules (auditctl -l), not just whether its file exists -
    the file existing doesn't guarantee it was successfully loaded (e.g.
    a syntax error, or a kernel that doesn't support 32-bit syscall
    auditing rejecting the b32 rules).
    """
    rule_set = _RULE_SETS_BY_KEY.get(key)
    if rule_set is None:
        return False
    result = run_privileged(["auditctl", "-l"])
    if not result.ok:
        return False
    return f"-k {rule_set.key}" in result.stdout or f"key={rule_set.key}" in result.stdout


def apply_audit_rule_set(key: str) -> CommandResult:
    """
    Writes one rule set to its own file under /etc/audit/rules.d/, then
    reloads auditd's rules (augenrules --load). If nothing in the set
    applies to this system (every watch path is missing and there are no
    syscall rules), nothing is written - reported as ok with no-op, not
    silently treated as success for a rule set that did nothing.
    """
    rule_set = _RULE_SETS_BY_KEY.get(key)
    if rule_set is None:
        raise ValueError(f"Unknown audit rule set: {key!r}")

    lines = _applicable_lines(rule_set)
    if not lines:
        return CommandResult(0, "nothing applicable on this system", "")

    content = "\n".join(lines) + "\n"
    rules_path = AUDIT_RULES_DIR / f"50-{rule_set.key}.rules"

    mkdir_result = run_privileged(["mkdir", "-p", str(AUDIT_RULES_DIR)])
    if not mkdir_result.ok:
        return mkdir_result
    write_result = run_privileged(["tee", str(rules_path)], input_text=content)
    if not write_result.ok:
        return write_result
    return run_privileged(["augenrules", "--load"])


def apply_all_rule_sets() -> dict[str, CommandResult]:
    """
    Applies every rule set in one pass, one file each, but a single final
    `augenrules --load` rather than one per set - writing all the files
    first means one reload picks up everything, instead of five separate
    reloads (and five separate chances for an unrelated rule set's
    problem to interrupt ones after it).
    """
    results: dict[str, CommandResult] = {}
    any_written = False

    for rule_set in RULE_SETS:
        lines = _applicable_lines(rule_set)
        if not lines:
            results[rule_set.key] = CommandResult(0, "nothing applicable on this system", "")
            continue
        content = "\n".join(lines) + "\n"
        rules_path = AUDIT_RULES_DIR / f"50-{rule_set.key}.rules"
        mkdir_result = run_privileged(["mkdir", "-p", str(AUDIT_RULES_DIR)])
        if not mkdir_result.ok:
            results[rule_set.key] = mkdir_result
            continue
        write_result = run_privileged(["tee", str(rules_path)], input_text=content)
        results[rule_set.key] = write_result
        if write_result.ok:
            any_written = True

    if any_written:
        reload_result = run_privileged(["augenrules", "--load"])
        if not reload_result.ok:
            # surfaced via the dedicated key so the caller can tell "every
            # file wrote fine, but the reload itself failed" apart from
            # any individual rule set's own write failure
            results["_reload"] = reload_result

    return results
