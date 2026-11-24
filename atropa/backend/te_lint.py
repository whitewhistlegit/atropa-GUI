"""
atropa.backend.te_lint
-------------------------
Warns when a drafted (or hand-written) SELinux module grants more than the
program should need.

A ``.te`` is parsed into rules (``parse``), each rule checked against a
table of patterns (``lint``), and every finding gets a severity:

- ``dangerous`` - root-equivalent, or switches a protection off (setenforce,
  loading kernel modules, shadow, writing binaries or /etc, leaving for
  unconfined_t, ptrace on another domain, tampering with audit logs).
  Installing needs each one acknowledged (``unacknowledged``), and
  selinux.py's install functions refuse otherwise.
- ``review`` - over-permissive: generic or unlabeled targets (usually a
  label problem), wildcard permissions, full manage sets on shared types,
  executing what the domain can also write, broad network access, broad
  capabilities, very large modules.
- ``note`` - a better route exists: a boolean, ``dontaudit`` for noise, a
  file-permission problem rather than a policy one.

What a program legitimately needs depends on what it is, so a module is
linted under a *category* (``CATEGORIES``): a system service binding a
port is normal, a desktop app doing it isn't; loading kernel modules is
expected at boot and nowhere else. A category can lower a severity where
something is expected (Boot: module loading -> review) or raise one where
it's out of place (Desktop app: any capability -> dangerous), and adds
"out of place for a <category>" findings. It never clears the hard
dangerous list. ``detect_category`` guesses one from the denials (the
process's systemd unit, else its domain); the user can change it, and the
choice is kept next to the module in ``<module>.atropa.json`` together with
the findings they acknowledged.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

DANGEROUS = "dangerous"
REVIEW = "review"
NOTE = "note"
_RANK = {DANGEROUS: 0, REVIEW: 1, NOTE: 2}

CATEGORIES = {
    "system_service": "System service",
    "boot": "Boot",
    "user_service": "User service",
    "dbus_service": "D-Bus service",
    "desktop_app": "Desktop app",
    "unsure": "Not sure",
}

# Rules above this many, or this many distinct targets, suggest a
# mislabelled program or the wrong domain rather than a few missing rules.
SIZE_THRESHOLD = 25


@dataclass
class Rule:
    kind: str  # allow | dontaudit | auditallow | neverallow | allowxperm | type_transition | ...
    source: str
    target: str
    classes: list[str]
    perms: list[str]  # ["*"] or ["~", ...] kept as written
    line: int  # 1-based line of the statement's start
    text: str


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str  # what, in plain words
    why: str  # why it matters
    line: int = 0  # 0: about the whole module
    fix: str = ""  # "" | drop | dontaudit | boolean | relabel | permissive
    perms: list[str] = field(default_factory=list)  # for fix == "drop": the permissions to take out
    detail: str = ""  # e.g. the boolean name

    @property
    def key(self) -> str:
        """Stable id for acknowledging: the rule and the line it's about."""
        return f"{self.rule_id}@{self.line}"


# ------------------------------------------------------------------ parsing --
#
# The linter is a gate, so it fails closed: every statement is accounted
# for. Declarations are skipped, access rules and transitions are checked,
# and anything else - a construct this parser doesn't know, a macro, a typo -
# becomes a dangerous "couldn't read this rule" finding instead of being
# skipped (a skipped rule is a rule nobody checked).

_ACCESS_KINDS = {"allow", "dontaudit", "auditallow", "neverallow"}
_XPERM_KINDS = {"allowxperm", "dontauditxperm", "auditallowxperm", "neverallowxperm"}
_TRANSITION_KINDS = {"type_transition", "type_change", "type_member", "range_transition"}
# Declarations that grant nothing by themselves. Everything else is checked:
# `type x_t, attr;` puts a type in an attribute (its rules come with it),
# `typealias` lets rules reach an existing type under another name.
_DECLARATIONS = {"module", "attribute", "bool", "class", "gen_require"}
_BASE_ONLY = {"sensitivity", "category", "level", "dominance", "policycap", "mlsconstrain", "constrain",
              "validatetrans", "mlsvalidatetrans", "sid", "fs_use_xattr", "fs_use_task", "fs_use_trans",
              "genfscon", "portcon", "netifcon", "nodecon"}

_SET = r"(?:~?\s*\{[^}]*\}|\*|~?\s*[^\s{};:]+)"
_ACCESS_RE = re.compile(rf"^(\w+)\s+({_SET})\s+({_SET})\s*:\s*({_SET})\s+({_SET})$")
_XPERM_RE = re.compile(rf"^(\w+)\s+({_SET})\s+({_SET})\s*:\s*({_SET})\s+(\w+)\s+(.+)$")
_TRANSITION_RE = re.compile(rf"^(\w+)\s+({_SET})\s+({_SET})\s*:\s*({_SET})\s+(\S+)(?:\s+\"[^\"]*\")?$")
_OPENER_RE = re.compile(r"^(?:optional|else|if\s*\([^)]*\))\s*\{")


def _words(value: str) -> list[str]:
    return value.strip("{} \t").split()


def _strip_comments(te_text: str) -> list[str]:
    return [raw.split("#", 1)[0] for raw in te_text.splitlines()]


def _statements(te_text: str) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """
    ([(line, statement)], [(line, leftover)]): every ';'-terminated
    statement outside require blocks, with optional/if/else block braces
    taken off; leftovers are text that never reached a ';'.
    """
    lines = _strip_comments(te_text)
    text = "\n".join(lines)
    statements: list[tuple[int, str]] = []
    leftovers: list[tuple[int, str]] = []
    position, depth_blocks = 0, 0
    length = len(text)

    def line_of(index: int) -> int:
        return text.count("\n", 0, index) + 1

    while position < length:
        while position < length and text[position].isspace():
            position += 1
        if position >= length:
            break
        rest = text[position:]
        require = re.match(r"require\s*\{", rest)
        if require:
            # Skip the declarations, braces balanced: "class file { read write };" nests.
            depth, index = 0, position + require.end() - 1
            while index < length:
                if text[index] == "{":
                    depth += 1
                elif text[index] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                index += 1
            position = index + 1
            continue
        opener = _OPENER_RE.match(rest)
        if opener:
            depth_blocks += 1
            position += opener.end()
            continue
        if rest.startswith("}") and depth_blocks:
            depth_blocks -= 1
            position += 1
            continue
        # A statement: up to the next ';' outside braces.
        depth, index = 0, position
        while index < length:
            char = text[index]
            if char == "{":
                depth += 1
            elif char == "}":
                if depth == 0:
                    break
                depth -= 1
            elif char == ";" and depth == 0:
                break
            index += 1
        chunk = " ".join(text[position:index].split())
        if index < length and text[index] == ";":
            statements.append((line_of(position), chunk))
            position = index + 1
        else:
            leftovers.append((line_of(position), chunk))
            position = index + 1 if index < length else length
    return statements, leftovers


def _expand(value: str) -> list[str]:
    """A source/target: one name, or each name of a { set }. A complement
    (~) or an exclusion (-name) stays as "*" - every type but a few."""
    value = value.strip()
    if value.startswith("~") or value == "*":
        return ["*"]
    names = _words(value)
    if any(name.startswith("-") for name in names):
        return ["*"]
    return names


def _scan(te_text: str) -> tuple[list[Rule], list[Finding]]:
    rules: list[Rule] = []
    problems: list[Finding] = []
    statements, leftovers = _statements(te_text)
    for line, chunk in leftovers:
        problems.append(Finding("unparseable", DANGEROUS, f"Couldn't read: {chunk[:80]}",
                                "Text that isn't a complete statement can't be checked; Atropa won't vouch for it.",
                                line))
    for line, statement in statements:
        keyword = statement.split(None, 1)[0] if statement else ""
        if keyword in _DECLARATIONS:
            continue
        if keyword in _ACCESS_KINDS and (match := _ACCESS_RE.match(statement)):
            _kind, sources, targets, classes, perms = match.groups()
            perm_words = perms.replace("~", " ~ ").split() if "~" in perms else _words(perms)
            for source in _expand(sources):
                for target in _expand(targets):
                    rules.append(Rule(keyword, source, target, _words(classes),
                                      [p for p in perm_words if p not in "{}"], line, statement))
            continue
        if keyword in _XPERM_KINDS and (match := _XPERM_RE.match(statement)):
            _kind, sources, targets, classes, operation, _values = match.groups()
            for source in _expand(sources):
                for target in _expand(targets):
                    rules.append(Rule(keyword, source, target, _words(classes), [operation], line, statement))
            continue
        if keyword in _TRANSITION_KINDS and (match := _TRANSITION_RE.match(statement)):
            _kind, sources, _targets, classes, new_type = match.groups()
            if "process" in _words(classes) and new_type.rstrip(";") in {"unconfined_t", "initrc_t", "kernel_t", "init_t"}:
                problems.append(Finding("to_unconfined", DANGEROUS, f"New processes become {new_type}",
                                        "Leaving for an unconfined domain ends confinement altogether.", line))
            continue
        if keyword == "permissive":
            problems.append(Finding("permissive", DANGEROUS, f"Makes {statement.split()[-1]} permissive",
                                    "A permissive domain isn't confined at all: SELinux only logs what it does. "
                                    "Use semanage permissive while investigating, not a module.", line))
            continue
        if keyword == "typealias":
            problems.append(Finding("type_alias", DANGEROUS, f"Aliases a type: {statement[:80]}",
                                    "An alias lets rules reach an existing type under a name the linter "
                                    "doesn't recognise.", line))
            continue
        if keyword == "type":
            # type NAME [alias NAME | alias { NAMES }] [, ATTR, ATTR ...]: the
            # attributes are everything after the first comma, alias or not.
            head, _comma, tail = statement.partition(",")
            if re.search(r"\balias\b", head):
                problems.append(Finding("type_alias", REVIEW, f"Declares a type alias: {statement[:80]}",
                                        "Rules on the alias name apply to the type.", line))
            attributes = [w for w in tail.replace(",", " ").split() if w]
            if attributes:
                problems.extend(_attribute_findings(attributes, line))
            continue
        if keyword in _BASE_ONLY:
            problems.append(Finding("unparseable", DANGEROUS, f"Base-policy statement: {statement[:80]}",
                                    "This belongs in the base policy, not a module; Atropa won't vouch for it.", line))
            continue
        if keyword in {"user", "roleattribute", "attribute_role"}:
            problems.append(Finding("role_types", REVIEW, f"User or role change: {statement[:80]}",
                                    "Changes which users and roles reach which domains.", line))
            continue
        if keyword == "typeattribute":
            attributes = [w.strip(",") for w in statement.split()[2:]]
            problems.extend(_attribute_findings(attributes, line))
            continue
        if keyword == "role":
            problems.append(Finding("role_types", REVIEW, f"Role change: {statement[:80]}",
                                    "Lets a role (and the users in it) run more domains.", line))
            continue
        problems.append(Finding("unparseable", DANGEROUS, f"Couldn't read: {statement[:80]}",
                                "A statement Atropa can't check - a macro, an unsupported construct or a typo - "
                                "could grant anything; Atropa won't vouch for it.", line))
    return rules, problems


def _attribute_findings(attributes: list[str], line: int) -> list[Finding]:
    privileged = [a for a in attributes if re.search(r"unconfined|^can_|exempt|bypass|^mls|^mcs|_trusted", a)]
    if privileged:
        return [Finding("privileged_attribute", DANGEROUS, f"Adds a type to {', '.join(privileged)}",
                        "These attributes exist to exempt types from the policy.", line)]
    return [Finding("attribute", REVIEW, f"Adds a type to {', '.join(attributes)}",
                    "An attribute carries rules of its own; the type gets all of them.", line)]


def parse(te_text: str) -> list[Rule]:
    """The access rules of a .te (sets expanded, one Rule per source and target)."""
    return _scan(te_text)[0]


# Attributes that stand for (nearly) every type of a kind: a rule on one of
# them is a rule on all of them.
_BROAD_ATTRIBUTES = {"domain", "file_type", "non_security_file_type", "non_auth_file_type", "exec_type",
                     "entry_type", "device_node", "filesystem_type", "port_type", "node_type", "netif_type",
                     "proc_type", "sysctl_type", "security_file_type", "packet_type", "*"}


# ---------------------------------------------------------------- the table --

_WRITE = {"write", "append", "create", "unlink", "rename", "setattr", "link", "add_name", "remove_name", "reparent",
          "rmdir", "relabelfrom", "relabelto", "truncate"}
_MANAGE = {"create", "write", "unlink", "rename"}
_EXEC = {"execute", "execute_no_trans", "entrypoint", "map"}

_ENFORCEMENT_PERMS = {"setenforce", "load_policy", "setbool", "setsecparam", "setcheckreqprot"}
_SELINUX_CONFIG_TYPES = {"selinux_config_t", "policy_config_t", "default_context_t", "file_context_t",
                         "semanage_store_t", "semanage_read_lock_t", "semanage_trans_lock_t"}
_CODE_TYPES = {"bin_t", "sbin_t", "lib_t", "shlib_t", "textrel_shlib_t", "ld_so_t", "boot_t", "shell_exec_t",
               "modules_object_t", "systemd_unit_file_t"}
_CREDENTIAL_WRITE = {"passwd_file_t", "sudo_exec_t", "etc_t", "pam_var_run_t", "auth_cache_t"}
_GENERIC_TARGETS = {"default_t", "file_t", "unlabeled_t", "var_t", "tmp_t", "usr_t"}
_SHARED_TYPES = {"etc_t", "var_t", "tmp_t", "usr_t", "user_home_t", "user_home_dir_t", "home_root_t", "var_lib_t",
                 "var_run_t", "var_log_t", "var_spool_t"}
_BROAD_PORTS = {"port_t", "unreserved_port_t", "reserved_port_t", "hi_reserved_port_t", "ephemeral_port_t"}
_CONFINED_USERS = {"guest_t", "xguest_t", "sandbox_t", "sandbox_web_t", "sandbox_x_t", "sandbox_net_t"}
_LIMITED_USERS = {"user_t", "staff_t"}
_HOME_TYPES = {"user_home_t", "user_home_dir_t", "home_root_t", "user_tmp_t"}
_DESKTOP_TYPES = {"xserver_t", "xserver_tmpfs_t", "xdm_t", "xdm_tmp_t", "user_tmp_t", "dri_device_t", "sound_device_t",
                  "pulseaudio_t", "pulseaudio_tmpfs_t", "pipewire_t"}

_CAP_DANGEROUS = {"sys_module", "sys_rawio", "mac_admin", "mac_override"}
_CAP_REVIEW = {"sys_admin", "net_admin", "setuid", "setgid", "sys_ptrace", "setfcap", "fowner", "chown", "kill",
               "sys_boot", "net_raw", "bpf", "perfmon", "sys_resource"}
_CAP_NOTE = {"dac_override", "dac_read_search"}


def _is_self(rule: Rule) -> bool:
    return rule.target in ("self", rule.source)


def _perms(rule: Rule) -> set[str]:
    return set(rule.perms)


def _wild(rule: Rule) -> bool:
    return "*" in rule.perms or "~" in rule.perms


def _f(rule_id, severity, message, why, rule: Rule | None = None, **extra) -> Finding:
    return Finding(rule_id, severity, message, why, rule.line if rule else 0, **extra)


def _base_findings(rule: Rule) -> list[Finding]:
    found: list[Finding] = []
    for name, role in ((rule.source, "source"), (rule.target, "target")):
        if name in _BROAD_ATTRIBUTES:
            found.append(_f("broad_attribute", DANGEROUS, f"Applies to every {'type' if name == '*' else name} ({role})",
                            "A rule on a broad attribute or a complement covers almost every type there is.", rule))
        elif name != "self" and not name.endswith("_t"):
            found.append(_f("attribute_rule", REVIEW, f"{name} is an attribute (a group of types), as {role}",
                            "The rule covers every type in it, now and later.", rule))
    perms = _perms(rule)
    classes = set(rule.classes)
    target = rule.target
    wild = _wild(rule)

    def has(group: set[str]) -> set[str]:
        return set(group) if wild else perms & group

    if "security" in classes and (wild or perms & _ENFORCEMENT_PERMS):
        found.append(_f("enforcement", DANGEROUS, f"{rule.source} could change SELinux itself "
                        f"({', '.join(sorted(has(_ENFORCEMENT_PERMS)))})",
                        "Turning enforcement off, loading policy or flipping booleans undoes every other rule.",
                        rule, fix="drop", perms=sorted(has(_ENFORCEMENT_PERMS))))
    if target in _SELINUX_CONFIG_TYPES and has(_WRITE):
        found.append(_f("selinux_config", DANGEROUS, f"Writes SELinux's own configuration ({target})",
                        "Whoever writes the policy store or its config decides the policy.", rule,
                        fix="drop", perms=sorted(has(_WRITE))))
    if target == "shadow_t":
        found.append(_f("shadow", DANGEROUS, "Access to /etc/shadow (shadow_t)",
                        "Password hashes: reading them allows offline cracking, writing them is root.", rule, fix="drop",
                        perms=sorted(perms)))
    if target in _CREDENTIAL_WRITE and has(_WRITE):
        found.append(_f("credential_write", DANGEROUS, f"Writes {target}",
                        "Accounts, sudo, PAM and /etc configuration decide who gets root.", rule,
                        fix="drop", perms=sorted(has(_WRITE))))
    if (target in _CODE_TYPES or target.endswith("_exec_t")) and has(_WRITE):
        found.append(_f("code_write", DANGEROUS, f"Writes {target} (programs or libraries)",
                        "Changing code other domains run - root's included - runs your code there.", rule,
                        fix="drop", perms=sorted(has(_WRITE))))
    if target == "memory_device_t" or (target == "fixed_disk_device_t" and has(_WRITE)):
        found.append(_f("raw_device", DANGEROUS, f"Raw access to {target}",
                        "/dev/mem or a raw disk bypasses every file permission.", rule, fix="drop", perms=sorted(perms)))
    elif target == "fixed_disk_device_t":
        found.append(_f("raw_disk_read", REVIEW, "Reads a raw disk (fixed_disk_device_t)",
                        "Reading the block device reads every file on it, permissions or not.", rule))
    if "system" in classes and has({"module_load"}):
        found.append(_f("module_load", DANGEROUS, "Loads kernel modules",
                        "A kernel module runs with full kernel privileges.", rule, fix="drop", perms=["module_load"]))
    if "memprotect" in classes and has({"mmap_zero"}):
        found.append(_f("mmap_zero", DANGEROUS, "Maps page zero (mmap_zero)",
                        "The classic way to turn a kernel NULL dereference into code execution.", rule))
    if target == "auditd_log_t" and has(_WRITE) and rule.source != "auditd_t":
        found.append(_f("audit_tamper", DANGEROUS, "Writes the audit logs",
                        "Something that can edit audit.log can erase its own tracks.", rule,
                        fix="drop", perms=sorted(has(_WRITE))))

    if "process" in classes:
        if has({"setcurrent", "dyntransition"}):
            found.append(_f("dyntransition", DANGEROUS, "Changes its own domain at runtime",
                            "A dynamic transition leaves the confinement this module is for.", rule))
        if not _is_self(rule) and has({"ptrace"}):
            found.append(_f("ptrace_other", DANGEROUS, f"ptrace on {target}",
                            "Tracing another domain means running code inside it.", rule, fix="drop", perms=["ptrace"]))
        if target in ("unconfined_t", "initrc_t", "kernel_t") and has({"transition"}):
            found.append(_f("to_unconfined", DANGEROUS, f"Transitions to {target}",
                            "Leaving for an unconfined domain ends confinement altogether.", rule))
        if not _is_self(rule) and has({"signal", "sigkill", "sigstop"}):
            found.append(_f("signal_other", REVIEW, f"Signals {target}",
                            "Killing or stopping another domain's processes.", rule))
        if has({"execmem", "execstack", "execheap", "execmod"}):
            found.append(_f("execmem", REVIEW, "Writable and executable memory",
                            "Needed by JITs; elsewhere it makes memory corruption easier to exploit.", rule))

    for cap_class in ("capability", "cap_userns", "capability2", "cap2_userns"):
        if cap_class in classes:
            dangerous = has(_CAP_DANGEROUS)
            if dangerous:
                found.append(_f("cap_dangerous", DANGEROUS, f"Capabilities {', '.join(sorted(dangerous))}",
                                "Each of these is root-equivalent on its own.", rule, fix="drop", perms=sorted(dangerous)))
            broad = has(_CAP_REVIEW)
            if broad:
                found.append(_f("cap_broad", REVIEW, f"Capabilities {', '.join(sorted(broad))}",
                                "Broad root powers; check the program really needs them.", rule, fix="drop",
                                perms=sorted(broad)))
            if perms & _CAP_NOTE:
                found.append(_f("dac_override", NOTE, f"{', '.join(sorted(perms & _CAP_NOTE))}",
                                "Usually a Unix file-permission problem (a root process reading a file it doesn't "
                                "own), better fixed with the file's owner or mode than with policy.", rule,
                                fix="drop", perms=sorted(perms & _CAP_NOTE)))

    if rule.source in _CONFINED_USERS or rule.source.endswith("_sandbox_t"):
        found.append(_f("confined_user", DANGEROUS, f"Widens {rule.source}, a sandbox or guest domain",
                        "The point of that domain is that it can't do this.", rule))
    elif rule.source in _LIMITED_USERS:
        found.append(_f("limited_user", REVIEW, f"Widens {rule.source}, a confined user domain",
                        "Everything that user runs gets this too.", rule))

    if target in _GENERIC_TARGETS:
        found.append(_f("generic_target", REVIEW, f"Uses the generic type {target}",
                        "Almost always a file without its proper label: relabelling (restorecon or semanage "
                        "fcontext) fixes the cause instead of allowing the symptom.", rule, fix="relabel"))
    if wild:
        found.append(_f("wildcard", REVIEW, "Wildcard permissions (* or ~)",
                        "Grants every permission of the class, including ones nobody asked for.", rule))
    elif target in _SHARED_TYPES and perms >= _MANAGE:
        found.append(_f("manage_shared", REVIEW, f"Full create/write/delete on {target}",
                        f"{target} is shared by many programs; this lets {rule.source} replace their files.", rule))
    if classes & {"tcp_socket", "udp_socket"} and target in _BROAD_PORTS and has({"name_bind", "name_connect"}):
        found.append(_f("broad_port", REVIEW, f"{'/'.join(sorted(has({'name_bind', 'name_connect'})))} on {target}",
                        "Any port of that range, not the program's own port type.", rule))
    if classes & {"rawip_socket", "packet_socket"}:
        found.append(_f("raw_socket", REVIEW, f"Raw network sockets ({', '.join(sorted(classes & {'rawip_socket', 'packet_socket'}))})",
                        "Can sniff or forge traffic.", rule))
    if "netlink_audit_socket" in classes and has({"nlmsg_relay", "nlmsg_write"}) or (
        "netlink_route_socket" in classes and has({"nlmsg_write"})
    ):
        found.append(_f("netlink_write", REVIEW, "Changes kernel state over netlink",
                        "Routing tables or the audit system, not just reading them.", rule))
    return found


def _module_findings(rules: list[Rule]) -> list[Finding]:
    found: list[Finding] = []
    allows = [r for r in rules if r.kind == "allow"]
    targets = {r.target for r in allows}
    if len(allows) > SIZE_THRESHOLD or len(targets) > SIZE_THRESHOLD:
        found.append(Finding(
            "size", REVIEW, f"{len(allows)} rules over {len(targets)} types",
            "A program needing this much is more likely mislabelled or running in the wrong domain. Making the "
            "domain permissive while you investigate (semanage permissive -a) is safer than allowing it all.",
            fix="permissive",
        ))
    # Execute what the same domain can write: write-then-run.
    writable = {(r.source, r.target) for r in allows if _wild(r) or _perms(r) & {"write", "create", "append"}}
    for rule in allows:
        if (rule.source, rule.target) in writable and (_wild(rule) or _perms(rule) & _EXEC) and "file" in rule.classes:
            found.append(_f("write_execute", REVIEW, f"Can both write and execute {rule.target}",
                            "A domain that runs what it writes runs whatever ends up there.", rule))
    connects = any("connectto" in r.perms for r in allows)
    for rule in allows:
        if "sock_file" in rule.classes and "write" in rule.perms and not connects:
            found.append(_f("sock_no_connect", NOTE, f"Writes the socket {rule.target} but has no connectto",
                            "Connecting still fails with this module alone - if the service isn't in use, dontaudit "
                            "is the better fix.", rule, fix="dontaudit"))
    return found


# ------------------------------------------------------------- categories --

def _ports_own(rule: Rule) -> bool:
    prefix = rule.source[:-2] if rule.source.endswith("_t") else rule.source
    return rule.target.startswith(prefix) and rule.target.endswith("_port_t")


def _category_findings(rule: Rule, category: str, label: str) -> tuple[list[Finding], dict[str, str]]:
    """Out-of-place findings for this rule, and severity changes {rule_id: severity}."""
    found: list[Finding] = []
    changes: dict[str, str] = {}
    perms, classes, target = _perms(rule), set(rule.classes), rule.target
    caps = classes & {"capability", "capability2", "cap_userns", "cap2_userns"}

    def out(severity: str, what: str) -> None:
        found.append(_f(f"out_of_place:{category}", severity, f"A {label.lower()} shouldn't need {what}",
                        "Either the category is wrong, or this program is doing something odd.", rule))

    if category == "boot":
        changes.update(module_load=REVIEW, cap_dangerous=REVIEW, raw_disk_read=NOTE)
        if classes & {"tcp_socket", "udp_socket"} and perms & {"name_connect", "name_bind"}:
            out(REVIEW, "the network")
        if target in _HOME_TYPES:
            out(REVIEW, f"home folders ({target})")
    elif category == "system_service":
        if target in _HOME_TYPES | {"xdg_pictures_t", "xdg_documents_t", "xdg_downloads_t"}:
            out(REVIEW, f"home folders ({target})")
        if target in _DESKTOP_TYPES - {"user_tmp_t"}:
            out(REVIEW, f"the desktop session ({target})")
        if target == "tmp_t" and perms & _EXEC:
            out(DANGEROUS, "to execute files from /tmp")
    elif category == "user_service":
        if caps:
            out(DANGEROUS, "root capabilities")
        if target in {"var_lib_t", "var_run_t", "var_log_t"} and perms & _WRITE:
            out(DANGEROUS, f"to write system state ({target})")
        if target in {"reserved_port_t", "hi_reserved_port_t"} and "name_bind" in perms:
            out(DANGEROUS, "a reserved port")
    elif category == "dbus_service":
        if target in _HOME_TYPES:
            out(REVIEW, f"home folders ({target})")
        if classes & {"tcp_socket", "udp_socket"} and "name_bind" in perms and not _ports_own(rule):
            out(REVIEW, "to listen on the network")
        changes.update(cap_broad=REVIEW)
    elif category == "desktop_app":
        if caps:
            out(DANGEROUS, "root capabilities")
            changes.update(cap_broad=DANGEROUS, dac_override=DANGEROUS)
        if classes & {"tcp_socket", "udp_socket"} and "name_bind" in perms:
            out(DANGEROUS, "to listen on the network")
        if target in {"var_lib_t", "var_run_t", "var_log_t", "etc_t"} and perms & _WRITE:
            out(DANGEROUS, f"to write system files ({target})")
    return found, changes


# ---------------------------------------------------------------- linting --

def lint(te_text: str, category: str = "unsure", booleans: list[str] | None = None) -> list[Finding]:
    """Findings for a .te, most severe first. `booleans`: ones audit2allow named for it."""
    from . import denial_advice

    rules, problems = _scan(te_text)
    label = CATEGORIES.get(category, CATEGORIES["unsure"])
    hard = {"enforcement", "selinux_config", "shadow", "credential_write", "code_write", "raw_device",
            "dyntransition", "ptrace_other", "to_unconfined", "audit_tamper", "mmap_zero", "confined_user",
            "unparseable", "permissive", "privileged_attribute", "broad_attribute", "type_alias"}
    found: list[Finding] = list(problems)
    out_of_place = 0
    allows = [r for r in rules if r.kind in ("allow", "allowxperm")]
    for rule in allows:
        base = _base_findings(rule)
        extra, changes = ([], {}) if category == "unsure" else _category_findings(rule, category, label)
        for finding in base:
            new = changes.get(finding.rule_id)
            if new and not (finding.rule_id in hard and _RANK[new] > _RANK[finding.severity]):
                finding.severity = new
        found += base + extra
        out_of_place += bool(extra)
        if not base and not extra:
            reason = denial_advice.noise_reason(rule.target, rule.classes[0] if rule.classes else "", rule.perms)
            if reason:
                found.append(_f("noise", NOTE, f"Known noise: {reason}",
                                "Allowing it changes nothing you'd notice; dontaudit only silences the log.",
                                rule, fix="dontaudit"))
    found += _module_findings(rules)
    for name in booleans if booleans is not None else denial_advice.te_booleans(te_text):
        found.append(Finding("boolean", NOTE, f"The boolean {name} would allow part of this",
                             "A boolean is maintained policy; a module is yours to keep up to date.",
                             fix="boolean", detail=name))
    if category != "unsure" and allows and out_of_place * 2 > len(allows):
        found.append(Finding("category_mismatch", NOTE,
                             f"Most of these rules are out of place for a {label.lower()}",
                             "The category may be wrong - pick the one that fits and the findings follow."))
    # Domain-wide findings (widening a user domain) once per module, not per rule.
    seen: set[tuple[str, str]] = set()
    unique = []
    for finding in found:
        if finding.rule_id in {"limited_user", "confined_user"}:
            if (finding.rule_id, finding.message) in seen:
                continue
            seen.add((finding.rule_id, finding.message))
        unique.append(finding)
    unique.sort(key=lambda f: (_RANK[f.severity], f.line))
    return unique


def verdict(findings: list[Finding]) -> str:
    """"dangerous", "review" or "fine" (notes only, or nothing)."""
    severities = {f.severity for f in findings}
    if DANGEROUS in severities:
        return DANGEROUS
    if REVIEW in severities:
        return REVIEW
    return "fine"


def unacknowledged(findings: list[Finding], acknowledged) -> list[Finding]:
    """The dangerous findings not in `acknowledged` (keys)."""
    ack = set(acknowledged or ())
    return [f for f in findings if f.severity == DANGEROUS and f.key not in ack]


# ------------------------------------------------------------ safer edits --

def drop_perms(te_text: str, finding: Finding) -> str:
    """The .te with `finding.perms` taken out of the rule on `finding.line`;
    the rule goes when nothing is left."""
    lines = te_text.splitlines()
    rule = next((r for r in parse(te_text) if r.line == finding.line), None)
    if rule is None or not finding.perms:
        return te_text
    remaining = [p for p in rule.perms if p not in finding.perms]
    end = finding.line - 1
    while not lines[end].split("#", 1)[0].rstrip().endswith(";"):
        end += 1
    if not remaining:
        replacement: list[str] = []
    else:
        perm_text = remaining[0] if len(remaining) == 1 else "{ " + " ".join(remaining) + " }"
        classes = rule.classes[0] if len(rule.classes) == 1 else "{ " + " ".join(rule.classes) + " }"
        replacement = [f"{rule.kind} {rule.source} {rule.target}:{classes} {perm_text};"]
    lines[finding.line - 1:end + 1] = replacement
    return "\n".join(lines) + "\n"


def to_dontaudit(te_text: str, finding: Finding) -> str:
    """The rule on `finding.line` as dontaudit instead of allow."""
    lines = te_text.splitlines()
    index = finding.line - 1
    if 0 <= index < len(lines):
        lines[index] = re.sub(r"^(\s*)allow\b", r"\1dontaudit", lines[index], count=1)
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------- category --

def detect_category(denial_lines: list[str], domain: str, proc: Path = Path("/proc")) -> tuple[str, str]:
    """(category, reason): from the denying process's systemd unit while it
    still runs, else from its domain and what it touched."""
    for line in denial_lines:
        match = re.search(r"\bpid=(\d+)", line)
        if not match:
            continue
        try:
            cgroup = (proc / match.group(1) / "cgroup").read_text()
        except OSError:
            continue
        path = cgroup.strip().splitlines()[-1].split(":", 2)[-1]
        unit = path.rstrip("/").rsplit("/", 1)[-1]
        if "/user@" in path:
            if unit.startswith("app-") or unit.endswith(".scope"):
                return "desktop_app", f"runs in your session as {unit}"
            return "user_service", f"started by your user manager as {unit}"
        if path.startswith("/system.slice/") or path.startswith("/init.scope"):
            if unit.startswith("dbus-") or unit.endswith("dbus.service"):
                return "dbus_service", f"{unit} is D-Bus activated"
            return "system_service", f"started by {unit}"
    touched = " ".join(denial_lines)
    if domain in {"user_t", "staff_t", "unconfined_t"} or domain.endswith("_app_t") or "brave" in domain:
        if re.search(r"tcontext=\S*:(xserver_t|xdm_t|dri_device_t|user_tmp_t|xserver_tmpfs_t)", touched):
            return "desktop_app", f"{domain} talks to the display server"
        return "desktop_app", f"{domain} is a user domain"
    if domain in {"fsadm_t", "mount_t", "udev_t", "kmod_t", "lvm_t", "systemd_generator_t", "init_t",
                  "plymouthd_t", "systemd_tmpfiles_t", "loadkeys_t"}:
        return "boot", f"{domain} runs at boot"
    # Without the process there's little to go by: a "*d_t" name is as often
    # passwd_t as a daemon. Only domains that are clearly one thing.
    if domain in _SERVICE_DOMAINS:
        return "system_service", f"{domain} is a service's domain"
    return "unsure", "nothing to go by"


_SERVICE_DOMAINS = {"auditd_t", "auditctl_t", "sshd_t", "dnsmasq_t", "virtd_t", "fwupd_t", "fwupdmgr_t", "cupsd_t",
                    "NetworkManager_t", "systemd_machined_t", "systemd_logind_t", "policykit_t", "devicekit_disk_t",
                    "chronyd_t", "ntpd_t", "fail2ban_t", "firewalld_t", "crond_t", "syslogd_t"}


# ------------------------------------------------------------ the sidecar --

def meta_path(module_dir: Path, module_name: str) -> Path:
    return module_dir / f"{module_name}.atropa.json"


def read_meta(module_dir: Path, module_name: str) -> dict:
    """{"category": ..., "acknowledged": [...]} kept next to the module."""
    try:
        data = json.loads(meta_path(module_dir, module_name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"category": "unsure", "acknowledged": []}
    category = data.get("category") if data.get("category") in CATEGORIES else "unsure"
    acknowledged = [k for k in data.get("acknowledged", []) if isinstance(k, str)]
    return {"category": category, "acknowledged": acknowledged, **({"reason": data["reason"]} if "reason" in data else {})}


def write_meta(module_dir: Path, module_name: str, category: str, acknowledged=(), reason: str | None = None) -> None:
    module_dir.mkdir(parents=True, exist_ok=True)
    data = {"category": category if category in CATEGORIES else "unsure", "acknowledged": sorted(set(acknowledged))}
    if reason:
        data["reason"] = reason
    meta_path(module_dir, module_name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
