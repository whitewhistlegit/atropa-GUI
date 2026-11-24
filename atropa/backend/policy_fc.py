"""
atropa.backend.policy_fc
--------------------------
File-context proposals for the SELinux Dev page, ported from atropa-scratch's
pkgscan and generate: a program's package files folded into .fc groups,
each with the label the running policy gives it now and a proposed type of
its own, plus the declarations and access the module needs so a relabel
doesn't cut the program off from its own files.

Defaults are conservative, because a new file type is the riskiest thing a
module can add:

- a group is only pre-selected when its current label is a generic one
  (etc_t, var_lib_t, ...) and it is plainly the program's own (its name is
  in the path);
- an *_exec_t label is never pre-selected: it decides which domain a binary
  runs in, and a policy may leave a binary generic on purpose to keep it
  from running (refpolicy-atropa does this to /usr/lib/ssh/sshd-session);
- nor is a catch-all *_file_t (a path in no known config, state or log
  location, such as /opt/<app>): that is usually the program's own install
  tree, binaries and libraries included, and relabelling it to a plain file
  type stops the program mapping its own libraries. Its own-access is
  read-only; write access is only granted on state, log, cache, spool,
  runtime and tmp types, where a program is expected to write;
- files in shared config locations (/etc/pam.d, /etc/xdg, ...) keep their
  generic label, and directories many packages use are never collapsed
  into one group.

Current labels come from the running policy's file contexts (matchpathcon):
that is what restorecon applies, and what this module would be added to.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
from dataclasses import dataclass

from .privilege import run_unprivileged

# Files nobody writes policy for.
NOISE = (
    "/usr/share/man/", "/usr/share/doc/", "/usr/share/licenses/", "/usr/share/locale/",
    "/usr/share/info/", "/usr/share/bash-completion/", "/usr/share/zsh/", "/usr/share/fish/",
    "/usr/include/", "/usr/lib/pkgconfig/", "/usr/share/pkgconfig/", "/usr/share/gtk-doc/",
    "/usr/share/help/", "/usr/share/icons/", "/usr/share/metainfo/", "/usr/lib/cmake/",
    "/usr/share/vim/", "/usr/share/applications/", "/usr/share/appdata/",
    "/usr/lib/tmpfiles.d/", "/usr/lib/sysusers.d/", "/usr/share/factory/",
    "/usr/share/libalpm/",
)

# Shared config locations: files here keep their generic label by default.
KEEP_GENERIC = (
    "/etc/pam.d/", "/etc/logrotate.d/", "/etc/sudoers.d/", "/etc/profile.d/", "/etc/security/",
    "/etc/default/", "/etc/xdg/", "/etc/dbus-1/", "/usr/share/dbus-1/", "/usr/share/polkit-1/",
    "/etc/sysctl.d/", "/etc/modprobe.d/", "/usr/lib/udev/",
)

# Directories many packages put things into: never collapse these into one group.
SHARED_DIRS = {
    "", "/etc", "/usr", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/libexec",
    "/usr/share", "/var", "/var/lib", "/var/log", "/var/cache", "/var/spool", "/run", "/opt",
    "/srv", "/boot", "/usr/lib/systemd", "/usr/lib/systemd/system", "/usr/lib/systemd/user",
    "/usr/lib/systemd/system-generators", "/usr/lib/systemd/system-preset",
    "/usr/lib/systemd/user-preset", "/usr/lib/systemd/network", "/usr/lib/udev",
    "/usr/lib/udev/rules.d", "/etc/pam.d", "/etc/systemd", "/etc/systemd/system",
    "/etc/default", "/etc/security", "/etc/profile.d", "/etc/xdg", "/etc/xdg/autostart",
    "/etc/dbus-1", "/etc/dbus-1/system.d", "/usr/share/dbus-1", "/usr/share/dbus-1/system.d",
    "/usr/share/dbus-1/services", "/usr/share/dbus-1/system-services", "/usr/share/polkit-1",
    "/usr/share/polkit-1/actions", "/usr/share/polkit-1/rules.d", "/etc/logrotate.d",
    "/etc/cron.d", "/usr/lib/modules-load.d", "/usr/lib/sysctl.d", "/etc/sysctl.d",
    "/etc/ld.so.conf.d", "/usr/share/selinux", "/usr/lib/environment.d", "/etc/modprobe.d",
    "/usr/lib/modprobe.d", "/etc/sudoers.d", "/usr/lib/firmware", "/usr/share/X11",
    "/etc/X11", "/usr/lib/security", "/usr/share/pam.d",
}

# Labels so broad that a program's files should get their own type instead.
GENERIC_TYPES = {
    "bin_t", "etc_t", "lib_t", "usr_t", "var_t", "var_lib_t", "var_log_t",
    "var_run_t", "runtime_t", "default_t", "unlabeled_t", "systemd_unit_t",
    "root_t", "src_t", "tmp_t", "textrel_shlib_t", "shell_exec_t",
    "user_home_t", "home_root_t", "var_spool_t", "cert_t",
}

MAX_GROUPS = 80
_FC_SPECIAL = set(".^$?*+|()[]{}\\")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")

# Suffix -> macros that turn a bare type into the right kind of file type;
# the first one the policy defines wins.
_DECL = [
    ("_conf_t", ("files_config_file",)),
    ("_etc_t", ("files_config_file",)),
    ("_log_t", ("logging_log_file",)),
    ("_runtime_t", ("files_runtime_file", "files_pid_file")),
    ("_unit_t", ("systemd_unit_file", "init_unit_file")),
    ("_exec_t", ("corecmd_executable_file",)),
    ("_tmp_t", ("files_tmp_file",)),
]

# What the program needs on each kind of type this module declares, or the
# relabel itself breaks the service.
_OWN_ACCESS = [
    (("_conf_t", "_etc_t", "_file_t"), [("dir", "list_dir_perms"), ("file", "read_file_perms"),
                                        ("lnk_file", "read_lnk_file_perms")]),
    (("_log_t", "_var_lib_t", "_cache_t", "_spool_t", "_runtime_t", "_tmp_t"),
     [("dir", "manage_dir_perms"), ("file", "manage_file_perms"), ("lnk_file", "manage_lnk_file_perms")]),
    (("_exec_t",), [("file", "exec_file_perms")]),
]

# refpolicy's definitions, for a source that doesn't define a set.
FALLBACK_SETS = {
    "list_dir_perms": "getattr search open read lock ioctl",
    "read_file_perms": "getattr open read lock ioctl",
    "read_lnk_file_perms": "getattr read",
    "manage_dir_perms": "create open getattr setattr read write link unlink rename search add_name "
                        "remove_name reparent rmdir lock ioctl",
    "manage_file_perms": "create open getattr setattr read write append rename link unlink ioctl lock",
    "manage_lnk_file_perms": "create read write getattr setattr link unlink rename ioctl lock",
    "exec_file_perms": "getattr open map read execute ioctl execute_no_trans",
}

# Interfaces generated in the .if for each kind of declared type.
_IF_VERBS = [
    ("_conf_t", "read_config", "Read %s configuration files.", "files_search_etc"),
    ("_etc_t", "read_config", "Read %s configuration files.", "files_search_etc"),
    ("_log_t", "read_log", "Read %s log files.", "logging_search_logs"),
    ("_var_lib_t", "read_lib_files", "Read %s state files in /var/lib.", "files_search_var_lib"),
    ("_runtime_t", "read_runtime_files", "Read %s runtime files.", "files_search_runtime"),
    ("_cache_t", "read_cache_files", "Read %s cache files.", "files_search_var"),
]


@dataclass
class FcGroup:
    regex: str
    ftype: str  # "--" for one file, "" for a directory tree
    sample: str  # a real path the regex covers, for label lookups
    mode: str  # "f" or "d"
    current: str = ""  # the running policy's label for sample
    type: str = ""  # the label to write
    include: bool = False  # write it to the .fc
    related: bool = True  # plainly the program's own (its name is in the path)


@dataclass
class Program:
    """What a domain's package looks like: its binary, package and file groups."""

    name: str
    path: str = ""
    package: str = ""
    groups: list = None
    hidden: int = 0  # groups beyond MAX_GROUPS, not shown
    files: list = None  # the package's file list (directories end in "/")

    def __post_init__(self):
        self.groups = self.groups or []
        self.files = self.files or []


def is_ident(name: str) -> bool:
    return bool(name) and _IDENT.match(name) is not None


def stem_of(name: str) -> str:
    s = re.sub(r"[^a-z0-9_]", "_", name.lower()).strip("_")
    if s and s[0].isdigit():
        s = "p" + s
    return s or "app"


def escape_fc(path: str) -> str:
    return "".join("\\" + c if c in _FC_SPECIAL else c for c in path)


# -- pacman ------------------------------------------------------------------

def _pacman(*args: str) -> list[str]:
    result = run_unprivileged(["pacman", *args], timeout=30)
    return result.stdout.split("\n") if result.ok else []


def resolve_program(name: str) -> str | None:
    if os.path.isabs(name):
        return name if os.path.exists(name) else None
    found = shutil.which(name)
    if found:
        return found
    for d in ("/usr/bin", "/usr/sbin", f"/usr/lib/{name}", "/usr/libexec"):
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    return None


def owning_package(path: str) -> str | None:
    out = [ln for ln in _pacman("-Qqo", path) if ln.strip()]
    return out[0].split()[0] if out else None


def package_files(package: str) -> list[str]:
    return [ln for ln in _pacman("-Qlq", package) if ln.startswith("/")]


def _owner_count(directory: str) -> int:
    return len([ln for ln in _pacman("-Qqo", directory + "/") if ln.strip()])


# -- grouping and labels -------------------------------------------------------

def _noise(path: str) -> bool:
    return any(path.startswith(n) or path + "/" == n for n in NOISE)


def _rank(sample: str) -> int:
    order = ("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/", "/etc/", "/var/lib/", "/var/log/",
             "/var/cache/", "/run/", "/usr/lib/systemd/", "/usr/share/")
    for i, prefix in enumerate(order):
        if prefix == "/usr/lib/" and sample.startswith("/usr/lib/systemd/"):
            continue  # unit files after config
        if sample.startswith(prefix):
            return i
    return 20


def group_paths(paths, program: str = "", program_path: str = "", is_shared=None) -> tuple[list[FcGroup], int]:
    """
    Fold a package's file list into .fc-style groups: a directory only this
    package owns becomes `dir(/.*)?`; files in shared directories stay exact;
    unit files that start with the program's name merge into one entry.
    Returns (groups, how many more weren't kept).
    """
    if is_shared is None:
        is_shared = lambda d: _owner_count(d) > 1  # noqa: E731
    dirs = sorted({p.rstrip("/") for p in paths if p.endswith("/")}, key=lambda d: (d.count("/"), d))
    files = [p for p in paths if not p.endswith("/")]

    tops: list[str] = []
    for d in dirs:
        if _noise(d + "/") or d in SHARED_DIRS or any(d.startswith(t + "/") for t in tops) or is_shared(d):
            continue
        tops.append(d)

    groups = [FcGroup(escape_fc(t) + "(/.*)?", "", t, "d") for t in tops]
    stem = program.lower()
    merged: dict[str, list[str]] = {}
    for f in files:
        if _noise(f) or any(f.startswith(t + "/") for t in tops):
            continue
        parent, base = os.path.split(f)
        if parent in ("/usr/lib/systemd/system", "/usr/lib/systemd/user") and stem and base.lower().startswith(stem):
            merged.setdefault(parent, []).append(f)
            continue
        groups.append(FcGroup(escape_fc(f), "--", f, "f"))
    for parent, members in merged.items():
        if len(members) == 1:
            groups.append(FcGroup(escape_fc(members[0]), "--", members[0], "f"))
        else:
            groups.append(FcGroup(escape_fc(parent + "/" + program) + ".*", "--", members[0], "f"))

    def related(g: FcGroup) -> bool:
        if not stem:
            return False
        low = g.sample.lower()
        if stem in low:
            return True
        # /usr/lib/ssh for sshd: the directory's name is a prefix of the program's.
        base = os.path.basename(low.rstrip("/")).split(".")[0]
        return g.mode == "d" and len(base) >= 3 and stem.startswith(base)

    for g in groups:
        g.related = related(g)
    groups.sort(key=lambda g: (g.sample != program_path, not g.related, _rank(g.sample), g.regex))
    return groups[:MAX_GROUPS], max(0, len(groups) - MAX_GROUPS)


def propose_type(group: FcGroup, stem: str) -> str:
    s = group.sample
    base = stem_of(os.path.basename(s.rstrip("/")))
    if s.startswith(("/usr/bin/", "/usr/sbin/")):
        return f"{stem if base == stem else base}_exec_t"
    if s.startswith("/usr/lib/systemd/"):
        return f"{stem}_unit_t"
    if s.startswith(("/usr/lib/", "/usr/libexec/")):
        if group.mode == "f" and ".so" in os.path.basename(s):
            return "lib_t"  # shared libraries keep the generic label
        return f"{stem}_exec_t"
    for prefix, suffix in (("/etc/", "conf"), ("/var/lib/", "var_lib"), ("/var/log/", "log"),
                           ("/var/cache/", "cache"), ("/var/spool/", "spool"), ("/run/", "runtime")):
        if s.startswith(prefix):
            return f"{stem}_{suffix}_t"
    if s.startswith("/usr/share/"):
        return "usr_t"
    return f"{stem}_file_t"


def system_label(path: str, mode: str) -> str:
    """The type the running policy's file contexts give path ("" if none)."""
    bits = stat.S_IFDIR if mode == "d" else stat.S_IFREG
    try:
        import selinux  # libselinux's Python binding

        rc, ctx = selinux.matchpathcon(path, bits)
        return ctx.split(":")[2] if rc == 0 and ctx else ""
    except Exception:  # noqa: BLE001 - no binding, or no context: try the tool
        pass
    result = run_unprivileged(["matchpathcon", "-n", "-m", "dir" if mode == "d" else "file", path], timeout=10)
    bits_ = result.stdout.strip().split(":")
    return bits_[2] if result.ok and len(bits_) >= 3 else ""


def label_groups(groups: list[FcGroup], stem: str, lookup=system_label) -> None:
    for g in groups:
        g.current = lookup(g.sample, g.mode)
        if g.current and g.current not in GENERIC_TYPES:
            g.type, g.include = g.current, False  # already has a label of its own
        else:
            g.type = propose_type(g, stem)
            g.include = (g.related and g.type not in GENERIC_TYPES and not g.sample.startswith(KEEP_GENERIC)
                         and not g.type.endswith(("_exec_t", "_file_t")))


def load_program(name: str, stem: str) -> Program:
    """A program's binary, package and labelled file groups; name is a comm= name or a path."""
    path = resolve_program(name)
    package = owning_package(path) if path else None
    if package is None:
        out = [ln for ln in _pacman("-Qq", name) if ln.strip()]
        package = out[0] if out else None
    if path is None and package is None:
        raise LookupError(f"{name}: no such program or installed package")
    files = package_files(package) if package else [path]
    program = Program(os.path.basename(path or name), path or "", package or "", files=files)
    program.groups, program.hidden = group_paths(files, program.name, program.path)
    label_groups(program.groups, stem)
    return program


# -- module text ---------------------------------------------------------------

def _pick(kb, names, fallback: str = "files_type") -> str:
    for name in names:
        if kb is None or kb.has_iface(name):
            return name
    return fallback


def declared_types(groups: list[FcGroup], kb) -> dict[str, list[str]]:
    """Ordered {type: [declaration lines]} the module declares itself: included labels the policy lacks."""
    decls: dict[str, list[str]] = {}
    for g in groups:
        t = g.type
        if not (g.include and t) or t in decls:
            continue
        known = kb.has_type(t) if kb is not None else None
        if known or (known is None and t == g.current):
            continue
        macro = next((_pick(kb, names) for suffix, names in _DECL if t.endswith(suffix)), "files_type")
        decls[t] = [f"type {t};", f"{macro}({t})"]
    return decls


def own_access(domain: str, decls) -> list[tuple[str, str, str, str]]:
    """[(src, tgt, class, perm set)] the domain needs on the types this module declares."""
    out = []
    for t in decls:
        for suffixes, rules in _OWN_ACCESS:
            if t.endswith(suffixes):
                out += [(domain, t, cls, name) for cls, name in rules]
                break
    return out


def render_set(kb, name: str) -> str:
    if kb is not None and name in kb.perm_sets:
        return name
    return "{ " + FALLBACK_SETS[name] + " }"


def gen_fc(groups: list[FcGroup]) -> str:
    rows = sorted((g.regex, g.ftype, g.type) for g in groups if g.include and g.type)
    if not rows:
        return "# No file labels: every listed path keeps the label it has.\n"
    width = max(len(r[0]) for r in rows)
    return "".join(f"{regex.ljust(width)}  {ftype:<2}  gen_context(system_u:object_r:{typ},s0)\n"
                   for regex, ftype, typ in rows)


def _iface(name: str, summary: str, require: list[str], body: list[str]) -> list[str]:
    return [
        "########################################",
        "## <summary>", f"##\t{summary}", "## </summary>",
        '## <param name="domain">', "##\t<summary>", "##\tDomain allowed access.", "##\t</summary>", "## </param>",
        "#",
        f"interface(`{name}',`",
        "\tgen_require(`", f"\t\ttype {', '.join(require)};", "\t')", "",
        *("\t" + b for b in body),
        "')", "",
    ]


def gen_if(module: str, program: str, decls, kb) -> str:
    """The module's .if: a read interface for each declared config, log, state, runtime or cache type."""
    out = [f"## <summary>{module}, drafted in Atropa for {program}.</summary>", ""]
    done: set[str] = set()
    for t in decls:
        for suffix, verb, summary, search in _IF_VERBS:
            if not t.endswith(suffix):
                continue
            name = f"{module}_{verb}"
            if name in done:
                name = f"{module}_{verb}_{t[:-2]}"
            done.add(name)
            body = [f"{search}($1)"] if kb is None or kb.has_iface(search) else []
            body += [f"allow $1 {t}:dir list_dir_perms;", f"read_files_pattern($1, {t}, {t})",
                     f"read_lnk_files_pattern($1, {t}, {t})"]
            out += _iface(name, summary % program, [t], body)
            break
    while out and out[-1] == "":
        out.pop()
    return "\n".join(out) + "\n"
