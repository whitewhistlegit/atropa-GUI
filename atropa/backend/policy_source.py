"""
atropa.backend.policy_source
------------------------------
Which Reference Policy source describes the policy this machine runs, and
what it knows: classes, permission sets, types, and the allow rules each
interface grants. Ported from atropa-scratch's policydb, for the SELinux
Dev page.

A module drafted with interfaces has to be compiled against the source of
the policy it will be loaded into. Interface names, permission sets and m4
build options differ between trees (refpolicy-arch, refpolicy-atropa,
Fedora's selinux-policy, a user's own fork), so a source is only used when
its name matches the running policy (SELINUXTYPE in /etc/selinux/config):

1. a source tree whose build.conf NAME is the running policy's name - a
   tree the user picked, or Atropa's own download (ATROPA_POLICY_DIR);
2. otherwise /usr/share/selinux/<SELINUXTYPE>/include, the policy's
   installed headers, if that package ships them;
3. otherwise nothing: no suggestions, and the Denials page's plain
   audit2allow drafts stay the only option.

Another policy's headers are never used as a stand-in. On an Atropa
install, /usr/share/selinux/refpolicy-arch/include exists while the running
policy is atropa-refpolicy, which ships no headers; compiling against the
former would check interfaces the running policy may not have.

A parsed source is cached as a pickle under ~/.cache/atropa/policy-source,
keyed by the size and mtime of every file it read. The cache is only ever
written by Atropa into the user's own 0700 directory, so it sits inside the
same trust boundary as the code that reads it.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import pickle
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import m4lite, refpolicy_build

SELINUX_CONFIG = Path("/etc/selinux/config")
SHARE_DIR = Path("/usr/share/selinux")
SELINUXFS_CLASSES = Path("/sys/fs/selinux/class")
CACHE_DIR = Path.home() / ".cache" / "atropa" / "policy-source"
CACHE_VERSION = 1
# Source trees the user picked on the Dev page, most recent first.
TREES_FILE = Path.home() / ".local" / "share" / "atropa" / "selinux-review" / "policy-trees.json"
# Interfaces whose expansion grants more distinct (target, class) pairs than
# this are broad role/admin templates, never a tight match for one denial.
MAX_IFACE_RULES = 40

_TYPE_DECL = re.compile(r"^\s*type\s+(\w+)", re.M)
_ATTR_DECL = re.compile(r"^\s*attribute\s+(\w+)\s*;", re.M)
_ALIAS_DECL = re.compile(r"\balias\s+(?:\{([^}]*)\}|(\w+))")
_SUMMARY = re.compile(r"<summary>\s*(.*?)\s*</summary>", re.S)
# build.conf is make syntax: "NAME = x", "NAME ?= x", "override NAME := x".
_CONF_LINE = re.compile(r"^\s*(?:override\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[?:+]?=\s*(.*?)\s*$")


@dataclass
class Interface:
    name: str
    module: str
    summary: str
    rules: dict  # (target, class) -> frozenset(perms) granted to $1 ("self" for $1 itself)
    total: int  # permissions granted across every rule


@dataclass
class PolicySource:
    """Where policy knowledge comes from, and whether it's the running policy's."""

    kind: str  # "tree", "headers" or "none"
    root: str = ""
    name: str = ""  # the policy name the source builds (build.conf NAME, or the headers' dir name)
    running: str = ""  # SELINUXTYPE
    note: str = ""  # one line for the page: why this source, or why none

    @property
    def usable(self) -> bool:
        return self.kind != "none"


@dataclass
class PolicyKB:
    source: PolicySource
    classes: dict = field(default_factory=dict)  # class -> [perms]
    perm_sets: dict = field(default_factory=dict)  # name -> frozenset(perms)
    perm_set_class: dict = field(default_factory=dict)  # name -> owning class, "*socket" or None
    types: set = field(default_factory=set)  # from a tree's .te files; empty for headers
    attributes: set = field(default_factory=set)
    interfaces: dict = field(default_factory=dict)  # name -> Interface
    iface_index: dict = field(default_factory=dict)  # (target, class) -> [interface names]
    iface_names: set = field(default_factory=set)  # every interface/template, single-argument or not
    module_names: set = field(default_factory=set)
    m4params: list = field(default_factory=list)
    mls: bool = False

    # -- queries -----------------------------------------------------------

    def has_iface(self, name: str) -> bool:
        return name in self.iface_names

    def has_type(self, name: str) -> bool | None:
        """True/False, or None when this source has no type list (headers)."""
        if not self.types:
            return None
        return name in self.types or name in self.attributes

    def perms_for(self, cls: str) -> list | None:
        return self.classes.get(cls)

    def perm_sets_for(self, cls: str) -> list[tuple[str, frozenset]]:
        """Permission sets that belong to `cls`, smallest first."""
        perms = self.classes.get(cls)
        owned = any(_owns(o, cls) for o in self.perm_set_class.values())
        out = []
        for name, ps in self.perm_sets.items():
            owner = self.perm_set_class.get(name)
            if not _owns(owner, cls):
                # Only a class with no sets of its own borrows the unnamed ones.
                if owner is not None or owned or not perms or name.startswith("all_"):
                    continue
            if perms and not ps <= set(perms):
                continue
            out.append((name, ps))
        out.sort(key=lambda x: (len(x[1]), x[0]))
        return out

    def perm_set_name(self, cls: str, perms) -> str | None:
        """The name of a set that is exactly `perms`, if the policy has one."""
        perms = frozenset(perms)
        for name, ps in self.perm_sets_for(cls):
            if ps == perms and not name.startswith("all_"):  # "all_x_perms" reads as "everything", not these
                return name
        return None

    def suggest_interfaces(self, src: str, tgt: str, cls: str, perms, limit: int = 6) -> list[tuple[str, int]]:
        """
        Interfaces that grant src at least `perms` on tgt:cls, tightest first,
        as (name, extra) - extra being how many more permissions the interface
        grants in all, on this target and any other.
        """
        key = ("self", cls) if tgt in (src, "self") else (tgt, cls)
        perms = frozenset(perms)
        found = []
        for name in self.iface_index.get(key, ()):
            iface = self.interfaces[name]
            if perms <= iface.rules[key]:
                found.append((iface.total - len(perms), len(name), name))
        found.sort()
        return [(name, extra) for extra, _, name in found[:limit]]


def _owns(owner, cls: str) -> bool:
    return owner == cls or (owner == "*socket" and cls.endswith("socket"))


# -- choosing a source ---------------------------------------------------------

def saved_trees() -> list[str]:
    try:
        data = json.loads(TREES_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [p for p in data if isinstance(p, str)] if isinstance(data, list) else []


def remember_tree(path: str) -> str:
    """Put a picked tree first in the saved list. Raises ValueError if it isn't a tree or headers dir."""
    kind, root = detect_layout(path)
    if kind is None:
        raise ValueError(f"{path} isn't a Reference Policy source tree or headers directory")
    trees = [root, *(p for p in saved_trees() if p != root)][:8]
    TREES_FILE.parent.mkdir(parents=True, exist_ok=True)
    TREES_FILE.write_text(json.dumps(trees, indent=2) + "\n", encoding="utf-8")
    return root


def parse_build_conf(path) -> dict[str, str]:
    """
    build.conf's settings. Distro headers write make's conditional and
    override forms (DISTRO ?= arch, override UBAC := n), not only NAME = x;
    reading those as plain "=" lines lost DISTRO and SYSTEMD, so interfaces
    that branch on distro_arch or init_systemd were read down the wrong
    branch.
    """
    conf: dict[str, str] = {}
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return conf
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        m = _CONF_LINE.match(line)
        if m:
            conf[m.group(1)] = m.group(2)
    return conf


def running_policy_name(config: Path = SELINUX_CONFIG) -> str:
    return parse_build_conf(config).get("SELINUXTYPE", "")


def detect_layout(root: str) -> tuple[str | None, str]:
    """("tree" | "headers" | None, normalised root) for a picked directory."""
    root = os.path.abspath(os.path.expanduser(root))
    if os.path.isdir(os.path.join(root, "policy/modules")) and \
            os.path.isfile(os.path.join(root, "policy/flask/access_vectors")):
        return "tree", root
    if os.path.isdir(os.path.join(root, "modules")) and os.path.isfile(os.path.join(root, "flask/access_vectors")):
        return "tree", os.path.dirname(root)  # picked the tree's policy/ dir
    if os.path.isfile(os.path.join(root, "support/obj_perm_sets.spt")):
        return "headers", root
    if os.path.isfile(os.path.join(root, "include/support/obj_perm_sets.spt")):
        return "headers", os.path.join(root, "include")
    return None, root


def source_name(kind: str, root: str) -> str:
    """The policy name a source builds: build.conf NAME, else the headers' parent dir."""
    name = parse_build_conf(os.path.join(root, "build.conf")).get("NAME", "")
    if not name and kind == "headers":
        name = os.path.basename(os.path.dirname(root.rstrip("/")))
    return name


def find_source(trees: list[str] | None = None, running: str | None = None,
                share_dir: Path | None = None) -> PolicySource:
    """
    The source to use for the running policy, per the module docstring.
    `trees` are directories the user picked (saved_trees() when None), tried
    before Atropa's download.
    """
    running = running_policy_name() if running is None else running
    trees = saved_trees() if trees is None else trees
    share_dir = SHARE_DIR if share_dir is None else share_dir
    if not running:
        return PolicySource("none", note="No SELINUXTYPE in /etc/selinux/config")
    mismatched = []
    for candidate in [*trees, str(refpolicy_build.ATROPA_POLICY_DIR)]:
        kind, root = detect_layout(candidate)
        if kind is None:
            continue
        name = source_name(kind, root)
        if name == running:
            return PolicySource(kind, root, name, running, f"{root} builds {running}, the running policy")
        mismatched.append(f"{root} ({name or 'no NAME'})")
    headers = share_dir / running / "include"
    if (headers / "Makefile").is_file():
        return PolicySource("headers", str(headers), running, running, f"Installed headers for {running}")
    others = sorted(str(p.parent) for p in share_dir.glob("*/include") if p.parent.name != running)
    why = [f"No source for {running}, the running policy"]
    if mismatched:
        why.append("not used, another policy: " + ", ".join(mismatched))
    if others:
        why.append("headers for other policies not used: " + ", ".join(others))
    return PolicySource("none", running=running, note="; ".join(why))


# -- loading -------------------------------------------------------------------

def _read(path) -> str:
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _signature(files) -> str:
    h = hashlib.sha1(str(CACHE_VERSION).encode())
    for p in sorted(files):
        try:
            st = os.stat(p)
        except OSError:
            continue
        h.update(f"{p}:{st.st_mtime_ns}:{st.st_size};".encode())
    return h.hexdigest()


def m4_defines(conf: dict) -> tuple[set, list]:
    """Build options as (ifdef names, m4 -D arguments), mirroring refpolicy's Makefile."""
    names, params = set(), []

    def d(name, value="true"):
        names.add(name)
        params.append(f"-D{name}={value}")

    typ = conf.get("TYPE", "standard")
    if typ == "mls":
        d("enable_mls")
    if typ == "mcs":
        d("enable_mcs")
    distro = conf.get("DISTRO", "")
    if distro:
        d("distro_" + distro)
        if distro == "ubuntu":
            d("distro_debian")
    if conf.get("SYSTEMD", "n") == "y":
        d("init_systemd")
    for opt in conf.get("CUSTOM_BUILDOPT", "").split():
        d(opt)
    if conf.get("DIRECT_INITRC", "n") == "y":
        d("direct_sysadm_daemon")
    if conf.get("WERROR", "n") == "y":
        d("m4_werror")
    if conf.get("UBAC", "n") == "y":
        d("enable_ubac")
    d("mls_num_sens", conf.get("MLS_SENS", "16"))
    d("mls_num_cats", conf.get("MLS_CATS", "1024"))
    d("mcs_num_cats", conf.get("MCS_CATS", "1024"))
    return names, params


def parse_access_vectors(text: str) -> dict[str, list[str]]:
    """{class: [perms]} from a flask access_vectors file."""
    text = m4lite.strip_comments(text)
    commons, classes = {}, {}
    for m in re.finditer(r"\b(common|class)\s+(\w+)(?:\s+inherits\s+(\w+))?\s*(?:\{([^}]*)\})?", text):
        kind, name, inherits, body = m.groups()
        perms = body.split() if body else []
        if kind == "common":
            commons[name] = perms
        else:
            classes[name] = (commons.get(inherits, []) if inherits else []) + perms
    return classes


def running_classes(root: Path | None = None) -> dict[str, list[str]]:
    """
    {class: [perms]} of the loaded policy, from selinuxfs - readable without
    root. Headers ship no flask files, and their policy is the running one.
    """
    root = SELINUXFS_CLASSES if root is None else root
    classes = {}
    try:
        for entry in root.iterdir():
            try:
                classes[entry.name] = sorted(p.name for p in (entry / "perms").iterdir())
            except OSError:
                continue
    except OSError:
        pass
    return classes


def _load_support(kb: PolicyKB, spt_files, defined) -> dict:
    macros = {}
    for path in spt_files:
        for _, name, body, _ in m4lite.iter_definitions(m4lite.strip_comments(_read(path)), ("define",)):
            macros[name] = body
    exp = m4lite.Expander(macros, defined)
    for name in macros:
        if not name.endswith("_perms"):
            continue
        words = exp.expand(name).replace("{", " ").replace("}", " ").split()
        if words and all(re.fullmatch(r"\w+", w) for w in words):
            kb.perm_sets[name] = frozenset(words)
    return macros


def _scan_te(kb: PolicyKB, te_files) -> None:
    for path in te_files:
        text = m4lite.strip_comments(_read(path))
        kb.module_names.add(os.path.basename(path)[:-3])
        kb.types.update(t for t in _TYPE_DECL.findall(text) if "$" not in t)
        for line in re.findall(r"^\s*(?:type|typealias)\b[^;]*;", text, re.M):
            for group, single in _ALIAS_DECL.findall(line):
                kb.types.update(group.split() if group else [single])
        kb.attributes.update(_ATTR_DECL.findall(text))


def _load_interfaces(kb: PolicyKB, macros: dict, if_files, defined) -> None:
    meta = {}
    for path in if_files:
        raw = _read(path)
        module = os.path.basename(path)[:-3]
        kb.module_names.add(module)
        # Summaries live in the ## comment block right above each definition.
        for m in re.finditer(r"((?:^##[^\n]*\n)+)(?:#\s*\n)?(interface|template)\(`(\w+)'", raw, re.M):
            sm = _SUMMARY.search(m.group(1).replace("##", ""))
            meta[m.group(3)] = [module, " ".join(sm.group(1).split()) if sm else "", m.group(2)]
        for kind, name, body, _ in m4lite.iter_definitions(m4lite.strip_comments(raw), ("interface", "template")):
            macros[name] = body
            kb.iface_names.add(name)
            meta.setdefault(name, [module, "", kind])[2] = kind

    exp = m4lite.Expander(macros, defined)
    for name, (module, summary, kind) in meta.items():
        if kind != "interface" or name not in macros:
            continue
        nums = [int(x) for x in re.findall(r"\$(\d+)", macros[name])]
        if not nums or max(nums) != 1:
            continue  # only single-argument interfaces: name(domain)
        try:
            text = exp.call(name, ["__src__"])
        except RecursionError:
            continue
        rules = {}
        for rule_kind, s, t, c, perms in m4lite.extract_rules(text):
            if rule_kind != "allow" or s != "__src__":
                continue
            key = ("self" if t in ("self", "__src__") else t, c)
            rules[key] = rules.get(key, frozenset()) | perms
        if not rules or len(rules) > MAX_IFACE_RULES:
            continue
        kb.interfaces[name] = Interface(name, module, summary, rules, sum(len(p) for p in rules.values()))
        for key in rules:
            kb.iface_index.setdefault(key, []).append(name)


def _assign_perm_set_classes(kb: PolicyKB, class_names) -> None:
    names = sorted(class_names, key=len, reverse=True)
    for set_name in kb.perm_sets:
        owner = next((c for c in names if set_name.endswith("_" + c + "_perms") or set_name == c + "_perms"), None)
        if owner is None and set_name.endswith("socket_perms"):
            owner = "*socket"
        kb.perm_set_class[set_name] = owner


def load(source: PolicySource, use_cache: bool = True) -> PolicyKB:
    """Parse a source (see find_source), from the cache when nothing it read has changed."""
    if not source.usable:
        raise ValueError(source.note or "No policy source")
    root = source.root
    if source.kind == "tree":
        pol = os.path.join(root, "policy")
        spt = sorted(glob.glob(os.path.join(pol, "support/*.spt")))
        if_files = sorted(glob.glob(os.path.join(pol, "modules/*/*.if")))
        te_files = sorted(glob.glob(os.path.join(pol, "modules/*/*.te")))
        av = os.path.join(pol, "flask/access_vectors")
        sig_files = spt + if_files + te_files + [av]
    else:
        spt = sorted(glob.glob(os.path.join(root, "support/*.spt")))
        if_files = sorted(glob.glob(os.path.join(root, "*/*.if")))
        te_files, av = [], None
        sig_files = spt + if_files
    conf_path = os.path.join(root, "build.conf")
    sig = _signature(sig_files + [conf_path])
    cache_file = CACHE_DIR / f"kb-{hashlib.sha1(root.encode()).hexdigest()[:16]}.pickle"
    if use_cache:
        try:
            # Safe to unpickle: only Atropa writes this file, 0600 in the
            # user's own 0700 cache dir (see the module docstring).
            with open(cache_file, "rb") as f:
                cached_sig, kb = pickle.load(f)
            if cached_sig == sig and isinstance(kb, PolicyKB):
                kb.source = source
                return kb
        except Exception:  # noqa: BLE001 - a missing or stale cache is rebuilt
            pass

    conf = parse_build_conf(conf_path)
    defined, params = m4_defines(conf)
    kb = PolicyKB(source=source, m4params=params, mls=conf.get("TYPE") in ("mls", "mcs"))
    kb.classes = parse_access_vectors(_read(av)) if av else running_classes()
    macros = _load_support(kb, spt, defined)
    _scan_te(kb, te_files)
    _load_interfaces(kb, dict(macros), if_files, defined)
    _assign_perm_set_classes(kb, kb.classes)

    try:
        CACHE_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
        tmp = cache_file.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            pickle.dump((sig, kb), f, protocol=pickle.HIGHEST_PROTOCOL)
        os.replace(tmp, cache_file)
    except OSError:
        pass
    return kb
