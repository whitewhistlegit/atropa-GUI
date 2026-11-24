"""
atropa.backend.policy_draft
-----------------------------
Refpolicy-style drafts for the SELinux Dev page, ported from atropa-scratch.

Denial lines become one rule per (source, target, class), permissions
merged. Each rule is written as a plain allow, a dontaudit, an interface
call the policy source offers, or skipped; the module comes out as
policy_module()/gen_require() text, which only the policy's own build can
compile. build() runs that build - the tree's own m4 -> checkmodule ->
semodule_package steps plus a link against every module the tree built, or
the installed headers' Makefile - in a private temp dir. Nothing here needs
root or touches the loaded policy.
"""

from __future__ import annotations

import glob
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field

from .policy_source import PolicyKB

ALLOW, IFACE, DONTAUDIT, SKIP = "allow", "iface", "dontaudit", "skip"
DECISIONS = (ALLOW, IFACE, DONTAUDIT, SKIP)

_AVC = re.compile(r"avc:\s+denied\s+\{([^}]*)\}\s+for\s+(.*)")
_FIELD = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_MODULE_NAME = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")


@dataclass
class Rule:
    src: str
    tgt: str  # "self" when the target is the source domain
    tclass: str
    perms: frozenset
    count: int = 0
    programs: list = field(default_factory=list)  # comm= names
    path: str = ""  # a sample path= or name=
    decision: str = ALLOW
    iface: str = ""
    choices: list = field(default_factory=list)  # [(interface, extra perms)], tightest first
    perm_set: str = ""  # a policy set that is exactly perms
    coverage: str | None = None  # None unchecked, "" not granted, "allowed", or "boolean:a,b" (granted when on)
    declared: bool = False  # added from the path explorer, not from a denial

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.src, self.tgt, self.tclass)


def _ctype(context: str) -> str:
    bits = context.split(":")
    return bits[2] if len(bits) >= 3 else ""


def rules_from_denials(lines: list[str]) -> dict[str, list[Rule]]:
    """{source domain: [Rule]} from AVC denial lines (journal or audit log), merged per target and class."""
    rules: dict[tuple, Rule] = {}
    for line in lines:
        m = _AVC.search(line)
        if not m:
            continue
        fields = {k: v.strip("\"'") for k, v in _FIELD.findall(m.group(2))}
        src, tgt, cls = _ctype(fields.get("scontext", "")), _ctype(fields.get("tcontext", "")), fields.get("tclass", "")
        if not (_IDENT.match(src or "-") and _IDENT.match(tgt or "-") and _IDENT.match(cls or "-")):
            continue
        key = (src, "self" if tgt == src else tgt, cls)
        rule = rules.get(key)
        if rule is None:
            rule = rules[key] = Rule(src, key[1], cls, frozenset())
        rule.perms = rule.perms | frozenset(m.group(1).split())
        rule.count += 1
        comm = fields.get("comm", "")
        if comm and comm not in rule.programs:
            rule.programs.append(comm)
        rule.path = rule.path or fields.get("path", "") or fields.get("name", "")
    by_domain: dict[str, list[Rule]] = {}
    for rule in sorted(rules.values(), key=lambda r: (r.src, r.tgt, r.tclass)):
        by_domain.setdefault(rule.src, []).append(rule)
    return by_domain


def annotate(rules: list[Rule], kb: PolicyKB) -> None:
    """Attach the policy's interface choices and permission-set name to each rule."""
    for rule in rules:
        rule.choices = kb.suggest_interfaces(rule.src, rule.tgt, rule.tclass, rule.perms)
        rule.perm_set = kb.perm_set_name(rule.tclass, rule.perms) or ""
        if rule.decision == IFACE and rule.iface not in [n for n, _ in rule.choices]:
            rule.decision, rule.iface = ALLOW, ""


# An interface may grant at most this many permissions beyond the denial
# before "Use the policy source" picks it.
TIGHT_EXTRA = 12


def use_tight_interfaces(rules: list[Rule]) -> int:
    """
    "Use the policy source": skip each rule the source's compiled policy
    already allows, and switch each remaining allow rule with a close-fitting
    interface to it. Returns how many rules changed.
    """
    changed = 0
    for rule in rules:
        if rule.coverage == "allowed" and rule.decision != SKIP:
            rule.decision, rule.iface = SKIP, ""
            changed += 1
        elif rule.decision == ALLOW and rule.choices and rule.choices[0][1] <= TIGHT_EXTRA:
            rule.decision, rule.iface = IFACE, rule.choices[0][0]
            changed += 1
    return changed


def policy_checker(source, runtime: dict[str, bool]):
    """
    A denial_advice.PolicyChecker for the source's compiled policy (see
    policy_source.compiled_policy), or None: no setools, a tree not built
    yet, or a policy file setools can't read. `runtime` is the running
    booleans' values, for rules behind a boolean.
    """
    from . import denial_advice, policy_source

    path = policy_source.compiled_policy(source)
    if path is None:
        return None
    try:
        import setools

        policy = setools.SELinuxPolicy(path) if path else setools.SELinuxPolicy()
        return denial_advice.PolicyChecker(runtime, policy=policy, setools_module=setools)
    except Exception:  # noqa: BLE001 - optional: ImportError, an unreadable policy, ...
        return None


def check_coverage(rules: list[Rule], checker) -> None:
    """Fill rule.coverage for rules not checked yet. Each lookup costs ~0.25 s: run it off the main thread."""
    for rule in rules:
        if rule.coverage is not None:
            continue
        verdict = checker.check(rule.src, rule.src if rule.tgt == "self" else rule.tgt, rule.tclass,
                                sorted(rule.perms))
        if verdict.status == "allowed":
            rule.coverage = "allowed"
        elif verdict.status == "boolean":
            rule.coverage = "boolean:" + ",".join(verdict.booleans)
        else:
            rule.coverage = ""


# What a path picked in the explorer gets by default: read it (or search a directory).
DEFAULT_PERMS = {
    "file": {"getattr", "open", "read"},
    "dir": {"getattr", "search", "open", "read"},
    "lnk_file": {"getattr", "read"},
    "sock_file": {"getattr", "write"},
    "fifo_file": {"getattr", "open", "read"},
    "chr_file": {"getattr", "open", "read"},
    "blk_file": {"getattr", "open", "read"},
}


def class_for_mode(mode: int) -> str:
    return {
        stat.S_IFDIR: "dir", stat.S_IFREG: "file", stat.S_IFLNK: "lnk_file", stat.S_IFSOCK: "sock_file",
        stat.S_IFIFO: "fifo_file", stat.S_IFCHR: "chr_file", stat.S_IFBLK: "blk_file",
    }.get(stat.S_IFMT(mode), "file")


def actual_label(path: str) -> str:
    """The type a path carries now ("" if unreadable)."""
    try:
        raw = os.getxattr(path, "security.selinux", follow_symlinks=False)
        return raw.rstrip(b"\0").decode().split(":")[2]
    except (OSError, IndexError, UnicodeDecodeError):
        return ""


def rule_for_path(path: str, domain: str) -> Rule | None:
    """A read rule for a path the program will need but no test run touched (the explorer's picks)."""
    from .policy_fc import system_label

    try:
        st = os.lstat(path)
    except OSError:
        return None
    cls = class_for_mode(st.st_mode)
    tgt = actual_label(path) or system_label(path, "d" if cls == "dir" else "f") or "unlabeled_t"
    if not _IDENT.match(tgt):
        return None
    return Rule(domain, "self" if tgt == domain else tgt, cls, frozenset(DEFAULT_PERMS.get(cls, {"getattr"})),
                path=path, declared=True)


def merge_rules(rules: list[Rule], new: list[Rule]) -> int:
    """Add `new` to `rules`, unioning permissions into an existing (target, class) rule. Returns how many were added."""
    index = {r.key: r for r in rules}
    added = 0
    for rule in new:
        old = index.get(rule.key)
        if old is None:
            rules.append(rule)
            index[rule.key] = rule
            added += 1
        elif not rule.perms <= old.perms:
            old.perms = old.perms | rule.perms
            old.coverage, old.perm_set = None, ""
    return added


def module_name_for(domain: str, kb: PolicyKB | None = None) -> str:
    stem = re.sub(r"[^a-z0-9_]", "_", domain.lower().removesuffix("_t")).strip("_") or "program"
    name = f"atropa_dev_{stem}"[:63]
    if kb is not None and name in kb.module_names:
        name = f"{name[:57]}_local"
    return name


def render_perms(perms, set_name: str = "") -> str:
    if set_name:
        return set_name
    ps = sorted(perms)
    return ps[0] if len(ps) == 1 else "{ " + " ".join(ps) + " }"


def gen_te(module: str, rules: list[Rule], decls: dict | None = None, own: list | None = None) -> str:
    """
    The module's .te in refpolicy style. `decls` ({type: [lines]}) are types
    the module declares itself and `own` ([(src, tgt, class, perms text)])
    the access its program needs on them - policy_fc's file labels.
    """
    if not _MODULE_NAME.match(module):
        raise ValueError(f"{module!r} isn't a valid module name")
    decls, own = decls or {}, own or []
    plain, calls, used = [], [], {src for src, _, _, _ in own}
    for rule in rules:
        if rule.decision == SKIP:
            continue
        used.add(rule.src)
        if rule.decision == IFACE and rule.iface:
            call = f"{rule.iface}({rule.src})"
            if call not in calls:
                calls.append(call)
            continue
        if rule.tgt != "self":
            used.add(rule.tgt)
        kind = "dontaudit" if rule.decision == DONTAUDIT else "allow"
        plain.append((kind != "allow", f"{kind} {rule.src} {rule.tgt}:{rule.tclass} "
                                       f"{render_perms(rule.perms, rule.perm_set)};"))
    out = [f"policy_module({module}, 1.0.0)", ""]
    required = sorted(t for t in used if t not in decls)
    if required:
        out += ["gen_require(`", "\ttype " + ", ".join(required) + ";", "')", ""]
    for lines in decls.values():
        out += lines
    if decls:
        out.append("")
    if own:
        out += [f"allow {src} {tgt}:{cls} {perms};" for src, tgt, cls, perms in own] + [""]
    out += [text for _, text in sorted(plain)]
    if plain and calls:
        out.append("")
    out += sorted(calls)
    while out and out[-1] == "":
        out.pop()
    return "\n".join(out) + "\n"


def gen_fc(module: str) -> str:
    return f"# {module} labels no files.\n"


def gen_if(module: str) -> str:
    return f"## <summary>{module}, drafted in Atropa from SELinux denials.</summary>\n"


# -- building ------------------------------------------------------------------

@dataclass
class Step:
    name: str
    ok: bool
    output: str = ""


@dataclass
class BuildResult:
    ok: bool
    steps: list = field(default_factory=list)
    workdir: str = ""

    @property
    def summary(self) -> str:
        if self.ok:
            return "Builds: " + ", ".join(s.name for s in self.steps)
        failed = next((s for s in self.steps if not s.ok), Step("build", False))
        first = next((ln for ln in failed.output.splitlines() if ln.strip()), "")
        return f"{failed.name} failed" + (f": {first[:160]}" if first else "")

    def log(self) -> str:
        parts = []
        for s in self.steps:
            parts.append(("✓ " if s.ok else "✗ ") + s.name)
            if s.output.strip():
                parts.append(s.output.rstrip())
            parts.append("")
        return "\n".join(parts)


def _run(argv, cwd, stdout_path=None, timeout=300) -> tuple[bool, str]:
    try:
        if stdout_path:
            with open(stdout_path, "w") as out:
                p = subprocess.run(argv, cwd=cwd, stdout=out, stderr=subprocess.PIPE, text=True, timeout=timeout)
            return p.returncode == 0, p.stderr
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, p.stdout + p.stderr
    except FileNotFoundError as exc:
        return False, f"{exc.filename}: not installed"
    except subprocess.TimeoutExpired:
        return False, "timed out: " + " ".join(argv[:3])


def _build_tree(kb: PolicyKB, mod: str, wd: str, steps: list) -> bool:
    root = kb.source.root
    gd = os.path.join(root, "tmp/generated_definitions.conf")
    ai = os.path.join(root, "tmp/all_interfaces.conf")
    missing = [os.path.relpath(p, root) for p in (gd, ai) if not os.path.isfile(p)]
    if missing:
        steps.append(Step("tree build files", False,
                          f"missing {', '.join(missing)} - build the tree once (SELinux: Build Policy) first"))
        return False
    sup = os.path.join(root, "support")
    spt = sorted(glob.glob(os.path.join(root, "policy/support/*.spt")))
    m4support = [os.path.join(sup, "divert.m4"), *spt, os.path.join(sup, "undivert.m4")]
    m4 = ["m4", "-E", "-E", *kb.m4params]
    checkmodule = ["checkmodule", *(["-M"] if kb.mls else [])]

    ok, err = _run([*m4, "-s", *m4support, gd, ai, mod + ".te", os.path.join(sup, "fatal_error.m4")],
                   wd, os.path.join(wd, mod + ".tmp"))
    steps.append(Step(f"m4 {mod}.te", ok, err))
    if not ok:
        return False
    ok, out = _run([*checkmodule, "-m", mod + ".tmp", "-o", mod + ".mod"], wd)
    steps.append(Step("checkmodule", ok, "" if ok else out))
    if not ok:
        return False
    ok, err = _run([*m4, *m4support, mod + ".fc"], wd, os.path.join(wd, mod + ".mod.fc"))
    steps.append(Step(f"m4 {mod}.fc", ok, err))
    if not ok:
        return False
    ok, out = _run(["semodule_package", "-o", mod + ".pp", "-m", mod + ".mod", "-f", mod + ".mod.fc"], wd)
    steps.append(Step("semodule_package", ok, out))
    if not ok:
        return False

    base = os.path.join(root, "base.pp")
    if not os.path.isfile(base):
        steps.append(Step("link", True, "the tree has no base.pp yet: skipped the link against its modules"))
        return True
    others = sorted(p for p in glob.glob(os.path.join(root, "*.pp"))
                    if os.path.basename(p) not in ("base.pp", mod + ".pp"))
    linked, expanded = os.path.join(wd, "linked.pp"), os.path.join(wd, "expanded.policy")
    ok, out = _run(["semodule_link", "-o", linked, base, *others, mod + ".pp"], wd)
    if ok:
        ok, out = _run(["semodule_expand", linked, expanded], wd)
    out = "\n".join(ln for ln in out.splitlines() if "loading package" not in ln)
    steps.append(Step(f"link against {len(others) + 1} tree modules", ok, out))
    for p in (linked, expanded):
        if os.path.exists(p):
            os.unlink(p)
    return ok


def _build_headers(kb: PolicyKB, mod: str, wd: str, steps: list) -> bool:
    # The Makefile finds its headers through SELINUXTYPE unless told: name
    # the ones find_source() chose (Fedora's live under .../devel/include).
    makefile = os.path.join(kb.source.root, "Makefile")
    ok, out = _run(["make", "-f", makefile, f"HEADERDIR={kb.source.root}", f"NAME={kb.source.name}", mod + ".pp"], wd)
    steps.append(Step(f"make -f {makefile}", ok, out))
    return ok


def build(module: str, te: str, kb: PolicyKB, workdir: str | None = None, fc: str | None = None,
          if_text: str | None = None) -> BuildResult:
    """Compile (and for a tree, link) the module without installing anything."""
    if not _MODULE_NAME.match(module):
        raise ValueError(f"{module!r} isn't a valid module name")
    wd = workdir or tempfile.mkdtemp(prefix="atropa-dev-")
    os.makedirs(wd, exist_ok=True)
    for ext, text in (("te", te), ("fc", fc or gen_fc(module)), ("if", if_text or gen_if(module))):
        with open(os.path.join(wd, f"{module}.{ext}"), "w", encoding="utf-8") as f:
            f.write(text)
    steps: list[Step] = []
    ok = _build_tree(kb, module, wd, steps) if kb.source.kind == "tree" else _build_headers(kb, module, wd, steps)
    ok = ok and os.path.isfile(os.path.join(wd, module + ".pp"))
    return BuildResult(ok, steps, wd)
