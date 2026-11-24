"""
atropa.backend.m4lite
-----------------------
Just enough m4 to read Reference Policy sources (ported from atropa-scratch).

This is not a general m4. It understands the subset refpolicy uses in
support/*.spt, *.if and *.fc files: define/interface/template bodies,
$N argument substitution, nested quoting, and the handful of control
macros (gen_require, optional_policy, ifdef, ifelse, tunable_policy) that
wrap the rules we care about. The aim is to recover the allow rules an
interface grants so denials can be matched against them.

It only ranks suggestions. Whether a module really compiles is decided by
the policy's own build (policy_draft.build), which runs the real m4.

tunable_policy() blocks are dropped by default: an interface that grants a
permission only while a tunable is on doesn't cover that permission on a
system where the tunable is off, and nothing at compile time would say so.
optional_policy() blocks are kept - the link step catches a missing module.
"""

from __future__ import annotations

import re

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_WORD = re.compile(r"\w+")
_DOLLAR = re.compile(r"\$(\d+|#|\*|@)")
_RULE = re.compile(r"\b(allow|dontaudit|auditallow)\s+([^;]*?)\s*;", re.S)

# Builtins that produce nothing we care about.
_DROP = {
    "gen_require", "require", "refpolicywarn", "refpolicyerr", "gen_tunable",
    "gen_bool", "gen_user", "dnl", "define", "undefine", "divert", "undivert",
    "policy_module", "m4exit", "errprint", "interface", "template",
}

MAX_DEPTH = 40


def strip_comments(text):
    """Drop '#' to end of line (refpolicy never quotes a '#')."""
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def parse_args(text, i):
    """Parse an m4 argument list starting at text[i] == '('.

    Returns (args, index_after_close_paren). One level of quoting is
    stripped from each argument, as m4 does when collecting arguments.
    """
    args, cur = [], []
    depth = quote = 0
    i += 1
    n = len(text)
    while i < n:
        c = text[i]
        if quote:
            if c == "`":
                quote += 1
                cur.append(c)
            elif c == "'":
                quote -= 1
                if quote:
                    cur.append(c)
            else:
                cur.append(c)
        elif c == "`":
            quote = 1
        elif c == "(":
            depth += 1
            cur.append(c)
        elif c == ")":
            if depth == 0:
                args.append("".join(cur).strip())
                return args, i + 1
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    args.append("".join(cur).strip())
    return args, n


def iter_definitions(text, kinds=("define", "interface", "template")):
    """Yield (kind, name, body, offset) for top-level definitions in text."""
    pattern = re.compile(r"\b(" + "|".join(kinds) + r")\(")
    pos = 0
    while True:
        m = pattern.search(text, pos)
        if not m:
            return
        args, end = parse_args(text, m.end() - 1)
        if len(args) >= 2 and _IDENT.fullmatch(args[0]):
            yield m.group(1), args[0], args[1], m.start()
        pos = end if end > m.end() else m.end()


def substitute(body, name, args):
    def repl(m):
        key = m.group(1)
        if key == "#":
            return str(len(args))
        if key in ("*", "@"):
            return ",".join(args)
        idx = int(key)
        if idx == 0:
            return name
        return args[idx - 1] if idx <= len(args) else ""

    return _DOLLAR.sub(repl, body)


class Expander:
    """Expands macro calls in refpolicy text.

    macros: name -> body (one quote level already stripped).
    defined: names that ifdef() should treat as defined (build options).
    """

    def __init__(self, macros, defined=(), tunables=False):
        self.macros = macros
        self.defined = set(defined)
        self.tunables = tunables
        self._memo = {}

    def call(self, name, args, depth=0):
        key = (name, tuple(args))
        hit = self._memo.get(key)
        if hit is not None:
            return hit
        self._memo[key] = ""  # recursion guard
        result = self.expand(substitute(self.macros[name], name, args), depth + 1)
        self._memo[key] = result
        return result

    def _builtin(self, name, args, depth):
        if name in _DROP:
            return ""
        if name == "optional_policy":
            return self.expand(args[0] if args else "", depth + 1)
        if name == "tunable_policy":
            # Only what the interface grants whatever the tunables are set to,
            # unless the caller asked for the "true" branch too.
            if not self.tunables:
                return ""
            return self.expand(args[1] if len(args) > 1 else "", depth + 1)
        if name in ("ifdef", "ifndef"):
            known = args[0] in self.defined or args[0] in self.macros
            if name == "ifndef":
                known = not known
            pick = args[1] if known else (args[2] if len(args) > 2 else "")
            return self.expand(pick, depth + 1)
        if name == "ifelse":
            while len(args) >= 3:
                a = self.expand(args[0], depth + 1).strip()
                b = self.expand(args[1], depth + 1).strip()
                if a == b:
                    return self.expand(args[2], depth + 1)
                if len(args) == 4:
                    return self.expand(args[3], depth + 1)
                args = args[3:]
            return ""
        if name == "gen_context":
            return args[0] if args else ""
        return None

    _BUILTINS = _DROP | {"optional_policy", "tunable_policy", "ifdef", "ifndef", "ifelse", "gen_context"}

    def expand(self, text, depth=0):
        if depth > MAX_DEPTH:
            return ""
        out = []
        i, n = 0, len(text)
        while i < n:
            c = text[i]
            if c == "`":
                # Stray quoted text: strip one level and keep scanning inside.
                q, j = 1, i + 1
                while j < n and q:
                    if text[j] == "`":
                        q += 1
                    elif text[j] == "'":
                        q -= 1
                    j += 1
                out.append(self.expand(text[i + 1:j - 1], depth + 1))
                i = j
                continue
            if c.isalpha() or c == "_":
                m = _IDENT.match(text, i)
                name = m.group(0)
                j = m.end()
                has_args = j < n and text[j] == "("
                if name in self._BUILTINS:
                    args, j = parse_args(text, j) if has_args else ([], j)
                    res = self._builtin(name, args, depth)
                    out.append(res if res is not None else name)
                    i = j
                    continue
                if name in self.macros:
                    args, j = parse_args(text, j) if has_args else ([], j)
                    out.append(self.call(name, args, depth))
                    i = j
                    continue
                out.append(name)
                i = j
                continue
            if c.isdigit():
                m = _WORD.match(text, i)
                out.append(m.group(0))
                i = m.end()
                continue
            out.append(c)
            i += 1
        return "".join(out)


def _take_set(s, i):
    """Read one rule field (a word or a {...} set) starting at s[i]."""
    n = len(s)
    while i < n and s[i].isspace():
        i += 1
    if i < n and s[i] == "{":
        depth, j = 0, i
        while j < n:
            if s[j] == "{":
                depth += 1
            elif s[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        words = s[i + 1:j].replace("{", " ").replace("}", " ").split()
        return words, j + 1
    j = i
    while j < n and not s[j].isspace() and s[j] != ":":
        j += 1
    return [s[i:j]] if j > i else [], j


def parse_rule_body(body):
    """'src tgt:cls perms' -> (srcs, tgts, classes, perms) or None."""
    srcs, i = _take_set(body, 0)
    tgts, i = _take_set(body, i)
    while i < len(body) and body[i].isspace():
        i += 1
    if i >= len(body) or body[i] != ":":
        return None
    classes, i = _take_set(body, i + 1)
    perms, i = _take_set(body, i)
    if not (srcs and tgts and classes and perms):
        return None
    return srcs, tgts, classes, perms


def extract_rules(text):
    """Yield (kind, src, tgt, cls, perms) for every AV rule in expanded text."""
    for m in _RULE.finditer(text):
        parsed = parse_rule_body(m.group(2))
        if not parsed:
            continue
        srcs, tgts, classes, perms = parsed
        if any(p in ("*", "~") or p.startswith("~") or p.startswith("-") for p in perms):
            continue
        for s in srcs:
            for t in tgts:
                for c in classes:
                    yield m.group(1), s, t, c, frozenset(perms)
