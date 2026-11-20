"""
atropa.backend.denial_advice
--------------------------------
Judgment on top of audit2allow, for SELinux Denial Review.

audit2allow turns any denial into an allow rule. That is the right answer
for a genuinely missing rule and the wrong one for three common cases, each
of which weakens the policy if the draft is installed as is:

- known noise: a program probes for something it doesn't need (net_admin
  for a socket buffer size, nss-systemd asking homed about every user, the
  process-state bits a domain transition clears on purpose). The fix is
  `dontaudit`, not `allow`.
- a missing label: the file has no proper type, or a helper lives where the
  policy doesn't expect it (/usr/lib vs /usr/libexec on Arch). The fix is a
  file context or restorecon.
- a boolean: the loaded policy already has the rule, behind a boolean that's
  off. Turning the boolean on is the policy's own answer - and the page says
  how much else it switches on.

It also checks the loaded policy for rules that already allow a denial (the
denial is then about labels, constraints, or from before a policy change),
and flags drafted rules that can't work on their own.

The policy lookups use setools' Python API (the library behind sesearch),
which loads the running policy once; without setools those checks are
skipped and the review behaves as before.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ------------------------------------------------------------------- noise --


@dataclass(frozen=True)
class NoisePattern:
    tclass: str
    perms: frozenset[str]  # a denial matches when all its permissions are in here
    tcontext: frozenset[str] | None  # None: any target
    reason: str


NOISE = (
    NoisePattern(
        "process", frozenset({"siginh", "rlimitinh", "noatsecure"}), None,
        "a domain transition clearing inherited signals, limits and environment on purpose - refpolicy "
        "dontaudits these",
    ),
    NoisePattern(
        "capability", frozenset({"net_admin"}), None,
        "usually a socket buffer-size probe (SO_RCVBUFFORCE); the program falls back without it",
    ),
    NoisePattern(
        "sock_file", frozenset({"read", "write", "getattr", "open"}),
        frozenset({"systemd_homed_runtime_t", "systemd_nsresourced_runtime_t", "systemd_userdbd_runtime_t"}),
        "nss-systemd asking systemd-homed/userdb about users; harmless when those services aren't in use",
    ),
)


def noise_reason(tcontext: str, tclass: str, perms: list[str]) -> str | None:
    """Why this denial is known noise, or None when it isn't."""
    wanted = set(perms)
    for pattern in NOISE:
        if pattern.tclass != tclass or not wanted or not wanted <= pattern.perms:
            continue
        if pattern.tcontext is not None and tcontext not in pattern.tcontext:
            continue
        return pattern.reason
    return None


# ------------------------------------------------------------------ labels --

_UNLABELED_TYPES = {"unlabeled_t", "file_t", "default_t"}
_LIBRARY_TYPES = {"lib_t", "usr_t"}
_USER_TYPES = {
    "user_home_t", "user_home_dir_t", "user_tmp_t", "xdg_cache_t", "xdg_config_t", "xdg_data_t",
    "xdg_downloads_t", "xdg_pictures_t", "xdg_documents_t",
}


def label_hint(tcontext: str, tclass: str, perms: list[str], path: str | None) -> str | None:
    """A likely labeling problem behind this denial, or None."""
    if tcontext in _UNLABELED_TYPES:
        return (f"The target has no proper label ({tcontext}) - it needs a file context or restorecon, "
                "not an allow rule.")
    if "execute_no_trans" in perms and tcontext in _LIBRARY_TYPES:
        return ("A helper in a library path runs without its own domain. Arch keeps helpers in /usr/lib where "
                "the policy expects /usr/libexec, so this path probably needs a file context.")
    if path and path.startswith(("/usr/", "/etc/", "/var/", "/opt/")) and tcontext in _USER_TYPES:
        return (f"A system path carries a home-directory label ({tcontext}) - usually moved or unpacked with "
                "its old label. restorecon fixes it.")
    return None


# ------------------------------------------------------------- draft rules --

_SOCK_WRITE_RE = re.compile(r"^\s*allow\s+\S+\s+\S+:sock_file\s+\{?[^;]*\bwrite\b", re.MULTILINE)
_CONNECTTO_RE = re.compile(r"^\s*allow\s+\S+\s+\S+:unix_stream_socket\s+\{?[^;]*\bconnectto\b", re.MULTILINE)
_BOOLEAN_COMMENT_RE = re.compile(r"boolean '([a-z0-9_]+)'")
_BOOLEAN_LIST_RE = re.compile(r"these booleans:\s*\n#\s*([a-z0-9_, ]+)")


def te_warnings(te_text: str) -> list[str]:
    """Problems with a drafted module that installing it won't reveal."""
    warnings = []
    if _SOCK_WRITE_RE.search(te_text) and not _CONNECTTO_RE.search(te_text):
        warnings.append(
            "Writes a socket file but has no unix_stream_socket connectto on the daemon: connecting still "
            "fails with this module alone - if the service isn't in use, dontaudit is the better fix."
        )
    return warnings


def te_booleans(te_text: str) -> list[str]:
    """Booleans audit2allow says would allow part of the draft."""
    found = set(_BOOLEAN_COMMENT_RE.findall(te_text))
    for group in _BOOLEAN_LIST_RE.findall(te_text):
        found.update(name.strip() for name in group.split(",") if name.strip())
    return sorted(found)


# ----------------------------------------------------------- loaded policy --


@dataclass
class PolicyVerdict:
    status: str  # allowed | boolean | none
    booleans: list[str]


class PolicyChecker:
    """
    Answers "does the loaded policy allow this?" with setools. `runtime` maps
    boolean names to their current values (getsebool), since the compiled
    defaults in the policy file can differ from what's set now.
    """

    def __init__(self, runtime: dict[str, bool], policy=None, setools_module=None):
        if setools_module is None:
            import setools as setools_module  # optional dependency: the caller handles ImportError

        setools = setools_module
        self._setools = setools
        self._policy = policy if policy is not None else setools.SELinuxPolicy()
        self._runtime = dict(runtime)
        self._defaults = {str(boolean): bool(boolean.state) for boolean in self._policy.bools()}

    def _state(self, name: str) -> bool:
        return self._runtime.get(name, self._defaults.get(name, False))

    def check(self, source: str, target: str, tclass: str, perms: list[str]) -> PolicyVerdict:
        wanted = set(perms)
        if not wanted:
            return PolicyVerdict("none", [])
        try:
            rules = list(
                self._setools.TERuleQuery(
                    self._policy, ruletype=["allow"], source=source, target=target, tclass=[tclass], perms=wanted
                ).results()
            )
        except Exception:  # noqa: BLE001 - an unknown type or class: the policy can't answer
            return PolicyVerdict("none", [])
        granted, possible, gates = set(), set(), set()
        for rule in rules:
            covered = set(rule.perms) & wanted
            try:
                condition, block = rule.conditional, rule.conditional_block
            except self._setools.exception.RuleNotConditional:
                granted |= covered
                possible |= covered
                continue
            names = {str(boolean) for boolean in condition.booleans}
            if condition.evaluate(**{name: self._state(name) for name in names}) == block:
                granted |= covered
            else:
                gates |= names
            possible |= covered
        if granted >= wanted:
            return PolicyVerdict("allowed", [])
        if possible >= wanted and gates:
            return PolicyVerdict("boolean", sorted(gates))
        return PolicyVerdict("none", [])

    def boolean_rule_count(self, name: str) -> int:
        """How many rules a boolean switches between - context for 'turn it on'."""
        try:
            return sum(1 for _ in self._setools.TERuleQuery(self._policy, boolean=[name]).results())
        except Exception:  # noqa: BLE001
            return 0
