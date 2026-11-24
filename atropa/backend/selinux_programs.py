"""
atropa.backend.selinux_programs
----------------------------------
The Denials page's model: one entry per program (SELinux source domain),
holding its classified denials and its drafted modules, with the single
best next step for it.

review_all_denials() sorts denials by *kind* (new, boolean, noise, ...) and
build_policy_review() drafts modules per domain; both are keyed by the
source domain, so they join here. The best next step, most urgent first:

- dangerous / review - the drafted module has findings at that level
- relabel - a denial a label probably explains (a hint, or one the loaded
  policy already allows yet keeps happening): restorecon, not a rule
- boolean - the loaded policy allows it behind a boolean that's off
- module - new denials and a draft that looks fine
- policy_gap - a class/permission the compiled policy doesn't define
- noise - only known noise: a dontaudit module, if anything
- done - nothing left (resolved, or already allowed and not recurring)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import te_lint

STEPS = ("dangerous", "review", "relabel", "boolean", "module", "policy_gap", "noise", "done")
STEP_LABELS = {
    "dangerous": "Dangerous",
    "review": "Review",
    "relabel": "Relabel",
    "boolean": "Boolean",
    "module": "Module",
    "policy_gap": "Policy gap",
    "noise": "Noise",
    "done": "Done",
}
# The page's filter chips.
NEEDS_ACTION = frozenset({"dangerous", "review", "relabel", "boolean", "module", "policy_gap"})


@dataclass
class Program:
    domain: str
    names: list[str] = field(default_factory=list)  # comm= names seen
    denials: list = field(default_factory=list)  # selinux.GroupedDenial, every classification
    draft: object | None = None  # selinux.ProgramPolicyReview for the allow rules
    noise_draft: object | None = None  # ...and the dontaudit one
    step: str = "done"

    @property
    def title(self) -> str:
        names = ", ".join(self.names[:3]) or self.domain
        return names

    @property
    def count(self) -> int:
        return sum(d.count for d in self.denials)

    @property
    def category(self) -> str:
        return getattr(self.draft, "category", "unsure") if self.draft else "unsure"


def _step(program: Program) -> str:
    kinds = {d.classification for d in program.denials}
    if "new" in kinds:
        if program.draft is not None and program.draft.te_content:
            verdict = te_lint.verdict(program.draft.findings)
            if verdict in ("dangerous", "review"):
                return verdict
        if any(d.hint for d in program.denials if d.classification == "new"):
            return "relabel"
        return "module"
    if "already_allowed" in kinds:
        return "relabel"
    if "boolean" in kinds:
        return "boolean"
    if "undefined_in_policy" in kinds:
        return "policy_gap"
    if "noise" in kinds:
        return "noise"
    return "done"


def overview(review, drafts: list) -> list[Program]:
    """Programs from an ExtensiveDenialReview and build_policy_review()'s drafts, most urgent first."""
    programs: dict[str, Program] = {}

    def program_for(domain: str) -> Program:
        return programs.setdefault(domain, Program(domain=domain))

    for group in (review.new, review.needs_boolean, review.noise, review.already_allowed,
                  review.undefined_in_policy, review.resolved):
        for denial in group:
            program = program_for(denial.scontext_type)
            program.denials.append(denial)
            if denial.program and denial.program not in program.names:
                program.names.append(denial.program)
    for draft in drafts:
        if draft.domain not in programs and draft.domain == "?":
            continue
        program = program_for(draft.domain)
        if draft.dontaudit:
            program.noise_draft = draft
        else:
            program.draft = draft
        for name in draft.program.split(", "):
            if name and name not in program.names:
                program.names.append(name)
    for program in programs.values():
        program.step = _step(program)
    return sorted(programs.values(), key=lambda p: (STEPS.index(p.step), -p.count, p.domain))


def counts(programs: list[Program]) -> dict[str, int]:
    """{"needs_action": n, "noise": n, "done": n} for the filter chips."""
    return {
        "needs_action": sum(p.step in NEEDS_ACTION for p in programs),
        "noise": sum(p.step == "noise" for p in programs),
        "done": sum(p.step == "done" for p in programs),
    }
