"""Tests for the Denials page's per-program model (selinux_programs.py) and draft save/discard."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from atropa.backend import selinux, selinux_programs, te_lint


def denial(domain, kind="new", count=1, program="prog", hint=None, booleans=(), path=None):
    return selinux.GroupedDenial(
        key=f"{domain}-{kind}-{count}", scontext_type=domain, tcontext_type="x_t", tclass="file",
        permissions=["read"], program=program, sample_line="avc: denied", sample_path=path, count=count,
        classification=kind, hint=hint, booleans=list(booleans),
    )


def review(*denials):
    groups = {"new": [], "boolean": [], "noise": [], "already_allowed": [], "undefined_in_policy": [], "resolved": []}
    for d in denials:
        groups[d.classification].append(d)
    return SimpleNamespace(new=groups["new"], needs_boolean=groups["boolean"], noise=groups["noise"],
                           already_allowed=groups["already_allowed"], undefined_in_policy=groups["undefined_in_policy"],
                           resolved=groups["resolved"])


def draft(domain, te="", dontaudit=False, category="unsure"):
    return selinux.ProgramPolicyReview(program="prog", safe_name=f"atropa_{domain}", denial_count=1, domain=domain,
                                       te_content=te, dontaudit=dontaudit, category=category,
                                       findings=te_lint.lint(te, category) if te else [])


SHADOW = "module m 1.0;\nallow a_t shadow_t:file read;\n"
PLAIN = "module m 1.0;\nallow c_t x_t:file read;\n"


def test_each_domain_gets_its_best_next_step():
    programs = selinux_programs.overview(
        review(
            denial("a_t", count=2), denial("b_t", "boolean", booleans=["b_bool"]), denial("c_t", count=9),
            denial("d_t", "noise"), denial("e_t", "resolved"), denial("f_t", hint="mislabeled", path="/x"),
            denial("g_t", "already_allowed"), denial("h_t", "undefined_in_policy"),
        ),
        [draft("a_t", SHADOW), draft("c_t", PLAIN)],
    )
    steps = {p.domain: p.step for p in programs}
    assert steps == {"a_t": "dangerous", "b_t": "boolean", "c_t": "module", "d_t": "noise", "e_t": "done",
                     "f_t": "relabel", "g_t": "relabel", "h_t": "policy_gap"}
    # Most urgent first, then by count.
    assert [p.domain for p in programs][:2] == ["a_t", "f_t"]


def test_noise_drafts_attach_separately():
    (program,) = selinux_programs.overview(review(denial("a_t", "noise")), [draft("a_t", PLAIN, dontaudit=True)])
    assert program.noise_draft is not None and program.draft is None


def test_counts_for_the_filter_chips():
    programs = selinux_programs.overview(review(denial("a_t"), denial("b_t", "noise"), denial("c_t", "resolved")), [])
    assert selinux_programs.counts(programs) == {"needs_action": 1, "noise": 1, "done": 1}


def test_save_and_discard_a_draft(monkeypatch):
    monkeypatch.setattr(selinux, "_compile_te", lambda te, name, directory: (
        directory.mkdir(parents=True, exist_ok=True), (directory / f"{name}.te").write_text(te),
        (directory / f"{name}.pp").write_bytes(b"pp"))[0] or str(directory / f"{name}.pp"))
    selinux.save_draft(PLAIN, "atropa_x", "desktop_app")
    assert te_lint.read_meta(selinux.REVIEW_MODULES_DIR, "atropa_x")["category"] == "desktop_app"
    selinux.discard_draft("atropa_x")
    assert not list(selinux.REVIEW_MODULES_DIR.glob("atropa_x.*"))


@pytest.mark.parametrize("name", ["../x", "a b", ""])
def test_discard_validates_the_name(name):
    with pytest.raises(ValueError):
        selinux.discard_draft(name)
