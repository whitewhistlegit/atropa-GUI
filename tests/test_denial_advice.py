"""Tests for atropa.backend.denial_advice and the Denial Review pass that uses it."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from atropa.backend import denial_advice, selinux

# ------------------------------------------------------------------- noise --

@pytest.mark.parametrize(
    ("tcontext", "tclass", "perms"),
    [
        ("unconfined_t", "process", ["siginh", "rlimitinh", "noatsecure"]),
        ("unconfined_t", "process", ["noatsecure"]),
        ("policykit_auth_t", "capability", ["net_admin"]),
        ("systemd_homed_runtime_t", "sock_file", ["write"]),
        ("systemd_nsresourced_runtime_t", "sock_file", ["read"]),
    ],
)
def test_known_noise(tcontext, tclass, perms):
    assert denial_advice.noise_reason(tcontext, tclass, perms)


@pytest.mark.parametrize(
    ("tcontext", "tclass", "perms"),
    [
        ("unconfined_t", "process", ["transition"]),  # the SSH login: a real gap
        ("unconfined_t", "process", ["transition", "noatsecure"]),
        ("policykit_auth_t", "capability", ["net_admin", "sys_admin"]),
        ("var_run_t", "sock_file", ["write"]),
        ("systemd_homed_runtime_t", "sock_file", ["unlink"]),
    ],
)
def test_not_noise(tcontext, tclass, perms):
    assert denial_advice.noise_reason(tcontext, tclass, perms) is None


# ------------------------------------------------------------------ labels --

def test_unlabeled_target_needs_a_label_not_a_rule():
    assert "file context or restorecon" in denial_advice.label_hint("unlabeled_t", "filesystem", ["mount"], None)


def test_execute_no_trans_on_lib_t_points_at_arch_paths():
    hint = denial_advice.label_hint("lib_t", "file", ["execute_no_trans"], "nm-dispatcher")
    assert "/usr/libexec" in hint


def test_system_path_with_a_home_label():
    hint = denial_advice.label_hint(
        "xdg_cache_t", "file", ["read"], "/usr/share/polkit-1/actions/org.atropa.pkexec.policy"
    )
    assert "restorecon" in hint


def test_home_path_with_a_home_label_is_fine():
    assert denial_advice.label_hint("xdg_cache_t", "file", ["read"], "/home/me/.cache/x") is None


# ------------------------------------------------------------- draft rules --

BRAVE_TE = """
module atropa_brave_t 1.0;

require {
\ttype brave_t;
\ttype xdg_pictures_t;
\tclass dir search;
\tclass process ptrace;
}

#============= brave_t ==============

#!!!! This avc can be allowed using one of the these booleans:
#     brave_read_all_user_content, brave_manage_all_user_content
allow brave_t xdg_pictures_t:dir search;

#!!!! This avc can be allowed using the boolean 'brave_ptrace'
allow brave_t self:process ptrace;
"""

POLKITD_TE = """
#============= policykit_t ==============
allow policykit_t systemd_homed_runtime_t:sock_file { read write };
"""


def test_booleans_are_read_from_audit2allow_comments():
    assert denial_advice.te_booleans(BRAVE_TE) == [
        "brave_manage_all_user_content", "brave_ptrace", "brave_read_all_user_content",
    ]


def test_socket_write_without_connectto_is_flagged():
    [warning] = denial_advice.te_warnings(POLKITD_TE)
    assert "connectto" in warning


def test_socket_write_with_connectto_is_fine():
    te = POLKITD_TE + "allow policykit_t systemd_homed_t:unix_stream_socket connectto;\n"
    assert denial_advice.te_warnings(te) == []


# ----------------------------------------------------------- loaded policy --

class _NotConditional(Exception):
    pass


class _Rule:
    def __init__(self, perms, boolean=None, block=True):
        self.perms = set(perms)
        self._boolean, self._block = boolean, block

    @property
    def conditional(self):
        if self._boolean is None:
            raise _NotConditional
        name = self._boolean
        return SimpleNamespace(booleans={name}, evaluate=lambda **state: state[name])

    @property
    def conditional_block(self):
        return self._block


def _fake_setools(rules_by_key, rules_by_boolean=None):
    class Query:
        def __init__(self, policy, ruletype=None, source=None, target=None, tclass=None, perms=None, boolean=None):
            if source == "missing_t":
                raise ValueError("InvalidType")
            self.key = (source, target, tclass[0]) if tclass else None
            self.boolean = boolean

        def results(self):
            if self.boolean:
                return iter(rules_by_boolean.get(self.boolean[0], []))
            return iter(rules_by_key.get(self.key, []))

    return SimpleNamespace(TERuleQuery=Query, exception=SimpleNamespace(RuleNotConditional=_NotConditional))


def _checker(rules, runtime=None, by_boolean=None):
    policy = SimpleNamespace(bools=lambda: [])
    return denial_advice.PolicyChecker(runtime or {}, policy=policy, setools_module=_fake_setools(rules, by_boolean))


def test_an_unconditional_rule_means_already_allowed():
    checker = _checker({("init_t", "etc_t", "file"): [_Rule({"read", "open"})]})
    assert checker.check("init_t", "etc_t", "file", ["read"]).status == "allowed"


def test_rules_split_across_two_allows_still_cover_it():
    checker = _checker({("a_t", "b_t", "file"): [_Rule({"read"}), _Rule({"open"})]})
    assert checker.check("a_t", "b_t", "file", ["read", "open"]).status == "allowed"


def test_a_rule_behind_an_off_boolean_suggests_the_boolean():
    checker = _checker({("brave_t", "gnome_xdg_config_t", "dir"): [_Rule({"read"}, "brave_read_all_user_content")]})
    verdict = checker.check("brave_t", "gnome_xdg_config_t", "dir", ["read"])
    assert (verdict.status, verdict.booleans) == ("boolean", ["brave_read_all_user_content"])


def test_a_boolean_that_is_already_on_means_allowed():
    checker = _checker(
        {("brave_t", "gnome_xdg_config_t", "dir"): [_Rule({"read"}, "brave_read_all_user_content")]},
        runtime={"brave_read_all_user_content": True},
    )
    assert checker.check("brave_t", "gnome_xdg_config_t", "dir", ["read"]).status == "allowed"


def test_a_partial_rule_is_not_enough():
    checker = _checker({("a_t", "b_t", "file"): [_Rule({"read"})]})
    assert checker.check("a_t", "b_t", "file", ["read", "write"]).status == "none"


def test_an_unknown_type_is_not_an_error():
    assert _checker({}).check("missing_t", "b_t", "file", ["read"]).status == "none"


def test_boolean_rule_count():
    checker = _checker({}, by_boolean={"brave_ptrace": [_Rule({"ptrace"}), _Rule({"signal"})]})
    assert checker.boolean_rule_count("brave_ptrace") == 2


# -------------------------------------------------------- advise_denials --

def _denial(scontext, tcontext, tclass, perms, path=None):
    return selinux.GroupedDenial(
        key=f"{scontext}|{tcontext}|{tclass}|{','.join(perms)}", scontext_type=scontext, tcontext_type=tcontext,
        tclass=tclass, permissions=perms, program="x", sample_line="", sample_path=path, count=3,
    )


def test_advise_sorts_denials_into_allowed_boolean_noise_and_new():
    checker = _checker({
        ("init_t", "etc_t", "file"): [_Rule({"read"})],
        ("brave_t", "gnome_xdg_config_t", "dir"): [_Rule({"read"}, "brave_read_all_user_content")],
    })
    grouped = [
        _denial("init_t", "etc_t", "file", ["read"]),
        _denial("brave_t", "gnome_xdg_config_t", "dir", ["read"]),
        _denial("polkit_t", "systemd_homed_runtime_t", "sock_file", ["write"]),
        _denial("sshd_t", "unconfined_t", "process", ["transition"]),
        _denial("mount_t", "unlabeled_t", "filesystem", ["mount"]),
    ]
    selinux.advise_denials(grouped, checker)
    assert [d.classification for d in grouped] == ["already_allowed", "boolean", "noise", "new", "new"]
    assert grouped[0].matched_module == "the loaded policy"
    assert grouped[1].booleans == ["brave_read_all_user_content"]
    assert grouped[4].hint and "restorecon" in grouped[4].hint


def test_advise_without_setools_still_finds_noise_and_hints():
    grouped = [_denial("polkit_t", "systemd_homed_runtime_t", "sock_file", ["write"])]
    selinux.advise_denials(grouped, None)
    assert grouped[0].classification == "noise"


def test_review_reports_whether_the_policy_was_checked(fake_run, fake_which, tmp_path, monkeypatch):
    monkeypatch.setattr(selinux, "REVIEW_BASE_DIR", tmp_path)
    monkeypatch.setattr(selinux, "LAST_REVIEW_FILE", tmp_path / "last.json")
    monkeypatch.setattr(selinux, "list_all_denials", lambda **kw: [])
    assert selinux.review_all_denials(source="journal").policy_checked is False


# ------------------------------------------------------- module drafting --

def test_noise_gets_its_own_dontaudit_module(fake_run, fake_which, module_dirs):
    fake_which.update({"audit2allow", "audit2why", "checkmodule", "semodule_package"})
    fake_run.set_response(
        ["journalctl", "-k"],
        stdout=(
            'avc:  denied  { write } for comm="polkitd" name="io.systemd.Home" '
            "scontext=system_u:system_r:policykit_t tcontext=system_u:object_r:systemd_homed_runtime_t "
            "tclass=sock_file\n"
            'avc:  denied  { read } for comm="polkitd" name="x" '
            "scontext=system_u:system_r:policykit_t tcontext=system_u:object_r:xdg_cache_t tclass=file\n"
        ),
    )
    reviews = selinux.build_policy_review(denial_limit=100)
    by_name = {review.safe_name: review for review in reviews}
    assert set(by_name) == {"atropa_policykit_t", "atropa_policykit_t_dontaudit"}
    assert by_name["atropa_policykit_t_dontaudit"].dontaudit
    assert ["audit2allow", "-D", "-m", "atropa_policykit_t_dontaudit"] in fake_run.calls
    # real gaps are listed before noise
    assert [r.dontaudit for r in reviews] == [False, True]


def test_one_domain_is_one_module_whatever_the_process_names(fake_run, fake_which, module_dirs):
    fake_which.update({"audit2allow", "audit2why", "checkmodule", "semodule_package"})
    fake_run.set_response(
        ["journalctl", "-k"],
        stdout=(
            'avc:  denied  { read } for comm="ThreadPoolForeg" scontext=u:r:brave_t tcontext=u:object_r:var_lib_t tclass=dir\n'
            'avc:  denied  { read } for comm="xdg-settings" scontext=u:r:brave_t tcontext=u:object_r:var_lib_t tclass=dir\n'
        ),
    )
    [review] = selinux.build_policy_review(denial_limit=100)
    assert review.safe_name == "atropa_brave_t"
    assert review.program == "ThreadPoolForeg, xdg-settings"
