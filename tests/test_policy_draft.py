import os

import pytest

from atropa.backend import policy_draft, policy_source
from tests.test_policy_source import make_tree


def avc(perms, tcontext="etc_t", tclass="file", scontext="sshd_t", comm="sshd", extra=""):
    return (f'type=AVC msg=audit(1.0:1): avc:  denied  {{ {perms} }} for  pid=1 comm="{comm}" {extra}'
            f'scontext=system_u:system_r:{scontext}:s0 tcontext=system_u:object_r:{tcontext}:s0 '
            f'tclass={tclass} permissive=0')


LINES = [
    avc("read", extra='name="sshd_config" '),
    avc("open getattr", extra='path="/etc/ssh/sshd_config" '),
    avc("signal", tcontext="sshd_t", tclass="process"),
    avc("search", tcontext="proc_t", tclass="dir"),
    avc("read", scontext="user_t", tcontext="shadow_t", comm="cat"),
    "type=SYSCALL msg=audit(1.0:1): arch=c000003e syscall=2",
    'avc:  denied  { read } for scontext=bad tcontext=also:bad tclass=file',
]


@pytest.fixture
def kb(tmp_path):
    tree = make_tree(tmp_path / "tree")
    return policy_source.load(policy_source.find_source([str(tree)], running="atropa-refpolicy", share_dir=tmp_path))


def test_denials_merge_per_target_and_class_by_domain():
    by = policy_draft.rules_from_denials(LINES)
    assert set(by) == {"sshd_t", "user_t"}
    etc = next(r for r in by["sshd_t"] if r.tgt == "etc_t")
    assert etc.perms == {"read", "open", "getattr"}
    assert (etc.count, etc.programs, etc.path) == (2, ["sshd"], "sshd_config")
    assert any(r.key == ("sshd_t", "self", "process") for r in by["sshd_t"])


def test_annotate_and_tight_interfaces(kb):
    rules = policy_draft.rules_from_denials(LINES)["sshd_t"]
    policy_draft.annotate(rules, kb)
    etc = next(r for r in rules if r.tgt == "etc_t")
    assert etc.choices[0][0] == "files_read_etc_files"
    assert policy_draft.use_tight_interfaces(rules) == 1
    assert (etc.decision, etc.iface) == (policy_draft.IFACE, "files_read_etc_files")


def test_annotate_drops_an_interface_the_source_no_longer_offers(kb):
    rule = policy_draft.Rule("sshd_t", "etc_t", "file", frozenset({"read"}), decision=policy_draft.IFACE, iface="gone")
    policy_draft.annotate([rule], kb)
    assert (rule.decision, rule.iface) == (policy_draft.ALLOW, "")


def test_te_is_refpolicy_style_with_requires_sets_and_calls():
    rules = [
        policy_draft.Rule("sshd_t", "etc_t", "file", frozenset({"read", "open"}), decision=policy_draft.IFACE,
                          iface="files_read_etc_files"),
        policy_draft.Rule("sshd_t", "proc_t", "dir", frozenset({"search"}), decision=policy_draft.DONTAUDIT),
        policy_draft.Rule("sshd_t", "var_t", "file", frozenset({"getattr", "open", "read", "lock", "ioctl"}),
                          perm_set="read_file_perms"),
        policy_draft.Rule("sshd_t", "self", "process", frozenset({"signal"})),
        policy_draft.Rule("sshd_t", "shadow_t", "file", frozenset({"read"}), decision=policy_draft.SKIP),
    ]
    te = policy_draft.gen_te("atropa_dev_sshd", rules)
    assert te == (
        "policy_module(atropa_dev_sshd, 1.0.0)\n\n"
        "gen_require(`\n\ttype proc_t, sshd_t, var_t;\n')\n\n"
        "allow sshd_t self:process signal;\n"
        "allow sshd_t var_t:file read_file_perms;\n"
        "dontaudit sshd_t proc_t:dir search;\n\n"
        "files_read_etc_files(sshd_t)\n"
    )


def test_module_names_are_valid_and_avoid_the_policys_own(kb):
    assert policy_draft.module_name_for("sshd_t") == "atropa_dev_sshd"
    kb.module_names.add("atropa_dev_sshd")
    assert policy_draft.module_name_for("sshd_t", kb) == "atropa_dev_sshd_local"
    with pytest.raises(ValueError):
        policy_draft.gen_te("Bad Name", [])


def test_tree_build_needs_the_tree_built_first(kb, tmp_path):
    result = policy_draft.build("atropa_dev_sshd", "policy_module(atropa_dev_sshd, 1.0.0)\n", kb, str(tmp_path))
    assert not result.ok
    assert "Build Policy" in result.summary
    assert (tmp_path / "atropa_dev_sshd.te").is_file()


def test_tree_build_runs_the_trees_own_steps_then_links(kb, tmp_path, monkeypatch):
    root = kb.source.root
    os.makedirs(os.path.join(root, "tmp"))
    for name in ("tmp/generated_definitions.conf", "tmp/all_interfaces.conf", "base.pp", "files.pp"):
        open(os.path.join(root, name), "w").close()
    calls = []

    def fake_run(argv, cwd, stdout_path=None, timeout=300):
        calls.append(argv)
        if argv[0] == "semodule_package":
            open(os.path.join(cwd, "atropa_dev_sshd.pp"), "w").close()
        return True, ""

    monkeypatch.setattr(policy_draft, "_run", fake_run)
    result = policy_draft.build("atropa_dev_sshd", "x", kb, str(tmp_path))
    assert result.ok, result.log()
    assert [c[0] for c in calls] == ["m4", "checkmodule", "m4", "semodule_package", "semodule_link", "semodule_expand"]
    assert "-Dinit_systemd=true" in calls[0] and "-Ddistro_arch=true" in calls[0]
    assert os.path.join(root, "files.pp") in calls[4]
    assert result.steps[-1].name == "link against 2 tree modules"


def test_headers_build_names_its_own_headers(tmp_path, monkeypatch):
    source = policy_source.PolicySource("headers", "/usr/share/selinux/devel/include", "targeted", "targeted")
    kb = policy_source.PolicyKB(source=source)
    calls = []
    monkeypatch.setattr(policy_draft, "_run", lambda argv, cwd, **k: (calls.append(argv), (False, "boom"))[1])
    result = policy_draft.build("atropa_dev_x", "x", kb, str(tmp_path))
    assert not result.ok and result.summary.endswith("failed: boom")
    assert "HEADERDIR=/usr/share/selinux/devel/include" in calls[0] and "NAME=targeted" in calls[0]


TREE = os.environ.get("ATROPA_TREE", os.path.expanduser("~/Atropa-Full/atropa-addons/refpolicy-atropa"))


@pytest.mark.skipif(not os.path.isfile(os.path.join(TREE, "tmp/all_interfaces.conf")),
                    reason="no built refpolicy tree (set ATROPA_TREE)")
def test_against_a_real_built_tree(tmp_path):
    source = policy_source.PolicySource("tree", TREE, "real", "real")
    kb = policy_source.load(source)
    rules = policy_draft.rules_from_denials([avc("getattr open read"), avc("search", tcontext="proc_t", tclass="dir")])
    rules = rules["sshd_t"]
    policy_draft.annotate(rules, kb)
    policy_draft.use_tight_interfaces(rules)
    assert any(r.iface == "files_read_etc_files" for r in rules)
    result = policy_draft.build("atropa_dev_test", policy_draft.gen_te("atropa_dev_test", rules), kb, str(tmp_path))
    assert result.ok, result.log()
    rules[0].perms = frozenset({"bogusperm"})
    rules[0].decision = policy_draft.ALLOW
    result = policy_draft.build("atropa_dev_test", policy_draft.gen_te("atropa_dev_test", rules), kb,
                                str(tmp_path / "bad"))
    assert not result.ok and "bogusperm" in result.log()
