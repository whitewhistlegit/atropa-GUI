import os
from pathlib import Path

import pytest

from atropa.backend import policy_source, refpolicy_build

ACCESS_VECTORS = """
common file { ioctl read write create getattr setattr lock append open }
class file inherits file { execute entrypoint }
class dir inherits file { search add_name }
class process { transition signal }
"""
SPT = """
define(`read_file_perms',`{ getattr open read lock ioctl }')
define(`search_dir_perms',`{ getattr search open }')
define(`read_files_pattern',`
	allow $1 $2:dir search_dir_perms;
	allow $1 $3:file read_file_perms;
')
"""
FILES_IF = """
## <summary>Read generic files in /etc.</summary>
interface(`files_read_etc_files',`
	gen_require(`
		type etc_t;
	')
	read_files_pattern($1, etc_t, etc_t)
')

## <summary>Manage generic files in /etc.</summary>
interface(`files_manage_etc_files',`
	gen_require(`
		type etc_t;
	')
	allow $1 etc_t:dir search_dir_perms;
	allow $1 etc_t:file { create getattr setattr read write open lock ioctl append };
')

## <summary>Two arguments: never suggested.</summary>
interface(`files_etc_filetrans',`
	allow $1 etc_t:dir $2;
')
"""
FILES_TE = "policy_module(files, 1.0)\ntype etc_t;\nattribute file_type;\n"


def make_tree(root: Path, name: str = "atropa-refpolicy") -> Path:
    (root / "policy/flask").mkdir(parents=True)
    (root / "policy/flask/access_vectors").write_text(ACCESS_VECTORS)
    (root / "policy/support").mkdir()
    (root / "policy/support/obj_perm_sets.spt").write_text(SPT)
    (root / "policy/modules/kernel").mkdir(parents=True)
    (root / "policy/modules/kernel/files.if").write_text(FILES_IF)
    (root / "policy/modules/kernel/files.te").write_text(FILES_TE)
    (root / "build.conf").write_text(f"TYPE = standard\nNAME = {name}\nDISTRO = arch\nSYSTEMD = y\n")
    return root


def make_headers(share: Path, name: str) -> Path:
    inc = share / name / "include"
    (inc / "support").mkdir(parents=True)
    (inc / "support/obj_perm_sets.spt").write_text(SPT)
    (inc / "kernel").mkdir()
    (inc / "kernel/files.if").write_text(FILES_IF)
    (inc / "Makefile").write_text("")
    (inc / "build.conf").write_text("TYPE ?= standard\nNAME ?= x\nDISTRO ?= arch\nSYSTEMD ?= y\noverride UBAC := n\n")
    return inc


def test_build_conf_reads_make_conditional_and_override_forms(tmp_path):
    conf = tmp_path / "build.conf"
    conf.write_text("# c\nTYPE ?= standard\nDISTRO ?= arch\noverride UBAC := n\nNAME = pol # trailing\nSYSTEMD=y\n")
    assert policy_source.parse_build_conf(conf) == {
        "TYPE": "standard", "DISTRO": "arch", "UBAC": "n", "NAME": "pol", "SYSTEMD": "y",
    }
    names, params = policy_source.m4_defines(policy_source.parse_build_conf(conf))
    assert {"distro_arch", "init_systemd"} <= names
    assert "-Ddistro_arch=true" in params


def test_a_tree_building_the_running_policy_is_used(tmp_path):
    tree = make_tree(tmp_path / "tree")
    source = policy_source.find_source([str(tree)], running="atropa-refpolicy", share_dir=tmp_path / "share")
    assert (source.kind, source.root, source.name) == ("tree", str(tree), "atropa-refpolicy")


def test_the_tree_dir_policy_subdir_is_accepted(tmp_path):
    tree = make_tree(tmp_path / "tree")
    source = policy_source.find_source([str(tree / "policy")], running="atropa-refpolicy", share_dir=tmp_path)
    assert source.root == str(tree)


def test_another_policys_tree_or_headers_are_never_used(tmp_path):
    tree = make_tree(tmp_path / "tree", name="refpolicy-git")
    share = tmp_path / "share"
    make_headers(share, "refpolicy-arch")
    source = policy_source.find_source([str(tree)], running="atropa-refpolicy", share_dir=share)
    assert not source.usable
    assert "refpolicy-git" in source.note and str(share / "refpolicy-arch") in source.note


def test_the_running_policys_headers_are_the_fallback(tmp_path):
    share = tmp_path / "share"
    inc = make_headers(share, "atropa-refpolicy")
    source = policy_source.find_source([], running="atropa-refpolicy", share_dir=share)
    assert (source.kind, source.root, source.name) == ("headers", str(inc), "atropa-refpolicy")


def test_atropas_download_is_tried_after_picked_trees(tmp_path):
    make_tree(Path(refpolicy_build.ATROPA_POLICY_DIR))
    source = policy_source.find_source([], running="atropa-refpolicy", share_dir=tmp_path)
    assert source.root == str(refpolicy_build.ATROPA_POLICY_DIR)


def test_no_selinuxtype_means_no_source(tmp_path):
    assert not policy_source.find_source([], running="", share_dir=tmp_path).usable


def test_picked_trees_are_saved_most_recent_first(tmp_path):
    a, b = make_tree(tmp_path / "a"), make_tree(tmp_path / "b")
    policy_source.remember_tree(str(a))
    policy_source.remember_tree(str(b / "policy"))
    policy_source.remember_tree(str(a))
    assert policy_source.saved_trees() == [str(a), str(b)]
    with pytest.raises(ValueError):
        policy_source.remember_tree(str(tmp_path))


def test_loaded_tree_suggests_the_tightest_single_argument_interface(tmp_path):
    tree = make_tree(tmp_path / "tree")
    kb = policy_source.load(policy_source.find_source([str(tree)], running="atropa-refpolicy", share_dir=tmp_path))
    assert kb.perms_for("dir")[-2:] == ["search", "add_name"]
    assert kb.has_type("etc_t") and kb.has_type("file_type") and kb.has_type("nope_t") is False
    assert "files_etc_filetrans" in kb.iface_names and "files_etc_filetrans" not in kb.interfaces
    names = [n for n, _ in kb.suggest_interfaces("sshd_t", "etc_t", "file", {"getattr", "open", "read"})]
    assert names == ["files_read_etc_files", "files_manage_etc_files"]
    assert kb.suggest_interfaces("sshd_t", "etc_t", "file", {"execute"}) == []
    assert kb.perm_set_name("file", {"getattr", "open", "read", "lock", "ioctl"}) == "read_file_perms"
    assert kb.interfaces["files_read_etc_files"].summary == "Read generic files in /etc."


def test_headers_take_classes_from_the_running_policy(tmp_path, monkeypatch):
    classes = tmp_path / "class"
    for cls, perms in (("file", ("read", "open")), ("dir", ("search",))):
        (classes / cls / "perms").mkdir(parents=True)
        for perm in perms:
            (classes / cls / "perms" / perm).write_text("")
    monkeypatch.setattr(policy_source, "SELINUXFS_CLASSES", classes)
    share = tmp_path / "share"
    make_headers(share, "atropa-refpolicy")
    kb = policy_source.load(policy_source.find_source([], running="atropa-refpolicy", share_dir=share))
    assert kb.perms_for("file") == ["open", "read"]
    assert "-Ddistro_arch=true" in kb.m4params
    assert kb.has_type("etc_t") is None  # headers carry no type list


def test_a_parsed_source_is_cached_until_a_file_changes(tmp_path, monkeypatch):
    tree = make_tree(tmp_path / "tree")
    source = policy_source.find_source([str(tree)], running="atropa-refpolicy", share_dir=tmp_path)
    first = policy_source.load(source)
    assert oct(os.stat(policy_source.CACHE_DIR).st_mode & 0o777) == "0o700"
    calls = []
    monkeypatch.setattr(policy_source, "_load_interfaces", lambda *a: calls.append(a))
    assert policy_source.load(source).interfaces.keys() == first.interfaces.keys()
    assert calls == []
    files_if = tree / "policy/modules/kernel/files.if"
    files_if.write_text(FILES_IF + "\n")
    os.utime(files_if, ns=(1, 1))
    policy_source.load(source)
    assert len(calls) == 1
