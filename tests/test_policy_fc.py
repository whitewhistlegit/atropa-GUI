from atropa.backend import policy_draft, policy_fc
from tests.test_policy_source import make_tree

FILES = [
    "/etc/", "/etc/ssh/", "/etc/ssh/sshd_config", "/etc/pam.d/", "/etc/pam.d/sshd",
    "/usr/", "/usr/bin/", "/usr/bin/sshd", "/usr/bin/ssh", "/usr/lib/", "/usr/lib/ssh/",
    "/usr/lib/ssh/sshd-session", "/usr/lib/ssh/sftp-server", "/usr/lib/libfoo.so.1",
    "/usr/lib/systemd/", "/usr/lib/systemd/system/", "/usr/lib/systemd/system/sshd.service",
    "/usr/lib/systemd/system/sshd@.service", "/usr/share/", "/usr/share/man/", "/usr/share/man/man8/sshd.8.gz",
    "/var/", "/var/lib/", "/var/lib/sshd/", "/opt/", "/opt/sshd-extras/", "/opt/sshd-extras/lib.so",
]
LABELS = {"/usr/bin/sshd": "sshd_exec_t", "/usr/lib/systemd/system/sshd.service": "sshd_unit_t"}


def groups():
    gs, hidden = policy_fc.group_paths(FILES, "sshd", "/usr/bin/sshd", is_shared=lambda d: False)
    assert hidden == 0
    policy_fc.label_groups(gs, "sshd", lookup=lambda path, mode: LABELS.get(path, "etc_t" if path.startswith("/etc")
                                                                             else "usr_t" if path.startswith("/opt")
                                                                             else "var_lib_t" if path.startswith("/var")
                                                                             else "bin_t"))
    return {g.regex: g for g in gs}


def test_owned_dirs_collapse_shared_files_stay_exact_noise_dropped():
    g = groups()
    assert "/etc/ssh(/.*)?" in g and "/usr/lib/ssh(/.*)?" in g and "/var/lib/sshd(/.*)?" in g
    assert g["/usr/bin/sshd"].ftype == "--"
    assert "/etc/pam\\.d/sshd" in g
    assert "/usr/lib/systemd/system/sshd.*" in g
    assert not any("man" in r for r in g)


def test_the_programs_binary_comes_first():
    gs, _ = policy_fc.group_paths(FILES, "sshd", "/usr/bin/sshd", is_shared=lambda d: False)
    assert gs[0].regex == "/usr/bin/sshd"


def test_escape():
    assert policy_fc.escape_fc("/usr/lib/libfoo.so.1") == "/usr/lib/libfoo\\.so\\.1"


def test_proposals_and_what_is_preselected():
    g = groups()
    assert (g["/etc/ssh(/.*)?"].type, g["/etc/ssh(/.*)?"].include) == ("sshd_conf_t", True)
    assert (g["/var/lib/sshd(/.*)?"].type, g["/var/lib/sshd(/.*)?"].include) == ("sshd_var_lib_t", True)
    # a label of its own already: kept, not rewritten
    assert (g["/usr/bin/sshd"].type, g["/usr/bin/sshd"].include) == ("sshd_exec_t", False)
    # exec labels decide which domain a binary runs in: never preselected
    assert (g["/usr/lib/ssh(/.*)?"].type, g["/usr/lib/ssh(/.*)?"].include) == ("sshd_exec_t", False)
    # shared config locations keep their generic label
    assert g["/etc/pam\\.d/sshd"].include is False
    # a catch-all install tree: binaries and libraries, never preselected
    assert (g["/opt/sshd-extras(/.*)?"].type, g["/opt/sshd-extras(/.*)?"].include) == ("sshd_file_t", False)
    assert policy_fc.propose_type(g["/usr/lib/libfoo\\.so\\.1"], "sshd") == "lib_t"


def test_declarations_own_access_and_files(tmp_path):
    from atropa.backend import policy_source

    tree = make_tree(tmp_path / "tree")
    kb = policy_source.load(policy_source.find_source([str(tree)], running="atropa-refpolicy", share_dir=tmp_path))
    g = groups()
    g["/opt/sshd-extras(/.*)?"].include = True
    decls = policy_fc.declared_types(list(g.values()), kb)
    assert list(decls) == ["sshd_conf_t", "sshd_var_lib_t", "sshd_file_t"]
    # the fake tree defines none of the kind macros: the generic one
    assert decls["sshd_conf_t"] == ["type sshd_conf_t;", "files_type(sshd_conf_t)"]
    own = {(t, c): n for _, t, c, n in policy_fc.own_access("sshd_t", decls)}
    assert own[("sshd_conf_t", "file")] == "read_file_perms"
    assert own[("sshd_var_lib_t", "file")] == "manage_file_perms"
    assert own[("sshd_file_t", "file")] == "read_file_perms"  # read-only: not the program's to rewrite
    assert policy_fc.render_set(kb, "read_file_perms") == "read_file_perms"
    assert policy_fc.render_set(kb, "manage_dir_perms").startswith("{ create")

    te = policy_draft.gen_te("atropa_dev_sshd", [], decls, [(s, t, c, policy_fc.render_set(kb, n))
                                                             for s, t, c, n in policy_fc.own_access("sshd_t", decls)])
    assert "gen_require(`\n\ttype sshd_t;\n')" in te
    assert "type sshd_conf_t;\nfiles_type(sshd_conf_t)" in te
    assert "allow sshd_t sshd_conf_t:file read_file_perms;" in te
    fc = policy_fc.gen_fc(list(g.values()))
    assert "/etc/ssh(/.*)?" in fc and "gen_context(system_u:object_r:sshd_conf_t,s0)" in fc
    assert "sshd_exec_t" not in fc
    iface = policy_fc.gen_if("atropa_dev_sshd", "sshd", decls, kb)
    assert "interface(`atropa_dev_sshd_read_config'" in iface
    assert "interface(`atropa_dev_sshd_read_lib_files'" in iface


def test_a_known_type_is_required_not_declared(tmp_path):
    g = policy_fc.FcGroup("/etc/x", "--", "/etc/x", "f", current="etc_t", type="etc_t", include=True)
    assert policy_fc.declared_types([g], None) == {}
    assert policy_fc.gen_fc([]).startswith("# No file labels")


def test_load_program_through_pacman(fake_run, fake_which, monkeypatch):
    monkeypatch.setattr(policy_fc, "resolve_program", lambda name: "/usr/bin/sshd")
    monkeypatch.setattr(policy_fc, "system_label", lambda path, mode: "")
    fake_run.set_response(["pacman", "-Qqo", "/usr/bin/sshd"], stdout="openssh\n")
    fake_run.set_response(["pacman", "-Qlq", "openssh"], stdout="\n".join(FILES) + "\n")
    fake_run.set_response(["pacman", "-Qqo"], stdout="openssh\n")  # every directory: this package's alone
    program = policy_fc.load_program("sshd", "sshd")
    assert (program.name, program.path, program.package) == ("sshd", "/usr/bin/sshd", "openssh")
    assert program.groups[0].regex == "/usr/bin/sshd"
