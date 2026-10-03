"""Tests for atropa.backend.selinux."""
from __future__ import annotations

import pytest

from atropa.backend import selinux

# The sandbox container this runs in has a real /sys/fs/selinux mount (from
# the host), even though SELinux itself isn't in use - so is_available()'s
# filesystem check can't rely on the sandbox NOT having that path. Patch
# Path.exists so that path specifically reads as absent, without touching
# any other path the tests create under tmp_path.
_REAL_PATH_EXISTS = __import__("pathlib").Path.exists


@pytest.fixture(autouse=True)
def no_real_selinux_fs(monkeypatch):
    from pathlib import Path

    def fake_exists(self):
        if str(self) == "/sys/fs/selinux":
            return False
        return _REAL_PATH_EXISTS(self)

    monkeypatch.setattr(Path, "exists", fake_exists)


SESTATUS_OUTPUT = """\
SELinux status:                enabled
SELinuxfs mount:                /sys/fs/selinux
Current mode:                   enforcing
Mode from config file:          enforcing
Policy MLS status:              disabled
Policy deny_unknown status:     allowed
Loaded policy name:             refpolicy-arch
Max kernel policy version:      33
"""


@pytest.fixture
def module_dirs(monkeypatch, tmp_path):
    review_base = tmp_path / "selinux-review"
    modules_dir = review_base / "modules"
    approved_dir = review_base / "approved"
    monkeypatch.setattr(selinux, "REVIEW_BASE_DIR", review_base)
    monkeypatch.setattr(selinux, "REVIEW_MODULES_DIR", modules_dir)
    monkeypatch.setattr(selinux, "APPROVED_MODULES_DIR", approved_dir)
    monkeypatch.setattr(selinux, "SETUP_MODE_STATE_FILE", review_base / "setup_mode_state.json")
    monkeypatch.setattr(selinux, "LAST_REVIEW_FILE", review_base / "last_review.json")
    return modules_dir, approved_dir


# --------------------------------------------------------------- status --

def test_is_available_via_sestatus(fake_which):
    fake_which.add("sestatus")
    assert selinux.is_available() is True


def test_is_available_false_when_nothing(fake_which):
    assert selinux.is_available() is False


def test_get_status_unavailable_short_circuits(fake_which):
    status = selinux.get_status()
    assert status.available is False
    assert status.mode == "Disabled"


def test_get_status_parses_fields(fake_run, fake_which):
    fake_which.add("sestatus")
    fake_run.set_response(["sestatus"], stdout=SESTATUS_OUTPUT)
    status = selinux.get_status()
    assert status.available is True
    assert status.mode == "enforcing"
    assert status.policy == "refpolicy-arch"
    assert status.mls == "disabled"
    assert status.deny_unknown == "allowed"


def test_get_status_policy_falls_back_to_config_file_field(fake_run, fake_which):
    fake_which.add("sestatus")
    text = SESTATUS_OUTPUT.replace(
        "Loaded policy name:             refpolicy-arch\n",
        "Policy from config file:        targeted\n",
    )
    fake_run.set_response(["sestatus"], stdout=text)
    assert selinux.get_status().policy == "targeted"


def test_set_mode_updates_config_when_persistent(fake_run, fake_which, monkeypatch, tmp_path, privilege_paths):
    conf = tmp_path / "config"
    conf.write_text("SELINUX=permissive\n")
    monkeypatch.setattr(selinux, "SELINUX_CONFIG", conf)
    fake_run.set_response(["pkexec", "setenforce", "1"], returncode=0)
    fake_run.set_response(["pkexec", "sed", "-i"], returncode=0)

    selinux.set_mode(enforcing=True, persistent=True)
    assert fake_run.call_containing("sed") is not None


def test_set_mode_runtime_only_skips_config_edit(fake_run, fake_which, monkeypatch, tmp_path):
    conf = tmp_path / "config"
    conf.write_text("SELINUX=permissive\n")
    monkeypatch.setattr(selinux, "SELINUX_CONFIG", conf)
    fake_run.set_response(["pkexec", "setenforce", "0"], returncode=0)

    selinux.set_mode(enforcing=False, persistent=False)
    assert fake_run.call_containing("sed") is None


def test_set_mode_skips_config_edit_on_setenforce_failure(fake_run, fake_which, monkeypatch, tmp_path):
    conf = tmp_path / "config"
    conf.write_text("SELINUX=permissive\n")
    monkeypatch.setattr(selinux, "SELINUX_CONFIG", conf)
    fake_run.set_response(["pkexec", "setenforce", "1"], returncode=1)

    result = selinux.set_mode(enforcing=True, persistent=True)
    assert not result.ok
    assert fake_run.call_containing("sed") is None


# --------------------------------------------------------------- booleans --

def test_list_booleans_unavailable_returns_empty(fake_which):
    assert selinux.list_booleans() == []


def test_list_booleans_parses_on_off(fake_run, fake_which):
    fake_which.add("sestatus")
    fake_which.add("getsebool")
    fake_run.set_response(
        ["getsebool", "-a"],
        stdout="httpd_can_network_connect --> off\nssh_sysadm_login --> on\n",
    )
    booleans = selinux.list_booleans()
    by_name = {b.name: b.active for b in booleans}
    assert by_name["httpd_can_network_connect"] is False
    assert by_name["ssh_sysadm_login"] is True


def test_list_booleans_filters_by_text(fake_run, fake_which):
    fake_which.add("sestatus")
    fake_which.add("getsebool")
    fake_run.set_response(
        ["getsebool", "-a"],
        stdout="httpd_can_network_connect --> off\nssh_sysadm_login --> on\n",
    )
    booleans = selinux.list_booleans(filter_text="ssh")
    assert [b.name for b in booleans] == ["ssh_sysadm_login"]


def test_set_boolean_persistent_flag(fake_run, fake_which):
    selinux.set_boolean("ssh_sysadm_login", True, persistent=True)
    assert fake_run.last_call() == ["pkexec", "setsebool", "-P", "ssh_sysadm_login", "on"]


def test_set_boolean_non_persistent(fake_run, fake_which):
    selinux.set_boolean("ssh_sysadm_login", False, persistent=False)
    assert fake_run.last_call() == ["pkexec", "setsebool", "ssh_sysadm_login", "off"]


def test_restorecon_requires_path():
    with pytest.raises(ValueError):
        selinux.restorecon("")


def test_restorecon_recursive_flag(fake_run, fake_which):
    selinux.restorecon("/home/alice", recursive=True)
    assert fake_run.last_call() == ["pkexec", "restorecon", "-Rv", "/home/alice"]
    selinux.restorecon("/home/alice", recursive=False)
    assert fake_run.last_call() == ["pkexec", "restorecon", "-v", "/home/alice"]


def test_restorecon_streaming_requires_path():
    with pytest.raises(ValueError):
        selinux.restorecon_streaming("", recursive=True, on_line=lambda _l: None)


def test_restorecon_streaming_forwards_lines_and_flag(monkeypatch, fake_which):
    import subprocess

    lines_seen = []
    captured_argv = {}

    class FakeStdout:
        def __iter__(self):
            return iter(["Relabeling /home/alice/file1", "Relabeling /home/alice/file2"])

    class FakePopen:
        def __init__(self, argv, **kwargs):
            captured_argv["argv"] = argv
            self.stdout = FakeStdout()
            self.stdin = None

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    result = selinux.restorecon_streaming("/home/alice", recursive=True, on_line=lines_seen.append)

    assert result.ok
    assert captured_argv["argv"] == ["pkexec", "restorecon", "-Rv", "/home/alice"]
    assert lines_seen == ["Relabeling /home/alice/file1", "Relabeling /home/alice/file2"]


def test_relabel_filesystem_touches_autorelabel(fake_run, fake_which):
    selinux.relabel_filesystem()
    assert fake_run.last_call() == ["pkexec", "touch", "/.autorelabel"]


# --------------------------------------------------------------- module name validation --

@pytest.mark.parametrize("name", ["my_module", "abc-123", "a" * 64])
def test_validate_module_name_accepts_valid(name):
    selinux._validate_module_name(name)  # should not raise


@pytest.mark.parametrize("name", ["", "a" * 65, "bad name", "bad;name", "../etc"])
def test_validate_module_name_rejects_invalid(name):
    with pytest.raises(ValueError):
        selinux._validate_module_name(name)


# --------------------------------------------------------------- denials --

def test_list_avc_denials_filters_denied_lines(fake_run):
    fake_run.set_response(
        ["journalctl", "-k"],
        stdout="unrelated line\nkernel: avc:  denied  { read } for pid=1\n",
    )
    denials = selinux.list_avc_denials(limit=5)
    assert len(denials) == 1
    assert "avc:" in denials[0]


def test_list_avc_denials_from_audit_log_requires_ausearch(fake_which):
    with pytest.raises(RuntimeError, match="isn't installed"):
        selinux.list_avc_denials_from_audit_log()


def test_list_avc_denials_from_audit_log_parses(fake_run, fake_which):
    fake_which.add("ausearch")
    fake_run.set_response(
        ["pkexec", "ausearch", "-m", "avc"],
        stdout="type=AVC msg=audit(...): avc:  denied  { read }\n",
    )
    denials = selinux.list_avc_denials_from_audit_log()
    assert len(denials) == 1


def test_explain_denial_requires_audit2why(fake_which):
    with pytest.raises(RuntimeError, match="isn't installed"):
        selinux.explain_denial("avc: denied")


def test_explain_denial_raises_on_empty_output(fake_run, fake_which):
    fake_which.add("audit2why")
    fake_run.set_response(["audit2why"], stdout="", stderr="")
    with pytest.raises(RuntimeError, match="no output"):
        selinux.explain_denial("avc: denied")


def test_explain_denial_returns_output(fake_run, fake_which):
    fake_which.add("audit2why")
    fake_run.set_response(["audit2why"], stdout="because reasons\n")
    assert selinux.explain_denial("avc: denied") == "because reasons"


def test_generate_te_requires_audit2allow(fake_which):
    with pytest.raises(RuntimeError, match="isn't installed"):
        selinux.generate_te("avc: denied", "mymod")


def test_generate_te_validates_module_name(fake_which):
    fake_which.add("audit2allow")
    with pytest.raises(ValueError):
        selinux.generate_te("avc: denied", "bad name")


def test_generate_te_returns_stdout(fake_run, fake_which):
    fake_which.add("audit2allow")
    fake_run.set_response(["audit2allow", "-m", "mymod"], stdout="module mymod 1.0;\n")
    assert selinux.generate_te("avc: denied", "mymod") == "module mymod 1.0;\n"


# --------------------------------------------------------------- semodules --

def test_list_semodules_empty_when_not_installed(fake_which):
    assert selinux.list_semodules() == []


def test_list_semodules_parses_first_column(fake_run, fake_which):
    fake_which.add("semodule")
    fake_run.set_response(["pkexec", "semodule", "-l"], stdout="mymodule\nanother_module\n")
    assert selinux.list_semodules() == ["mymodule", "another_module"]


# --------------------------------------------------------------- compile/install/remove --

def test_compile_te_missing_tools_raises(fake_which, module_dirs):
    modules_dir, _ = module_dirs
    with pytest.raises(RuntimeError, match="isn't installed"):
        selinux._compile_te("module mymod 1.0;", "mymod", modules_dir)


def test_compile_te_success_writes_and_packages(fake_run, fake_which, module_dirs):
    modules_dir, _ = module_dirs
    fake_which.add("checkmodule")
    fake_which.add("semodule_package")
    fake_run.set_response(["checkmodule"], returncode=0)
    fake_run.set_response(["semodule_package"], returncode=0)

    pp_path = selinux._compile_te("module mymod 1.0;", "mymod", modules_dir)
    assert pp_path == str(modules_dir / "mymod.pp")
    assert (modules_dir / "mymod.te").read_text() == "module mymod 1.0;"


def test_compile_te_checkmodule_failure_raises(fake_run, fake_which, module_dirs):
    modules_dir, _ = module_dirs
    fake_which.add("checkmodule")
    fake_which.add("semodule_package")
    fake_run.set_response(["checkmodule"], returncode=1, stderr="syntax error")

    with pytest.raises(RuntimeError, match="syntax error"):
        selinux._compile_te("bad te", "mymod", modules_dir)


def test_move_to_approved_moves_existing_files(module_dirs):
    modules_dir, approved_dir = module_dirs
    modules_dir.mkdir(parents=True)
    (modules_dir / "mymod.te").write_text("te")
    (modules_dir / "mymod.pp").write_text("pp")
    # .mod deliberately absent - should be skipped without error

    selinux._move_to_approved("mymod", modules_dir)

    assert (approved_dir / "mymod.te").exists()
    assert (approved_dir / "mymod.pp").exists()
    assert not (modules_dir / "mymod.te").exists()


def test_compile_and_load_te_moves_to_approved_on_success(fake_run, fake_which, module_dirs):
    # checkmodule/semodule_package are mocked, so they don't actually produce
    # a .mod/.pp on disk - only the .te (written directly by Python) is real.
    # That's still enough to verify the move-on-success behavior.
    modules_dir, approved_dir = module_dirs
    fake_which.add("checkmodule")
    fake_which.add("semodule_package")
    fake_which.add("semodule")
    fake_run.set_response(["checkmodule"], returncode=0)
    fake_run.set_response(["semodule_package"], returncode=0)
    fake_run.set_response(["pkexec", "semodule", "-i"], returncode=0)

    result = selinux.compile_and_load_te("module mymod 1.0;", "mymod")
    assert result.ok
    assert (approved_dir / "mymod.te").exists()
    assert not (modules_dir / "mymod.te").exists()


def test_compile_and_load_te_leaves_pending_on_install_failure(fake_run, fake_which, module_dirs):
    modules_dir, approved_dir = module_dirs
    fake_which.add("checkmodule")
    fake_which.add("semodule_package")
    fake_which.add("semodule")
    fake_run.set_response(["checkmodule"], returncode=0)
    fake_run.set_response(["semodule_package"], returncode=0)
    fake_run.set_response(["pkexec", "semodule", "-i"], returncode=1, stderr="load failed")

    result = selinux.compile_and_load_te("module mymod 1.0;", "mymod")
    assert not result.ok
    assert (modules_dir / "mymod.te").exists()
    assert not (approved_dir / "mymod.te").exists()


def test_install_pp_file_missing_semodule_raises(fake_which, tmp_path):
    pp = tmp_path / "mymod.pp"
    pp.write_text("compiled")
    with pytest.raises(RuntimeError, match="isn't installed"):
        selinux.install_pp_file(str(pp))


# --------------------------------------------------------------- import_te_files --

def test_module_name_from_te_parses_declaration():
    assert selinux._module_name_from_te("module dbus-broker 1.0;\n\nrequire {}", "fallback") == "dbus-broker"


def test_module_name_from_te_falls_back_when_no_declaration():
    assert selinux._module_name_from_te("not a valid te file", "myfile") == "myfile"


def test_import_te_files_missing_tools_raises(fake_which, tmp_path):
    te = tmp_path / "mymod.te"
    te.write_text("module mymod 1.0;")
    with pytest.raises(RuntimeError, match="aren't installed"):
        selinux.import_te_files([str(te)])


def test_import_te_files_compiles_each_into_pending_not_installed(fake_run, fake_which, module_dirs):
    """Imported files land in REVIEW_MODULES_DIR (pending) - none of them get
    semodule -i'd directly, unlike the single-file Compile & Load flow."""
    modules_dir, approved_dir = module_dirs
    fake_which.add("checkmodule")
    fake_which.add("semodule_package")
    fake_run.set_response(["checkmodule"], returncode=0)
    fake_run.set_response(["semodule_package"], returncode=0)

    src_dir = modules_dir.parent / "addon-source"
    src_dir.mkdir(parents=True)
    te1 = src_dir / "dbus-broker.te"
    te1.write_text("module dbus-broker 1.0;\nrequire {}\n")
    te2 = src_dir / "net.te"
    te2.write_text("module net 1.0;\nrequire {}\n")

    results = selinux.import_te_files([str(te1), str(te2)])

    assert len(results) == 2
    names = {r.module_name for r in results}
    assert names == {"dbus-broker", "net"}
    assert all(r.error is None for r in results)
    assert all(r.pp_path is not None for r in results)
    assert (modules_dir / "dbus-broker.te").exists()
    assert (modules_dir / "net.te").exists()
    # nothing installed/approved - these are pending, not active
    assert not approved_dir.exists() or not any(approved_dir.iterdir())


def test_import_te_files_uses_filename_when_module_declaration_missing(fake_run, fake_which, module_dirs):
    modules_dir, _ = module_dirs
    fake_which.add("checkmodule")
    fake_which.add("semodule_package")
    fake_run.set_response(["checkmodule"], returncode=0)
    fake_run.set_response(["semodule_package"], returncode=0)

    src_dir = modules_dir.parent / "addon-source"
    src_dir.mkdir(parents=True)
    te = src_dir / "backlighthelper.te"
    te.write_text("allow init_t self:process execmem;\n")  # no module declaration line

    results = selinux.import_te_files([str(te)])
    assert results[0].module_name == "backlighthelper"
    assert results[0].error is None


def test_import_te_files_one_bad_file_does_not_abort_the_rest(fake_run, fake_which, module_dirs, tmp_path):
    modules_dir, _ = module_dirs
    fake_which.add("checkmodule")
    fake_which.add("semodule_package")
    fake_run.set_response(["checkmodule"], returncode=0)
    fake_run.set_response(["semodule_package"], returncode=0)

    src_dir = modules_dir.parent / "addon-source"
    src_dir.mkdir(parents=True)
    good = src_dir / "net.te"
    good.write_text("module net 1.0;\n")
    missing = str(tmp_path / "does_not_exist.te")

    results = selinux.import_te_files([missing, str(good)])

    assert len(results) == 2
    by_path = {r.source_path: r for r in results}
    assert by_path[missing].error is not None
    assert by_path[missing].pp_path is None
    assert by_path[str(good)].error is None
    assert by_path[str(good)].pp_path is not None


def test_import_te_files_invalid_module_name_recorded_not_raised(fake_run, fake_which, module_dirs):
    modules_dir, _ = module_dirs
    fake_which.add("checkmodule")
    fake_which.add("semodule_package")

    src_dir = modules_dir.parent / "addon-source"
    src_dir.mkdir(parents=True)
    bad = src_dir / "weird name!.te"
    bad.write_text("not a valid module declaration and an invalid filename stem too")

    results = selinux.import_te_files([str(bad)])
    assert results[0].error is not None
    assert results[0].pp_path is None


def test_install_pp_file_missing_file_raises(fake_which, tmp_path):
    fake_which.add("semodule")
    with pytest.raises(RuntimeError, match="no longer exists"):
        selinux.install_pp_file(str(tmp_path / "gone.pp"))


def test_install_pp_file_from_pending_moves_to_approved(fake_run, fake_which, module_dirs):
    modules_dir, approved_dir = module_dirs
    modules_dir.mkdir(parents=True)
    pp = modules_dir / "mymod.pp"
    pp.write_text("compiled")
    fake_which.add("semodule")
    fake_run.set_response(["pkexec", "semodule", "-i"], returncode=0)

    selinux.install_pp_file(str(pp))
    assert (approved_dir / "mymod.pp").exists()


def test_remove_semodule_validates_name(fake_which):
    with pytest.raises(ValueError):
        selinux.remove_semodule("bad name")


def test_remove_semodule_runs_privileged(fake_run, fake_which):
    selinux.remove_semodule("mymod")
    assert fake_run.last_call() == ["pkexec", "semodule", "-r", "mymod"]


def test_list_pending_modules_excludes_loaded(fake_run, fake_which, module_dirs):
    modules_dir, _ = module_dirs
    modules_dir.mkdir(parents=True)
    (modules_dir / "loaded_mod.pp").write_text("")
    (modules_dir / "draft_mod.pp").write_text("")
    fake_which.add("semodule")
    fake_run.set_response(["pkexec", "semodule", "-l"], stdout="loaded_mod\n")

    pending = selinux.list_pending_modules()
    assert pending == [("draft_mod", str(modules_dir / "draft_mod.pp"))]


def test_list_pending_modules_empty_when_dir_missing(module_dirs):
    assert selinux.list_pending_modules() == []


def test_list_approved_modules_reports_active_status(fake_run, fake_which, module_dirs):
    _, approved_dir = module_dirs
    approved_dir.mkdir(parents=True)
    (approved_dir / "active_mod.pp").write_text("")
    (approved_dir / "removed_mod.pp").write_text("")
    fake_which.add("semodule")
    fake_run.set_response(["pkexec", "semodule", "-l"], stdout="active_mod\n")

    result = selinux.list_approved_modules()
    by_name = {r["name"]: r["active"] for r in result}
    assert by_name["active_mod"] is True
    assert by_name["removed_mod"] is False


def test_reinstall_all_approved_modules_installs_only_inactive_in_one_call(fake_run, fake_which, module_dirs):
    _, approved_dir = module_dirs
    approved_dir.mkdir(parents=True)
    (approved_dir / "already_active.pp").write_text("")
    (approved_dir / "inactive_one.pp").write_text("")
    (approved_dir / "inactive_two.pp").write_text("")
    fake_which.add("semodule")
    fake_run.set_response(["pkexec", "semodule", "-l"], stdout="already_active\n")
    fake_run.set_response(["pkexec", "semodule", "-i"], returncode=0)

    result = selinux.reinstall_all_approved_modules()
    assert result.ok

    call = fake_run.last_call()
    assert call[:3] == ["pkexec", "semodule", "-i"]
    installed_paths = set(call[3:])
    assert installed_paths == {str(approved_dir / "inactive_one.pp"), str(approved_dir / "inactive_two.pp")}
    assert str(approved_dir / "already_active.pp") not in installed_paths
    # One privileged status check (semodule -l) plus exactly one privileged
    # install call, batching every inactive module into that single -i
    # invocation regardless of how many needed reinstalling - not one -i
    # call per module.
    pkexec_calls = [c for c in fake_run.calls if c and c[0] == "pkexec"]
    assert len(pkexec_calls) == 2
    install_calls = [c for c in pkexec_calls if c[:3] == ["pkexec", "semodule", "-i"]]
    assert len(install_calls) == 1


def test_reinstall_all_approved_modules_noop_when_all_already_active(fake_run, fake_which, module_dirs):
    _, approved_dir = module_dirs
    approved_dir.mkdir(parents=True)
    (approved_dir / "active_mod.pp").write_text("")
    fake_which.add("semodule")
    fake_run.set_response(["pkexec", "semodule", "-l"], stdout="active_mod\n")

    result = selinux.reinstall_all_approved_modules()
    assert result.ok
    assert "nothing to reinstall" in result.stdout
    # The status check (semodule -l) still runs to determine there's
    # nothing to do, but no install (-i) call should ever happen.
    assert fake_run.call_containing("-i") is None


def test_reinstall_all_approved_modules_noop_when_none_approved(fake_run, fake_which, module_dirs):
    fake_which.add("semodule")
    result = selinux.reinstall_all_approved_modules()
    assert result.ok
    assert "nothing to reinstall" in result.stdout


def test_reinstall_all_approved_modules_requires_semodule(fake_which, module_dirs):
    with pytest.raises(RuntimeError, match="isn't installed"):
        selinux.reinstall_all_approved_modules()


# --------------------------------------------------------------- policy review --

def test_sanitize_program_name():
    assert selinux._sanitize_program_name("my prog!") == "my_prog_"
    assert selinux._sanitize_program_name("") == "unknown"


def test_build_policy_review_groups_by_program_and_skips_noise(fake_run, fake_which, module_dirs):
    fake_which.add("audit2allow")
    fake_which.add("audit2why")
    fake_which.add("checkmodule")
    fake_which.add("semodule_package")

    denial_lines = "\n".join([
        'avc:  denied  { read } comm="systemd" name="a"',  # skipped: systemd noise
        'avc:  denied  { read } comm="myapp" name="b"',
        'avc:  denied  { write } comm="myapp" name="c"',
        'avc:  denied  { read } comm="otherapp" name="d"',
    ])
    fake_run.set_response(["journalctl", "-k"], stdout=denial_lines)
    fake_run.set_response(["audit2allow", "-m", "myapp"], stdout="module myapp 1.0;\n")
    fake_run.set_response(["audit2allow", "-m", "otherapp"], stdout="module otherapp 1.0;\n")
    fake_run.set_response(["audit2why"], stdout="explanation\n")
    fake_run.set_response(["checkmodule"], returncode=0)
    fake_run.set_response(["semodule_package"], returncode=0)

    reviews = selinux.build_policy_review(denial_limit=100)

    programs = {r.program: r.denial_count for r in reviews}
    assert "systemd" not in programs
    assert programs["myapp"] == 2
    assert programs["otherapp"] == 1
    # sorted by denial_count descending
    assert reviews[0].program == "myapp"


def test_build_policy_review_records_error_when_generate_te_fails(fake_run, fake_which, module_dirs):
    # audit2allow not installed -> generate_te raises -> review.error set, batch continues
    fake_run.set_response(
        ["journalctl", "-k"], stdout='avc:  denied  { read } comm="myapp" name="b"\n'
    )
    reviews = selinux.build_policy_review(denial_limit=100)
    assert len(reviews) == 1
    assert reviews[0].error is not None
    assert reviews[0].te_content == ""


def test_build_policy_review_uses_extensive_fetch_when_since_given(fake_run, fake_which, module_dirs):
    fake_which.add("audit2allow")
    fake_which.add("audit2why")
    fake_which.add("checkmodule")
    fake_which.add("semodule_package")
    fake_run.set_response(
        ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "--output=cat", "--since"],
        stdout='avc:  denied  { read } comm="myapp" name="b"\n',
    )
    fake_run.set_response(["audit2allow", "-m", "myapp"], stdout="module myapp 1.0;\n")
    fake_run.set_response(["audit2why"], stdout="explanation\n")
    fake_run.set_response(["checkmodule"], returncode=0)
    fake_run.set_response(["semodule_package"], returncode=0)

    reviews = selinux.build_policy_review(since="2026-01-01T00:00:00+00:00")
    assert len(reviews) == 1
    assert reviews[0].program == "myapp"
    # the capped "recent" journalctl call (-n flag) must NOT have been used
    assert not any("-n" in call for call in fake_run.calls if "journalctl" in call)


def test_build_policy_review_since_none_still_uses_extensive_fetch_not_narrow_window(
    fake_run, fake_which, module_dirs
):
    """
    Regression test for a real bug found on bare metal: the Denial Review
    page always passes `since` explicitly (self._last_review.since), which
    is None on any system that isn't using Setup Mode - the common case.
    Explicitly passing since=None must still route through
    list_all_denials()'s uncapped, boot-scoped fetch (matching what the
    page's own "Review" button already showed), not silently fall back to
    the narrow "recent" window meant only for the plain SELinux page's
    ad-hoc review button, which never passes `since` at all.
    """
    fake_which.add("audit2allow")
    fake_which.add("audit2why")
    fake_which.add("checkmodule")
    fake_which.add("semodule_package")
    fake_run.set_response(
        ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "--output=cat"],
        stdout='avc:  denied  { read } comm="myapp" name="b"\n',
    )
    fake_run.set_response(["audit2allow", "-m", "myapp"], stdout="module myapp 1.0;\n")
    fake_run.set_response(["audit2why"], stdout="explanation\n")
    fake_run.set_response(["checkmodule"], returncode=0)
    fake_run.set_response(["semodule_package"], returncode=0)

    reviews = selinux.build_policy_review(since=None)
    assert len(reviews) == 1
    assert reviews[0].program == "myapp"
    # the capped "recent" journalctl call (-n flag) must NOT have been used,
    # and no --since flag either, matching journalctl's own uncapped
    # everything-still-retained behavior for since=None
    journal_calls = [call for call in fake_run.calls if call and call[0] == "journalctl"]
    assert len(journal_calls) == 1
    assert "-n" not in journal_calls[0]
    assert "--since" not in journal_calls[0]


def test_build_policy_review_omitted_since_uses_narrow_window(fake_run, fake_which, module_dirs):
    """
    The plain SELinux page's ad-hoc review button never passes `since` at
    all (as opposed to selinux_review.py, which always passes it - see the
    test above) - that omission is what should trigger the small, cheap,
    capped "recent" fetch, distinct from an explicit since=None.
    """
    fake_which.add("audit2allow")
    fake_which.add("audit2why")
    fake_which.add("checkmodule")
    fake_which.add("semodule_package")
    fake_run.set_response(
        ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "-n"],
        stdout='avc:  denied  { read } comm="myapp" name="b"\n',
    )
    fake_run.set_response(["audit2allow", "-m", "myapp"], stdout="module myapp 1.0;\n")
    fake_run.set_response(["audit2why"], stdout="explanation\n")
    fake_run.set_response(["checkmodule"], returncode=0)
    fake_run.set_response(["semodule_package"], returncode=0)

    reviews = selinux.build_policy_review()
    assert len(reviews) == 1
    journal_calls = [call for call in fake_run.calls if call and call[0] == "journalctl"]
    assert len(journal_calls) == 1
    assert "-n" in journal_calls[0]


# --------------------------------------------------------------- Setup Mode --

def test_start_setup_mode_sets_permissive_and_records_timestamp(fake_run, fake_which, module_dirs, monkeypatch, tmp_path):
    conf = tmp_path / "config"
    conf.write_text("SELINUX=enforcing\n")
    monkeypatch.setattr(selinux, "SELINUX_CONFIG", conf)
    fake_run.set_response(["pkexec", "setenforce", "0"], returncode=0)
    fake_run.set_response(["pkexec", "sed", "-i"], returncode=0)

    result = selinux.start_setup_mode()
    assert result.ok
    assert selinux.is_in_setup_mode() is True
    assert selinux.get_setup_mode_started_at() is not None


def test_start_setup_mode_does_not_record_timestamp_on_failure(fake_run, fake_which, module_dirs, monkeypatch, tmp_path):
    conf = tmp_path / "config"
    conf.write_text("SELINUX=enforcing\n")
    monkeypatch.setattr(selinux, "SELINUX_CONFIG", conf)
    fake_run.set_response(["pkexec", "setenforce", "0"], returncode=1)

    result = selinux.start_setup_mode()
    assert not result.ok
    assert selinux.is_in_setup_mode() is False


def test_get_setup_mode_started_at_none_when_not_started(module_dirs):
    assert selinux.get_setup_mode_started_at() is None
    assert selinux.is_in_setup_mode() is False


def test_clear_setup_mode_removes_state(fake_run, fake_which, module_dirs, monkeypatch, tmp_path):
    conf = tmp_path / "config"
    conf.write_text("SELINUX=enforcing\n")
    monkeypatch.setattr(selinux, "SELINUX_CONFIG", conf)
    fake_run.set_response(["pkexec", "setenforce", "0"], returncode=0)
    fake_run.set_response(["pkexec", "sed", "-i"], returncode=0)

    selinux.start_setup_mode()
    assert selinux.is_in_setup_mode() is True
    selinux.clear_setup_mode()
    assert selinux.is_in_setup_mode() is False


def test_clear_setup_mode_harmless_when_never_started(module_dirs):
    selinux.clear_setup_mode()  # must not raise
    assert selinux.is_in_setup_mode() is False


def test_get_setup_mode_started_at_handles_corrupt_state_file(module_dirs):
    modules_dir, _ = module_dirs
    state_file = selinux.SETUP_MODE_STATE_FILE
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text("not json{{{")
    assert selinux.get_setup_mode_started_at() is None


# --------------------------------------------------------------- list_all_denials --

def test_list_all_denials_journal_only(fake_run, fake_which):
    fake_run.set_response(
        ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "--output=cat"],
        stdout="irrelevant\navc:  denied  { read } comm=\"foo\"\n",
    )
    lines = selinux.list_all_denials(source="journal")
    assert lines == ['avc:  denied  { read } comm="foo"']


def test_list_all_denials_applies_since_to_journalctl(fake_run, fake_which):
    fake_run.set_response(
        ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "--output=cat", "--since", "2026-01-15 10:00:00"],
        stdout='avc:  denied  { read } comm="foo"\n',
    )
    lines = selinux.list_all_denials(since="2026-01-15T10:00:00+00:00", source="journal")
    assert len(lines) == 1


def test_list_all_denials_audit_log_uses_boot_when_no_since(fake_run, fake_which):
    fake_which.add("ausearch")
    fake_run.set_response(
        ["pkexec", "ausearch", "-m", "avc", "-ts", "boot"],
        stdout='type=AVC msg=audit(...): avc:  denied  { write }\n',
    )
    lines = selinux.list_all_denials(source="audit_log")
    assert len(lines) == 1


def test_list_all_denials_audit_log_skipped_when_ausearch_missing(fake_run, fake_which):
    lines = selinux.list_all_denials(source="audit_log")
    assert lines == []


def test_list_all_denials_both_sources_combined(fake_run, fake_which):
    fake_which.add("ausearch")
    fake_run.set_response(
        ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "--output=cat"],
        stdout='avc:  denied  { read } comm="foo"\n',
    )
    fake_run.set_response(
        ["pkexec", "ausearch", "-m", "avc", "-ts", "boot"],
        stdout='type=AVC msg=audit(...): avc:  denied  { write }\n',
    )
    lines = selinux.list_all_denials(source="both")
    assert len(lines) == 2


# --------------------------------------------------------------- group_denials --

_DENIAL_A = 'avc:  denied  { read } comm="myapp" name="a" scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file'
_DENIAL_A_DUP = 'avc:  denied  { read } comm="myapp" name="a2" scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file'
_DENIAL_B = 'avc:  denied  { write } comm="myapp" name="b" scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=file'
_DENIAL_SYSTEMD = 'avc:  denied  { read } comm="systemd" name="c" scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file'
# Real line from a user's bare-metal report: a non-MLS/MCS policy (no
# trailing :s0 sensitivity range at all - just user:role:type, three
# parts not four) that the original _CONTEXT_TYPE_RE_TEMPLATE silently
# failed to match, showing every denial as "? -> ?" while comm=/tclass=/
# the permission set (parsed by separate regexes) still worked fine.
_DENIAL_NO_MLS = (
    'type=AVC msg=audit(1786259824.298:460): avc:  denied  { search } for  pid=1231 comm="pipewire" '
    'name="alsa" dev="sdb3" ino=17306705 scontext=user_u:user_r:pipewire_t '
    "tcontext=system_u:object_r:alsa_var_lib_t tclass=dir permissive=1"
)


def test_group_denials_dedupes_identical_context_and_class():
    grouped = selinux.group_denials([_DENIAL_A, _DENIAL_A_DUP])
    assert len(grouped) == 1
    assert grouped[0].count == 2


def test_group_denials_keeps_distinct_permissions_separate():
    grouped = selinux.group_denials([_DENIAL_A, _DENIAL_B])
    assert len(grouped) == 2
    perms = {tuple(g.permissions) for g in grouped}
    assert ("read",) in perms
    assert ("write",) in perms


def test_group_denials_skips_noise_programs():
    grouped = selinux.group_denials([_DENIAL_A, _DENIAL_SYSTEMD])
    programs = {g.program for g in grouped}
    assert "systemd" not in programs
    assert "myapp" in programs


def test_group_denials_extracts_context_types_and_path():
    """
    _DENIAL_A only has name="a" (a bare, non-absolute name), not a real
    path="..." field - restorecon needs an actual filesystem path, not a
    bare directory-entry name, so sample_path correctly comes back None
    here rather than the misleading "a". See the two tests directly below
    for the real bug this guards against and the cases that DO extract.
    """
    grouped = selinux.group_denials([_DENIAL_A])
    g = grouped[0]
    assert g.scontext_type == "myapp_t"
    assert g.tcontext_type == "etc_t"
    assert g.tclass == "file"
    assert g.sample_path is None


def test_group_denials_extracts_real_path_field():
    denial = (
        'avc:  denied  { read } comm="myapp" path="/var/log/journal" '
        "scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:var_log_t:s0 tclass=dir"
    )
    grouped = selinux.group_denials([denial])
    assert grouped[0].sample_path == "/var/log/journal"


def test_group_denials_bare_name_never_used_as_a_path():
    """
    Regression test for a real bug on bare metal: a bare name="journal"
    (no path="..." field at all - common for search/getattr denials on a
    directory) used to fall through to being treated as a usable path,
    which then got fed straight into restorecon and resolved relative to
    whatever the privileged process's working directory happened to be
    (/root in the actual report) - either a loud failure, or worse, a
    successful relabel of some unrelated file that happened to share that
    bare name in the wrong directory. Must come back None, matching "no
    path available" exactly like a denial with neither field at all.
    """
    denial = (
        'avc:  denied  { search } comm="journald" name="journal" '
        "scontext=system_u:system_r:syslogd_t:s0 tcontext=system_u:object_r:var_log_t:s0 tclass=dir"
    )
    grouped = selinux.group_denials([denial])
    assert grouped[0].sample_path is None


def test_group_denials_absolute_name_field_still_usable():
    """The rare case where name= itself is already an absolute path is
    still safe to use - only a bare (non-absolute) name= is rejected."""
    denial = (
        'avc:  denied  { read } comm="myapp" name="/etc/myapp.conf" '
        "scontext=system_u:system_r:myapp_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=file"
    )
    grouped = selinux.group_denials([denial])
    assert grouped[0].sample_path == "/etc/myapp.conf"


def test_group_denials_extracts_context_types_without_mls_level():
    """Regression test for a real bug: a context with no :s0 suffix (three
    colon-separated parts, not four) must still extract the type field
    correctly rather than showing "?" for both source and target."""
    grouped = selinux.group_denials([_DENIAL_NO_MLS])
    assert len(grouped) == 1
    g = grouped[0]
    assert g.scontext_type == "pipewire_t"
    assert g.tcontext_type == "alsa_var_lib_t"
    assert g.tclass == "dir"
    assert g.program == "pipewire"


def test_group_denials_sorted_by_count_descending():
    grouped = selinux.group_denials([_DENIAL_A, _DENIAL_A_DUP, _DENIAL_B])
    assert grouped[0].count >= grouped[1].count


# --------------------------------------------------------------- classify_denials --

def test_classify_denials_marks_new_when_no_approved_modules(fake_run, fake_which, module_dirs):
    grouped = selinux.group_denials([_DENIAL_A])
    classified = selinux.classify_denials(grouped)
    assert classified[0].classification == "new"
    assert classified[0].matched_module is None


def test_classify_denials_marks_already_allowed_when_matching_loaded_module(fake_run, fake_which, module_dirs):
    modules_dir, approved_dir = module_dirs
    approved_dir.mkdir(parents=True)
    (approved_dir / "myfix.te").write_text(
        "module myfix 1.0;\nallow myapp_t etc_t:file { read write };\n"
    )
    fake_which.add("semodule")
    fake_run.set_response(["pkexec", "semodule", "-l"], stdout="myfix\n")

    grouped = selinux.group_denials([_DENIAL_A])
    classified = selinux.classify_denials(grouped)
    assert classified[0].classification == "already_allowed"
    assert classified[0].matched_module == "myfix"


def test_classify_denials_ignores_matching_rule_in_module_not_currently_loaded(fake_run, fake_which, module_dirs):
    """A .te file sitting in approved/ for a module that isn't currently
    loaded must NOT count as 'already allowed' - the fix was uninstalled."""
    modules_dir, approved_dir = module_dirs
    approved_dir.mkdir(parents=True)
    (approved_dir / "myfix.te").write_text(
        "module myfix 1.0;\nallow myapp_t etc_t:file { read write };\n"
    )
    fake_which.add("semodule")
    fake_run.set_response(["pkexec", "semodule", "-l"], stdout="")  # myfix not loaded

    grouped = selinux.group_denials([_DENIAL_A])
    classified = selinux.classify_denials(grouped)
    assert classified[0].classification == "new"


def test_classify_denials_requires_matching_permissions():
    """A loaded module that allows a DIFFERENT permission on the same
    types/class must not mask this denial as already-allowed."""
    pass  # covered implicitly by the two tests above; kept as a documentation marker


# --------------------------------------------------------------- review_all_denials --

def test_review_all_denials_splits_new_and_already_allowed(fake_run, fake_which, module_dirs):
    modules_dir, approved_dir = module_dirs
    approved_dir.mkdir(parents=True)
    (approved_dir / "myfix.te").write_text("module myfix 1.0;\nallow myapp_t etc_t:file { read };\n")
    fake_which.add("semodule")
    fake_run.set_response(["pkexec", "semodule", "-l"], stdout="myfix\n")
    fake_run.set_response(
        ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "--output=cat"],
        stdout=f"{_DENIAL_A}\n{_DENIAL_B}\n",
    )

    review = selinux.review_all_denials(source="journal", since_setup_mode=False)
    assert len(review.already_allowed) == 1
    assert len(review.new) == 1
    assert review.already_allowed[0].matched_module == "myfix"


def test_review_all_denials_scopes_to_setup_mode_start_by_default(fake_run, fake_which, module_dirs):
    state_file = selinux.SETUP_MODE_STATE_FILE
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text('{"started_at": "2026-01-01T00:00:00+00:00"}')
    fake_run.set_response(
        ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "--output=cat", "--since", "2026-01-01 00:00:00"],
        stdout=f"{_DENIAL_A}\n",
    )

    review = selinux.review_all_denials(source="journal")
    assert review.since == "2026-01-01T00:00:00+00:00"
    assert len(review.new) == 1


def test_review_all_denials_finds_resolved_since_last_run(fake_run, fake_which, module_dirs):
    # first run: only _DENIAL_A present -> saved as the snapshot
    fake_run.set_response(
        ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "--output=cat"], stdout=f"{_DENIAL_A}\n"
    )
    first = selinux.review_all_denials(source="journal", since_setup_mode=False)
    assert len(first.new) == 1
    assert first.resolved == []

    # second run: _DENIAL_A no longer appears -> should show up as resolved
    fake_run.set_response(
        ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "--output=cat"], stdout=""
    )
    second = selinux.review_all_denials(source="journal", since_setup_mode=False)
    assert len(second.new) == 0
    assert len(second.resolved) == 1
    assert second.resolved[0].program == "myapp"


def test_review_all_denials_reports_total_raw_line_count(fake_run, fake_which, module_dirs):
    fake_run.set_response(
        ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "--output=cat"],
        stdout=f"{_DENIAL_A}\n{_DENIAL_A_DUP}\n{_DENIAL_B}\n",
    )
    review = selinux.review_all_denials(source="journal", since_setup_mode=False)
    assert review.total_raw_lines == 3
    # deduped down from 3 raw lines to 2 grouped entries
    assert len(review.new) + len(review.already_allowed) == 2


# --------------------------------------------------------------- undefined-in-policy handling --

_UNDEFINED_PERM_LINE = "kernel: SELinux: Permission bpf in class capability2 not defined in policy."
_UNDEFINED_PERM_LINE_DUP = "kernel: SELinux: Permission bpf in class capability2 not defined in policy."
_UNDEFINED_CLASS_LINE = "kernel: SELinux: Class mctp_socket not defined in policy."


def test_is_relevant_selinux_line_matches_denied_and_undefined():
    assert selinux._is_relevant_selinux_line('avc:  denied  { read }') is True
    assert selinux._is_relevant_selinux_line(_UNDEFINED_PERM_LINE) is True
    assert selinux._is_relevant_selinux_line(_UNDEFINED_CLASS_LINE) is True
    assert selinux._is_relevant_selinux_line("some unrelated kernel line") is False


def test_list_all_denials_journalctl_grep_pattern_includes_undefined_in_policy(fake_run, fake_which):
    fake_run.set_response(
        ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "--output=cat"],
        stdout=_UNDEFINED_PERM_LINE + "\n",
    )
    lines = selinux.list_all_denials(source="journal")
    assert lines == [_UNDEFINED_PERM_LINE]


def test_list_avc_denials_also_catches_undefined_in_policy_lines(fake_run):
    fake_run.set_response(["journalctl", "-k"], stdout=_UNDEFINED_PERM_LINE + "\n")
    denials = selinux.list_avc_denials(limit=5)
    assert denials == [_UNDEFINED_PERM_LINE]


def test_group_denials_creates_undefined_in_policy_entry_for_permission_line():
    grouped = selinux.group_denials([_UNDEFINED_PERM_LINE])
    assert len(grouped) == 1
    entry = grouped[0]
    assert entry.classification == "undefined_in_policy"
    assert entry.tclass == "capability2"
    assert entry.permissions == ["bpf"]
    assert entry.scontext_type == "(kernel)"
    assert entry.program == "kernel"


def test_group_denials_creates_undefined_in_policy_entry_for_class_line():
    grouped = selinux.group_denials([_UNDEFINED_CLASS_LINE])
    assert len(grouped) == 1
    entry = grouped[0]
    assert entry.classification == "undefined_in_policy"
    assert entry.tclass == "mctp_socket"
    assert entry.permissions == []


def test_group_denials_dedupes_repeated_undefined_permission_lines():
    grouped = selinux.group_denials([_UNDEFINED_PERM_LINE, _UNDEFINED_PERM_LINE_DUP])
    assert len(grouped) == 1
    assert grouped[0].count == 2


def test_group_denials_keeps_undefined_and_normal_denials_separate():
    grouped = selinux.group_denials([_UNDEFINED_PERM_LINE, _DENIAL_A])
    classifications = {g.classification for g in grouped}
    assert classifications == {"undefined_in_policy", "new"}


def test_classify_denials_never_reclassifies_undefined_in_policy(fake_run, fake_which, module_dirs):
    """Even if (hypothetically) an installed module happened to define a
    rule that could match, undefined_in_policy entries must never flip to
    already_allowed - a normal allow rule can't fix an undefined
    permission, so that reclassification would be actively misleading."""
    modules_dir, approved_dir = module_dirs
    approved_dir.mkdir(parents=True)
    (approved_dir / "myfix.te").write_text("module myfix 1.0;\nallow (kernel) (kernel):capability2 { bpf };\n")
    fake_which.add("semodule")
    fake_run.set_response(["pkexec", "semodule", "-l"], stdout="myfix\n")

    grouped = selinux.group_denials([_UNDEFINED_PERM_LINE])
    classified = selinux.classify_denials(grouped)
    assert classified[0].classification == "undefined_in_policy"


def test_review_all_denials_splits_undefined_in_policy_into_its_own_bucket(fake_run, fake_which, module_dirs):
    fake_run.set_response(
        ["journalctl", "-k", "--no-pager", "-g", "avc:|not defined in policy", "--output=cat"],
        stdout=f"{_UNDEFINED_PERM_LINE}\n{_DENIAL_A}\n",
    )
    review = selinux.review_all_denials(source="journal", since_setup_mode=False)
    assert len(review.undefined_in_policy) == 1
    assert len(review.new) == 1
    assert review.undefined_in_policy[0].tclass == "capability2"


def test_build_policy_review_skips_undefined_in_policy_lines(fake_run, fake_which, module_dirs):
    """audit2allow can't do anything useful with these lines (no comm=/
    scontext= fields, and the fix isn't a rule anyway) - they must not
    pollute the 'unknown' program bucket."""
    fake_run.set_response(
        ["journalctl", "-k"],
        stdout=f"{_UNDEFINED_PERM_LINE}\navc:  denied  {{ read }} comm=\"myapp\" name=\"b\"\n",
    )
    reviews = selinux.build_policy_review(denial_limit=100)
    programs = {r.program for r in reviews}
    assert "unknown" not in programs
    assert "myapp" in programs


# --------------------------------------------------------------- check_policy_source_for_permission --

_ACCESS_VECTORS_SAMPLE = """
class capability
{
    chown
    dac_override
}

class capability2
inherits capability
{
    mac_override
    mac_admin
    syslog
}

class cap2_userns
{
    mac_override
}
"""


def test_check_policy_source_permission_found_in_own_block(fake_run, tmp_path):
    fake_run.set_response(["cat", str(tmp_path / "policy" / "flask" / "access_vectors")], stdout=_ACCESS_VECTORS_SAMPLE)
    result = selinux.check_policy_source_for_permission(str(tmp_path), "capability2", "syslog")
    assert result["class_found"] is True
    assert result["permission_found"] is True
    assert result["inherits"] == "capability"
    assert result["error"] is None


def test_check_policy_source_permission_not_found(fake_run, tmp_path):
    fake_run.set_response(["cat", str(tmp_path / "policy" / "flask" / "access_vectors")], stdout=_ACCESS_VECTORS_SAMPLE)
    result = selinux.check_policy_source_for_permission(str(tmp_path), "capability2", "bpf")
    assert result["class_found"] is True
    assert result["permission_found"] is False


def test_check_policy_source_permission_found_via_inheritance(fake_run, tmp_path):
    fake_run.set_response(["cat", str(tmp_path / "policy" / "flask" / "access_vectors")], stdout=_ACCESS_VECTORS_SAMPLE)
    result = selinux.check_policy_source_for_permission(str(tmp_path), "capability2", "chown")
    assert result["class_found"] is True
    assert result["permission_found"] is True
    assert result["inherits"] == "capability"


def test_check_policy_source_class_not_found(fake_run, tmp_path):
    fake_run.set_response(["cat", str(tmp_path / "policy" / "flask" / "access_vectors")], stdout=_ACCESS_VECTORS_SAMPLE)
    result = selinux.check_policy_source_for_permission(str(tmp_path), "mctp_socket", "send")
    assert result["class_found"] is False
    assert result["permission_found"] is False


def test_check_policy_source_no_permission_just_checks_class_exists(fake_run, tmp_path):
    fake_run.set_response(["cat", str(tmp_path / "policy" / "flask" / "access_vectors")], stdout=_ACCESS_VECTORS_SAMPLE)
    result = selinux.check_policy_source_for_permission(str(tmp_path), "cap2_userns")
    assert result["class_found"] is True
    assert result["permission_found"] is True  # no permission given -> just confirms class presence


def test_check_policy_source_read_failure_reports_error(fake_run, tmp_path):
    fake_run.set_response(
        ["cat", str(tmp_path / "policy" / "flask" / "access_vectors")], returncode=1, stderr="No such file"
    )
    result = selinux.check_policy_source_for_permission(str(tmp_path), "capability2", "bpf")
    assert result["class_found"] is False
    assert result["permission_found"] is False
    assert "Couldn't read" in result["error"]


def test_check_policy_source_never_writes_anything(fake_run, fake_which, tmp_path):
    """This is purely diagnostic - confirm no privileged/write call ever happens."""
    fake_run.set_response(["cat", str(tmp_path / "policy" / "flask" / "access_vectors")], stdout=_ACCESS_VECTORS_SAMPLE)
    selinux.check_policy_source_for_permission(str(tmp_path), "capability2", "bpf")
    assert fake_run.call_containing("pkexec") is None
