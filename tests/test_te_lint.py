"""Tests for the SELinux module linter (te_lint.py) and its install gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from atropa.backend import compliance, selinux, te_lint

FIXTURES = Path(__file__).parent / "fixtures" / "te"


def module(*rules: str, requires: str = "type x_t;") -> str:
    return "module test 1.0;\n\nrequire {\n\t" + requires + "\n\tclass file { read write };\n}\n\n" + "\n".join(rules) + "\n"


def ids(text: str, category: str = "unsure") -> dict[str, str]:
    return {f.rule_id: f.severity for f in te_lint.lint(text, category, booleans=[])}


# ------------------------------------------------------------------ parsing --

def test_parse_skips_require_blocks_with_braces_of_their_own():
    rules = te_lint.parse(module("allow a_t b_t:file { read write };", "allow a_t self:capability chown;"))
    assert [(r.source, r.target, r.classes, r.perms) for r in rules] == [
        ("a_t", "b_t", ["file"], ["read", "write"]),
        ("a_t", "self", ["capability"], ["chown"]),
    ]
    assert rules[0].line == 8


def test_parse_joins_statements_across_lines_and_drops_comments():
    rules = te_lint.parse("allow a_t b_t:{ file dir } { read\n  getattr }; # trailing\n#allow c_t d_t:file read;\n")
    assert len(rules) == 1 and rules[0].classes == ["file", "dir"] and rules[0].perms == ["read", "getattr"]


def test_parse_keeps_wildcards():
    assert te_lint.parse("allow a_t b_t:file *;")[0].perms == ["*"]
    assert te_lint.parse("allow a_t b_t:file ~{ write };")[0].perms[0] == "~"


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.te")), ids=lambda p: p.stem)
def test_every_rule_of_real_drafts_is_parsed(path):
    text = path.read_text()
    statements = [line for line in text.splitlines() if line.strip().startswith(("allow", "dontaudit"))]
    assert len(te_lint.parse(text)) == len(statements)


# --------------------------------------------------------------- base rules --

@pytest.mark.parametrize("rule, rule_id", [
    ("allow a_t security_t:security setenforce;", "enforcement"),
    ("allow a_t selinux_config_t:file write;", "selinux_config"),
    ("allow a_t shadow_t:file read;", "shadow"),
    ("allow a_t etc_t:file { create write };", "credential_write"),
    ("allow a_t bin_t:file write;", "code_write"),
    ("allow a_t foo_exec_t:file append;", "code_write"),
    ("allow a_t memory_device_t:chr_file read;", "raw_device"),
    ("allow a_t kernel_t:system module_load;", "module_load"),
    ("allow a_t self:capability sys_module;", "cap_dangerous"),
    ("allow a_t b_t:process ptrace;", "ptrace_other"),
    ("allow a_t unconfined_t:process transition;", "to_unconfined"),
    ("allow a_t auditd_log_t:file { write unlink };", "audit_tamper"),
    ("allow a_t self:memprotect mmap_zero;", "mmap_zero"),
    ("allow guest_t b_t:file read;", "confined_user"),
])
def test_dangerous_rules(rule, rule_id):
    assert ids(module(rule))[rule_id] == te_lint.DANGEROUS


@pytest.mark.parametrize("rule, rule_id", [
    ("allow a_t default_t:file read;", "generic_target"),
    ("allow a_t b_t:file *;", "wildcard"),
    ("allow a_t user_home_t:file { create write unlink rename };", "manage_shared"),
    ("allow a_t unreserved_port_t:tcp_socket name_bind;", "broad_port"),
    ("allow a_t self:rawip_socket create;", "raw_socket"),
    ("allow a_t self:capability sys_admin;", "cap_broad"),
    ("allow a_t b_t:process sigkill;", "signal_other"),
    ("allow a_t self:process execmem;", "execmem"),
    ("allow user_t b_t:file read;", "limited_user"),
    ("allow a_t fixed_disk_device_t:blk_file read;", "raw_disk_read"),
])
def test_review_rules(rule, rule_id):
    assert ids(module(rule))[rule_id] == te_lint.REVIEW


@pytest.mark.parametrize("rule", [
    "allow a_t etc_t:file { read open getattr };",  # reading /etc is normal
    "allow a_t self:process ptrace;",  # its own processes
    "allow a_t a_port_t:tcp_socket name_bind;",  # its own port type
    "allow a_t b_t:file { read open };",
    "allow auditd_t auditd_log_t:file { write append };",  # auditd writes its own logs
])
def test_ordinary_rules_are_not_flagged(rule):
    assert te_lint.verdict(te_lint.lint(module(rule), booleans=[])) == "fine"


def test_dac_override_is_a_note_with_a_drop_fix():
    (finding,) = [f for f in te_lint.lint(module("allow a_t self:capability dac_override;"), booleans=[])]
    assert finding.severity == te_lint.NOTE and finding.fix == "drop" and finding.perms == ["dac_override"]


def test_write_then_execute_is_flagged():
    text = module("allow a_t b_t:file { write create };", "allow a_t b_t:file { execute map };")
    assert ids(text)["write_execute"] == te_lint.REVIEW


def test_a_large_module_suggests_permissive():
    rules = [f"allow a_t t{i}_t:file read;" for i in range(te_lint.SIZE_THRESHOLD + 1)]
    finding = next(f for f in te_lint.lint(module(*rules), booleans=[]) if f.rule_id == "size")
    assert finding.fix == "permissive"


def test_booleans_and_noise_are_notes():
    found = te_lint.lint(module("allow a_t b_t:file read;"), booleans=["x_read_all"])
    assert [(f.rule_id, f.fix, f.detail) for f in found] == [("boolean", "boolean", "x_read_all")]


def test_user_domain_widening_is_reported_once():
    text = module("allow user_t b_t:file read;", "allow user_t c_t:file read;")
    assert [f.rule_id for f in te_lint.lint(text, booleans=[])].count("limited_user") == 1


# --------------------------------------------------------------- categories --

def test_boot_lowers_module_loading_to_review():
    text = module("allow a_t kernel_t:system module_load;")
    assert ids(text)["module_load"] == te_lint.DANGEROUS
    assert ids(text, "boot")["module_load"] == te_lint.REVIEW


def test_a_category_never_lowers_the_hard_list():
    text = module("allow a_t shadow_t:file read;")
    for category in te_lint.CATEGORIES:
        assert ids(text, category)["shadow"] == te_lint.DANGEROUS


def test_desktop_app_capabilities_are_dangerous():
    text = module("allow a_t self:capability net_admin;")
    assert ids(text)["cap_broad"] == te_lint.REVIEW
    found = ids(text, "desktop_app")
    assert found["cap_broad"] == te_lint.DANGEROUS and found["out_of_place:desktop_app"] == te_lint.DANGEROUS


@pytest.mark.parametrize("category, rule, severity", [
    ("system_service", "allow a_t user_home_t:file read;", te_lint.REVIEW),
    ("system_service", "allow a_t tmp_t:file execute;", te_lint.DANGEROUS),
    ("user_service", "allow a_t var_lib_t:file write;", te_lint.DANGEROUS),
    ("boot", "allow a_t http_port_t:tcp_socket name_connect;", te_lint.REVIEW),
    ("dbus_service", "allow a_t user_home_t:dir search;", te_lint.REVIEW),
    ("desktop_app", "allow a_t self:tcp_socket name_bind;", te_lint.DANGEROUS),
])
def test_out_of_place_for_the_category(category, rule, severity):
    assert ids(module(rule), category)[f"out_of_place:{category}"] == severity


def test_a_module_mostly_outside_its_category_says_so():
    text = module("allow a_t user_home_t:file read;", "allow a_t xserver_t:unix_stream_socket connectto;")
    assert "category_mismatch" in ids(text, "system_service")


def test_detect_category_from_the_processes_cgroup(tmp_path):
    for pid, cgroup in (("10", "0::/system.slice/sshd.service\n"), ("20", "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-brave.scope\n"),
                        ("30", "0::/user.slice/user-1000.slice/user@1000.service/app.slice/pipewire.service\n")):
        (tmp_path / pid).mkdir()
        (tmp_path / pid / "cgroup").write_text(cgroup)
    assert te_lint.detect_category(["avc: denied pid=10 comm=sshd"], "sshd_t", tmp_path)[0] == "system_service"
    assert te_lint.detect_category(["avc: denied pid=20 comm=brave"], "user_t", tmp_path)[0] == "desktop_app"
    assert te_lint.detect_category(["avc: denied pid=30 comm=pipewire"], "user_t", tmp_path)[0] == "user_service"


def test_detect_category_falls_back_to_the_domain(tmp_path):
    assert te_lint.detect_category(["pid=99"], "kmod_t", tmp_path)[0] == "boot"
    assert te_lint.detect_category(["pid=99"], "passwd_t", tmp_path) == ("unsure", "nothing to go by")
    assert te_lint.detect_category(["pid=99"], "dnsmasq_t", tmp_path)[0] == "system_service"


# ----------------------------------------------------- calibration corpus --

@pytest.mark.parametrize("name, category", [
    ("atropa_brave_brave_t", "desktop_app"),
    ("atropa_fwupdmgr_fwupdmgr_t", "system_service"),
    ("atropa_libvirt", "system_service"),
    ("atropa_systemd-tmpfile_systemd_tmpfiles_t", "boot"),
    ("atropa_kmod_t", "boot"),
])
def test_real_drafts_are_not_called_dangerous(name, category):
    # Drafts from a real enforcing desktop: none grants anything root-equivalent.
    text = (FIXTURES / f"{name}.te").read_text()
    assert te_lint.verdict(te_lint.lint(text, category)) != te_lint.DANGEROUS


# --------------------------------------------------------------- safer edits --

def test_drop_perms_rewrites_the_rule_without_them():
    text = module("allow a_t self:capability { sys_admin chown };")
    finding = next(f for f in te_lint.lint(text, booleans=[]) if f.rule_id == "cap_broad")
    edited = te_lint.drop_perms(text, te_lint.Finding("x", "review", "", "", finding.line, "drop", ["sys_admin"]))
    assert "allow a_t self:capability chown;" in edited and "sys_admin" not in edited.split("}")[-1]


def test_drop_perms_removes_an_emptied_rule():
    text = module("allow a_t shadow_t:file read;")
    finding = next(f for f in te_lint.lint(text, booleans=[]) if f.rule_id == "shadow")
    assert "shadow_t:file" not in te_lint.drop_perms(text, finding)


def test_to_dontaudit():
    text = module("allow a_t b_t:file read;")
    rule = te_lint.parse(text)[0]
    assert "dontaudit a_t b_t:file read;" in te_lint.to_dontaudit(text, te_lint.Finding("x", "note", "", "", rule.line))


# -------------------------------------------------------------------- gate --

DANGEROUS_TE = module("allow a_t shadow_t:file read;").replace("module test", "module atropa_test")


def test_compile_and_load_refuses_unacknowledged_dangerous_rules(fake_run, fake_which, monkeypatch):
    monkeypatch.setattr(selinux.shutil, "which", lambda name: f"/usr/bin/{name}")
    with pytest.raises(selinux.LintRefused) as raised:
        selinux.compile_and_load_te(DANGEROUS_TE, "atropa_test")
    assert raised.value.findings[0].rule_id == "shadow"
    assert not any("semodule" in call for call in fake_run.calls)


def test_compile_and_load_with_the_acknowledgement_installs_and_keeps_it(fake_run, fake_which, monkeypatch):
    monkeypatch.setattr(selinux.shutil, "which", lambda name: f"/usr/bin/{name}")
    key = te_lint.unacknowledged(te_lint.lint(DANGEROUS_TE), ())[0].key
    assert selinux.compile_and_load_te(DANGEROUS_TE, "atropa_test", [key]).ok
    assert any("semodule" in " ".join(call) for call in fake_run.calls)
    meta = json.loads((selinux.APPROVED_MODULES_DIR / "atropa_test.atropa.json").read_text())
    assert meta["acknowledged"] == [key]


def test_install_pp_file_gates_on_the_te_next_to_it(fake_run, fake_which, monkeypatch):
    monkeypatch.setattr(selinux.shutil, "which", lambda name: f"/usr/bin/{name}")
    selinux.REVIEW_MODULES_DIR.mkdir(parents=True)
    (selinux.REVIEW_MODULES_DIR / "atropa_test.te").write_text(DANGEROUS_TE)
    pp = selinux.REVIEW_MODULES_DIR / "atropa_test.pp"
    pp.write_bytes(b"pp")
    with pytest.raises(selinux.LintRefused):
        selinux.install_pp_file(str(pp))
    te_lint.write_meta(selinux.REVIEW_MODULES_DIR, "atropa_test", "boot")
    with pytest.raises(selinux.LintRefused):  # the category doesn't change the hard list
        selinux.install_pp_file(str(pp))


def test_reinstall_holds_back_unacknowledged_modules(fake_run, fake_which, monkeypatch):
    monkeypatch.setattr(selinux.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(selinux, "list_semodules", lambda: [])
    approved = selinux.APPROVED_MODULES_DIR
    approved.mkdir(parents=True)
    for name, text in (("atropa_bad", DANGEROUS_TE), ("atropa_ok", module("allow a_t b_t:file read;"))):
        (approved / f"{name}.te").write_text(text)
        (approved / f"{name}.pp").write_bytes(b"pp")
    result = selinux.reinstall_all_approved_modules()
    semodule = next(call for call in fake_run.calls if "semodule" in " ".join(call))
    assert str(approved / "atropa_ok.pp") in semodule and str(approved / "atropa_bad.pp") not in semodule
    assert "atropa_bad" in result.stderr


def test_compliance_warns_about_installed_dangerous_modules():
    approved = selinux.APPROVED_MODULES_DIR
    approved.mkdir(parents=True)
    (approved / "atropa_bad.te").write_text(DANGEROUS_TE)
    (approved / "atropa_ok.te").write_text(module("allow a_t b_t:file read;"))
    (check,) = compliance._selinux_module_checks()
    assert check.status == "warn" and "atropa_bad" in check.detail


def test_sidecar_round_trip(tmp_path):
    te_lint.write_meta(tmp_path, "m", "desktop_app", ["a@1", "a@1"], reason="why")
    assert te_lint.read_meta(tmp_path, "m") == {"category": "desktop_app", "acknowledged": ["a@1"], "reason": "why"}
    (tmp_path / "n.atropa.json").write_text('{"category": "nonsense", "acknowledged": [1, "x@2"]}')
    assert te_lint.read_meta(tmp_path, "n") == {"category": "unsure", "acknowledged": ["x@2"]}


# ------------------------------------------------------------- fails closed --
#
# The linter is an install gate: anything it doesn't understand must come out
# dangerous, never silently skipped.

@pytest.mark.parametrize("rule, rule_id", [
    ("allow { a_t b_t } shadow_t:file read;", "shadow"),                         # set as source
    ("allow a_t { etc_t shadow_t }:file write;", "shadow"),                       # set as target
    ("if (some_bool) {\n\tallow a_t shadow_t:file read;\n}", "shadow"),           # conditional block
    ("if (b) { allow a_t b_t:file read; } else { allow a_t shadow_t:file read; }", "shadow"),
    ("optional {\n\tallow a_t security_t:security setenforce;\n}", "enforcement"),
    ("allow a_t ~{ b_t }:file write;", "broad_attribute"),                       # complement = every type
    ("allow a_t { file_type -shadow_t }:file write;", "broad_attribute"),         # exclusion
    ("allow a_t file_type:file write;", "broad_attribute"),
    ("allow domain self:capability sys_admin;", "broad_attribute"),
    ("permissive sshd_t;", "permissive"),
    ("typeattribute a_t unconfined_domain_type;", "privileged_attribute"),
    ("type_transition a_t b_exec_t:process unconfined_t;", "to_unconfined"),
    ("files_read_etc_files(a_t)", "unparseable"),                               # an m4 macro, no ';'
    ("files_read_etc_files(a_t);", "unparseable"),
    ("allow a_t b_t file read;", "unparseable"),                                 # typo: no ':'
])
def test_constructs_that_used_to_slip_through_are_dangerous(rule, rule_id):
    found = te_lint.lint(module(rule), booleans=[])
    assert te_lint.verdict(found) == te_lint.DANGEROUS
    assert rule_id in {f.rule_id for f in found}


def test_require_blocks_with_nested_braces_are_skipped_whole():
    text = "module m 1.0;\nrequire {\n\ttype a_t;\n\tclass file { read write };\n\tclass dir { search };\n}\nallow a_t b_t:file read;\n"
    found = te_lint.lint(text, booleans=[])
    assert te_lint.verdict(found) == "fine" and [r.target for r in te_lint.parse(text)] == ["b_t"]


def test_allowxperm_is_read():
    rules = te_lint.parse("allowxperm a_t b_t:tcp_socket ioctl { 0x8910 };")
    assert [(r.kind, r.perms) for r in rules] == [("allowxperm", ["ioctl"])]


def test_an_attribute_that_isnt_broad_is_review():
    found = {f.rule_id: f.severity for f in te_lint.lint(module("allow a_t some_files:file read;"), booleans=[])}
    assert found == {"attribute_rule": te_lint.REVIEW}


def test_unparseable_is_never_lowered_by_a_category():
    for category in te_lint.CATEGORIES:
        found = te_lint.lint(module("frobnicate a_t;"), category, booleans=[])
        assert te_lint.verdict(found) == te_lint.DANGEROUS


def test_the_gate_refuses_a_set_that_hides_shadow(fake_run, fake_which, monkeypatch):
    monkeypatch.setattr(selinux.shutil, "which", lambda name: f"/usr/bin/{name}")
    text = module("allow { a_t b_t } shadow_t:file read;").replace("module test", "module atropa_sets")
    with pytest.raises(selinux.LintRefused):
        selinux.compile_and_load_te(text, "atropa_sets")
