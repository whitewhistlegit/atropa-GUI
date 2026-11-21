"""Tests for atropa.helper - the one program pkexec is allowed to run."""

from __future__ import annotations

import ast
import os
import stat
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from atropa import helper

REPO = Path(__file__).resolve().parent.parent
POLICY = REPO / "atropa" / "resources" / "org.atropa.pkexec.policy"


def _bin_dir(tmp_path, name="systemctl", mode=0o755):
    directory = tmp_path / "bin"
    directory.mkdir(exist_ok=True)
    program = directory / name
    program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    program.chmod(mode)
    return program, (str(directory),)


def handle(argv, data=b"", tier=None):
    """handle() as the keep helper runs it, unless a test says otherwise."""
    return helper.handle(argv, data, tier=tier or helper.KEEP)


# ------------------------------------------------------------- resolution --

def test_resolve_returns_the_real_path_of_a_known_command(tmp_path):
    program, directories = _bin_dir(tmp_path)
    assert helper.resolve("systemctl", directories) == str(program)


def test_check_validates_the_arguments_and_resolves_the_program(tmp_path):
    program, directories = _bin_dir(tmp_path, "systemctl")
    assert helper.check(["systemctl", "restart", "sshd"], directories) == [str(program), "restart", "sshd"]


def test_check_refuses_a_shape_atropa_does_not_use(tmp_path):
    _program, directories = _bin_dir(tmp_path, "systemctl")
    with pytest.raises(helper.Refused):
        helper.check(["systemctl", "link", "/home/me/evil.service"], directories)


def test_resolve_refuses_an_unknown_program(tmp_path):
    _bin_dir(tmp_path, "sh")
    with pytest.raises(helper.Refused, match="isn't a program Atropa runs"):
        helper.resolve("sh", (str(tmp_path / "bin"),))


def test_resolve_refuses_a_program_missing_from_the_search_path(tmp_path):
    with pytest.raises(helper.Refused, match="not found"):
        helper.resolve("systemctl", (str(tmp_path / "empty"),))


@pytest.mark.parametrize("name", ["../bin/tee", "/usr/bin/tee", "./tee", "sub/tee", "", ".", ".."])
def test_check_refuses_paths_instead_of_resolving_them(name):
    with pytest.raises(helper.Refused):
        helper.check([name])


def test_check_refuses_an_empty_argv():
    with pytest.raises(helper.Refused, match="no command"):
        helper.check([])


def test_a_non_executable_file_is_not_a_command(tmp_path):
    _bin_dir(tmp_path, "systemctl", mode=0o644)
    with pytest.raises(helper.Refused, match="not found"):
        helper.resolve("systemctl", (str(tmp_path / "bin"),))


# ------------------------------------------------------------------- main --

def test_main_refuses_to_run_without_root(monkeypatch):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 1000)
    assert helper.main(["true"]) == 126


def test_main_execs_the_validated_command_with_a_clean_environment(monkeypatch):
    calls = []

    def fake_execve(path, argv, env):
        calls.append((path, argv, env))

    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    monkeypatch.setattr(helper.os, "execve", fake_execve)

    helper.main(["systemctl", "restart", "sshd"])

    path, argv, env = calls[0]
    assert path == os.path.realpath(env["PATH"].split(":")[0] + "/systemctl")
    assert argv == [path, "restart", "sshd"]
    assert env["LC_ALL"] == "C.UTF-8"
    assert env["HOME"] == "/root"


def test_main_refuses_a_shell(monkeypatch):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    assert helper.main(["bash", "-c", "id"]) == 126


def test_main_in_the_keep_helper_refuses_an_ask_operation(monkeypatch):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    monkeypatch.setattr(helper.os, "execve", lambda *a: pytest.fail("must not exec"))
    monkeypatch.setattr(helper.sys, "argv", [helper.KEEP_HELPER_PATH])
    assert helper.main(["setenforce", "0"]) == 126


def test_running_tier_comes_from_the_installed_path(tmp_path, monkeypatch):
    ask = tmp_path / "atropa-helper-ask"
    ask.write_text("")
    monkeypatch.setattr(helper, "ASK_HELPER_PATH", str(ask))
    assert helper.running_tier(str(ask)) == helper.ASK
    assert helper.running_tier(str(tmp_path / "atropa-helper")) == helper.KEEP


# ------------------------------------------------------- command shapes --
#
# Any new run_privileged(["...", ...]) call with a literal program must be
# known to the helper too, or the feature stops working once it's installed.

def _literal_privileged_argvs() -> dict[str, list[tuple[str, list]]]:
    found: dict[str, list[tuple[str, list]]] = {}
    for path in sorted((REPO / "atropa" / "backend").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if name not in {"run_privileged", "run_privileged_streaming"}:
                continue
            first = node.args[0] if node.args else None
            if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
                head = first.elts[0]
                if isinstance(head, ast.Constant) and isinstance(head.value, str):
                    literal = None
                    if all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in first.elts):
                        literal = [e.value for e in first.elts]
                    found.setdefault(head.value, []).append((f"{path.name}:{node.lineno}", literal))
    return found


def test_every_literal_privileged_program_is_known():
    known = set(helper.COMMANDS) | helper.FILE_COMMANDS | helper.OPERATIONS
    missing = {program: sites for program, sites in _literal_privileged_argvs().items() if program not in known}
    assert missing == {}, f"privileged programs the helper doesn't know: {missing}"


def test_every_fully_literal_privileged_argv_passes_its_validator():
    # Literal argvs (no variables) can be checked as they stand; the dynamic
    # ones are covered per backend function below.
    bad = {}
    for program, sites in _literal_privileged_argvs().items():
        if program not in helper.COMMANDS:
            continue
        for site, literal in sites:
            if literal is None:
                continue
            try:
                helper.validate_command(literal)
            except helper.Refused as exc:
                bad[site] = str(exc)
    assert bad == {}


def test_sed_is_refused_even_though_it_is_handled():
    # sed scripts can write any file (`w /etc/sudoers`), so the operation is
    # replace-in-file; sed itself must never execute.
    with pytest.raises(helper.Refused, match="replace-in-file"):
        handle(["sed", "-i", "-E", "s/x/y/", "/etc/hosts"])


def test_no_shell_or_interpreter_is_a_known_program():
    forbidden = {"sh", "bash", "dash", "zsh", "python", "python3", "perl", "env", "xargs", "find", "awk", "su", "sudo"}
    assert set(helper.COMMANDS).isdisjoint(forbidden)


# ---------------------------------------------------------------- policy --

def _actions():
    root = ET.parse(POLICY).getroot()
    found = {}
    for action in root.findall("action"):
        annotations = {entry.get("key"): (entry.text or "").strip() for entry in action.findall("annotate")}
        found[annotations.get("org.freedesktop.policykit.exec.path")] = action.find("defaults")
    return found


def test_policy_annotates_the_keep_helper_with_a_keep_action():
    defaults = _actions()[helper.KEEP_HELPER_PATH]
    assert defaults.findtext("allow_active") == "auth_admin_keep"


def test_policy_never_remembers_the_ask_helper():
    defaults = _actions()[helper.ASK_HELPER_PATH]
    assert {child.text for child in defaults} == {"auth_admin"}


def test_policy_is_valid_xml():
    assert ET.parse(POLICY).getroot().tag == "policyconfig"


# ------------------------------------------------------------ file policy --

def _tmp_policy(monkeypatch, tmp_path, *paths):
    """Point the write policy at tmp files, so tests never touch /etc."""
    monkeypatch.setattr(helper, "WRITE_FILES", frozenset(str(p) for p in paths))
    monkeypatch.setattr(helper, "WRITE_DIRS", ())


def test_tee_writes_the_content(tmp_path, monkeypatch):
    target = tmp_path / "conf"
    _tmp_policy(monkeypatch, tmp_path, target)

    assert handle(["tee", str(target)], b"deny = 5\n") == 0
    assert target.read_text() == "deny = 5\n"


def test_tee_append_keeps_what_was_there(tmp_path, monkeypatch):
    target = tmp_path / "conf"
    target.write_text("first\n")
    _tmp_policy(monkeypatch, tmp_path, target)

    handle(["tee", "-a", str(target)], b"second\n")

    assert target.read_text() == "first\nsecond\n"


def test_tee_refuses_a_path_outside_the_policy(tmp_path, monkeypatch):
    _tmp_policy(monkeypatch, tmp_path, tmp_path / "allowed")
    with pytest.raises(helper.Refused, match="allowed to write"):
        handle(["tee", str(tmp_path / "other")], b"x")


def test_tee_refuses_a_symlink_to_an_allowed_file(tmp_path, monkeypatch):
    target = tmp_path / "conf"
    target.write_text("original")
    link = tmp_path / "link"
    link.symlink_to(target)
    _tmp_policy(monkeypatch, tmp_path, link)

    with pytest.raises(helper.Refused, match="symlink"):
        handle(["tee", str(link)], b"x")
    assert target.read_text() == "original"


def test_tee_refuses_relative_paths(tmp_path, monkeypatch):
    _tmp_policy(monkeypatch, tmp_path, tmp_path / "conf")
    with pytest.raises(helper.Refused, match="absolute"):
        handle(["tee", "etc/conf"], b"x")


def test_install_sets_content_and_mode(tmp_path, monkeypatch):
    target = tmp_path / "rules"
    _tmp_policy(monkeypatch, tmp_path, target)

    assert handle(["install", "-m", "0600", "/dev/stdin", str(target)], b"allow\n") == 0
    assert target.read_text() == "allow\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_install_refuses_a_format_it_does_not_use(tmp_path, monkeypatch):
    target = tmp_path / "rules"
    _tmp_policy(monkeypatch, tmp_path, target)
    with pytest.raises(helper.Refused, match="install must be"):
        handle(["install", "-o", "root", str(target)], b"x")


def test_replace_in_file_updates_only_the_matching_line(tmp_path, monkeypatch):
    target = tmp_path / "conf"
    target.write_text("deny = 3\nunlock_time = 600\n")
    _tmp_policy(monkeypatch, tmp_path, target)

    assert handle(
        ["replace-in-file", str(target), r"^#?\s*deny\s*=.*$", "deny = 5"]
    ) == 0
    assert target.read_text() == "deny = 5\nunlock_time = 600\n"


def test_replace_in_file_preserves_the_mode(tmp_path, monkeypatch):
    target = tmp_path / "conf"
    target.write_text("a = 1\n")
    target.chmod(0o600)
    _tmp_policy(monkeypatch, tmp_path, target)

    handle(["replace-in-file", str(target), r"^a\s*=.*$", "a = 2"])

    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_replace_in_file_rejects_a_bad_pattern(tmp_path, monkeypatch):
    target = tmp_path / "conf"
    target.write_text("x\n")
    _tmp_policy(monkeypatch, tmp_path, target)
    with pytest.raises(helper.Refused, match="bad pattern"):
        handle(["replace-in-file", str(target), "(", "x"])


# ------------------------------------------------------- other operations --

def test_checked_copy_accepts_the_aide_paths(tmp_path, monkeypatch):
    source = tmp_path / "aide.db.new"
    destination = tmp_path / "aide.db"
    monkeypatch.setattr(helper, "COPY_SOURCES", (str(tmp_path) + "/",))
    monkeypatch.setattr(helper, "COPY_DEST_DIRS", (str(tmp_path) + "/",))

    assert helper._checked_copy(str(source), str(destination)) == (str(source), str(destination))


def test_checked_copy_keeps_a_trailing_slash_dot_for_cp(tmp_path, monkeypatch):
    # `cp -rn src/. dst` copies contents; normalising the path would make cp
    # create dst/<basename> instead. Validation must not rewrite it.
    source = tmp_path / "plugins"
    source.mkdir()
    monkeypatch.setattr(helper, "COPY_SOURCES", (str(tmp_path) + "/",))
    monkeypatch.setattr(helper, "COPY_DEST_DIRS", (str(tmp_path) + "/",))

    returned_source, _ = helper._checked_copy(str(source) + "/.", str(tmp_path / "dest"))

    assert returned_source == str(source) + "/."


def test_checked_copy_refuses_an_arbitrary_destination(tmp_path, monkeypatch):
    monkeypatch.setattr(helper, "COPY_SOURCES", (str(tmp_path) + "/",))
    monkeypatch.setattr(helper, "COPY_DEST_DIRS", ("/var/lib/aide/",))

    with pytest.raises(helper.Refused, match="destination"):
        helper._checked_copy(str(tmp_path / "src"), "/etc/sudoers")


def test_mkdir_only_creates_the_atropa_directories():
    assert helper._checked_mkdir("/etc/atropa") == "/etc/atropa"
    assert helper._checked_mkdir("/etc/audit/rules.d") == "/etc/audit/rules.d"
    with pytest.raises(helper.Refused):
        helper._checked_mkdir("/etc")


def test_rm_only_removes_the_legacy_plugin_tree():
    assert helper._checked_remove("/etc/archyast") == "/etc/archyast"
    assert helper._checked_remove("/etc/archyast/plugins") == "/etc/archyast/plugins"
    with pytest.raises(helper.Refused):
        helper._checked_remove("/etc")


def test_touch_is_only_the_autorelabel_marker(tmp_path, monkeypatch):
    with pytest.raises(helper.Refused, match="isn't allowed"):
        handle(["touch", str(tmp_path / "x")])


def test_chown_only_hands_files_back_to_the_invoking_user(monkeypatch):
    import pwd

    account = pwd.getpwuid(os.getuid())
    monkeypatch.setenv("PKEXEC_UID", str(account.pw_uid))
    inside = str(Path(account.pw_dir) / "atropa-build")

    argv = ["chown", "-R", "-h", "--from=0:0", f"{account.pw_uid}:{account.pw_gid}", "--", inside]
    assert helper._checked_chown(argv) == argv

    with pytest.raises(helper.Refused, match="outside"):
        helper._checked_chown(["chown", "-R", "--from=0:0", f"{account.pw_uid}:{account.pw_gid}", "--", "/etc/shadow"])


def test_chown_refuses_another_owner(monkeypatch):
    import pwd

    account = pwd.getpwuid(os.getuid())
    monkeypatch.setenv("PKEXEC_UID", str(account.pw_uid))
    with pytest.raises(helper.Refused, match="isn't"):
        helper._checked_chown(
            ["chown", "-R", "--from=0:0", "0:0", "--", str(Path(account.pw_dir) / "x")]
        )


# ------------------------------------------------------ policy coverage ----

def test_policy_covers_every_path_the_backend_manages(monkeypatch):
    # About the policy, not this machine's disk: on an SELinux install
    # /etc/selinux/config is a symlink, which made this fail there.
    monkeypatch.setattr(helper.os.path, "realpath", os.path.normpath)
    from atropa.backend import (
        aide, apparmor, audit_rules, bootloader, hardening, mirrors, pacman, plugins, power, security, selinux,
        sleep, snapshots, system_config,
    )

    managed = [
        hardening.SYSCTL_HARDENING_FILE,
        str(hardening.FAILLOCK_CONF),
        hardening.FAIL2BAN_SSHD_JAIL,
        hardening.USBGUARD_RULES,
        str(hardening.PWQUALITY_CONF),
        str(security.SSHD_CONFIG),
        str(selinux.SELINUX_CONFIG),
        str(bootloader.GRUB_DEFAULT_PATH),
        str(system_config.LOCALE_GEN_PATH),
        str(pacman.PACMAN_CONF),
        str(mirrors.MIRRORLIST),
        str(power.ZRAM_GENERATOR_CONF),
        str(sleep.LOGIND_DROPIN),
        str(sleep.SLEEP_DROPIN),
        str(snapshots.SNAPPER_CONFIG),
        str(snapshots.SNAPPER_CONFD),
        str(plugins.ENABLED_STATE_FILE),
        *aide.DB_ACTIVE_CANDIDATES,
        *aide.DB_NEW_CANDIDATES,
        str(apparmor.PROFILES_DIR / "usr.bin.example"),
        str(audit_rules.AUDIT_RULES_DIR / "99-atropa.rules"),
        str(plugins.PLUGINS_DIR / "example" / "manifest.toml"),
        "/boot/loader/loader.conf",
        "/.autorelabel",
    ]
    for path in managed:
        assert helper.checked_write_path(path), path


# --------------------------------------------------------------- .pacnew ----

def _pacnew_tree(tmp_path, monkeypatch):
    etc = tmp_path / "etc"
    etc.mkdir()
    monkeypatch.setattr(helper, "ETC_ROOT", str(etc))
    return etc


def test_pacnew_apply_replaces_the_live_file_and_keeps_its_mode(tmp_path, monkeypatch):
    etc = _pacnew_tree(tmp_path, monkeypatch)
    live = etc / "pacman.conf"
    live.write_text("old\n")
    candidate = etc / "pacman.conf.pacnew"
    candidate.write_text("new\n")
    candidate.chmod(0o600)

    assert handle(["pacnew-apply", str(candidate)]) == 0
    assert live.read_text() == "new\n"
    assert stat.S_IMODE(live.stat().st_mode) == 0o600
    assert candidate.exists()  # the review step keeps it until the user removes it


def test_pacnew_apply_creates_a_missing_live_file_from_a_pacsave(tmp_path, monkeypatch):
    etc = _pacnew_tree(tmp_path, monkeypatch)
    saved = etc / "removed.conf.pacsave"
    saved.write_text("saved\n")

    handle(["pacnew-apply", str(saved)])

    assert (etc / "removed.conf").read_text() == "saved\n"


@pytest.mark.parametrize("name", ["passwd", "group", "shadow", "gshadow"])
def test_pacnew_apply_refuses_the_account_databases(tmp_path, monkeypatch, name):
    # The filesystem package's passwd/shadow have none of this machine's
    # users: "use new" would delete every account.
    etc = _pacnew_tree(tmp_path, monkeypatch)
    live = etc / name
    live.write_text("me:x:1000:1000::/home/me:/bin/bash\n")
    candidate = etc / f"{name}.pacnew"
    candidate.write_text("root:x:0:0::/root:/bin/bash\n")

    with pytest.raises(helper.Refused, match="by hand"):
        handle(["pacnew-apply", str(candidate)])
    assert "me:" in live.read_text()
    # Discarding the stock copy is still fine.
    assert handle(["pacnew-remove", str(candidate)]) == 0


def test_pacnew_apply_allows_a_same_named_file_elsewhere(tmp_path, monkeypatch):
    etc = _pacnew_tree(tmp_path, monkeypatch)
    (etc / "app").mkdir()
    candidate = etc / "app" / "passwd.pacnew"
    candidate.write_text("new\n")
    assert handle(["pacnew-apply", str(candidate)]) == 0
    assert (etc / "app" / "passwd").read_text() == "new\n"


def test_pacnew_remove_deletes_only_the_candidate(tmp_path, monkeypatch):
    etc = _pacnew_tree(tmp_path, monkeypatch)
    live = etc / "x.conf"
    live.write_text("live\n")
    candidate = etc / "x.conf.pacnew"
    candidate.write_text("new\n")

    assert handle(["pacnew-remove", str(candidate)]) == 0
    assert not candidate.exists()
    assert live.read_text() == "live\n"


def test_pacnew_operations_refuse_other_files(tmp_path, monkeypatch):
    etc = _pacnew_tree(tmp_path, monkeypatch)
    other = etc / "x.conf"
    other.write_text("x\n")
    with pytest.raises(helper.Refused, match=".pacnew"):
        handle(["pacnew-apply", str(other)])
    with pytest.raises(helper.Refused, match=".pacnew"):
        handle(["pacnew-remove", str(other)])


def test_pacnew_refuses_a_symlinked_candidate(tmp_path, monkeypatch):
    etc = _pacnew_tree(tmp_path, monkeypatch)
    target = etc / "real.pacnew"
    target.write_text("x\n")
    link = etc / "link.pacnew"
    link.symlink_to(target)

    with pytest.raises(helper.Refused, match="regular file"):
        handle(["pacnew-apply", str(link)])


def test_pacnew_refuses_to_replace_a_symlinked_live_file(tmp_path, monkeypatch):
    etc = _pacnew_tree(tmp_path, monkeypatch)
    real = etc / "real.conf"
    real.write_text("x\n")
    live = etc / "live.conf"
    live.symlink_to(real)
    candidate = etc / "live.conf.pacnew"
    candidate.write_text("new\n")

    with pytest.raises(helper.Refused, match="symlink"):
        handle(["pacnew-apply", str(candidate)])
    assert real.read_text() == "x\n"


def _selinux_config_link(tmp_path, monkeypatch, target_name):
    directory = tmp_path / "selinux"
    directory.mkdir()
    config = directory / "config"
    target = directory / target_name
    target.write_text("SELINUX=permissive\n")
    config.symlink_to(target_name)
    monkeypatch.setattr(helper, "SYMLINKED_FILES", {str(config): str(directory / "config.")})
    return config, target


def test_selinux_config_symlinked_by_the_policy_package_is_writable(tmp_path, monkeypatch):
    # selinux-refpolicy-arch links /etc/selinux/config -> config.refpolicy-arch
    # when there's no config yet; Atropa must still be able to set the mode.
    config, target = _selinux_config_link(tmp_path, monkeypatch, "config.refpolicy-arch")
    assert helper.checked_write_path(str(config)) == str(target)
    handle(["replace-in-file", str(config), "^SELINUX=.*$", "SELINUX=enforcing"])
    assert target.read_text() == "SELINUX=enforcing\n"
    assert config.is_symlink()  # the package's link stays a link


def test_selinux_config_symlink_elsewhere_is_refused(tmp_path, monkeypatch):
    config, _target = _selinux_config_link(tmp_path, monkeypatch, "not-config")
    with pytest.raises(helper.Refused, match="sibling"):
        helper.checked_write_path(str(config))


# ---------------------------------------------------------- shadow-status --

def test_shadow_status_reports_emptiness_without_any_hash(tmp_path, monkeypatch, capsys):
    shadow = tmp_path / "shadow"
    shadow.write_text(
        "root:$6$saltsalt$hashhashhash:19700:0:99999:7:::\n"
        "ghost::19700:0:99999:7:::\n"
        "bin:!*:19700::::::\n"
        "daemon:*:19700::::::\n"
    )
    monkeypatch.setattr(helper, "SHADOW", str(shadow))

    assert handle(["shadow-status"]) == 0

    out = capsys.readouterr().out
    assert out.splitlines() == ["root:set", "ghost:empty", "bin:locked", "daemon:locked"]
    assert "$6$" not in out


def test_shadow_status_takes_no_arguments():
    with pytest.raises(helper.Refused):
        handle(["shadow-status", "/etc/passwd"])


def test_cat_can_no_longer_read_shadow():
    with pytest.raises(helper.Refused):
        helper.validate_command(["cat", "/etc/shadow"])
