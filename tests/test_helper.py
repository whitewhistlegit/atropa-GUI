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


# ------------------------------------------------------------- resolution --

def test_resolve_returns_the_real_path_of_an_allowed_command(tmp_path):
    program, directories = _bin_dir(tmp_path)
    assert helper.resolve("systemctl", directories) == str(program)


def test_check_keeps_the_arguments_and_resolves_the_program(tmp_path):
    program, directories = _bin_dir(tmp_path, "systemctl")
    assert helper.check(["systemctl", "status"], directories) == [str(program), "status"]


def test_resolve_refuses_a_command_that_is_not_allowlisted(tmp_path):
    _bin_dir(tmp_path, "sh")
    with pytest.raises(helper.Refused, match="allowlist"):
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


def test_main_execs_the_resolved_command_with_a_clean_environment(monkeypatch):
    calls = []

    def fake_execve(path, argv, env):
        calls.append((path, argv, env))

    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    monkeypatch.setattr(helper.os, "execve", fake_execve)

    helper.main(["true", "extra"])

    path, argv, env = calls[0]
    assert path == os.path.realpath(env["PATH"].split(":")[0] + "/true")
    assert argv == [path, "extra"]
    assert env["LC_ALL"] == "C.UTF-8"
    assert env["HOME"] == "/root"


def test_main_refuses_an_allowlisted_name_that_is_actually_a_shell(monkeypatch):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    assert helper.main(["bash", "-c", "id"]) == 126


# -------------------------------------------------------------- allowlist --
#
# This is the test that keeps ALLOWED honest: any new run_privileged(["...",
# ...]) call with a literal command name must be added to the helper too, or
# the feature silently stops working when the helper is installed.

def _literal_privileged_commands() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
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
                    found.setdefault(head.value, set()).add(path.name)
    return found


def test_every_literal_privileged_command_is_allowlisted_or_handled():
    known = helper.ALLOWED | helper.FILE_COMMANDS | helper.OPERATIONS
    missing = {command: files for command, files in _literal_privileged_commands().items() if command not in known}
    assert missing == {}, f"privileged commands missing from ALLOWED/FILE_COMMANDS: {missing}"


def test_sed_is_refused_even_though_it_is_handled():
    # sed scripts can write any file (`w /etc/sudoers`), so the operation is
    # replace-in-file; sed itself must never execute.
    with pytest.raises(helper.Refused, match="replace-in-file"):
        helper.handle(["sed", "-i", "-E", "s/x/y/", "/etc/hosts"])


def test_rootkit_operations_use_a_fixed_argv(monkeypatch):
    calls = []
    monkeypatch.setattr(helper, "_exec", lambda program, argv: calls.append((program, argv)) or 0)
    monkeypatch.setattr(helper, "_system_binary", lambda name: "/usr/bin/" + name)

    expected = {
        "rootkit-scan": ["rkhunter", "--check", "--sk", "--nocolors", "--rwo"],
        "rootkit-update": ["rkhunter", "--update", "--nocolors"],
        "rootkit-baseline": ["rkhunter", "--propupd", "--nocolors"],
    }
    for operation, argv in expected.items():
        calls.clear()
        assert helper.handle([operation]) == 0
        assert calls == [("/usr/bin/rkhunter", argv)]


def test_rootkit_operations_refuse_extra_arguments():
    # Caller-supplied flags would defeat the point of a fixed operation -
    # rkhunter --propupd would otherwise be reachable through the cache.
    with pytest.raises(helper.Refused, match="no arguments"):
        helper.handle(["rootkit-scan", "--propupd"])


def test_rkhunter_is_not_a_bare_allowed_command():
    assert "rkhunter" not in helper.ALLOWED


def test_allowlist_contains_no_shells_or_interpreters():
    forbidden = {"sh", "bash", "dash", "python", "python3", "perl", "env", "xargs", "find", "awk"}
    assert helper.ALLOWED.isdisjoint(forbidden)


# ---------------------------------------------------------------- policy --

def test_policy_annotates_the_helper_path_with_a_keep_action():
    root = ET.parse(POLICY).getroot()
    action = root.find("action")
    assert action is not None
    defaults = action.find("defaults")
    assert defaults.findtext("allow_active") == "auth_admin_keep"
    annotations = {entry.get("key"): (entry.text or "").strip() for entry in action.findall("annotate")}
    assert annotations.get("org.freedesktop.policykit.exec.path") == "/usr/lib/atropa/atropa-helper"


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

    assert helper.handle(["tee", str(target)], b"deny = 5\n") == 0
    assert target.read_text() == "deny = 5\n"


def test_tee_append_keeps_what_was_there(tmp_path, monkeypatch):
    target = tmp_path / "conf"
    target.write_text("first\n")
    _tmp_policy(monkeypatch, tmp_path, target)

    helper.handle(["tee", "-a", str(target)], b"second\n")

    assert target.read_text() == "first\nsecond\n"


def test_tee_refuses_a_path_outside_the_policy(tmp_path, monkeypatch):
    _tmp_policy(monkeypatch, tmp_path, tmp_path / "allowed")
    with pytest.raises(helper.Refused, match="allowed to write"):
        helper.handle(["tee", str(tmp_path / "other")], b"x")


def test_tee_refuses_a_symlink_to_an_allowed_file(tmp_path, monkeypatch):
    target = tmp_path / "conf"
    target.write_text("original")
    link = tmp_path / "link"
    link.symlink_to(target)
    _tmp_policy(monkeypatch, tmp_path, link)

    with pytest.raises(helper.Refused, match="symlink"):
        helper.handle(["tee", str(link)], b"x")
    assert target.read_text() == "original"


def test_tee_refuses_relative_paths(tmp_path, monkeypatch):
    _tmp_policy(monkeypatch, tmp_path, tmp_path / "conf")
    with pytest.raises(helper.Refused, match="absolute"):
        helper.handle(["tee", "etc/conf"], b"x")


def test_install_sets_content_and_mode(tmp_path, monkeypatch):
    target = tmp_path / "rules"
    _tmp_policy(monkeypatch, tmp_path, target)

    assert helper.handle(["install", "-m", "0600", "/dev/stdin", str(target)], b"allow\n") == 0
    assert target.read_text() == "allow\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_install_refuses_a_format_it_does_not_use(tmp_path, monkeypatch):
    target = tmp_path / "rules"
    _tmp_policy(monkeypatch, tmp_path, target)
    with pytest.raises(helper.Refused, match="install must be"):
        helper.handle(["install", "-o", "root", str(target)], b"x")


def test_replace_in_file_updates_only_the_matching_line(tmp_path, monkeypatch):
    target = tmp_path / "conf"
    target.write_text("deny = 3\nunlock_time = 600\n")
    _tmp_policy(monkeypatch, tmp_path, target)

    assert helper.handle(
        ["replace-in-file", str(target), r"^#?\s*deny\s*=.*$", "deny = 5"]
    ) == 0
    assert target.read_text() == "deny = 5\nunlock_time = 600\n"


def test_replace_in_file_preserves_the_mode(tmp_path, monkeypatch):
    target = tmp_path / "conf"
    target.write_text("a = 1\n")
    target.chmod(0o600)
    _tmp_policy(monkeypatch, tmp_path, target)

    helper.handle(["replace-in-file", str(target), r"^a\s*=.*$", "a = 2"])

    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_replace_in_file_rejects_a_bad_pattern(tmp_path, monkeypatch):
    target = tmp_path / "conf"
    target.write_text("x\n")
    _tmp_policy(monkeypatch, tmp_path, target)
    with pytest.raises(helper.Refused, match="bad pattern"):
        helper.handle(["replace-in-file", str(target), "(", "x"])


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
        helper.handle(["touch", str(tmp_path / "x")])


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
        system_config,
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

    assert helper.handle(["pacnew-apply", str(candidate)]) == 0
    assert live.read_text() == "new\n"
    assert stat.S_IMODE(live.stat().st_mode) == 0o600
    assert candidate.exists()  # the review step keeps it until the user removes it


def test_pacnew_apply_creates_a_missing_live_file_from_a_pacsave(tmp_path, monkeypatch):
    etc = _pacnew_tree(tmp_path, monkeypatch)
    saved = etc / "removed.conf.pacsave"
    saved.write_text("saved\n")

    helper.handle(["pacnew-apply", str(saved)])

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
        helper.handle(["pacnew-apply", str(candidate)])
    assert "me:" in live.read_text()
    # Discarding the stock copy is still fine.
    assert helper.handle(["pacnew-remove", str(candidate)]) == 0


def test_pacnew_apply_allows_a_same_named_file_elsewhere(tmp_path, monkeypatch):
    etc = _pacnew_tree(tmp_path, monkeypatch)
    (etc / "app").mkdir()
    candidate = etc / "app" / "passwd.pacnew"
    candidate.write_text("new\n")
    assert helper.handle(["pacnew-apply", str(candidate)]) == 0
    assert (etc / "app" / "passwd").read_text() == "new\n"


def test_pacnew_remove_deletes_only_the_candidate(tmp_path, monkeypatch):
    etc = _pacnew_tree(tmp_path, monkeypatch)
    live = etc / "x.conf"
    live.write_text("live\n")
    candidate = etc / "x.conf.pacnew"
    candidate.write_text("new\n")

    assert helper.handle(["pacnew-remove", str(candidate)]) == 0
    assert not candidate.exists()
    assert live.read_text() == "live\n"


def test_pacnew_operations_refuse_other_files(tmp_path, monkeypatch):
    etc = _pacnew_tree(tmp_path, monkeypatch)
    other = etc / "x.conf"
    other.write_text("x\n")
    with pytest.raises(helper.Refused, match=".pacnew"):
        helper.handle(["pacnew-apply", str(other)])
    with pytest.raises(helper.Refused, match=".pacnew"):
        helper.handle(["pacnew-remove", str(other)])


def test_pacnew_refuses_a_symlinked_candidate(tmp_path, monkeypatch):
    etc = _pacnew_tree(tmp_path, monkeypatch)
    target = etc / "real.pacnew"
    target.write_text("x\n")
    link = etc / "link.pacnew"
    link.symlink_to(target)

    with pytest.raises(helper.Refused, match="regular file"):
        helper.handle(["pacnew-apply", str(link)])


def test_pacnew_refuses_to_replace_a_symlinked_live_file(tmp_path, monkeypatch):
    etc = _pacnew_tree(tmp_path, monkeypatch)
    real = etc / "real.conf"
    real.write_text("x\n")
    live = etc / "live.conf"
    live.symlink_to(real)
    candidate = etc / "live.conf.pacnew"
    candidate.write_text("new\n")

    with pytest.raises(helper.Refused, match="symlink"):
        helper.handle(["pacnew-apply", str(candidate)])
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
    helper.handle(["replace-in-file", str(config), "^SELINUX=.*$", "SELINUX=enforcing"])
    assert target.read_text() == "SELINUX=enforcing\n"
    assert config.is_symlink()  # the package's link stays a link


def test_selinux_config_symlink_elsewhere_is_refused(tmp_path, monkeypatch):
    config, _target = _selinux_config_link(tmp_path, monkeypatch, "not-config")
    with pytest.raises(helper.Refused, match="sibling"):
        helper.checked_write_path(str(config))
