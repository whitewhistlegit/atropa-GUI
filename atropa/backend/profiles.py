"""
atropa.backend.profiles
----------------------------
Exports the current machine's security-relevant configuration as a
portable JSON profile, and imports one to reproduce that posture on
another machine (or re-apply it after a reinstall).

Deliberately does NOT capture or replay arbitrary raw values for
everything it touches - sysctl and the quicksetup-catalog items are
recorded as "was this configured" booleans and re-applied via
quicksetup's existing curated, safe appliers (the same ones the Quick
Setup page uses), not as a literal dump of every current value. That
keeps a profile import exactly as safe as running Quick Setup by hand:
same order (firewall's SSH pre-allow still happens first), same refusal
to auto-enforce SELinux, same opt-out-by-default on USBGuard.

AppArmor profile modes and SELinux booleans ARE captured and replayed
value-for-value, since each is a single well-defined, already-safe
action (`set_profile_mode`, `set_boolean`) - anything captured that
doesn't exist on the target machine is skipped and reported, never
guessed at.

SSH settings (root login, password auth, port) are captured and
replayable too, but importing them is the one section a caller should
gate behind an explicit opt-in and a clear warning: the existing
validate-before-reload rollback in security.py catches a broken sshd
config, but it can't catch a VALID config that still doesn't fit this
particular machine (e.g. disabling password auth where no key is set
up yet).
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import apparmor, hardening, quicksetup, security, selinux
from .privilege import CommandResult

PROFILE_VERSION = 1

SECTIONS = ["quicksetup", "apparmor_profiles", "selinux_booleans", "ssh"]

# The aa-status modes apparmor.set_profile_mode() can actually apply.
_SETTABLE_APPARMOR_MODES = ("enforce", "complain")

# Hand-written profiles sometimes use true/false/on/off; exports use the
# literal sshd value.
_SSH_YES_NO = {"yes": "yes", "true": "yes", "on": "yes", "no": "no", "false": "no", "off": "no"}


@dataclass
class ProfileSummary:
    """A lightweight preview of a profile's contents, for display before importing."""

    hostname: str
    exported_at: str
    quicksetup_keys: list[str] = field(default_factory=list)
    apparmor_profile_count: int = 0
    selinux_boolean_count: int = 0
    has_ssh_section: bool = False


def _is_key_configured(key: str) -> bool:
    if key == "firewall":
        return security.firewall_status().active
    if key == "fail2ban":
        return hardening.fail2ban_status().active
    if key == "sysctl":
        return hardening.sysctl_hardening_file_exists()
    if key == "faillock":
        return hardening.faillock_wired_into_pam()
    if key == "apparmor":
        return hardening.apparmor_status().active
    if key == "auditd":
        return hardening.auditd_status().active
    if key == "usbguard":
        return hardening.usbguard_status().active
    if key == "selinux":
        return selinux.get_status().available
    return False


def export_profile() -> dict:
    """Snapshots the current machine's security-relevant configuration."""
    configured_keys = [item.key for item in quicksetup.CATALOG if _is_key_configured(item.key)]

    apparmor_profiles: dict[str, str] = {}
    if apparmor.is_available():
        try:
            apparmor_profiles = {p.path: p.mode for p in apparmor.list_profiles()}
        except RuntimeError:
            apparmor_profiles = {}

    selinux_booleans: dict[str, bool] = {}
    if selinux.get_status().available:
        selinux_booleans = {b.name: b.active for b in selinux.list_booleans()}

    ssh_section: dict | None = None
    ssh_status = security.ssh_status()
    if ssh_status.installed:
        # "unknown" = sshd_config never sets it (OpenSSH's compiled-in
        # default applies); import leaves such settings alone, so the
        # display-only default port must not be recorded as a real "22".
        ssh_section = {
            "root_login": ssh_status.root_login,
            "password_auth": ssh_status.password_auth,
            "port": ssh_status.port if ssh_status.port_explicit else "unknown",
        }

    return {
        "atropa_profile_version": PROFILE_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "quicksetup_keys": configured_keys,
        "apparmor_profiles": apparmor_profiles,
        "selinux_booleans": selinux_booleans,
        "ssh": ssh_section,
    }


def summarize_profile(profile: dict) -> ProfileSummary:
    """A lightweight preview of a profile's contents, for display before importing."""
    return ProfileSummary(
        hostname=profile.get("hostname", "unknown"),
        exported_at=profile.get("exported_at", "unknown"),
        quicksetup_keys=list(profile.get("quicksetup_keys", [])),
        apparmor_profile_count=len(profile.get("apparmor_profiles", {}) or {}),
        selinux_boolean_count=len(profile.get("selinux_booleans", {}) or {}),
        has_ssh_section=bool(profile.get("ssh")),
    )


def save_profile_to_file(profile: dict, path: str) -> None:
    Path(path).write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_profile_from_file(path: str) -> dict:
    """Raises ValueError for an unreadable file, invalid JSON, or an
    unsupported profile version - never silently misapplies a profile it
    doesn't recognize."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Couldn't read profile file: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Not a valid profile file (bad JSON): {exc}") from exc

    version = data.get("atropa_profile_version")
    if version != PROFILE_VERSION:
        raise ValueError(f"Unsupported profile version: {version!r} (this Atropa expects version {PROFILE_VERSION})")
    return data


def _import_apparmor_profiles(profiles: dict, on_line: Callable[[str], None]) -> CommandResult:
    if not profiles:
        on_line("Profile has no AppArmor profile modes to apply.")
        return CommandResult(0, "nothing to apply", "")
    if not apparmor.is_available():
        on_line("AppArmor isn't available on this machine - skipping.")
        return CommandResult(0, "skipped: apparmor unavailable", "")

    try:
        current = {p.path: p.mode for p in apparmor.list_profiles()}
    except RuntimeError as exc:
        on_line(f"Couldn't list profiles: {exc}")
        return CommandResult(1, "", str(exc))

    applied, unchanged, skipped, failed = 0, 0, 0, 0
    for path, mode in profiles.items():
        if path not in current:
            on_line(f"Skipping {path} (not present on this machine)")
            skipped += 1
            continue
        # aa-status also reports modes like "unconfined", "kill" and
        # "prompt" (AppArmor 4), which set_profile_mode() can't apply -
        # passing one through used to raise and abort the whole import.
        if mode not in _SETTABLE_APPARMOR_MODES:
            on_line(f"Skipping {path} - Atropa can only set enforce/complain, not {mode!r}")
            skipped += 1
            continue
        if current[path] == mode:
            unchanged += 1
            continue
        on_line(f"Setting {path} to {mode}...")
        try:
            result = apparmor.set_profile_mode(path, mode)
        except (RuntimeError, ValueError) as exc:
            result = CommandResult(1, "", str(exc))
        if result.ok:
            applied += 1
        else:
            on_line(f"Failed: {result.stderr.strip()}")
            failed += 1

    on_line(f"AppArmor profiles: {applied} applied, {unchanged} already set, {skipped} skipped, {failed} failed.")
    return CommandResult(
        0 if failed == 0 else 1, f"applied={applied} unchanged={unchanged} skipped={skipped} failed={failed}", ""
    )


def _import_selinux_booleans(booleans: dict, on_line: Callable[[str], None]) -> CommandResult:
    if not booleans:
        on_line("Profile has no SELinux booleans to apply.")
        return CommandResult(0, "nothing to apply", "")
    if not selinux.get_status().available:
        on_line("SELinux isn't available on this machine - skipping.")
        return CommandResult(0, "skipped: selinux unavailable", "")

    current = {b.name: b.active for b in selinux.list_booleans()}
    applied, unchanged, skipped, failed = 0, 0, 0, 0
    changes: dict[str, bool] = {}
    for name, value in booleans.items():
        if name not in current:
            on_line(f"Skipping {name} (not present on this machine)")
            skipped += 1
            continue
        # Exports always write JSON true/false. Anything else came from a
        # hand-edited file, and bool() would read a string like "off" as on.
        if not isinstance(value, bool):
            on_line(f"Skipping {name} - {value!r} isn't true/false")
            skipped += 1
            continue
        if current[name] == value:
            unchanged += 1
            continue
        changes[name] = value

    if changes:
        # One setsebool for all of them - one prompt and one policy rebuild,
        # instead of one each.
        on_line("Setting " + ", ".join(f"{name}={'on' if value else 'off'}" for name, value in changes.items()) + "...")
        result = selinux.set_booleans(changes)
        if result.ok:
            applied = len(changes)
        else:
            on_line(f"Failed: {result.stderr.strip()}")
            failed = len(changes)

    on_line(f"SELinux booleans: {applied} applied, {unchanged} already set, {skipped} skipped, {failed} failed.")
    return CommandResult(
        0 if failed == 0 else 1, f"applied={applied} unchanged={unchanged} skipped={skipped} failed={failed}", ""
    )


def _import_ssh(ssh_section: dict, on_line: Callable[[str], None]) -> CommandResult:
    on_line(
        "Applying SSH settings from the profile. Each change is validated with "
        "'sshd -t' before reload and rolled back automatically if invalid - but a "
        "VALID config that still doesn't fit this machine (e.g. disabling password "
        "auth without a key already set up here) won't be caught by that check."
    )
    # Only explicit, recognized values are applied. Anything else - above
    # all "unknown", which is what an export records when sshd_config never
    # sets the key and OpenSSH's own default applies - is left alone. Mapping
    # "anything but yes" to "no" used to turn a profile exported from a
    # default config into PermitRootLogin no + PasswordAuthentication no on
    # the importing machine: a lockout for anyone relying on passwords there.
    changes: list[tuple[str, Callable[[], CommandResult]]] = []
    skipped = 0

    def leave_unchanged(setting: str, raw: object) -> None:
        nonlocal skipped
        skipped += 1
        if str(raw).strip().lower() == "unknown":
            on_line(f"Leaving {setting} unchanged - the exporting machine didn't set it explicitly.")
        else:
            on_line(f"Leaving {setting} unchanged - {raw!r} isn't a value Atropa can apply.")

    if "root_login" in ssh_section:
        raw = str(ssh_section["root_login"]).strip().lower()
        value = _SSH_YES_NO.get(raw, raw)
        if value in security.SSH_PERMIT_ROOT_LOGIN_VALUES:
            changes.append((f"PermitRootLogin to {value}", lambda v=value: security.set_ssh_permit_root_login(v)))
        else:
            leave_unchanged("PermitRootLogin", ssh_section["root_login"])

    if "password_auth" in ssh_section:
        value = _SSH_YES_NO.get(str(ssh_section["password_auth"]).strip().lower())
        if value is not None:
            changes.append(
                (f"PasswordAuthentication to {value}", lambda v=value: security.set_ssh_password_auth(v == "yes"))
            )
        else:
            leave_unchanged("PasswordAuthentication", ssh_section["password_auth"])

    if "port" in ssh_section:
        raw_port = ssh_section["port"]
        if str(raw_port).strip().lower() == "unknown":
            leave_unchanged("the SSH port", raw_port)
        else:
            try:
                port = int(raw_port)
            except (TypeError, ValueError):
                on_line(f"Skipping port - '{raw_port}' isn't a valid number.")
                skipped += 1
            else:
                if 1 <= port <= 65535:
                    changes.append((f"SSH port to {port}", lambda p=port: security.set_ssh_port(p)))
                else:
                    on_line(f"Skipping port - {port} is outside 1-65535.")
                    skipped += 1

    applied, failed = 0, 0
    for label, apply in changes:
        on_line(f"Setting {label}...")
        try:
            result = apply()
        except (RuntimeError, ValueError) as exc:  # e.g. sshd -t rejected it (already rolled back)
            result = CommandResult(1, "", str(exc))
        if result.ok:
            applied += 1
        else:
            on_line(f"Failed: {result.stderr.strip()}")
            failed += 1

    return CommandResult(0 if failed == 0 else 1, f"applied={applied} skipped={skipped} failed={failed}", "")


def import_profile(profile: dict, sections: list[str], on_line: Callable[[str], None]) -> dict[str, CommandResult]:
    """
    Applies the selected sections of `profile` on this machine. `sections`
    is any subset of profiles.SECTIONS. Each section is independent - one
    failing doesn't stop the others from being attempted.
    """
    results: dict[str, CommandResult] = {}

    def run_section(key: str, apply: Callable[[], None]) -> None:
        # A profile file is untrusted input - a malformed section (or an
        # unexpected error while applying it) is recorded against that
        # section, and the remaining sections still run.
        try:
            apply()
        except Exception as exc:  # noqa: BLE001 - reported per section, not swallowed
            on_line(f"Failed: {exc}")
            results[key] = CommandResult(1, "", str(exc))
        on_line("")

    if "quicksetup" in sections:
        def apply_quicksetup() -> None:
            keys = [key for key in profile.get("quicksetup_keys", []) if key in {item.key for item in quicksetup.CATALOG}]
            on_line("=== Re-applying quick-setup modules from profile ===")
            if keys:
                results.update(quicksetup.apply_items(keys, on_line))
            else:
                on_line("Profile has no quick-setup modules to apply.")

        run_section("quicksetup", apply_quicksetup)

    if "apparmor_profiles" in sections:
        def apply_apparmor() -> None:
            on_line("=== AppArmor profile modes ===")
            results["apparmor_profiles"] = _import_apparmor_profiles(profile.get("apparmor_profiles", {}) or {}, on_line)

        run_section("apparmor_profiles", apply_apparmor)

    if "selinux_booleans" in sections:
        def apply_selinux() -> None:
            on_line("=== SELinux booleans ===")
            results["selinux_booleans"] = _import_selinux_booleans(profile.get("selinux_booleans", {}) or {}, on_line)

        run_section("selinux_booleans", apply_selinux)

    if "ssh" in sections:
        def apply_ssh() -> None:
            on_line("=== SSH hardening ===")
            ssh_section = profile.get("ssh")
            if ssh_section:
                results["ssh"] = _import_ssh(ssh_section, on_line)
            else:
                on_line("Profile has no SSH section to apply.")
                results["ssh"] = CommandResult(0, "nothing to apply", "")

        run_section("ssh", apply_ssh)

    return results
