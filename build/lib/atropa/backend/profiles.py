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
        ssh_section = {
            "root_login": ssh_status.root_login,
            "password_auth": ssh_status.password_auth,
            "port": ssh_status.port,
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
        current = {p.path for p in apparmor.list_profiles()}
    except RuntimeError as exc:
        on_line(f"Couldn't list profiles: {exc}")
        return CommandResult(1, "", str(exc))

    applied, skipped, failed = 0, 0, 0
    for path, mode in profiles.items():
        if path not in current:
            on_line(f"Skipping {path} (not present on this machine)")
            skipped += 1
            continue
        on_line(f"Setting {path} to {mode}...")
        result = apparmor.set_profile_mode(path, mode)
        if result.ok:
            applied += 1
        else:
            on_line(f"Failed: {result.stderr.strip()}")
            failed += 1

    on_line(f"AppArmor profiles: {applied} applied, {skipped} skipped, {failed} failed.")
    return CommandResult(0 if failed == 0 else 1, f"applied={applied} skipped={skipped} failed={failed}", "")


def _import_selinux_booleans(booleans: dict, on_line: Callable[[str], None]) -> CommandResult:
    if not booleans:
        on_line("Profile has no SELinux booleans to apply.")
        return CommandResult(0, "nothing to apply", "")
    if not selinux.get_status().available:
        on_line("SELinux isn't available on this machine - skipping.")
        return CommandResult(0, "skipped: selinux unavailable", "")

    current_names = {b.name for b in selinux.list_booleans()}
    applied, skipped, failed = 0, 0, 0
    for name, value in booleans.items():
        if name not in current_names:
            on_line(f"Skipping {name} (not present on this machine)")
            skipped += 1
            continue
        on_line(f"Setting {name} to {'on' if value else 'off'}...")
        result = selinux.set_boolean(name, bool(value))
        if result.ok:
            applied += 1
        else:
            on_line(f"Failed: {result.stderr.strip()}")
            failed += 1

    on_line(f"SELinux booleans: {applied} applied, {skipped} skipped, {failed} failed.")
    return CommandResult(0 if failed == 0 else 1, f"applied={applied} skipped={skipped} failed={failed}", "")


def _import_ssh(ssh_section: dict, on_line: Callable[[str], None]) -> CommandResult:
    on_line(
        "Applying SSH settings from the profile. Each change is validated with "
        "'sshd -t' before reload and rolled back automatically if invalid - but a "
        "VALID config that still doesn't fit this machine (e.g. disabling password "
        "auth without a key already set up here) won't be caught by that check."
    )
    last_result = CommandResult(0, "no ssh settings applied", "")

    if "root_login" in ssh_section:
        allow = str(ssh_section["root_login"]).strip().lower() in ("yes", "true", "on")
        on_line(f"Setting PermitRootLogin to {ssh_section['root_login']}...")
        last_result = security.set_ssh_root_login(allow)
        if not last_result.ok:
            on_line(f"Failed: {last_result.stderr.strip()}")

    if "password_auth" in ssh_section:
        allow = str(ssh_section["password_auth"]).strip().lower() in ("yes", "true", "on")
        on_line(f"Setting PasswordAuthentication to {ssh_section['password_auth']}...")
        last_result = security.set_ssh_password_auth(allow)
        if not last_result.ok:
            on_line(f"Failed: {last_result.stderr.strip()}")

    if "port" in ssh_section:
        try:
            port = int(ssh_section["port"])
        except (TypeError, ValueError):
            on_line(f"Skipping port - '{ssh_section['port']}' isn't a valid number.")
        else:
            on_line(f"Setting SSH port to {port}...")
            last_result = security.set_ssh_port(port)
            if not last_result.ok:
                on_line(f"Failed: {last_result.stderr.strip()}")

    return last_result


def import_profile(profile: dict, sections: list[str], on_line: Callable[[str], None]) -> dict[str, CommandResult]:
    """
    Applies the selected sections of `profile` on this machine. `sections`
    is any subset of profiles.SECTIONS. Each section is independent - one
    failing doesn't stop the others from being attempted.
    """
    results: dict[str, CommandResult] = {}

    if "quicksetup" in sections:
        keys = [key for key in profile.get("quicksetup_keys", []) if key in {item.key for item in quicksetup.CATALOG}]
        on_line("=== Re-applying quick-setup modules from profile ===")
        if keys:
            results.update(quicksetup.apply_items(keys, on_line))
        else:
            on_line("Profile has no quick-setup modules to apply.")
        on_line("")

    if "apparmor_profiles" in sections:
        on_line("=== AppArmor profile modes ===")
        results["apparmor_profiles"] = _import_apparmor_profiles(profile.get("apparmor_profiles", {}) or {}, on_line)
        on_line("")

    if "selinux_booleans" in sections:
        on_line("=== SELinux booleans ===")
        results["selinux_booleans"] = _import_selinux_booleans(profile.get("selinux_booleans", {}) or {}, on_line)
        on_line("")

    if "ssh" in sections:
        on_line("=== SSH hardening ===")
        ssh_section = profile.get("ssh")
        if ssh_section:
            results["ssh"] = _import_ssh(ssh_section, on_line)
        else:
            on_line("Profile has no SSH section to apply.")
            results["ssh"] = CommandResult(0, "nothing to apply", "")
        on_line("")

    return results
