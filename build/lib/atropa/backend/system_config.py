"""
atropa.backend.system_config
--------------------------------
Basic system configuration: hostname, timezone/NTP, locale, and keyboard
layout - the same four things every distro's system-setup tool covers,
handled here via systemd's own trio (hostnamectl/timedatectl/localectl)
rather than editing their underlying config files directly.

Locale generation is the one exception that touches a raw config file
(/etc/locale.gen) - there's no systemd tool for it, since deciding which
locale definitions actually get *compiled* by locale-gen is a step below
what localectl manages (localectl only picks among locales already
generated). That edit goes through the same backup_file() safety net
every other config-editing function in this app uses.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from .privilege import CommandResult, backup_file, run_privileged, run_unprivileged

LOCALE_GEN_PATH = Path("/etc/locale.gen")


# ---------------------------------------------------------------- hostname --

@dataclass
class HostnameStatus:
    static_hostname: str
    pretty_hostname: str
    icon_name: str
    chassis: str
    os_name: str
    kernel: str


def get_hostname_status() -> HostnameStatus:
    result = run_unprivileged(["hostnamectl", "status"])
    fields = _parse_colon_fields(result.stdout)
    return HostnameStatus(
        static_hostname=fields.get("static hostname", ""),
        pretty_hostname=fields.get("pretty hostname", ""),
        icon_name=fields.get("icon name", ""),
        chassis=fields.get("chassis", ""),
        os_name=fields.get("operating system", ""),
        kernel=fields.get("kernel", ""),
    )


def set_hostname(name: str) -> CommandResult:
    if not name or not name.strip():
        raise ValueError("Hostname is required")
    return run_privileged(["hostnamectl", "set-hostname", name.strip()])


# ---------------------------------------------------------------- time/NTP --

@dataclass
class TimeStatus:
    timezone: str
    local_time: str
    ntp_service_active: bool
    system_clock_synchronized: bool


def get_time_status() -> TimeStatus:
    result = run_unprivileged(["timedatectl", "status"])
    fields = _parse_colon_fields(result.stdout)
    return TimeStatus(
        timezone=fields.get("time zone", ""),
        local_time=fields.get("local time", ""),
        ntp_service_active=fields.get("ntp service", "").strip().lower() == "active",
        system_clock_synchronized=fields.get("system clock synchronized", "").strip().lower() == "yes",
    )


def list_timezones() -> list[str]:
    result = run_unprivileged(["timedatectl", "list-timezones"])
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def set_timezone(tz: str) -> CommandResult:
    if not tz or not tz.strip():
        raise ValueError("Timezone is required")
    return run_privileged(["timedatectl", "set-timezone", tz.strip()])


def set_ntp(enabled: bool) -> CommandResult:
    return run_privileged(["timedatectl", "set-ntp", "true" if enabled else "false"])


# ---------------------------------------------------------------- locale --

@dataclass
class LocaleStatus:
    lang: str
    vc_keymap: str
    x11_layout: str


def get_locale_status() -> LocaleStatus:
    result = run_unprivileged(["localectl", "status"])
    fields = _parse_colon_fields(result.stdout)
    system_locale = fields.get("system locale", "")
    lang_match = re.search(r"LANG=(\S+)", system_locale)
    return LocaleStatus(
        lang=lang_match.group(1) if lang_match else "",
        vc_keymap=fields.get("vc keymap", ""),
        x11_layout=fields.get("x11 layout", ""),
    )


def list_generated_locales() -> list[str]:
    """Locales already generated and available to select via set_locale()."""
    result = run_unprivileged(["localectl", "list-locales"])
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def set_locale(lang: str) -> CommandResult:
    if not lang or not lang.strip():
        raise ValueError("Locale is required")
    return run_privileged(["localectl", "set-locale", f"LANG={lang.strip()}"])


@dataclass
class LocaleGenEntry:
    locale: str
    charmap: str
    enabled: bool


_LOCALE_GEN_LINE_RE = re.compile(r"^(#)?\s*([\w.@-]+)\s+([\w-]+)\s*$")


def list_locale_gen_entries() -> list[LocaleGenEntry]:
    """
    Parses /etc/locale.gen: every locale definition it knows about, and
    whether each is currently uncommented (enabled -> will actually be
    produced by the next locale-gen run). This is a different, lower-level
    list than list_generated_locales() - that one only shows locales
    ALREADY compiled; this shows what's available to enable in the first
    place, which is the step people forget on a fresh Arch install.
    """
    result = run_unprivileged(["cat", str(LOCALE_GEN_PATH)])
    if not result.ok:
        return []
    entries = []
    for line in result.stdout.splitlines():
        m = _LOCALE_GEN_LINE_RE.match(line)
        if not m:
            continue
        commented, locale, charmap = m.groups()
        entries.append(LocaleGenEntry(locale=locale, charmap=charmap, enabled=commented is None))
    return entries


def set_locale_gen_enabled(locale: str, charmap: str, enabled: bool) -> CommandResult:
    """
    Uncomments (or re-comments) the matching line in /etc/locale.gen, then
    runs locale-gen so the change actually takes effect immediately -
    otherwise "enabled" here would be a config-file fiction until whenever
    locale-gen next happened to run.

    Reads, edits, and rewrites the file entirely in Python rather than
    building a sed expression - re.escape() output doesn't translate
    cleanly into sed's BRE syntax (they disagree about characters like
    `+`/`?`), so matching and replacing the target line here avoids that
    whole class of escaping mismatch.
    """
    read_result = run_unprivileged(["cat", str(LOCALE_GEN_PATH)])
    if not read_result.ok:
        return read_result

    target_suffix = f"{locale} {charmap}"
    new_lines = []
    matched = False
    for line in read_result.stdout.splitlines():
        m = _LOCALE_GEN_LINE_RE.match(line)
        if m and m.group(2) == locale and m.group(3) == charmap:
            matched = True
            new_lines.append(target_suffix if enabled else f"#{target_suffix}")
        else:
            new_lines.append(line)

    if not matched:
        return CommandResult(1, "", f"No entry for {locale} {charmap} found in {LOCALE_GEN_PATH}")

    backup_file(str(LOCALE_GEN_PATH))
    new_content = "\n".join(new_lines) + "\n"
    write_result = run_privileged(["tee", str(LOCALE_GEN_PATH)], input_text=new_content)
    if not write_result.ok:
        return write_result
    return run_privileged(["locale-gen"])


# ---------------------------------------------------------------- keyboard --

def list_keymaps() -> list[str]:
    """Console (VC) keymaps - what set_keymap() accepts."""
    result = run_unprivileged(["localectl", "list-keymaps"])
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def set_keymap(keymap: str) -> CommandResult:
    if not keymap or not keymap.strip():
        raise ValueError("Keymap is required")
    return run_privileged(["localectl", "set-keymap", keymap.strip()])


def list_x11_layouts() -> list[str]:
    """X11/Wayland keyboard layout codes - what set_x11_layout() accepts."""
    if shutil.which("localectl") is None:
        return []
    result = run_unprivileged(["localectl", "list-x11-keymap-layouts"])
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def set_x11_layout(layout: str) -> CommandResult:
    if not layout or not layout.strip():
        raise ValueError("Layout is required")
    return run_privileged(["localectl", "set-x11-keymap", layout.strip()])


# ---------------------------------------------------------------- shared parsing --

def _parse_colon_fields(text: str) -> dict[str, str]:
    """
    Parses the "  Some Key: value" format common to hostnamectl/timedatectl/
    localectl's status output into {lowercased key: value}. Keys with
    internal spaces are preserved as given (lowercased), e.g. "static
    hostname", "ntp service".
    """
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if not key:
            continue
        fields[key] = value.strip()
    return fields
