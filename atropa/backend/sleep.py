"""
atropa.backend.sleep
-----------------------
Lid, power button and suspend-then-hibernate settings.

Atropa writes its own drop-ins rather than editing logind.conf or
sleep.conf, so a hand-edited main file is never rewritten:

- ``/etc/systemd/logind.conf.d/50-atropa.conf`` - what closing the lid
  (on battery and plugged in) and pressing the power button do.
- ``/etc/systemd/sleep.conf.d/50-atropa.conf`` - how long
  suspend-then-hibernate stays suspended before hibernating.

Applying the logind one reloads systemd-logind (``systemctl reload``), which
re-reads its configuration without ending the graphical session - unlike a
restart. systemd-sleep reads sleep.conf at every suspend, so that one needs
nothing.

Reading follows systemd's own precedence (systemd.syntax(7)): the main file
from the first of /etc, /run, /usr/local/lib, /usr/lib that has one, then
every ``*.conf`` drop-in from those directories' ``.d`` folders in file-name
order, where a name in /etc hides the same name further down. The last
assignment wins. Each value is reported with the file it came from, so a
drop-in sorting after Atropa's (``60-foo.conf``) shows up as the reason a
change didn't take.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .privilege import CommandResult, path_exists, run_privileged

CONFIG_ROOTS = (
    Path("/etc/systemd"),
    Path("/run/systemd"),
    Path("/usr/local/lib/systemd"),
    Path("/usr/lib/systemd"),
)
LOGIND_DROPIN = Path("/etc/systemd/logind.conf.d/50-atropa.conf")
SLEEP_DROPIN = Path("/etc/systemd/sleep.conf.d/50-atropa.conf")
LID_DIR = Path("/proc/acpi/button/lid")

# What Atropa offers. logind knows a few more (halt, kexec, factory-reset,
# ...), which are shown when set but not offered.
ACTIONS = ("suspend", "suspend-then-hibernate", "hibernate", "hybrid-sleep", "lock", "poweroff", "ignore")
HIBERNATING_ACTIONS = frozenset({"suspend-then-hibernate", "hibernate", "hybrid-sleep"})

LID = "HandleLidSwitch"
LID_EXTERNAL_POWER = "HandleLidSwitchExternalPower"
POWER_KEY = "HandlePowerKey"
HIBERNATE_DELAY = "HibernateDelaySec"

# logind's built-in defaults (logind.conf(5)). HandleLidSwitchExternalPower
# falls back to HandleLidSwitch, so it has no fixed default of its own.
LOGIND_DEFAULTS = {LID: "suspend", POWER_KEY: "poweroff"}

# A systemd time span (systemd.time(7)): numbers with units, like "2h" or
# "1h 30min". One line, nothing else, so it can't add other settings.
_UNIT = r"(?:usec|us|msec|ms|seconds?|sec|s|minutes?|min|m|hours?|hr|h|days?|d|weeks?|w)"
_DELAY_RE = re.compile(rf"^[0-9]{{1,6}} ?{_UNIT}(?: ?[0-9]{{1,6}} ?{_UNIT})*$")


@dataclass
class Setting:
    value: str | None  # None: systemd decides (no default value to show)
    source: str  # the file it came from, or "systemd default"


@dataclass
class SleepSettings:
    lid: Setting
    lid_external_power: Setting
    power_key: Setting
    hibernate_delay: Setting
    has_lid: bool


def _config_files(name: str) -> list[Path]:
    """`name` is "logind" or "sleep"; the files systemd reads, in order."""
    files = []
    for root in CONFIG_ROOTS:
        main = root / f"{name}.conf"
        if path_exists(main):
            files.append(main)
            break
    dropins: dict[str, Path] = {}
    for root in reversed(CONFIG_ROOTS):  # /etc last, so its names win
        directory = root / f"{name}.conf.d"
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.name.endswith(".conf"):
                dropins[entry.name] = entry
    return files + [dropins[key] for key in sorted(dropins)]


def parse(text: str, section: str) -> dict[str, str]:
    """Key=value assignments in [section] of a systemd INI file; the last one wins."""
    values: dict[str, str] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            continue
        if current != section or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def _effective(name: str, section: str) -> dict[str, Setting]:
    settings: dict[str, Setting] = {}
    for path in _config_files(name):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for key, value in parse(text, section).items():
            # An empty assignment resets the key to its default.
            if value:
                settings[key] = Setting(value, str(path))
            else:
                settings.pop(key, None)
    return settings


def read_settings() -> SleepSettings:
    logind = _effective("logind", "Login")
    sleep = _effective("sleep", "Sleep")
    default = "systemd default"

    lid = logind.get(LID) or Setting(LOGIND_DEFAULTS[LID], default)
    lid_external = logind.get(LID_EXTERNAL_POWER) or Setting(lid.value, "same as on battery")
    return SleepSettings(
        lid=lid,
        lid_external_power=lid_external,
        power_key=logind.get(POWER_KEY) or Setting(LOGIND_DEFAULTS[POWER_KEY], default),
        hibernate_delay=sleep.get(HIBERNATE_DELAY) or Setting(None, default),
        has_lid=bool(path_exists(LID_DIR)),
    )


def _check_action(value: str) -> str:
    if value not in ACTIONS:
        raise ValueError(f"{value!r} isn't one of: {', '.join(ACTIONS)}")
    return value


def logind_content(lid: str, lid_external_power: str, power_key: str) -> str:
    return (
        "# Written by Atropa (Power page). Edit it there, or delete this file\n"
        "# to go back to logind.conf and systemd's defaults.\n"
        "[Login]\n"
        f"{LID}={_check_action(lid)}\n"
        f"{LID_EXTERNAL_POWER}={_check_action(lid_external_power)}\n"
        f"{POWER_KEY}={_check_action(power_key)}\n"
    )


def sleep_content(hibernate_delay: str | None) -> str:
    lines = [
        "# Written by Atropa (Power page). Edit it there, or delete this file\n",
        "# to go back to sleep.conf and systemd's defaults.\n",
        "[Sleep]\n",
    ]
    if hibernate_delay is not None:
        if not _DELAY_RE.match(hibernate_delay):
            raise ValueError("the hibernate delay must be a time span, e.g. 90min or 2h")
        lines.append(f"{HIBERNATE_DELAY}={hibernate_delay}\n")
    return "".join(lines)


def apply_logind(lid: str, lid_external_power: str, power_key: str) -> CommandResult:
    """Write Atropa's logind drop-in and reload logind (the session stays up)."""
    content = logind_content(lid, lid_external_power, power_key)
    for argv, kwargs in (
        (["mkdir", "-p", str(LOGIND_DROPIN.parent)], {}),
        (["tee", str(LOGIND_DROPIN)], {"input_text": content}),
        (["systemctl", "reload", "systemd-logind.service"], {}),
    ):
        result = run_privileged(argv, **kwargs)
        if not result.ok:
            return result
    return result


def apply_sleep(hibernate_delay: str | None) -> CommandResult:
    """Write Atropa's sleep drop-in; systemd-sleep reads it at the next suspend."""
    content = sleep_content(hibernate_delay)
    made = run_privileged(["mkdir", "-p", str(SLEEP_DROPIN.parent)])
    if not made.ok:
        return made
    return run_privileged(["tee", str(SLEEP_DROPIN)], input_text=content)
