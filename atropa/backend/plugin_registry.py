"""
atropa.backend.plugin_registry
------------------------------------
The fixed, curated list of actions a plugin manifest is allowed to
reference. This IS the security boundary for the plugin system - a
manifest can only point at a key defined here, never at arbitrary code,
a shell command, or a function this file doesn't explicitly list. Adding
a new entry means deliberately deciding it's safe enough to expose to
plugins, the same scrutiny as any other feature in this app - it is not
a generic "expose everything" shim.

Every entry is a RegistryAction: the real callable, whether it mutates
system state (mutating=True means the UI must show a confirm dialog with
the REAL call before running it - a plugin's friendly label is never a
substitute for that), and a short human-readable description of exactly
what it does, shown alongside the plugin's own description so a user
isn't relying solely on a plugin author's framing.

Deliberately excluded for now, regardless of how a plugin might phrase a
request for it: anything touching users, firewall/SSH, bootloader,
SELinux/AppArmor policy, restorecon, or quicksetup/profile
import/export. Those have meaningfully higher blast radius and stay
built-in-only until there's a specific, considered reason to expose one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from . import compliance, dependencies, hardening, network, pacman, services


@dataclass
class RegistryAction:
    key: str
    func: Callable[..., Any]
    mutating: bool
    description: str
    param_names: list[str]  # ordered positional parameter names this action accepts, if any


def _action(key, func, mutating, description, param_names=None) -> RegistryAction:
    return RegistryAction(key=key, func=func, mutating=mutating, description=description, param_names=param_names or [])


# --------------------------------------------------------------- the registry --

_ACTIONS: list[RegistryAction] = [
    # Read-only: safe to run without a confirm dialog.
    _action("dependencies.check_all", dependencies.check_all, False,
            "Checks install status of every tool Atropa's built-in modules use."),
    _action("hardening.run_audit", hardening.run_audit, False,
            "Runs the built-in security audit rollup (firewall, SSH, fail2ban, AppArmor, SELinux, etc.)."),
    _action("compliance.generate_report", compliance.generate_report, False,
            "Generates the categorized, scored compliance report."),
    _action("pacman.check_updates", pacman.check_updates, False,
            "Lists pending package updates (pacman -Qu) - does not install anything."),
    _action("pacman.list_explicit", pacman.list_explicit, False,
            "Lists explicitly-installed packages (pacman -Qe)."),
    _action("services.list_services", services.list_services, False,
            "Lists systemd services and their state."),
    _action("network.list_devices", network.list_devices, False,
            "Lists network devices and their connection state."),

    # Mutating: the UI must always show the real call in a confirm dialog
    # before running these, regardless of what the plugin's manifest calls
    # the button - see run_plugin_action() in plugins.py.
    _action("pacman.clean_cache", pacman.clean_cache, True,
            "Removes old/uninstalled packages from the pacman cache (pacman -Sc)."),
    _action("pacman.sync_database", pacman.sync_database, True,
            "Refreshes the package database (pacman -Sy) - does not install/upgrade anything."),
    _action("services.restart", services.restart, True,
            "Restarts a systemd service.", param_names=["unit"]),
    _action("services.start", services.start, True,
            "Starts a systemd service.", param_names=["unit"]),
    _action("services.stop", services.stop, True,
            "Stops a systemd service.", param_names=["unit"]),
    _action("services.enable", services.enable, True,
            "Enables a systemd service.", param_names=["unit"]),
    _action("services.disable", services.disable, True,
            "Disables a systemd service.", param_names=["unit"]),
]

REGISTRY: dict[str, RegistryAction] = {action.key: action for action in _ACTIONS}


def get_action(key: str) -> RegistryAction | None:
    return REGISTRY.get(key)


def describe_call(key: str, params: dict) -> str:
    """Renders the REAL call a plugin row would make, e.g. services.restart('sshd') -
    shown in the confirm dialog regardless of the plugin's own label, so a
    misleadingly-titled button can't hide what it actually does."""
    action = REGISTRY.get(key)
    if action is None:
        return f"{key}(?)  [unknown action]"
    args = ", ".join(repr(params.get(name, "")) for name in action.param_names)
    return f"{key}({args})"
