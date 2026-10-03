"""
atropa.backend.services
---------------------------
Wraps systemctl for the Services module (start/stop/enable/disable/status).
"""

from __future__ import annotations

from dataclasses import dataclass

from .privilege import CommandResult, run_privileged, run_unprivileged


@dataclass
class Service:
    unit: str
    load: str
    active: str
    sub: str
    description: str
    enabled: str = "unknown"


def list_services(pattern: str = "*.service") -> list[Service]:
    result = run_unprivileged(
        ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", pattern]
    )
    services = []
    for line in result.stdout.strip().splitlines():
        parts = line.split(maxsplit=4)
        if len(parts) < 4:
            continue
        unit, load, active, sub = parts[0], parts[1], parts[2], parts[3]
        desc = parts[4] if len(parts) > 4 else ""
        services.append(Service(unit=unit, load=load, active=active, sub=sub, description=desc))

    # Enrich with enabled/disabled state
    for svc in services:
        enabled = run_unprivileged(["systemctl", "is-enabled", svc.unit])
        svc.enabled = enabled.stdout.strip() or "unknown"

    return services


def status(unit: str) -> str:
    result = run_unprivileged(["systemctl", "status", unit, "--no-pager"])
    return result.stdout or result.stderr


def start(unit: str) -> CommandResult:
    return run_privileged(["systemctl", "start", unit])


def stop(unit: str) -> CommandResult:
    return run_privileged(["systemctl", "stop", unit])


def restart(unit: str) -> CommandResult:
    return run_privileged(["systemctl", "restart", unit])


def enable(unit: str, now: bool = False) -> CommandResult:
    argv = ["systemctl", "enable", unit]
    if now:
        argv.append("--now")
    return run_privileged(argv)


def disable(unit: str, now: bool = False) -> CommandResult:
    argv = ["systemctl", "disable", unit]
    if now:
        argv.append("--now")
    return run_privileged(argv)


def journal_tail(unit: str, lines: int = 100) -> str:
    result = run_unprivileged(["journalctl", "-u", unit, "-n", str(lines), "--no-pager"])
    return result.stdout
