"""
atropa.backend.lockdown
--------------------------
"Lockdown" is a reversible radio-silence mode, not a hardening preset and
not a session lock:

- NetworkManager networking off (wired and Wi-Fi)
- the Wi-Fi radio off
- Bluetooth stopped

The state from before the switch is saved, so exiting restores exactly what
was on before - a machine that already had Wi-Fi or Bluetooth off does not
get them turned on afterwards. No firewall or SSH configuration is touched
here: networking off already removes the remote surface, and changing sshd
behind the user's back is the kind of surprise this app avoids.

Deliberately absent: `loginctl lock-sessions`. It only locks the screen (the
user's own password unlocks it), so it is not a lockout - but it is also not
useful for a mode someone is actively toggling, and with a Bluetooth
keyboard it could make the restore button unreachable. The real lockout
risks are handled where they arise: a refusal when the app is running over
SSH, and a confirmation that says Bluetooth input devices will disconnect.

Commands stay on the already-allowed side of the privileged helper
(`nmcli`, `systemctl`); no new helper verb and no new writable path is
needed for lockdown. The snapshot is ordinary user state, not a security
boundary.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .privilege import CommandResult, run_privileged, run_unprivileged

LOCKDOWN_FILE = Path.home() / ".local" / "share" / "atropa" / "lockdown.json"
BLUETOOTH_UNIT = "bluetooth"


@dataclass
class RadioSnapshot:
    networking: bool
    wifi: bool
    bluetooth_active: bool
    bluetooth_enabled: bool
    saved_at: str = ""


@dataclass
class LockdownStatus:
    active: bool
    networking: bool | None = None
    wifi: bool | None = None
    bluetooth_active: bool | None = None
    snapshot: RadioSnapshot | None = None


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _nmcli_state(*args: str) -> bool | None:
    """True/False from nmcli's "enabled"/"disabled", None when it can't tell."""
    result = run_unprivileged(["nmcli", *args], timeout=20)
    value = result.stdout.strip().lower()
    if value == "enabled":
        return True
    if value == "disabled":
        return False
    return None


def _bluetooth_active() -> bool:
    return run_unprivileged(["systemctl", "is-active", BLUETOOTH_UNIT], timeout=10).stdout.strip() == "active"


def _bluetooth_enabled() -> bool:
    return run_unprivileged(["systemctl", "is-enabled", BLUETOOTH_UNIT], timeout=10).stdout.strip() == "enabled"


def current_snapshot() -> RadioSnapshot:
    """The state lockdown would restore to; raises when it can't be read."""
    if shutil.which("nmcli") is None:
        raise RuntimeError("Lockdown needs NetworkManager (nmcli) to turn networking and Wi-Fi off")
    networking = _nmcli_state("networking")
    wifi = _nmcli_state("radio", "wifi")
    if networking is None or wifi is None:
        raise RuntimeError("Couldn't read NetworkManager's networking/Wi-Fi state")
    try:
        bluetooth_active = _bluetooth_active()
        bluetooth_enabled = _bluetooth_enabled()
    except Exception:  # noqa: BLE001 - no Bluetooth unit is a normal desktop state
        bluetooth_active = bluetooth_enabled = False
    return RadioSnapshot(networking, wifi, bluetooth_active, bluetooth_enabled, _now())


def save_snapshot(snapshot: RadioSnapshot) -> None:
    LOCKDOWN_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "saved_at": snapshot.saved_at,
        "networking": snapshot.networking,
        "wifi": snapshot.wifi,
        "bluetooth_active": snapshot.bluetooth_active,
        "bluetooth_enabled": snapshot.bluetooth_enabled,
    }
    temporary = LOCKDOWN_FILE.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    temporary.replace(LOCKDOWN_FILE)


def load_snapshot() -> RadioSnapshot | None:
    try:
        data = json.loads(LOCKDOWN_FILE.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        snapshot = RadioSnapshot(
            networking=bool(data["networking"]),
            wifi=bool(data["wifi"]),
            bluetooth_active=bool(data["bluetooth_active"]),
            bluetooth_enabled=bool(data.get("bluetooth_enabled", False)),
            saved_at=str(data.get("saved_at", "")),
        )
    except (KeyError, TypeError, ValueError):
        return None
    return snapshot


def clear_snapshot() -> None:
    try:
        LOCKDOWN_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def is_active() -> bool:
    """True only when a usable snapshot exists - a corrupt file isn't a mode."""
    return load_snapshot() is not None


def status() -> LockdownStatus:
    """Everything the page shows; each read is isolated so one missing tool doesn't blank it."""
    snapshot = load_snapshot()

    def safe(read):
        try:
            return read()
        except Exception:  # noqa: BLE001 - a status row, not an operation
            return None

    return LockdownStatus(
        active=snapshot is not None,
        networking=safe(lambda: _nmcli_state("networking")),
        wifi=safe(lambda: _nmcli_state("radio", "wifi")),
        bluetooth_active=safe(_bluetooth_active),
        snapshot=snapshot,
    )


def _require(result: CommandResult, action: str) -> CommandResult:
    if not result.ok:
        detail = result.stderr.strip()[:200] or f"exit code {result.returncode}"
        raise RuntimeError(f"Couldn't {action}: {detail}")
    return result


def _rollback(snapshot: RadioSnapshot, completed: list[str]) -> None:
    """Best effort: put back only what this switch actually changed."""
    for step in reversed(completed):
        try:
            if step == "networking" and snapshot.networking:
                run_privileged(["nmcli", "networking", "on"], timeout=60)
            elif step == "wifi" and snapshot.wifi:
                run_privileged(["nmcli", "radio", "wifi", "on"], timeout=60)
            elif step == "bluetooth" and snapshot.bluetooth_active:
                run_privileged(["systemctl", "start", BLUETOOTH_UNIT], timeout=60)
        except Exception:  # noqa: BLE001 - a rollback failure must not mask the original error
            continue


def enable() -> CommandResult:
    """
    Turn the radios off, remembering what was on. Raises RuntimeError (after
    rolling back anything already changed) when a step fails.
    """
    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"):
        raise RuntimeError(
            "This session looks like it came over SSH - turning networking off would cut it. "
            "Run lockdown from the machine itself."
        )

    snapshot = current_snapshot()
    save_snapshot(snapshot)

    completed: list[str] = []
    try:
        if snapshot.bluetooth_active:
            _require(run_privileged(["systemctl", "stop", BLUETOOTH_UNIT], timeout=60), "stop Bluetooth")
            completed.append("bluetooth")
        _require(run_privileged(["nmcli", "radio", "wifi", "off"], timeout=60), "turn the Wi-Fi radio off")
        completed.append("wifi")
        result = _require(run_privileged(["nmcli", "networking", "off"], timeout=60), "turn networking off")
        completed.append("networking")
        return result
    except RuntimeError:
        _rollback(snapshot, completed)
        clear_snapshot()
        raise


def disable() -> CommandResult:
    """Restore the saved state; raises RuntimeError (keeping the snapshot) if a step fails."""
    snapshot = load_snapshot()
    if snapshot is None:
        raise RuntimeError("Lockdown isn't active")

    result = CommandResult(0, "nothing needed restoring", "")
    if snapshot.networking:
        result = _require(run_privileged(["nmcli", "networking", "on"], timeout=60), "restore networking")
    if snapshot.wifi:
        result = _require(run_privileged(["nmcli", "radio", "wifi", "on"], timeout=60), "restore the Wi-Fi radio")
    if snapshot.bluetooth_active:
        result = _require(run_privileged(["systemctl", "start", BLUETOOTH_UNIT], timeout=60), "restore Bluetooth")
    clear_snapshot()
    return result
