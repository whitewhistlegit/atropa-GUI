"""
atropa.backend.plugins
----------------------------
Discovers, parses, and validates declarative plugin manifests - and gates
turning any of them on behind a privileged (pkexec) write, so enabling a
plugin always requires the same authentication barrier as any other
privileged action in this app.

Two deliberate security properties, not just conventions:

1. Manifests are DATA, never code. Parsing a manifest never imports,
   execs, or evals anything from it - tomllib.loads() reads a TOML
   document into plain dicts/lists/strings, full stop. There is no path
   from "a manifest exists on disk" to "arbitrary code ran."

2. Both the manifest files AND the enabled-state file live under
   /etc/atropa, which is root-owned - so placing, editing, OR enabling
   a plugin all require root. A non-privileged process (including
   Atropa's own GTK process, which runs as the desktop user) cannot do
   any of the three on its own; enabling specifically goes through
   run_privileged() (pkexec), which pops the same polkit authentication
   prompt as installing a package or changing a firewall rule.

A manifest can only reference action keys already defined in
plugin_registry.REGISTRY - see that module for why that's the actual
security boundary for what a plugin can DO, not just where its files live.
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import plugin_registry
from .privilege import CommandResult, run_privileged

PLUGINS_DIR = Path("/etc/atropa/plugins")
ENABLED_STATE_FILE = Path("/etc/atropa/plugins-enabled.json")


@dataclass
class PluginRow:
    title: str
    action_key: str
    params: dict = field(default_factory=dict)
    button_label: str | None = None


@dataclass
class PluginGroup:
    title: str
    description: str = ""
    rows: list[PluginRow] = field(default_factory=list)


@dataclass
class PluginManifest:
    id: str
    title: str
    description: str = ""
    icon: str = "puzzle-piece-symbolic"
    author: str = ""
    version: str = ""
    groups: list[PluginGroup] = field(default_factory=list)
    path: str = ""


@dataclass
class DiscoveredPlugin:
    plugin_id: str
    path: str
    enabled: bool
    manifest: PluginManifest | None = None  # None if parsing/validation failed
    errors: list[str] = field(default_factory=list)


def _load_enabled_state() -> dict[str, bool]:
    if not ENABLED_STATE_FILE.exists():
        return {}
    try:
        return json.loads(ENABLED_STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _parse_manifest(path: Path) -> tuple[PluginManifest | None, list[str]]:
    """Parses and validates one manifest.toml. Never executes anything
    from it - every field is read as plain data. Returns (None, errors)
    on any validation failure rather than a best-effort partial manifest,
    so an invalid plugin never silently renders a broken/incomplete page."""
    errors: list[str] = []

    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return None, [f"Couldn't read manifest: {exc}"]
    except tomllib.TOMLDecodeError as exc:
        return None, [f"Not valid TOML: {exc}"]

    plugin_id = raw.get("id")
    title = raw.get("title")
    if not plugin_id:
        errors.append("Missing required field: id")
    if not title:
        errors.append("Missing required field: title")

    groups: list[PluginGroup] = []
    for raw_group in raw.get("groups", []):
        if not isinstance(raw_group, dict):
            errors.append("Each entry in [[groups]] must be a table")
            continue
        rows: list[PluginRow] = []
        for raw_row in raw_group.get("rows", []):
            if not isinstance(raw_row, dict):
                errors.append("Each entry in [[groups.rows]] must be a table")
                continue
            row_title = raw_row.get("title")
            action_key = raw_row.get("action")
            if not row_title:
                errors.append(f"A row in group '{raw_group.get('title', '?')}' is missing a title")
                continue
            if not action_key:
                errors.append(f"Row '{row_title}' is missing an action")
                continue
            if plugin_registry.get_action(action_key) is None:
                errors.append(f"Row '{row_title}' references unknown action '{action_key}' - not in the approved registry")
                continue
            params = {k: v for k, v in raw_row.items() if k not in ("title", "action", "button_label")}
            rows.append(PluginRow(title=row_title, action_key=action_key, params=params, button_label=raw_row.get("button_label")))
        groups.append(PluginGroup(title=raw_group.get("title", "Untitled"), description=raw_group.get("description", ""), rows=rows))

    if errors:
        return None, errors

    manifest = PluginManifest(
        id=plugin_id, title=title, description=raw.get("description", ""),
        icon=raw.get("icon", "puzzle-piece-symbolic"), author=raw.get("author", ""),
        version=raw.get("version", ""), groups=groups, path=str(path),
    )
    return manifest, []


def discover_plugins() -> list[DiscoveredPlugin]:
    """
    Scans PLUGINS_DIR for <plugin-id>/manifest.toml files, parses and
    validates each against the approved action registry, and
    cross-references the enabled-state file. Read-only and side-effect
    free throughout.
    """
    discovered: list[DiscoveredPlugin] = []
    if not PLUGINS_DIR.exists():
        return discovered

    enabled_state = _load_enabled_state()
    for plugin_dir in sorted(p for p in PLUGINS_DIR.iterdir() if p.is_dir()):
        manifest_path = plugin_dir / "manifest.toml"
        if not manifest_path.is_file():
            continue
        plugin_id = plugin_dir.name
        manifest, errors = _parse_manifest(manifest_path)
        if manifest is not None and manifest.id != plugin_id:
            errors = [f"Manifest 'id' ({manifest.id!r}) doesn't match its folder name ({plugin_id!r})"]
            manifest = None
        discovered.append(
            DiscoveredPlugin(
                plugin_id=plugin_id, path=str(manifest_path),
                enabled=enabled_state.get(plugin_id, False), manifest=manifest, errors=errors,
            )
        )
    return discovered


def enabled_plugins() -> list[DiscoveredPlugin]:
    """Only the discovered plugins that are both valid and enabled - what
    main_window.py actually renders as live sidebar pages. Everything
    else (invalid, or valid-but-disabled) only ever shows up in the
    Add-ons page's listing, never as a live page."""
    return [p for p in discover_plugins() if p.manifest is not None and p.enabled]


def set_plugin_enabled(plugin_id: str, enabled: bool) -> CommandResult:
    """
    Flips a plugin's enabled state - the actual security gate the plugin
    system rests on. This is a write to a root-owned file via
    run_privileged() (pkexec): the same authentication barrier as any
    other privileged action here. Neither a plugin nor Atropa's own
    unprivileged process can complete this without a human finishing that
    prompt.
    """
    state = _load_enabled_state()
    state[plugin_id] = enabled
    content = json.dumps(state, indent=2, sort_keys=True) + "\n"

    mkdir_result = run_privileged(["mkdir", "-p", str(ENABLED_STATE_FILE.parent)])
    if not mkdir_result.ok:
        return mkdir_result
    return run_privileged(["tee", str(ENABLED_STATE_FILE)], input_text=content)


def run_plugin_action(action_key: str, params: dict) -> Any:
    """
    Executes the real registry-backed function for a plugin row. Only
    ever called with an action_key that already passed validation in
    _parse_manifest - raises for an unknown key rather than silently
    doing nothing, since a supposedly-mutating action silently no-op'ing
    would be its own confusing failure mode.
    """
    action = plugin_registry.get_action(action_key)
    if action is None:
        raise ValueError(f"Unknown plugin action: {action_key!r}")
    args = [params.get(name) for name in action.param_names]
    return action.func(*args)
