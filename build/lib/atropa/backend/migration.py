"""
atropa.backend.migration
----------------------------
One-time migration of local data from a previous ArchYaST install to
Atropa's renamed paths (~/.local/share/archyast -> ~/.local/share/atropa,
/etc/archyast -> /etc/atropa).

Deliberately never runs automatically - the caller decides when to check
and when to migrate, since discovering "your history just moved" without
being asked would be its own kind of surprise. Just as deliberately,
migration never deletes or overwrites anything: existing files at the new
location always win, and only genuinely missing pieces get copied in.
Removing the old data entirely is a separate, explicit, confirm-gated
step (remove_legacy_user_data/remove_legacy_plugin_data) - not a side
effect of migrating.

The plugin directory lives under /etc, so migrating it needs root, same
as any other write there - this isn't a special case, it's the same
authentication barrier as enabling a plugin.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import plugins as plugins_mod
from . import privilege
from . import selinux as selinux_mod
from .privilege import CommandResult, run_privileged

OLD_USER_DATA_DIR = Path.home() / ".local" / "share" / "archyast"
OLD_PLUGINS_DIR = Path("/etc/archyast")


@dataclass
class LegacyDataStatus:
    old_user_data_found: bool
    old_actions_log: bool
    old_backup_count: int
    old_selinux_review_found: bool
    old_plugins_dir_found: bool
    old_plugin_count: int

    @property
    def anything_found(self) -> bool:
        return self.old_user_data_found or self.old_plugins_dir_found


def detect_legacy_data() -> LegacyDataStatus:
    """Read-only scan for leftover data from a previous ArchYaST install.
    Never modifies anything."""
    old_actions_log = (OLD_USER_DATA_DIR / "actions.log").is_file()

    old_backups_dir = OLD_USER_DATA_DIR / "backups"
    old_backup_count = 0
    if old_backups_dir.is_dir():
        old_backup_count = sum(1 for p in old_backups_dir.iterdir() if p.is_file() and p.name != "manifest.jsonl")

    old_selinux_review_found = (OLD_USER_DATA_DIR / "selinux-review").is_dir()

    old_plugin_count = 0
    old_plugins_subdir = OLD_PLUGINS_DIR / "plugins"
    if old_plugins_subdir.is_dir():
        old_plugin_count = sum(1 for p in old_plugins_subdir.iterdir() if p.is_dir())

    return LegacyDataStatus(
        old_user_data_found=OLD_USER_DATA_DIR.is_dir(),
        old_actions_log=old_actions_log,
        old_backup_count=old_backup_count,
        old_selinux_review_found=old_selinux_review_found,
        old_plugins_dir_found=OLD_PLUGINS_DIR.is_dir(),
        old_plugin_count=old_plugin_count,
    )


def _copy_if_missing(src: Path, dest: Path, on_line: Callable[[str], None]) -> None:
    """Copies src to dest only if dest doesn't already exist - the new
    location always wins, this only fills in genuinely missing pieces."""
    if dest.exists():
        on_line(f"Skipping {dest.name} (already exists at the new location)")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    on_line(f"Copied {src} -> {dest}")


def _prepend_log(src: Path, dest: Path, on_line: Callable[[str], None]) -> None:
    """For append-only logs (actions.log, the backup manifest): old
    content logically precedes whatever's been written since the rename,
    so it's merged in front rather than skipped or overwritten. Safe to
    run twice - if the old content is already present, it's a no-op."""
    old_text = src.read_text(encoding="utf-8")
    if not old_text.strip():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    existing_text = dest.read_text(encoding="utf-8") if dest.exists() else ""
    if old_text.rstrip("\n") in existing_text:
        on_line(f"{dest.name} already contains this history - skipping")
        return
    combined = old_text.rstrip("\n") + "\n" + existing_text
    dest.write_text(combined, encoding="utf-8")
    on_line(f"Merged {src.name} into {dest}")


def migrate_user_data(on_line: Callable[[str], None]) -> CommandResult:
    """
    Copies/merges the previous ArchYaST install's user-level data
    (activity log, config backups, SELinux review artifacts) into
    Atropa's paths. Nothing here needs root - it's all under $HOME.
    """
    if not OLD_USER_DATA_DIR.is_dir():
        on_line("No previous ArchYaST user data found - nothing to migrate.")
        return CommandResult(0, "nothing to migrate", "")

    old_log = OLD_USER_DATA_DIR / "actions.log"
    if old_log.is_file():
        _prepend_log(old_log, privilege.LOG_PATH, on_line)

    old_backups_dir = OLD_USER_DATA_DIR / "backups"
    if old_backups_dir.is_dir():
        privilege.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        for item in sorted(old_backups_dir.iterdir()):
            if item.is_file() and item.name != "manifest.jsonl":
                _copy_if_missing(item, privilege.BACKUP_DIR / item.name, on_line)
        old_manifest = old_backups_dir / "manifest.jsonl"
        if old_manifest.is_file():
            _prepend_log(old_manifest, privilege.BACKUP_MANIFEST, on_line)

    old_review_dir = OLD_USER_DATA_DIR / "selinux-review"
    if old_review_dir.is_dir():
        for subdir_name, new_subdir in (
            ("modules", selinux_mod.REVIEW_MODULES_DIR),
            ("approved", selinux_mod.APPROVED_MODULES_DIR),
        ):
            old_subdir = old_review_dir / subdir_name
            if not old_subdir.is_dir():
                continue
            new_subdir.mkdir(parents=True, exist_ok=True)
            for item in sorted(old_subdir.iterdir()):
                if item.is_file():
                    _copy_if_missing(item, new_subdir / item.name, on_line)

        old_setup_mode = old_review_dir / "setup_mode_state.json"
        if old_setup_mode.is_file():
            _copy_if_missing(old_setup_mode, selinux_mod.SETUP_MODE_STATE_FILE, on_line)

        old_last_review = old_review_dir / "last_review.json"
        if old_last_review.is_file():
            _copy_if_missing(old_last_review, selinux_mod.LAST_REVIEW_FILE, on_line)

    on_line("User data migration complete.")
    return CommandResult(0, "migrated", "")


def migrate_plugin_data(on_line: Callable[[str], None]) -> CommandResult:
    """
    Copies the previous ArchYaST install's plugin manifests and
    enabled-state into Atropa's /etc location. Requires root - the same
    authentication barrier as any other write under /etc/atropa,
    including enabling a plugin. Uses `cp -n` (no-clobber) so anything
    already at the new location wins; nothing existing gets overwritten.
    """
    if not OLD_PLUGINS_DIR.is_dir():
        on_line("No previous ArchYaST plugin directory found - nothing to migrate.")
        return CommandResult(0, "nothing to migrate", "")

    result = run_privileged(["mkdir", "-p", str(plugins_mod.PLUGINS_DIR)])
    if not result.ok:
        on_line(f"Failed to create {plugins_mod.PLUGINS_DIR}: {result.stderr.strip()}")
        return result

    old_plugins_subdir = OLD_PLUGINS_DIR / "plugins"
    if old_plugins_subdir.is_dir():
        on_line(f"Copying plugin manifests from {old_plugins_subdir} to {plugins_mod.PLUGINS_DIR}...")
        result = run_privileged(["cp", "-rn", f"{old_plugins_subdir}/.", str(plugins_mod.PLUGINS_DIR)])
        on_line("Copied plugin manifests." if result.ok else f"Failed: {result.stderr.strip()}")
        if not result.ok:
            return result

    old_state_file = OLD_PLUGINS_DIR / "plugins-enabled.json"
    if old_state_file.is_file():
        if plugins_mod.ENABLED_STATE_FILE.exists():
            on_line("Enabled-state file already exists at the new location - skipping (existing state wins).")
        else:
            result = run_privileged(["cp", "-n", str(old_state_file), str(plugins_mod.ENABLED_STATE_FILE)])
            on_line("Copied plugin enabled-state." if result.ok else f"Failed: {result.stderr.strip()}")
            if not result.ok:
                return result

    on_line("Plugin data migration complete.")
    return CommandResult(0, "migrated", "")


def remove_legacy_user_data() -> CommandResult:
    """Deletes the old ~/.local/share/archyast directory entirely. Only
    call this after confirming migration succeeded - there's no undo."""
    if not OLD_USER_DATA_DIR.is_dir():
        return CommandResult(0, "nothing to remove", "")
    shutil.rmtree(OLD_USER_DATA_DIR)
    return CommandResult(0, f"removed {OLD_USER_DATA_DIR}", "")


def remove_legacy_plugin_data() -> CommandResult:
    """Deletes the old /etc/archyast directory entirely (requires root).
    Only call this after confirming migration succeeded - there's no undo."""
    if not OLD_PLUGINS_DIR.is_dir():
        return CommandResult(0, "nothing to remove", "")
    return run_privileged(["rm", "-rf", str(OLD_PLUGINS_DIR)])
