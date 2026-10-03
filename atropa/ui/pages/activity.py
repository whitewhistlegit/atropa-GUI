"""atropa.ui.pages.activity - Activity log and config backups, with one-click restore."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import migration, privilege
from atropa.ui.pages import BasePage, esc


class ActivityPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self.migration_group = self.add_group(
            "Migrate from ArchYaST",
            "Found data from a previous ArchYaST install. Migrating copies it into Atropa's "
            "paths - nothing already here gets overwritten, and the old data is left in place "
            "until you explicitly remove it.",
        )
        self.migration_group.set_visible(False)
        self._migration_rows: list = []

        backups_group = self.add_group(
            "Config Backups",
            "Every risky edit (SSH config, bootloader, sysctl, faillock, SELinux config, ...) "
            "is backed up here first. Restore puts the old file back immediately.",
        )
        self.backups_group = backups_group

        actions_group = self.add_group(
            "Recent Activity", "Every privileged command Atropa has run, most recent first"
        )
        self.actions_group = actions_group

        self.refresh()

    def refresh(self) -> None:
        self.run_async(migration.detect_legacy_data, self._on_legacy_status_loaded)

        self.clear_rows(self.backups_group, getattr(self, "_backup_rows", []))
        self._backup_rows = [self.start_loading(self.backups_group, "Loading backups…")]
        self.run_async(privilege.list_backups, self._on_backups_loaded)
        self.clear_rows(self.actions_group, getattr(self, "_action_rows", []))
        self._action_rows = [self.start_loading(self.actions_group, "Loading activity log…")]
        self.run_async(privilege.get_recent_actions, self._on_actions_loaded)

    # --------------------------------------------------------- migration --

    def _on_legacy_status_loaded(self, status, error) -> bool:
        self.clear_rows(self.migration_group, self._migration_rows)
        self._migration_rows = []

        if error or status is None or not status.anything_found:
            self.migration_group.set_visible(False)
            return False

        self.migration_group.set_visible(True)

        if status.old_user_data_found:
            details = []
            if status.old_actions_log:
                details.append("activity log")
            if status.old_backup_count:
                details.append(f"{status.old_backup_count} backup(s)")
            if status.old_selinux_review_found:
                details.append("SELinux review history")
            row = Adw.ActionRow(
                title="User data (~/.local/share/archyast)",
                subtitle=esc(", ".join(details) or "found"),
            )
            migrate_btn = Gtk.Button(label="Migrate", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
            migrate_btn.connect("clicked", self._on_migrate_user_data_clicked)
            row.add_suffix(migrate_btn)
            remove_btn = Gtk.Button(label="Remove Old", valign=Gtk.Align.CENTER)
            remove_btn.connect("clicked", self._on_remove_legacy_user_data_clicked)
            row.add_suffix(remove_btn)
            self.migration_group.add(row)
            self._migration_rows.append(row)

        if status.old_plugins_dir_found:
            row = Adw.ActionRow(
                title="Plugin data (/etc/archyast)",
                subtitle=esc(f"{status.old_plugin_count} plugin(s) found - requires admin authentication"),
            )
            migrate_btn = Gtk.Button(label="Migrate", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
            migrate_btn.connect("clicked", self._on_migrate_plugin_data_clicked)
            row.add_suffix(migrate_btn)
            remove_btn = Gtk.Button(label="Remove Old", valign=Gtk.Align.CENTER)
            remove_btn.connect("clicked", self._on_remove_legacy_plugin_data_clicked)
            row.add_suffix(remove_btn)
            self.migration_group.add(row)
            self._migration_rows.append(row)

        return False

    def _on_migrate_user_data_clicked(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Migrate ArchYaST user data?",
            "Copies the old activity log, config backups, and SELinux review history into "
            "Atropa's paths. Anything already here is left untouched - only missing pieces "
            "are copied in. The old data isn't deleted by this step.",
            "Migrate",
            lambda: self.run_streaming_operation(
                "Migrating User Data", migration.migrate_user_data, self._on_migration_done
            ),
        )

    def _on_migrate_plugin_data_clicked(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Migrate ArchYaST plugin data?",
            "Copies plugin manifests and enabled-state from /etc/archyast into /etc/atropa. "
            "Requires administrator authentication, same as enabling a plugin normally. "
            "Anything already at the new location is left untouched.",
            "Migrate",
            lambda: self.run_streaming_operation(
                "Migrating Plugin Data", migration.migrate_plugin_data, self._on_migration_done
            ),
        )

    def _on_migration_done(self, result, error) -> bool:
        if error:
            self.notify(f"Migration failed: {error}", is_error=True)
        elif result is not None and not result.ok:
            self.notify(f"Migration failed: {result.stderr.strip()[:150]}", is_error=True)
        else:
            self.notify("Migration complete")
        self.refresh()
        return False

    def _on_remove_legacy_user_data_clicked(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Remove old ArchYaST user data?",
            "Permanently deletes ~/.local/share/archyast. Only do this after confirming the "
            "migration above worked - there's no undo.",
            "Remove",
            lambda: self.run_async(migration.remove_legacy_user_data, self.handle_command_result),
        )

    def _on_remove_legacy_plugin_data_clicked(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Remove old ArchYaST plugin data?",
            "Permanently deletes /etc/archyast (requires administrator authentication). Only "
            "do this after confirming the migration above worked - there's no undo.",
            "Remove",
            lambda: self.run_async(migration.remove_legacy_plugin_data, self.handle_command_result),
        )

    # --------------------------------------------------------- backups/activity --

    def _on_backups_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_backup_rows", [])):
            self.backups_group.remove(row)
        self._backup_rows = []

        if error:
            self.notify(f"Couldn't list backups: {error}", is_error=True)
            return False

        if not result:
            row = Adw.ActionRow(title="No backups yet")
            self.backups_group.add(row)
            self._backup_rows.append(row)
            return False

        for entry in result[:100]:
            subtitle = f"{entry['original_path']} · {self._format_timestamp(entry['timestamp'])}"
            row = Adw.ActionRow(title=esc(entry["backup_file"]), subtitle=esc(subtitle))

            view_btn = Gtk.Button(label="View", valign=Gtk.Align.CENTER, css_classes=["flat"])
            view_btn.connect("clicked", self._on_view_backup, entry)
            row.add_suffix(view_btn)

            restore_btn = Gtk.Button(label="Restore", valign=Gtk.Align.CENTER)
            restore_btn.connect("clicked", self._on_restore_backup, entry)
            row.add_suffix(restore_btn)

            self.backups_group.add(row)
            self._backup_rows.append(row)
        return False

    @staticmethod
    def _format_timestamp(raw: str) -> str:
        # raw looks like "20260725_182005_014555"
        try:
            date_part, time_part, _ = raw.split("_")
            return f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:]} {time_part[:2]}:{time_part[2:4]}:{time_part[4:]}"
        except ValueError:
            return raw

    def _on_view_backup(self, _btn: Gtk.Button, entry: dict) -> None:
        try:
            content = (privilege.BACKUP_DIR / entry["backup_file"]).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self.notify(f"Couldn't read backup: {exc}", is_error=True)
            return

        buffer = Gtk.TextBuffer()
        buffer.set_text(content)
        text_view = Gtk.TextView(buffer=buffer, editable=False, monospace=True)
        text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        scroller = Gtk.ScrolledWindow(min_content_height=320, min_content_width=480)
        scroller.set_child(text_view)

        dialog = Adw.AlertDialog(heading=f"{entry['original_path']} @ {self._format_timestamp(entry['timestamp'])}")
        dialog.set_extra_child(scroller)
        dialog.add_response("close", "Close")
        dialog.present(self.get_root())

    def _on_restore_backup(self, _btn: Gtk.Button, entry: dict) -> None:
        self.confirm(
            f"Restore {entry['original_path']}?",
            f"This overwrites the current file with the backup from "
            f"{self._format_timestamp(entry['timestamp'])}. Depending on what this file "
            "controls, you may need to reload the relevant service afterward "
            "(e.g. sshd, fail2ban) for the restored config to take effect.",
            "Restore",
            lambda: self.run_async(
                lambda: privilege.restore_file(entry["backup_file"], entry["original_path"]),
                lambda result, error: self.handle_command_result(result, error, success_message="Restored"),
            ),
        )

    def _on_actions_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_action_rows", [])):
            self.actions_group.remove(row)
        self._action_rows = []

        if error:
            self.notify(f"Couldn't read activity log: {error}", is_error=True)
            return False

        if not result:
            row = Adw.ActionRow(title="No activity logged yet")
            self.actions_group.add(row)
            self._action_rows.append(row)
            return False

        for line in result[:150]:
            row = Adw.ActionRow(title=esc(line))
            self.actions_group.add(row)
            self._action_rows.append(row)
        return False
