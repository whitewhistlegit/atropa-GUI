"""atropa.ui.pages.users - Users & Groups module."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import users
from atropa.ui.pages import BasePage, esc


class UsersPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        new_group = self.add_group(
            "Add User",
            "A new account has no password, so nobody can log in to it until you set one in the list below.",
        )
        self.username_row = Adw.EntryRow(title="Username")
        new_group.add(self.username_row)
        self.fullname_row = Adw.EntryRow(title="Full name (optional)")
        new_group.add(self.fullname_row)
        self.groups_row = Adw.EntryRow(title="Extra groups, comma separated (e.g. wheel,audio)")
        new_group.add(self.groups_row)

        create_btn = Gtk.Button(label="Create user", css_classes=["suggested-action"])
        create_btn.set_margin_top(8)
        create_btn.connect("clicked", self._on_create_clicked)
        new_group.add(create_btn)

        self.users_group = self.add_group("Existing Users")
        self.groups_group = self.add_group("Groups")
        self.new_group_row = Adw.EntryRow(title="New group name")
        create_group_btn = Gtk.Button(label="Create", valign=Gtk.Align.CENTER, css_classes=["flat"])
        create_group_btn.connect("clicked", self._on_create_group_clicked)
        self.new_group_row.add_suffix(create_group_btn)
        self.groups_group.add(self.new_group_row)

        self.refresh()

    def refresh(self) -> None:
        self.clear_rows(self.users_group, getattr(self, "_user_rows", []))
        self._user_rows = [self.start_loading(self.users_group, "Loading users…")]
        self.run_async(lambda: users.list_users(include_system=False), self._on_users_loaded)
        self.clear_rows(self.groups_group, getattr(self, "_group_rows", []))
        self._group_rows = [self.start_loading(self.groups_group, "Loading groups…")]
        self.run_async(lambda: users.list_groups(include_system=False), self._on_groups_loaded)

    def _on_users_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_user_rows", [])):
            self.users_group.remove(row)
        self._user_rows = []

        if error:
            self.notify(f"Failed to list users: {error}", is_error=True)
            return False

        for user in result:
            row = Adw.ActionRow(
                title=esc(f"{user.username} (uid {user.uid})"),
                subtitle=esc(f"{user.full_name or 'no full name set'} · groups: {', '.join(user.groups) or 'none'}"),
            )
            password_btn = Gtk.Button(
                icon_name="dialog-password-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"]
            )
            password_btn.set_tooltip_text("Set password")
            password_btn.connect("clicked", self._on_password_clicked, user.username)
            row.add_suffix(password_btn)

            groups_btn = Gtk.Button(icon_name="system-users-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"])
            groups_btn.set_tooltip_text("Change groups")
            groups_btn.connect("clicked", self._on_groups_clicked, user.username)
            row.add_suffix(groups_btn)

            # Lock state lives in /etc/shadow, which needs root to read, so
            # both buttons are always offered rather than showing a guess.
            lock_btn = Gtk.Button(icon_name="changes-prevent-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"])
            refusal = users.lock_refusal(user.username)
            lock_btn.set_tooltip_text(refusal or "Lock password (blocks password logins)")
            lock_btn.set_sensitive(refusal is None)
            lock_btn.connect("clicked", self._on_lock_clicked, user.username)
            row.add_suffix(lock_btn)

            unlock_btn = Gtk.Button(icon_name="changes-allow-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"])
            unlock_btn.set_tooltip_text("Unlock password")
            unlock_btn.connect("clicked", self._on_unlock_clicked, user.username)
            row.add_suffix(unlock_btn)

            del_btn = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"])
            refusal = users.delete_refusal(user.username)
            del_btn.set_tooltip_text(refusal or "Delete user")
            del_btn.set_sensitive(refusal is None)
            del_btn.connect("clicked", self._on_delete_clicked, user.username)
            row.add_suffix(del_btn)

            self.users_group.add(row)
            self._user_rows.append(row)
        return False

    def _on_groups_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_group_rows", [])):
            self.groups_group.remove(row)
        self._group_rows = []

        if error:
            self.notify(f"Failed to list groups: {error}", is_error=True)
            return False

        for group in result:
            row = Adw.ActionRow(
                title=esc(f"{group.name} (gid {group.gid})"),
                subtitle=esc(f"members: {', '.join(group.members) or 'none'}"),
            )
            del_btn = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"])
            refusal = users.group_delete_refusal(group.name)
            del_btn.set_tooltip_text(refusal or "Delete group")
            del_btn.set_sensitive(refusal is None)
            del_btn.connect("clicked", self._on_delete_group_clicked, group.name, list(group.members))
            row.add_suffix(del_btn)
            self.groups_group.add(row)
            self._group_rows.append(row)
        return False

    def _on_create_clicked(self, _btn: Gtk.Button) -> None:
        username = self.username_row.get_text().strip()
        full_name = self.fullname_row.get_text().strip()
        extra_groups = [g.strip() for g in self.groups_row.get_text().split(",") if g.strip()]

        if not username:
            self.notify("Username is required")
            return

        self.run_action(
            lambda: users.create_user(username, full_name=full_name, extra_groups=extra_groups),
            self.handle_command_result,
        )

    def _on_password_clicked(self, _btn: Gtk.Button, username: str) -> None:
        dialog = Adw.AlertDialog(
            heading=f"Set a password for {username}",
            body="This replaces the current password. If the password was locked, setting one unlocks it.",
        )
        dialog.set_heading_use_markup(False)
        dialog.set_body_use_markup(False)
        new_entry = Gtk.PasswordEntry(placeholder_text="New password", show_peek_icon=True, activates_default=True)
        repeat_entry = Gtk.PasswordEntry(placeholder_text="Repeat it", show_peek_icon=True, activates_default=True)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.append(new_entry)
        box.append(repeat_entry)
        dialog.set_extra_child(box)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("set", "Set password")
        dialog.set_response_appearance("set", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("set")
        dialog.set_close_response("cancel")
        # Only offered once both boxes hold the same thing: a typo here locks
        # the account's owner out just as well as a wrong password does.
        dialog.set_response_enabled("set", False)

        def on_changed(_entry: Gtk.PasswordEntry) -> None:
            password = new_entry.get_text()
            dialog.set_response_enabled("set", bool(password) and password == repeat_entry.get_text())

        new_entry.connect("changed", on_changed)
        repeat_entry.connect("changed", on_changed)

        def on_response(_dlg: Adw.AlertDialog, response: str) -> None:
            if response == "set":
                password = new_entry.get_text()
                self.run_action(
                    lambda: users.set_password(username, password),
                    lambda result, error: self.handle_command_result(
                        result, error, f"Password set for {username}", refresh=False
                    ),
                )

        dialog.connect("response", on_response)
        dialog.present(self.get_root())

    def _on_groups_clicked(self, _btn: Gtk.Button, username: str) -> None:
        current = users.supplementary_groups(username)
        dialog = Adw.AlertDialog(
            heading=f"Groups of {username}",
            body="Comma separated. The account ends up in exactly these groups, next to its own primary group.",
        )
        dialog.set_heading_use_markup(False)
        dialog.set_body_use_markup(False)
        entry = Gtk.Entry(text=", ".join(current), activates_default=True)
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("apply", "Change groups")
        dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("apply")
        dialog.set_close_response("cancel")

        def on_response(_dlg: Adw.AlertDialog, response: str) -> None:
            if response != "apply":
                return
            groups = sorted({name.strip() for name in entry.get_text().split(",") if name.strip()})
            if groups == current:
                self.notify("Nothing to change")
                return

            def apply() -> None:
                self.run_action(
                    lambda: users.set_groups(username, groups),
                    lambda result, error: self.handle_command_result(result, error, f"Groups of {username} changed"),
                )

            warning = users.groups_warning(username, groups)
            if warning:
                self.confirm(f"Take {username} out of {users.ADMIN_GROUP}?", warning, "Change groups", apply)
            else:
                apply()

        dialog.connect("response", on_response)
        dialog.present(self.get_root())

    def _on_create_group_clicked(self, _btn: Gtk.Button) -> None:
        name = self.new_group_row.get_text().strip()
        if not name:
            self.notify("Group name is required")
            return

        def on_done(result, error) -> bool:
            if error is None and getattr(result, "ok", False):
                self.new_group_row.set_text("")
            return self.handle_command_result(result, error, f"Created group {name}")

        self.run_action(lambda: users.create_group(name), on_done)

    def _on_delete_group_clicked(self, _btn: Gtk.Button, name: str, members: list[str]) -> None:
        refusal = users.group_delete_refusal(name)
        if refusal:
            self.notify(refusal, is_error=True)
            return
        body = "Files that belong to this group keep its number, with no group name to go with it."
        if members:
            body = f"{', '.join(members)} will no longer be in it. {body}"
        self.confirm(
            f"Delete the group {name}?",
            body,
            "Delete",
            lambda: self.run_action(lambda: users.delete_group(name), self.handle_command_result),
        )

    def _on_lock_clicked(self, _btn: Gtk.Button, username: str) -> None:
        refusal = users.lock_refusal(username)
        if refusal:
            self.notify(refusal, is_error=True)
            return
        body = (
            f"{username} won't be able to log in or authenticate with their password until it's "
            "unlocked again. SSH key logins still work - Arch's default sshd setup (UsePAM) doesn't "
            "check the lock."
        )
        warning = users.lock_warning(username)
        if warning:
            body += f"\n\n{warning}"
        self.confirm(
            f"Lock the password of {username}?",
            body,
            "Lock",
            lambda: self.run_action(lambda: users.modify_user(username, lock=True), self.handle_command_result),
        )

    def _on_unlock_clicked(self, _btn: Gtk.Button, username: str) -> None:
        self.run_action(
            lambda: users.modify_user(username, lock=False),
            lambda result, error: self.handle_command_result(result, error, f"Unlocked {username}"),
        )

    def _on_delete_clicked(self, _btn: Gtk.Button, username: str) -> None:
        refusal = users.delete_refusal(username)
        if refusal:
            self.notify(refusal, is_error=True)
            return
        dialog = Adw.AlertDialog(
            heading=f"Delete user {username}?",
            body="This removes the account. Its home folder is kept unless you delete that too.",
        )
        dialog.set_heading_use_markup(False)
        dialog.set_body_use_markup(False)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete")
        dialog.add_response("delete-home", "Delete with home folder")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_response_appearance("delete-home", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def on_response(_dlg: Adw.AlertDialog, response: str) -> None:
            if response in ("delete", "delete-home"):
                remove_home = response == "delete-home"
                self.run_action(
                    lambda: users.delete_user(username, remove_home=remove_home), self.handle_command_result
                )

        dialog.connect("response", on_response)
        dialog.present(self.get_root())
