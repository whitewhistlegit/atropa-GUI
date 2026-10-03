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

        new_group = self.add_group("Add User")
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
            lock_btn = Gtk.Button(icon_name="changes-prevent-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"])
            lock_btn.set_tooltip_text("Lock account")
            lock_btn.connect("clicked", self._on_lock_clicked, user.username)
            row.add_suffix(lock_btn)

            del_btn = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"])
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

        self.run_async(
            lambda: users.create_user(username, full_name=full_name, extra_groups=extra_groups),
            self.handle_command_result,
        )

    def _on_lock_clicked(self, _btn: Gtk.Button, username: str) -> None:
        self.run_async(lambda: users.modify_user(username, lock=True), self.handle_command_result)

    def _on_delete_clicked(self, _btn: Gtk.Button, username: str) -> None:
        self.confirm(
            f"Delete user {username}?",
            "This removes the account. Home directory is kept unless you choose to remove it too.",
            "Delete",
            lambda: self.run_async(lambda: users.delete_user(username, remove_home=False), self.handle_command_result),
        )
