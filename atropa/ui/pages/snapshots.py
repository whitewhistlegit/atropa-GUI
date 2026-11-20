"""atropa.ui.pages.snapshots - Btrfs snapshots with snapper: setup, list, compare, restore files."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import snapshots
from atropa.ui.pages import BasePage, esc

_MAX_SNAPSHOT_ROWS = 60
_MAX_CHANGE_ROWS = 300
_LAYOUT_TITLES = {
    "top-level": "Btrfs, / on the top-level subvolume",
    "subvolume": "Btrfs, / on its own subvolume",
    "default-subvolume": "Btrfs, / on the default subvolume",
    "not-btrfs": "Not Btrfs",
}


class SnapshotsPage(BasePage):
    def __init__(self) -> None:
        super().__init__()
        self.system_group = self.add_group(
            "This system",
            "snap-pac takes a snapshot before and after every pacman transaction - including Atropa's own "
            "upgrades - so there is always a state to compare with and restore files from.",
        )
        self.rollback_group = self.add_group("Rolling back the whole system")
        self.create_group = self.add_group("Take a snapshot")
        self.list_group = self.add_group("Snapshots")

        self.description_row = Adw.EntryRow(title="Description (e.g. before trying a new kernel)")
        self.create_group.add(self.description_row)
        create_row = Adw.ActionRow(title="Snapshot / now", subtitle="Kept until snapper's number cleanup removes it")
        self.create_btn = Gtk.Button(label="Create", valign=Gtk.Align.CENTER)
        self.create_btn.connect("clicked", self._on_create)
        create_row.add_suffix(self.create_btn)
        self.create_group.add(create_row)

        self._system_rows: list = []
        self._list_rows: list = []
        self.refresh()

    # -- loading ---------------------------------------------------------------

    def refresh(self) -> None:
        self.clear_rows(self.system_group, self._system_rows)
        self._system_rows = [self.start_loading(self.system_group, "Looking at the filesystem…")]
        self.clear_rows(self.list_group, self._list_rows)
        self._list_rows = []
        self.run_async(lambda: (snapshots.layout(), snapshots.snapper_status()), self._on_status)

    def _on_status(self, result, error) -> bool:
        self.clear_rows(self.system_group, self._system_rows)
        self._system_rows = []
        if error:
            self._add_system_row(Adw.ActionRow(title="Couldn't check the filesystem", subtitle=esc(error)))
            return False
        layout, status = result
        subvol = f" (subvolume {layout.subvol})" if layout.subvol not in {"", "/"} else ""
        self._add_system_row(
            Adw.ActionRow(title=_LAYOUT_TITLES.get(layout.kind, layout.kind), subtitle=esc(f"{layout.device}{subvol}"))
        )
        self.rollback_group.set_description(layout.rollback)

        ready = layout.btrfs and status.snapper and status.snap_pac and status.configured
        self.create_btn.set_sensitive(ready)
        if not layout.btrfs:
            return False

        snapper_row = Adw.ActionRow(title="snapper and snap-pac")
        if ready:
            snapper_row.set_subtitle(
                "Set up - snapshots before and after every pacman transaction"
                + ("" if status.cleanup_timer else "; snapper-cleanup.timer is off, old snapshots pile up")
            )
        else:
            missing = [name for name, ok in (("snapper", status.snapper), ("snap-pac", status.snap_pac),
                                             ("the root config", status.configured)) if not ok]
            snapper_row.set_subtitle(esc("Not set up yet - missing " + ", ".join(missing)))
            button = Gtk.Button(label="Set up", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
            button.connect("clicked", lambda _b: self._on_setup())
            snapper_row.add_suffix(button)
        self._add_system_row(snapper_row)

        if status.grub:
            grub_row = Adw.ActionRow(title="Snapshots in the GRUB menu")
            if status.grub_btrfs:
                grub_row.set_subtitle("grub-btrfs is installed: pick a snapshot under the boot menu's snapshot entry")
            else:
                grub_row.set_subtitle("grub-btrfs adds a submenu to boot any snapshot read-only")
                button = Gtk.Button(label="Install", valign=Gtk.Align.CENTER)
                button.connect("clicked", lambda _b: self._on_install_grub_btrfs())
                grub_row.add_suffix(button)
            self._add_system_row(grub_row)

        if ready:
            self._list_rows = [self.start_loading(self.list_group, "Listing snapshots…")]
            self.run_async(snapshots.snapshots, self._on_list)
        return False

    def _add_system_row(self, row) -> None:
        self.system_group.add(row)
        self._system_rows.append(row)

    def _on_list(self, result, error) -> bool:
        self.clear_rows(self.list_group, self._list_rows)
        self._list_rows = []
        if error:
            self._add_list_row(Adw.ActionRow(title="Couldn't list snapshots", subtitle=esc(error)))
            return False
        if not result:
            self._add_list_row(Adw.ActionRow(title="No snapshots yet", subtitle="The next pacman run makes the first pair"))
            return False
        for snapshot in result[:_MAX_SNAPSHOT_ROWS]:
            self._add_snapshot_row(snapshot)
        return False

    def _add_list_row(self, row) -> None:
        self.list_group.add(row)
        self._list_rows.append(row)

    def _add_snapshot_row(self, snapshot: snapshots.Snapshot) -> None:
        label = {"pre": "before", "post": "after"}.get(snapshot.type, "")
        description = snapshot.description or "snapshot"
        if description.startswith("/"):  # snap-pac stores Atropa's helper-run command by its path
            head, _sep, rest = description.partition(" ")
            description = f"{head.rsplit('/', 1)[-1]} {rest}".strip()
        title = f"#{snapshot.number} · " + (f"{label}: " if label else "") + description
        row = Adw.ActionRow(title=esc(title), subtitle=esc(snapshot.date))

        changes_btn = Gtk.Button(label="Changes", valign=Gtk.Align.CENTER)
        changes_btn.set_tooltip_text("Files that differ between this snapshot and now; restore any of them")
        changes_btn.connect("clicked", lambda _b: self._on_changes(snapshot))
        row.add_suffix(changes_btn)

        delete_btn = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"])
        delete_btn.set_tooltip_text("Delete this snapshot")
        delete_btn.connect("clicked", lambda _b: self._on_delete(snapshot))
        row.add_suffix(delete_btn)
        self._add_list_row(row)

    # -- actions ---------------------------------------------------------------

    def _on_setup(self) -> None:
        self.confirm(
            "Set up snapshots?",
            "Installs snapper and snap-pac, creates snapper's config for /, and turns on the cleanup timer. "
            "From then on every pacman transaction makes a snapshot before and after. Snapshots share "
            "unchanged data, but they do hold on to replaced files until cleanup removes them.",
            "Set up",
            lambda: self.run_streaming_operation("Setting up snapshots", snapshots.setup, self._after),
        )

    def _on_install_grub_btrfs(self) -> None:
        self.confirm(
            "Add snapshots to the GRUB menu?",
            "Installs grub-btrfs and inotify-tools, enables grub-btrfsd (which keeps the menu up to date), and "
            "regenerates grub.cfg. Booted snapshots are read-only.",
            "Install",
            lambda: self.run_streaming_operation("Installing grub-btrfs", snapshots.install_grub_btrfs, self._after),
        )

    def _on_create(self, _btn) -> None:
        description = self.description_row.get_text()
        self.run_action(lambda: snapshots.create(description), self._after_create)

    def _after_create(self, result, error) -> None:
        self.description_row.set_text("")
        self.handle_command_result(result, error, "Snapshot created")

    def _on_delete(self, snapshot: snapshots.Snapshot) -> None:
        self.confirm(
            f"Delete snapshot #{snapshot.number}?",
            f"\"{snapshot.description or 'snapshot'}\" ({snapshot.date}) is removed for good, and with it this way "
            "back. Asks for your password.",
            "Delete",
            lambda: self.run_action(lambda: snapshots.delete(snapshot.number), self._after),
        )

    def _after(self, result, error) -> None:
        self.handle_command_result(result, error)

    def _on_changes(self, snapshot: snapshots.Snapshot) -> None:
        self.notify(f"Comparing snapshot #{snapshot.number} with now…")
        self.run_async(
            lambda: snapshots.changes(snapshot.number),
            lambda files, error: self._present_changes(snapshot, files, error),
        )

    def _present_changes(self, snapshot: snapshots.Snapshot, files, error) -> bool:
        if error:
            self.notify(f"Couldn't compare: {error}", is_error=True)
            return False

        listing = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        if not files:
            listing.append(Adw.ActionRow(title="No differences - this snapshot matches the live system"))
        for change in files[:_MAX_CHANGE_ROWS]:
            row = Adw.ActionRow(title=esc(change.path), subtitle=esc(change.kind))
            row.set_title_lines(2)
            button = Gtk.Button(label="Restore", valign=Gtk.Align.CENTER)
            button.connect("clicked", lambda _b, path=change.path: self._on_restore(snapshot, path))
            row.add_suffix(button)
            listing.append(row)
        if len(files) > _MAX_CHANGE_ROWS:
            listing.append(Adw.ActionRow(title=esc(f"… and {len(files) - _MAX_CHANGE_ROWS} more")))

        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_child(listing)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=12,
                      margin_start=12, margin_end=12)
        summary = Gtk.Label(
            label=esc(f"Snapshot #{snapshot.number} ({snapshot.date}) vs now: {len(files)} file(s) differ"),
            xalign=0,
        )
        summary.add_css_class("dim-label")
        box.append(summary)
        box.append(scroller)

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        toolbar.set_content(box)
        dialog = Adw.Dialog()
        dialog.set_title(f"Changes since snapshot #{snapshot.number}")
        dialog.set_content_width(720)
        dialog.set_content_height(520)
        dialog.set_child(toolbar)
        dialog.present(self.get_root())
        return False

    def _on_restore(self, snapshot: snapshots.Snapshot, path: str) -> None:
        self.confirm(
            "Restore this file?",
            f"{path} goes back to how it was in snapshot #{snapshot.number} ({snapshot.date}). A file created "
            "since is removed. Asks for your password.",
            "Restore",
            lambda: self.run_action(
                lambda: snapshots.restore(snapshot.number, [path]),
                lambda result, error: self.handle_command_result(result, error, "Restored", refresh=False),
            ),
        )
