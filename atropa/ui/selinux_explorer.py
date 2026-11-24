"""
atropa.ui.selinux_explorer - pick paths a program will need that no test
run touched (ported from atropa-scratch's explorer).

Recognition over recall: browse, see each entry's current label and whether
the program's package owns it, and tick what the program will need. The
SELinux: Dev page turns each pick into a read rule on its real label.
"""

from __future__ import annotations

import os
from typing import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gtk, Pango  # noqa: E402

from atropa.backend import policy_draft, policy_fc

MAX_ENTRIES = 600


def places(package_files: list[str]) -> list[tuple[str, str]]:
    """(label, path) for the sidebar: the package's own top directories first, then common ones."""
    out, seen = [], set()
    for p in package_files:
        d = p.rstrip("/")
        if p.endswith("/") and d not in policy_fc.SHARED_DIRS and os.path.dirname(d) in policy_fc.SHARED_DIRS \
                and d not in seen and os.path.isdir(d):
            seen.add(d)
            out.append((f"{d} (package)", d))
    home = os.path.expanduser("~")
    for d in ("/etc", "/var/lib", "/var/log", "/var/cache", "/run", "/usr/share", "/usr/lib", "/tmp", home, "/"):
        if d not in seen and os.path.isdir(d):
            out.append(("~ (home)" if d == home else d, d))
    return out


class PathExplorer(Adw.Dialog):
    def __init__(self, package_files: list[str], on_done: Callable[[list[str]], None]) -> None:
        super().__init__(title="Add paths the program will need", content_width=760, content_height=600)
        self.on_done = on_done
        self.picked: list[str] = []
        self.pkg_files = {p.rstrip("/") for p in package_files}
        self.cwd: str | None = None

        self.list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.list.connect("row-activated", self._on_activate)
        keys = Gtk.EventControllerKey()
        keys.connect("key-pressed", self._on_key)
        self.list.add_controller(keys)

        self.places = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE, css_classes=["navigation-sidebar"])
        self.places.connect("row-activated", lambda _l, row: self.go(row.path))
        place_list = places(package_files)
        for label, path in place_list:
            row = Gtk.ListBoxRow()
            row.path = path
            row.set_child(Gtk.Label(label=label, xalign=0, ellipsize=Pango.EllipsizeMode.END, tooltip_text=path))
            self.places.append(row)

        self.path_label = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.START, hexpand=True,
                                    css_classes=["monospace"])
        up = Gtk.Button(icon_name="go-up-symbolic", tooltip_text="Parent folder (Backspace)", css_classes=["flat"])
        up.connect("clicked", lambda _b: self.up())
        top = Gtk.Box(spacing=8, margin_start=12, margin_end=12, margin_top=6, margin_bottom=6)
        top.append(up)
        top.append(self.path_label)

        self.count_label = Gtk.Label(label="Nothing picked", css_classes=["dim-label"])
        self.add_btn = Gtk.Button(label="Add rules", sensitive=False, css_classes=["suggested-action", "pill"])
        self.add_btn.connect("clicked", lambda _b: self.finish())
        hint = Gtk.Label(label="Enter opens a folder or picks a file · Space picks", xalign=0,
                         css_classes=["dim-label"])
        bottom = Gtk.Box(spacing=12, margin_start=12, margin_end=12, margin_top=8, margin_bottom=8)
        bottom.append(hint)
        bottom.append(Gtk.Box(hexpand=True))
        bottom.append(self.count_label)
        bottom.append(self.add_btn)

        body = Gtk.Box()
        body.append(Gtk.ScrolledWindow(child=self.places, hscrollbar_policy=Gtk.PolicyType.NEVER, width_request=180))
        body.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))
        body.append(Gtk.ScrolledWindow(child=self.list, hexpand=True, vexpand=True))

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        for widget in (top, Gtk.Separator(), body, Gtk.Separator(), bottom):
            box.append(widget)
        view = Adw.ToolbarView(content=box)
        view.add_top_bar(Adw.HeaderBar())
        self.set_child(view)
        self.go(place_list[0][1] if place_list else "/")

    def go(self, path: str) -> None:
        try:
            names = sorted(os.listdir(path))
        except OSError as exc:
            self.path_label.set_label(f"{path} - {exc.strerror}")
            return
        self.cwd = path
        self.path_label.set_label(path)
        while (row := self.list.get_row_at_index(0)) is not None:
            self.list.remove(row)
        entries = []
        for name in names[:MAX_ENTRIES]:
            full = os.path.join(path, name)
            isdir = os.path.isdir(full) and not os.path.islink(full)
            entries.append((not isdir, name, full, isdir))
        for _, name, full, isdir in sorted(entries):
            self.list.append(self._row(name, full, isdir))
        if len(names) > MAX_ENTRIES:
            more = Gtk.ListBoxRow(activatable=False, selectable=False)
            more.set_child(Gtk.Label(label=f"… {len(names) - MAX_ENTRIES} more not shown"))
            self.list.append(more)
        first = self.list.get_row_at_index(0)
        if first is not None:
            self.list.select_row(first)

    def _row(self, name: str, full: str, isdir: bool) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        row.path, row.isdir = full, isdir
        box = Gtk.Box(spacing=10, margin_top=3, margin_bottom=3, margin_start=6, margin_end=6)
        row.check = Gtk.Image(icon_name="object-select-symbolic", visible=full in self.picked, css_classes=["accent"])
        box.append(row.check)
        box.append(Gtk.Image(icon_name="folder-symbolic" if isdir else "text-x-generic-symbolic"))
        box.append(Gtk.Label(label=name + ("/" if isdir else ""), xalign=0, hexpand=True,
                             ellipsize=Pango.EllipsizeMode.END))
        if full in self.pkg_files:
            box.append(Gtk.Label(label="package", css_classes=["caption", "accent"]))
        box.append(Gtk.Label(label=policy_draft.actual_label(full) or "?", xalign=1,
                             css_classes=["dim-label", "monospace"]))
        row.set_child(box)
        return row

    def toggle(self, row=None) -> None:
        row = row or self.list.get_selected_row()
        if row is None or not hasattr(row, "path"):
            return
        if row.path in self.picked:
            self.picked.remove(row.path)
        else:
            self.picked.append(row.path)
        row.check.set_visible(row.path in self.picked)
        n = len(self.picked)
        self.count_label.set_label(f"{n} picked" if n else "Nothing picked")
        self.add_btn.set_label(f"Add {n} rule(s)" if n else "Add rules")
        self.add_btn.set_sensitive(n > 0)

    def up(self) -> None:
        if self.cwd and self.cwd != "/":
            self.go(os.path.dirname(self.cwd))

    def _on_activate(self, _list, row) -> None:
        if getattr(row, "isdir", False):
            self.go(row.path)
        else:
            self.toggle(row)

    def _on_key(self, _ctl, keyval, _code, _state) -> bool:
        if keyval == Gdk.KEY_BackSpace:
            self.up()
            return True
        if keyval == Gdk.KEY_space:
            self.toggle()
            return True
        return False

    def finish(self) -> None:
        picked = list(self.picked)
        self.close()
        if picked:
            self.on_done(picked)
