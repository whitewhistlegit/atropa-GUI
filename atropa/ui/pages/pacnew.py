"""atropa.ui.pages.pacnew - review .pacnew/.pacsave files left under /etc."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import pacnew
from atropa.ui.pages import BasePage, esc

# Why each suffix exists, in the words the row should say. Kept here (not in
# the backend) because it's presentation, not data.
_SUBTITLES = {
    "pacnew": "new version available (.pacnew)",
    "pacsave": "config saved on removal (.pacsave)",
}


class PacnewPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self.group = self.add_group(
            "Pending config changes",
            "pacman leaves .pacnew files when a package ships a config it will not overwrite, and .pacsave "
            "when a package is removed but its config was modified; reviewing them is how configs stay "
            "current after upgrades.",
        )

        self._rows: list = []
        self.refresh()

    # -- data loading -----------------------------------------------------------

    def refresh(self) -> None:
        # Clear before the spinner goes in, and keep every row (spinner, empty
        # message, error, entries) in _rows: otherwise a second refresh leaves
        # the previous load's rows orphaned in the group forever and they pile
        # up as duplicates.
        self.clear_rows(self.group, self._rows)
        self._rows = [self.start_loading(self.group, "Looking for .pacnew and .pacsave files…")]
        self.run_async(pacnew.scan, self._on_scanned)

    def _on_scanned(self, entries, error) -> bool:
        self.clear_rows(self.group, self._rows)
        self._rows = []

        if error:
            self._add_row(
                Adw.ActionRow(
                    title=esc("Couldn't look for .pacnew/.pacsave files"),
                    subtitle=esc(str(error)),
                )
            )
            return False

        if not entries:
            row = Adw.ActionRow(
                title=esc("Nothing to review - no .pacnew or .pacsave files under /etc"),
                subtitle=esc("Pacman writes these when the config on disk differs from the package's version"),
            )
            row.add_css_class("dim-label")
            self._add_row(row)
            return False

        for entry in entries:
            self._add_entry_row(entry)
        return False

    def _add_row(self, row: Adw.ActionRow) -> None:
        self.group.add(row)
        self._rows.append(row)

    def _add_entry_row(self, entry: pacnew.PacnewEntry) -> None:
        row = Adw.ActionRow(title=esc(entry.live))
        row.set_subtitle(esc(_SUBTITLES.get(entry.kind, "pending review")))

        diff_btn = Gtk.Button(label="Show diff", valign=Gtk.Align.CENTER)
        diff_btn.connect("clicked", lambda _btn: self._show_diff(entry))
        row.add_suffix(diff_btn)

        # A .pacsave is the config of a package that is gone, so its live side
        # usually doesn't exist: "restore" describes the same helper call from
        # the user's side better than "use new version".
        apply_label = "Restore saved config" if entry.kind == "pacsave" else "Use new version"
        apply_btn = Gtk.Button(label=apply_label, valign=Gtk.Align.CENTER)
        apply_btn.add_css_class("suggested-action")
        apply_btn.connect("clicked", lambda _btn: self._on_use_new(entry))
        row.add_suffix(apply_btn)

        keep_btn = Gtk.Button(label="Keep current", valign=Gtk.Align.CENTER)
        keep_btn.connect("clicked", lambda _btn: self._on_keep_current(entry))
        row.add_suffix(keep_btn)

        self._add_row(row)

    # -- actions ----------------------------------------------------------------

    def _show_diff(self, entry: pacnew.PacnewEntry) -> None:
        # Reading two files under /etc can still block on an unsearchable
        # directory, so the diff is built on a worker and only presented after.
        self.run_async(
            lambda: pacnew.diff_text(entry),
            lambda text, error: self._present_diff(entry, text, error),
        )

    def _present_diff(self, entry: pacnew.PacnewEntry, text, error) -> bool:
        if error:
            self.notify(f"Couldn't load the diff: {error}", is_error=True)
            return False

        buffer = Gtk.TextBuffer()
        # Identical files are a valid answer; saying so beats opening an empty
        # monospaced box that the user has to interpret.
        buffer.set_text(text or "No differences - the two files are identical.")

        text_view = Gtk.TextView(buffer=buffer, editable=False, monospace=True, cursor_visible=False)
        text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)

        scroller = Gtk.ScrolledWindow()
        scroller.set_child(text_view)
        scroller.set_min_content_width(640)
        scroller.set_min_content_height(480)
        scroller.set_vexpand(True)

        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=12,
            margin_top=12,
            margin_bottom=12,
            margin_start=12,
            margin_end=12,
        )
        # The diff's own headers carry the paths too, but they scroll away;
        # this keeps the file being reviewed visible above the text.
        path_label = Gtk.Label(label=esc(entry.candidate), xalign=0)
        path_label.add_css_class("dim-label")
        box.append(path_label)
        box.append(scroller)

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        toolbar.set_content(box)

        dialog = Adw.Dialog()
        dialog.set_title("Config diff")
        dialog.set_content_width(640)
        dialog.set_content_height(480)
        dialog.set_child(toolbar)
        dialog.present(self.get_root())
        return False

    def _on_use_new(self, entry: pacnew.PacnewEntry) -> None:
        # Raw paths, not esc(): BasePage.confirm() turns markup off for the
        # heading and body, so escaping here would show "&amp;" literally.
        # One confirm for both suffixes - the outcome is the same overwrite,
        # only the button on the row is worded differently.
        self.confirm(
            "Replace the current config?",
            f"{entry.live} will be overwritten with {entry.candidate} after a backup. "
            "Review the diff first.",
            "Replace",
            lambda: self.run_action(
                lambda: pacnew.apply_new(entry),
                lambda result, error: self.handle_command_result(result, error, "Config replaced"),
            ),
        )

    def _on_keep_current(self, entry: pacnew.PacnewEntry) -> None:
        # Also raw paths: confirm() renders body as plain text (see above).
        # Deleting only the candidate is what "keep current" means for both
        # kinds - a .pacsave's live side may not exist, and if it does it is
        # the file the user chose to keep.
        self.confirm(
            "Delete the new file?",
            f"{entry.candidate} will be deleted; {entry.live} stays as it is.",
            "Delete",
            lambda: self.run_action(
                lambda: pacnew.discard(entry),
                lambda result, error: self.handle_command_result(result, error, "New config file deleted"),
            ),
        )
