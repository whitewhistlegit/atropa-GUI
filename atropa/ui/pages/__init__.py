"""
atropa.ui.pages
--------------------
Shared BasePage: every module page gets a toast overlay for feedback and a
helper to run backend calls (which shell out and can block) on a worker
thread so the GTK main loop never freezes.
"""

from __future__ import annotations

import threading
from typing import Any, Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402


def esc(text: object) -> str:
    """
    Escape text for use in Adw.ActionRow/PreferencesGroup titles and
    subtitles, which render as Pango markup. Anything sourced from the
    system (usernames, package descriptions, SSIDs, service descriptions,
    etc.) can legally contain '&', '<', or '>' and must go through this
    before being handed to set_title()/set_subtitle() - otherwise GTK
    fails to parse the markup and silently renders blank text instead of
    raising a visible error.
    """
    if text is None:
        return ""
    return GLib.markup_escape_text(str(text))


class BasePage(Gtk.Box):
    """
    Common scaffolding for a module page:
      - self.toast_overlay wraps all content so pages can call self.notify(...)
      - self.run_async(work_fn, on_done) offloads blocking backend calls
      - self.preferences_page is a scrollable Adw.PreferencesPage subclasses fill in
    """

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)

        self.toast_overlay = Adw.ToastOverlay()
        self.append(self.toast_overlay)
        self.toast_overlay.set_vexpand(True)
        self.toast_overlay.set_hexpand(True)

        self.preferences_page = Adw.PreferencesPage()
        self.toast_overlay.set_child(self.preferences_page)

    def add_group(self, title: str, description: str = "") -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup()
        group.set_title(title)
        if description:
            group.set_description(description)
        self.preferences_page.add(group)
        return group

    def notify(self, message: str, timeout: int | None = None, is_error: bool = False) -> None:
        # Toast titles render as Pango markup; messages are frequently built
        # from raw command stderr or exception text, so escape here rather
        # than relying on every call site to do it.
        #
        # Error text needs longer on screen than a quick "Done" confirmation -
        # 3s is enough to notice a toast appeared, not enough to read a
        # sentence of command stderr. Only applies when the caller hasn't
        # already picked a specific timeout.
        if timeout is None:
            timeout = 6 if is_error else 3
        toast = Adw.Toast(title=esc(message), timeout=timeout)
        self.toast_overlay.add_toast(toast)

    def clear_rows(self, group: Adw.PreferencesGroup, rows: list) -> None:
        """
        Removes every widget in `rows` from `group`. Call this before
        replacing a page's `self._x_rows` list (e.g. right before adding a
        start_loading() placeholder) - otherwise the old data rows from the
        previous load are orphaned in the group (never removed, since the
        list reference tracking them just got overwritten) and pile up as
        duplicates every time refresh() runs.
        """
        for row in rows:
            group.remove(row)

    def start_loading(self, group: Adw.PreferencesGroup, message: str = "Loading…") -> Adw.ActionRow:
        """
        Adds a spinner+label placeholder row to `group` and returns it.
        Callers should stash it in whatever list they track "rows belonging
        to this group" in (the same list already cleared and rebuilt on
        every refresh) so it gets removed automatically the moment real
        data arrives - avoiding a list that's empty one moment and full the
        next with nothing in between to show something is happening.
        """
        spinner = Gtk.Spinner()
        spinner.start()
        row = Adw.ActionRow(title=message)
        row.add_prefix(spinner)
        group.add(row)
        return row

    def handle_command_result(
        self, result: Any, error: Exception | None, success_message: str = "Done", refresh: bool = True
    ) -> bool:
        """
        Shared outcome handler for run_async(backend_fn, ...) calls that
        return a CommandResult - every page had this exact block
        copy-pasted as its own `_on_command_done`. Centralizing it means a
        fix (like the error-toast timeout) applies everywhere at once, and
        pages can just pass `self.handle_command_result` directly as the
        run_async callback instead of defining their own wrapper.
        """
        if error:
            self.notify(f"Error: {error}", is_error=True)
        elif result is not None and not getattr(result, "ok", True):
            self.notify(f"Command failed: {result.stderr.strip()[:150]}", is_error=True)
        else:
            self.notify(success_message)
            if refresh:
                self.refresh()
        return False

    def run_streaming_operation(
        self,
        title: str,
        work_fn: Callable[[Callable[[str], None]], Any],
        on_done: Callable[[Any, Exception | None], None] | None = None,
    ) -> None:
        """
        Runs work_fn(on_line) on a worker thread, showing a modal dialog
        with a live-scrolling log (fed by on_line calls) and a spinner,
        instead of one toast then silence - for long operations like a
        full system upgrade or a recursive relabel. on_done(result, error)
        fires once work_fn returns, same contract as run_async; defaults to
        self.handle_command_result if not given.
        """
        if on_done is None:
            on_done = self.handle_command_result

        dialog = Adw.Dialog()
        dialog.set_title(title)
        dialog.set_content_width(560)
        dialog.set_content_height(420)
        dialog.set_can_close(False)  # don't let it be dismissed mid-operation

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(False)
        toolbar.add_top_bar(header)

        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=12,
            margin_top=12,
            margin_bottom=12,
            margin_start=12,
            margin_end=12,
        )

        spinner = Gtk.Spinner()
        spinner.start()
        status_row = Adw.ActionRow(title="Running…")
        status_row.add_prefix(spinner)
        box.append(status_row)

        buffer = Gtk.TextBuffer()
        text_view = Gtk.TextView(buffer=buffer, editable=False, monospace=True, cursor_visible=False)
        text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        text_view.add_css_class("card")

        scroller = Gtk.ScrolledWindow()
        scroller.set_child(text_view)
        scroller.set_vexpand(True)
        scroller.set_min_content_height(260)
        box.append(scroller)

        close_btn = Gtk.Button(label="Close")
        close_btn.set_sensitive(False)
        close_btn.set_halign(Gtk.Align.END)
        close_btn.connect("clicked", lambda _b: dialog.close())
        box.append(close_btn)

        toolbar.set_content(box)
        dialog.set_child(toolbar)

        def append_line(line: str) -> bool:
            end_iter = buffer.get_end_iter()
            buffer.insert(end_iter, line + "\n")
            text_view.scroll_mark_onscreen(buffer.get_insert())
            return False

        def on_line(line: str) -> None:
            GLib.idle_add(append_line, line)

        def finish(result: Any, error: Exception | None) -> bool:
            spinner.stop()
            spinner.set_visible(False)
            dialog.set_can_close(True)
            close_btn.set_sensitive(True)
            if error:
                status_row.set_title("Failed")
                status_row.set_subtitle(esc(str(error)))
            elif result is not None and not getattr(result, "ok", True):
                status_row.set_title("Finished with errors")
            else:
                status_row.set_title("Done")
            on_done(result, error)
            return False

        def worker() -> None:
            result, error = None, None
            try:
                result = work_fn(on_line)
            except Exception as exc:  # noqa: BLE001 - surfaced in the dialog, not swallowed
                error = exc
            GLib.idle_add(finish, result, error)

        dialog.present(self.get_root())
        threading.Thread(target=worker, daemon=True).start()

    def run_async(self, work_fn: Callable[[], Any], on_done: Callable[[Any, Exception | None], None]) -> None:
        """
        Run work_fn() on a background thread; on_done(result, error) is
        invoked back on the GTK main thread once it finishes.
        """

        def worker() -> None:
            result, error = None, None
            try:
                result = work_fn()
            except Exception as exc:  # noqa: BLE001 - surfaced to the UI, not swallowed
                error = exc
            GLib.idle_add(on_done, result, error)

        threading.Thread(target=worker, daemon=True).start()

    def confirm(
        self,
        heading: str,
        body: str,
        danger_label: str,
        on_confirm: Callable[[], None],
        on_cancel: Callable[[], None] | None = None,
    ) -> None:
        """Show a destructive-action confirmation dialog before running on_confirm().

        on_cancel is optional and rarely needed - most callers have nothing
        to undo since nothing was applied to the widget yet. It exists for
        cases like a Gtk.Switch mid-drag: GTK's own default state-set
        handling would otherwise apply the requested visual position
        immediately, so a caller that returns True from state-set (to stop
        that default handling) needs an explicit way to put the widget back
        if the user cancels, rather than leaving it showing a state that was
        requested but never actually applied.
        """
        root = self.get_root()
        dialog = Adw.AlertDialog(heading=heading, body=body)
        # heading/body often embed live data (package names, usernames, etc.)
        # which can legally contain '&', '<', '>' - treat both as plain text
        # rather than Pango markup so callers don't need to escape everywhere.
        dialog.set_heading_use_markup(False)
        dialog.set_body_use_markup(False)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("confirm", danger_label)
        dialog.set_response_appearance("confirm", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def on_response(_dlg: Adw.AlertDialog, response: str) -> None:
            if response == "confirm":
                on_confirm()
            elif on_cancel is not None:
                on_cancel()

        dialog.connect("response", on_response)
        dialog.present(root)
