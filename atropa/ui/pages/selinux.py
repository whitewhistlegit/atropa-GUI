"""atropa.ui.pages.selinux - SELinux module (status, mode, relabel, restorecon, booleans); denials have their own page."""

from __future__ import annotations


import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import selinux
from atropa.ui.pages import BasePage, esc


class SelinuxPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        status_group = self.add_group("Status")
        self.status_row = Adw.ActionRow(title="Checking SELinux status…")
        status_group.add(self.status_row)

        self.mode_row = Adw.ActionRow(title="Enforcing mode")
        # Locked by default - a lock icon must be clicked to arm the switch
        # before it can be moved at all, on top of (not instead of) the
        # confirm dialog below. SELinux enforcing/permissive is exactly the
        # kind of toggle a stray click or fat-fingered tab/space shouldn't
        # be able to flip - the confirm dialog alone doesn't stop an
        # accidental drag from registering as a real GTK state-set signal
        # in the first place, only from completing once it has.
        self.mode_lock_btn = Gtk.Button(valign=Gtk.Align.CENTER, css_classes=["flat"])
        self.mode_lock_btn.set_icon_name("changes-prevent-symbolic")
        self.mode_lock_btn.set_tooltip_text("Click to unlock before changing enforcing mode")
        self.mode_lock_btn.connect("clicked", self._on_mode_lock_clicked)
        self.mode_toggle = Gtk.Switch(valign=Gtk.Align.CENTER, sensitive=False)
        self.mode_toggle.connect("state-set", self._on_mode_toggle)
        self.mode_row.add_suffix(self.mode_lock_btn)
        self.mode_row.add_suffix(self.mode_toggle)
        self._mode_unlocked = False
        self._mode_toggleable = False  # whether SELinux is even in a state where flipping mode is possible
        status_group.add(self.mode_row)

        relabel_row = Adw.ActionRow(
            title="Schedule full filesystem relabel",
            subtitle="Touches /.autorelabel; relabels everything on next boot (can take a while)",
        )
        relabel_btn = Gtk.Button(label="Schedule", valign=Gtk.Align.CENTER)
        relabel_btn.connect("clicked", self._on_relabel)
        relabel_row.add_suffix(relabel_btn)
        status_group.add(relabel_row)

        # --- denials: their own page now ------------------------------------
        denials_group = self.add_group("Denials")
        denials_row = Adw.ActionRow(
            title="Review denials and modules",
            subtitle="SELinux: Denials groups them by program with the best next step for each; "
                     "SELinux: Modules lists what's installed and pending.",
        )
        open_btn = Gtk.Button(label="Open Denials", valign=Gtk.Align.CENTER)
        open_btn.connect("clicked", self._on_open_denials)
        denials_row.add_suffix(open_btn)
        denials_group.add(denials_row)

        # --- restorecon -----------------------------------------------------
        restore_group = self.add_group(
            "Restore File Contexts", "Fixes SELinux labels on files after moving/copying them outside their normal tools"
        )
        self.path_row = Adw.EntryRow(title="Path (e.g. /home/user/myfile or /srv/www)")
        restore_group.add(self.path_row)
        restore_btn = Gtk.Button(label="Run restorecon -R", css_classes=["suggested-action"])
        restore_btn.set_margin_top(8)
        restore_btn.connect("clicked", self._on_restorecon)
        restore_group.add(restore_btn)

        # --- booleans -----------------------------------------------------
        bool_group = self.add_group("Booleans", "Toggle policy switches (persisted with setsebool -P)")
        self.bool_filter_row = Adw.EntryRow(title="Filter by name")
        filter_btn = Gtk.Button(label="Apply", valign=Gtk.Align.CENTER, css_classes=["flat"])
        filter_btn.connect("clicked", lambda _b: self._load_booleans())
        self.bool_filter_row.add_suffix(filter_btn)
        bool_group.add(self.bool_filter_row)
        self.bool_group = bool_group

        self._load_page = None  # wired in by main_window after both pages exist

        self._suppress_signals = False
        self.refresh()

    def set_load_page(self, load_page) -> None:
        """Called by main_window so 'Generate .te' can offer to open the result in the Load Policy page."""
        self._load_page = load_page

    def refresh(self) -> None:
        self.run_async(selinux.get_status, self._on_status_loaded)
        self._load_booleans()

    def _on_open_denials(self, _btn: Gtk.Button) -> None:
        window = self.get_root()
        if hasattr(window, "_activate_module"):
            window._activate_module("selinux_review")

    def _load_booleans(self) -> None:
        term = self.bool_filter_row.get_text().strip()
        self.clear_rows(self.bool_group, getattr(self, "_bool_rows", []))
        self._bool_rows = [self.start_loading(self.bool_group, "Loading booleans…")]
        self.run_async(lambda: selinux.list_booleans(term), self._on_booleans_loaded)

    def _on_status_loaded(self, result, error) -> bool:
        self._suppress_signals = True
        if error:
            self.status_row.set_title("Could not read SELinux status")
            self.status_row.set_subtitle(esc(error))
            self._mode_toggleable = False
            self.mode_lock_btn.set_sensitive(False)
            self.mode_toggle.set_sensitive(False)
        elif not result.available:
            self.status_row.set_title("SELinux is not available on this system")
            if result.raw:
                # The tools are installed; the kernel isn't running SELinux.
                self.status_row.set_subtitle(
                    "sestatus reports SELinux as disabled - turning it on needs a policy, kernel parameters "
                    "and a reboot"
                )
            else:
                self.status_row.set_subtitle("No /sys/fs/selinux and no sestatus tool found")
            self._mode_toggleable = False
            self.mode_lock_btn.set_sensitive(False)
            self.mode_toggle.set_sensitive(False)
        else:
            subtitle = f"Policy: {result.policy or 'unknown'} · MLS: {result.mls or 'unknown'}"
            self.status_row.set_title(f"SELinux is {result.mode}")
            self.status_row.set_subtitle(esc(subtitle))
            # Real `sestatus` output is lowercase ("enforcing"/"permissive"/
            # "disabled") - confirmed by the user's own bare-metal report,
            # and by backend/selinux.py's own test fixture, which already
            # asserted `status.mode == "enforcing"` correctly. This UI file
            # was comparing against Title-case "Enforcing"/"Permissive"
            # instead, which never matched real sestatus output at all - the
            # switch and the lock button (added in the same session as this
            # fix) were both silently stuck locked-and-unusable on every
            # real system, not just showing the wrong position. `.lower()`
            # makes the comparison robust regardless of exactly how a given
            # sestatus build capitalizes it, rather than hardcoding one
            # specific casing a second time.
            mode_lower = (result.mode or "").lower()
            self._mode_toggleable = mode_lower in ("enforcing", "permissive")
            self.mode_lock_btn.set_sensitive(self._mode_toggleable)
            self.mode_toggle.set_active(mode_lower == "enforcing")
        # Every fresh read of real status (sestatus, via get_status()) re-locks
        # the switch - an unlock only ever authorizes the one change that
        # follows it, not open season on every future refresh of this page.
        self._mode_unlocked = False
        self.mode_lock_btn.set_icon_name("changes-prevent-symbolic")
        self.mode_toggle.set_sensitive(False)
        self._suppress_signals = False
        return False

    def _on_booleans_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_bool_rows", [])):
            self.bool_group.remove(row)
        self._bool_rows = []

        if error:
            self.notify(f"Failed to list booleans: {error}", is_error=True)
            return False

        for b in result[:200]:
            row = Adw.ActionRow(title=esc(b.name))
            switch = Gtk.Switch(valign=Gtk.Align.CENTER)
            switch.set_active(b.active)
            switch.connect("state-set", self._on_boolean_toggle, b.name)
            row.add_suffix(switch)
            self.bool_group.add(row)
            self._bool_rows.append(row)
        return False

    def _on_mode_lock_clicked(self, _btn: Gtk.Button) -> None:
        self._mode_unlocked = not self._mode_unlocked
        self.mode_lock_btn.set_icon_name("changes-allow-symbolic" if self._mode_unlocked else "changes-prevent-symbolic")
        self.mode_toggle.set_sensitive(self._mode_unlocked and self._mode_toggleable)

    def _on_mode_toggle(self, _switch: Gtk.Switch, state: bool) -> bool:
        if self._suppress_signals or not self._mode_unlocked:
            return False
        label = "Enforcing" if state else "Permissive"
        previous_state = not state  # what the switch already showed before this drag

        def revert_and_relock() -> None:
            # Cancelling must not leave the switch showing a mode that was
            # never actually applied - re-set the widget to what it was
            # before this drag, don't trust GTK's own default state-set
            # handling to do it (that's what silently didn't happen before
            # this fix: a cancel used to leave the switch visually flipped
            # to the requested-but-never-applied mode).
            self._suppress_signals = True
            self.mode_toggle.set_active(previous_state)
            self._suppress_signals = False
            self._mode_unlocked = False
            self.mode_lock_btn.set_icon_name("changes-prevent-symbolic")
            self.mode_toggle.set_sensitive(False)

        self.confirm(
            f"Switch to {label} mode?",
            "Enforcing actively blocks policy violations; Permissive only logs them. "
            "This also updates /etc/selinux/config so it survives a reboot.",
            "Switch",
            lambda: self.run_async(lambda: selinux.set_mode(state), self._on_mode_set_done),
            on_cancel=revert_and_relock,
        )
        # Prevent GTK's own default state-set handling from applying the
        # requested state immediately - the switch only reflects reality
        # once set_mode() actually succeeds (_on_mode_set_done re-reads
        # sestatus), or reverts if the dialog is cancelled (revert_and_relock
        # above). Without this, a cancelled dialog used to leave the switch
        # showing the never-applied mode until the page was next refreshed.
        return True

    def _on_mode_set_done(self, result, error) -> bool:
        # One unlock authorizes exactly one change - re-lock regardless of
        # whether it succeeded, rather than leaving the switch armed.
        self._mode_unlocked = False
        self.mode_lock_btn.set_icon_name("changes-prevent-symbolic")
        succeeded = not error and getattr(result, "ok", True)
        # handle_command_result() already calls self.refresh() (which
        # re-reads sestatus via _on_status_loaded) on success - don't
        # duplicate that call here. On a failed/errored set_mode(), refresh()
        # does NOT run automatically, but the switch still needs to reflect
        # whatever mode SELinux is really still in rather than whatever
        # position the drag left it showing, so re-read sestatus explicitly
        # only for that path.
        handled = self.handle_command_result(result, error)
        if not succeeded:
            self.run_async(selinux.get_status, self._on_status_loaded)
        return handled

    def _on_relabel(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Schedule a full filesystem relabel?",
            "The next boot will relabel every file with correct SELinux contexts. "
            "This can take a long time on a large disk and the system will be "
            "unusable until it finishes.",
            "Schedule",
            lambda: self.run_action(selinux.relabel_filesystem, self.handle_command_result),
        )

    def _on_restorecon(self, _btn: Gtk.Button) -> None:
        path = self.path_row.get_text().strip()
        if not path:
            self.notify("Enter a path first", is_error=True)
            return
        self.confirm(
            f"Run restorecon -R on {path}?",
            "This can take a while on a large directory (or '/'). Progress is shown live.",
            "Run",
            lambda: self.run_streaming_operation(
                f"Restoring contexts: {path}",
                lambda on_line: selinux.restorecon_streaming(path, recursive=True, on_line=on_line),
            ),
        )

    def _on_boolean_toggle(self, switch: Gtk.Switch, state: bool, name: str) -> bool:
        return self.apply_switch(switch, state, lambda: selinux.set_boolean(name, state))
