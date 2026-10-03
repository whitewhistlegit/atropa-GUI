"""atropa.ui.pages.selinux - SELinux module (sestatus, setenforce, setsebool, restorecon)."""

from __future__ import annotations

import re

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

        # --- denials -----------------------------------------------------
        denials_group = self.add_group(
            "Recent Denials",
            "AVC denials from the kernel log. Click 'Why?' for an explanation, or 'Generate .te' to draft an allow rule.",
        )
        self.denials_group = denials_group
        refresh_denials_row = Adw.ActionRow(title="Source: kernel log (journalctl -k)")
        refresh_btn = Gtk.Button(label="Refresh", valign=Gtk.Align.CENTER)
        refresh_btn.connect("clicked", lambda _b: self._load_denials())
        refresh_denials_row.add_suffix(refresh_btn)
        audit_log_btn = Gtk.Button(label="Also check audit.log (needs auth)", valign=Gtk.Align.CENTER)
        audit_log_btn.connect("clicked", self._on_check_audit_log)
        refresh_denials_row.add_suffix(audit_log_btn)
        denials_group.add(refresh_denials_row)

        # --- per-application batch review -----------------------------------------------------
        review_group = self.add_group(
            "Per-Application Policy Review",
            "Groups denials by the program that triggered them and drafts one policy per "
            "program - usually more useful than reviewing single denials, since audit2allow "
            "sees the full picture. Compiles a .pp for each but installs nothing automatically.",
        )
        run_review_row = Adw.ActionRow(title="Run a review batch")
        run_review_btn = Gtk.Button(label="From kernel log", valign=Gtk.Align.CENTER)
        run_review_btn.connect("clicked", lambda _b: self._on_run_review("journal"))
        run_review_row.add_suffix(run_review_btn)
        run_review_audit_btn = Gtk.Button(label="From audit.log (needs auth)", valign=Gtk.Align.CENTER)
        run_review_audit_btn.connect("clicked", lambda _b: self._on_run_review("audit_log"))
        run_review_row.add_suffix(run_review_audit_btn)
        review_group.add(run_review_row)
        self.review_group = review_group

        self._load_page = None  # wired in by main_window after both pages exist

        self._suppress_signals = False
        self.refresh()

    def set_load_page(self, load_page) -> None:
        """Called by main_window so 'Generate .te' can offer to open the result in the Load Policy page."""
        self._load_page = load_page

    def refresh(self) -> None:
        self.run_async(selinux.get_status, self._on_status_loaded)
        self._load_booleans()
        self._load_denials()

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

    def _load_denials(self) -> None:
        self.clear_rows(self.denials_group, getattr(self, "_denial_rows", []))
        self._denial_rows = [self.start_loading(self.denials_group, "Loading denials…")]
        self.run_async(selinux.list_avc_denials, self._on_denials_loaded)

    def _on_check_audit_log(self, _btn: Gtk.Button) -> None:
        self.notify("Checking audit.log (authentication required)…")
        self.clear_rows(self.denials_group, getattr(self, "_denial_rows", []))
        self._denial_rows = [self.start_loading(self.denials_group, "Checking audit.log…")]
        self.run_async(selinux.list_avc_denials_from_audit_log, self._on_denials_loaded)

    def _on_denials_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_denial_rows", [])):
            self.denials_group.remove(row)
        self._denial_rows = []

        if error:
            self.notify(f"Couldn't read denials: {error}", is_error=True)
            return False

        if not result:
            row = Adw.ActionRow(title="No denials found", subtitle="Nothing logged recently, or try 'Also check audit.log'")
            self.denials_group.add(row)
            self._denial_rows.append(row)
            return False

        for raw_line in reversed(result[-50:]):
            summary = self._summarize_denial(raw_line)
            row = Adw.ActionRow(title=esc(summary), subtitle=esc(raw_line[:160]))

            why_btn = Gtk.Button(label="Why?", valign=Gtk.Align.CENTER, css_classes=["flat"])
            why_btn.connect("clicked", self._on_why_clicked, raw_line)
            row.add_suffix(why_btn)

            gen_btn = Gtk.Button(label="Generate .te", valign=Gtk.Align.CENTER)
            gen_btn.connect("clicked", self._on_generate_te_clicked, raw_line)
            row.add_suffix(gen_btn)

            self.denials_group.add(row)
            self._denial_rows.append(row)
        return False

    @staticmethod
    def _summarize_denial(raw_line: str) -> str:
        """Pulls comm=, tclass=, and the requested permission out of a raw AVC line for a readable title."""
        comm = re.search(r'comm="([^"]+)"', raw_line)
        tclass = re.search(r"tclass=(\S+)", raw_line)
        perm = re.search(r"\{\s*(\S+)\s*\}", raw_line)
        parts = []
        if comm:
            parts.append(comm.group(1))
        if perm:
            parts.append(f"denied {perm.group(1)}")
        if tclass:
            parts.append(f"on {tclass.group(1)}")
        return " ".join(parts) if parts else "AVC denial"

    def _on_why_clicked(self, _btn: Gtk.Button, raw_line: str) -> None:
        self.run_async(lambda: selinux.explain_denial(raw_line), self._on_why_result)

    def _on_why_result(self, result, error) -> bool:
        dialog = Adw.AlertDialog(heading="Why was this denied?")
        dialog.set_body(esc(error) if error else esc(result))
        dialog.set_body_use_markup(True)  # esc() already escaped it; markup is fine for line wrapping
        dialog.add_response("close", "Close")
        dialog.present(self.get_root())
        return False

    def _on_generate_te_clicked(self, _btn: Gtk.Button, raw_line: str) -> None:
        entry = Gtk.Entry(text="local_policy", placeholder_text="module name")
        dialog = Adw.AlertDialog(heading="Generate allow rule", body="Choose a name for the policy module:")
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("generate", "Generate")
        dialog.set_response_appearance("generate", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_dlg, response: str) -> None:
            if response != "generate":
                return
            module_name = entry.get_text().strip() or "local_policy"
            self.run_async(lambda: selinux.generate_te(raw_line, module_name), lambda r, e: self._on_te_generated(r, e, module_name))

        dialog.connect("response", on_response)
        dialog.present(self.get_root())

    def _on_te_generated(self, result, error, module_name: str) -> bool:
        if error:
            self.notify(f"Error: {error}", is_error=True)
            return False

        buffer = Gtk.TextBuffer()
        buffer.set_text(result)
        text_view = Gtk.TextView(buffer=buffer, editable=False, monospace=True)
        text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        scroller = Gtk.ScrolledWindow(min_content_height=240)
        scroller.set_child(text_view)

        dialog = Adw.AlertDialog(heading=f"Generated: {module_name}.te")
        dialog.set_extra_child(scroller)
        dialog.add_response("close", "Close")
        if self._load_page is not None:
            dialog.add_response("open", "Open in Load Policy page")
            dialog.set_response_appearance("open", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_dlg, response: str) -> None:
            if response == "open" and self._load_page is not None:
                self._load_page.load_te_text(result, module_name)
                self.notify("Opened in Load Policy page")

        dialog.connect("response", on_response)
        dialog.present(self.get_root())
        return False

    def _on_run_review(self, source: str) -> None:
        self.notify("Running policy review… this can take a moment" + (" (authentication required)" if source == "audit_log" else ""))
        self.clear_rows(self.review_group, getattr(self, "_review_rows", []))
        self._review_rows = [self.start_loading(self.review_group, "Running review batch…")]
        self.run_async(lambda: selinux.build_policy_review(source=source), self._on_review_done)

    def _on_review_done(self, result, error) -> bool:
        for row in list(getattr(self, "_review_rows", [])):
            self.review_group.remove(row)
        self._review_rows = []

        if error:
            self.notify(f"Review failed: {error}", is_error=True)
            return False

        if not result:
            row = Adw.ActionRow(title="No application denials found to review")
            self.review_group.add(row)
            self._review_rows.append(row)
            return False

        for review in result:
            if review.error and not review.te_content:
                subtitle = f"{review.denial_count} denial(s) · {review.error}"
            elif review.pp_path:
                subtitle = f"{review.denial_count} denial(s) · compiled, ready to review"
            else:
                subtitle = f"{review.denial_count} denial(s) · {review.error or 'not compiled'}"

            row = Adw.ActionRow(title=esc(review.program), subtitle=esc(subtitle))

            view_btn = Gtk.Button(label="View", valign=Gtk.Align.CENTER, css_classes=["flat"])
            view_btn.connect("clicked", self._on_view_review, review)
            row.add_suffix(view_btn)

            if review.pp_path:
                install_btn = Gtk.Button(label="Install", valign=Gtk.Align.CENTER)
                install_btn.connect("clicked", self._on_install_review, review)
                row.add_suffix(install_btn)

            self.review_group.add(row)
            self._review_rows.append(row)
        return False

    def _on_view_review(self, _btn: Gtk.Button, review) -> None:
        sections = [f"=== {review.program} ({review.denial_count} denial(s)) ==="]
        if review.sample_denials:
            sections.append("--- Sample denials ---")
            sections.extend(review.sample_denials)
        if review.te_content:
            sections.append("\n--- Proposed policy (.te) ---")
            sections.append(review.te_content.rstrip())
        if review.why_text:
            sections.append("\n--- audit2why explanation ---")
            sections.append(review.why_text)
        if review.error:
            sections.append("\n--- Error ---")
            sections.append(review.error)

        buffer = Gtk.TextBuffer()
        buffer.set_text("\n".join(sections))
        text_view = Gtk.TextView(buffer=buffer, editable=False, monospace=True)
        text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        scroller = Gtk.ScrolledWindow(min_content_height=320, min_content_width=480)
        scroller.set_child(text_view)

        dialog = Adw.AlertDialog(heading=f"Review: {review.program}")
        dialog.set_extra_child(scroller)
        dialog.add_response("close", "Close")
        if self._load_page is not None and review.te_content:
            dialog.add_response("open", "Open in Load Policy page")
            dialog.set_response_appearance("open", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_dlg, response: str) -> None:
            if response == "open" and self._load_page is not None:
                self._load_page.load_te_text(review.te_content, review.safe_name)
                self.notify("Opened in Load Policy page")

        dialog.connect("response", on_response)
        dialog.present(self.get_root())

    def _on_install_review(self, _btn: Gtk.Button, review) -> None:
        self.confirm(
            f"Install policy for {review.program}?",
            f"This loads {review.safe_name}.pp into the running SELinux policy with semodule -i. "
            "Review the proposed rules first if you haven't already.",
            "Install",
            lambda: self.run_async(lambda: selinux.install_pp_file(review.pp_path), self.handle_command_result),
        )

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
            lambda: self.run_async(selinux.relabel_filesystem, self.handle_command_result),
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

    def _on_boolean_toggle(self, _switch: Gtk.Switch, state: bool, name: str) -> bool:
        self.run_async(lambda: selinux.set_boolean(name, state), self.handle_command_result)
        return False
