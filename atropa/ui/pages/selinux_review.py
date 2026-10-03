"""atropa.ui.pages.selinux_review - SELinux: Denial Review. Setup Mode + an extensive, classified denial review for bootstrapping a policy."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import selinux
from atropa.ui.pages import BasePage, esc


def _denial_title(denial) -> str:
    perms = ",".join(denial.permissions) or "?"
    return f"{denial.scontext_type} → {denial.tcontext_type} : {denial.tclass} {{{perms}}}"


class SelinuxReviewPage(BasePage):
    def __init__(self) -> None:
        super().__init__()
        self._load_page = None  # wired in by main_window.py, same pattern as the SELinux page

        intro_group = self.add_group(
            "SELinux: Denial Review",
            "For bootstrapping a policy from scratch: set permissive, do normal work for a while, "
            "then review everything that happened in one pass instead of hunting through 'recent N' "
            "denials. 'All' always means all still retained by the log backend - journald and "
            "audit.log both rotate - not a literal complete history.",
        )
        self.setup_mode_row = Adw.ActionRow(title="Checking Setup Mode status…")
        self.setup_mode_btn = Gtk.Button(label="…", valign=Gtk.Align.CENTER)
        self.setup_mode_btn.connect("clicked", self._on_setup_mode_btn_clicked)
        self.setup_mode_row.add_suffix(self.setup_mode_btn)
        intro_group.add(self.setup_mode_row)

        run_group = self.add_group(
            "Run Review",
            "Scoped to Setup Mode's start time if you're in it, otherwise to since-boot for the "
            "audit log (journald has its own retention regardless).",
        )
        run_journal_btn = Gtk.Button(label="Review (kernel log)", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        run_journal_btn.connect("clicked", lambda _b: self._on_run_review("journal"))
        run_audit_btn = Gtk.Button(label="Review (audit.log, needs auth)", valign=Gtk.Align.CENTER)
        run_audit_btn.connect("clicked", lambda _b: self._on_run_review("audit_log"))
        run_row = Adw.ActionRow(title="Fetch and classify all available denials")
        run_row.add_suffix(run_journal_btn)
        run_row.add_suffix(run_audit_btn)
        run_group.add(run_row)
        self.summary_row = Adw.ActionRow(title="No review run yet")
        run_group.add(self.summary_row)

        self.new_group = self.add_group(
            "New — needs a policy rule",
            "No matching rule found in anything Atropa has installed and currently has loaded.",
        )
        self.generate_btn = Gtk.Button(label="Generate Policy for All New Denials", valign=Gtk.Align.CENTER)
        self.generate_btn.connect("clicked", self._on_generate_clicked)
        self.generate_btn.set_sensitive(False)
        generate_row = Adw.ActionRow(title="Groups by program and drafts one module per program")
        generate_row.add_suffix(self.generate_btn)
        self.new_group.add(generate_row)

        self.already_allowed_group = self.add_group(
            "Already allowed, but still denied",
            "A matching rule IS loaded, yet this kept happening - usually a file-context/labeling "
            "problem, not a missing rule. Try restorecon on the path first.",
        )

        self.undefined_group = self.add_group(
            "Policy doesn't define this permission",
            "The kernel knows a permission/class the compiled policy predates (common with newer "
            "capability bits like bpf/perfmon on an older policy). Not fixable with an allow rule - "
            "the policy's own class/permission definitions need updating: rebuild the policy source "
            "with UNK_PERMS=allow in build.conf (see 'checking deny_unknown status' on the SELinux "
            "page), or get an updated policy that defines these.",
        )

        self.resolved_group = self.add_group(
            "Resolved since last review",
            "Stopped recurring since the last time you ran a review here.",
        )

        self._new_rows: list = []
        self._already_allowed_rows: list = []
        self._undefined_rows: list = []
        self._resolved_rows: list = []
        self._review_result_rows: list = []
        self._last_review = None

        self.refresh()

    def set_load_page(self, load_page) -> None:
        self._load_page = load_page

    def refresh(self) -> None:
        self.run_async(selinux.is_in_setup_mode, self._on_setup_mode_status_loaded)

    def _on_setup_mode_status_loaded(self, in_setup_mode, error) -> bool:
        if error:
            self.setup_mode_row.set_title("Couldn't check Setup Mode status")
            self.setup_mode_row.set_subtitle(esc(error))
            return False
        if in_setup_mode:
            started_at = selinux.get_setup_mode_started_at()
            self.setup_mode_row.set_title("In Setup Mode")
            self.setup_mode_row.set_subtitle(esc(f"Started {started_at}"))
            self.setup_mode_btn.set_label("Exit Setup Mode")
        else:
            self.setup_mode_row.set_title("Not in Setup Mode")
            self.setup_mode_row.set_subtitle("")
            self.setup_mode_btn.set_label("Start Setup Mode")
        return False

    def _on_setup_mode_btn_clicked(self, _btn: Gtk.Button) -> None:
        if self.setup_mode_btn.get_label() == "Exit Setup Mode":
            self.confirm(
                "Exit Setup Mode?",
                "This only clears the local start-time marker - it doesn't change the current "
                "enforcing/permissive mode. Set that separately on the SELinux page when you're ready.",
                "Exit",
                self._do_exit_setup_mode,
            )
        else:
            self.confirm(
                "Start Setup Mode?",
                "Sets SELinux to permissive and records a start time, so a later review can cover "
                "everything since now in one pass instead of a small recent window.",
                "Start",
                lambda: self.run_async(
                    selinux.start_setup_mode,
                    lambda result, error: self.handle_command_result(result, error, success_message="Setup Mode started"),
                ),
            )

    def _do_exit_setup_mode(self) -> None:
        selinux.clear_setup_mode()
        self.notify("Exited Setup Mode")
        self.refresh()

    # --------------------------------------------------------- run review --

    def _on_run_review(self, source: str) -> None:
        self.summary_row.set_title("Running review…")
        self.summary_row.set_subtitle("")
        for group, rows_attr in (
            (self.new_group, "_new_rows"), (self.already_allowed_group, "_already_allowed_rows"),
            (self.undefined_group, "_undefined_rows"), (self.resolved_group, "_resolved_rows"),
        ):
            self.clear_rows(group, getattr(self, rows_attr))
            setattr(self, rows_attr, [self.start_loading(group, "Scanning…")])
        self.generate_btn.set_sensitive(False)
        self.run_async(lambda: selinux.review_all_denials(source=source), self._on_review_loaded)

    def _on_review_loaded(self, result, error) -> bool:
        for group, rows_attr in (
            (self.new_group, "_new_rows"), (self.already_allowed_group, "_already_allowed_rows"),
            (self.undefined_group, "_undefined_rows"), (self.resolved_group, "_resolved_rows"),
        ):
            self.clear_rows(group, getattr(self, rows_attr))
            setattr(self, rows_attr, [])

        if error:
            self.summary_row.set_title("Review failed")
            self.summary_row.set_subtitle(esc(error))
            return False

        self._last_review = result
        scope = f"since {result.since}" if result.since else "since boot / all retained"
        self.summary_row.set_title(
            f"{result.total_raw_lines} raw line(s) → {len(result.new)} new, "
            f"{len(result.already_allowed)} already-allowed, {len(result.undefined_in_policy)} undefined-in-policy, "
            f"{len(result.resolved)} resolved"
        )
        self.summary_row.set_subtitle(esc(scope))
        self.generate_btn.set_sensitive(bool(result.new))

        if not result.new:
            row = Adw.ActionRow(title="Nothing new")
            self.new_group.add(row)
            self._new_rows.append(row)
        for denial in result.new:
            row = Adw.ActionRow(
                title=esc(_denial_title(denial)),
                subtitle=esc(f"{denial.count} occurrence(s) · program: {denial.program} · sources: {', '.join(denial.sources)}"),
            )
            self.new_group.add(row)
            self._new_rows.append(row)

        if not result.already_allowed:
            row = Adw.ActionRow(title="None")
            self.already_allowed_group.add(row)
            self._already_allowed_rows.append(row)
        for denial in result.already_allowed:
            row = Adw.ActionRow(
                title=esc(_denial_title(denial)),
                subtitle=esc(f"Matched module: {denial.matched_module} · {denial.count} occurrence(s) · program: {denial.program}"),
            )
            if denial.sample_path:
                fix_btn = Gtk.Button(label="Try restorecon", valign=Gtk.Align.CENTER)
                fix_btn.connect("clicked", self._on_try_restorecon, denial.sample_path)
                row.add_suffix(fix_btn)
            else:
                row.add_suffix(Gtk.Label(label="no path available", css_classes=["dim-label"]))
            self.already_allowed_group.add(row)
            self._already_allowed_rows.append(row)

        if not result.undefined_in_policy:
            row = Adw.ActionRow(title="None")
            self.undefined_group.add(row)
            self._undefined_rows.append(row)
        for denial in result.undefined_in_policy:
            perm_text = denial.permissions[0] if denial.permissions else "(whole class)"
            row = Adw.ActionRow(
                title=esc(f"class {denial.tclass}: {perm_text}"),
                subtitle=esc(f"{denial.count} occurrence(s) - not defined in the compiled policy"),
            )
            row.add_prefix(Gtk.Image.new_from_icon_name("dialog-warning-symbolic"))
            help_btn = Gtk.Button(label="Help", valign=Gtk.Align.CENTER)
            help_btn.connect("clicked", self._on_undefined_help_clicked, denial)
            row.add_suffix(help_btn)
            self.undefined_group.add(row)
            self._undefined_rows.append(row)

        if not result.resolved:
            row = Adw.ActionRow(title="None yet")
            self.resolved_group.add(row)
            self._resolved_rows.append(row)
        for denial in result.resolved:
            row = Adw.ActionRow(
                title=esc(_denial_title(denial)),
                subtitle=esc(f"Was seen {denial.count} time(s) before · program: {denial.program}"),
            )
            row.add_prefix(Gtk.Image.new_from_icon_name("emblem-ok-symbolic"))
            self.resolved_group.add(row)
            self._resolved_rows.append(row)

        return False

    def _on_try_restorecon(self, _btn: Gtk.Button, path: str) -> None:
        self.confirm(
            f"Run restorecon on {path}?",
            "Fixes the file's SELinux context if it was mislabeled, which is the most common "
            "reason a denial recurs despite a matching rule already being loaded.",
            "Run",
            lambda: self.run_streaming_operation(
                f"Restoring context: {path}",
                lambda on_line: selinux.restorecon_streaming(path, recursive=False, on_line=on_line),
            ),
        )

    # --------------------------------------------------------- generate policy --

    def _on_generate_clicked(self, _btn: Gtk.Button) -> None:
        if self._last_review is None:
            return
        source = "audit_log" if "audit_log" in self._last_review.source else "journal"
        since = self._last_review.since
        self.clear_rows(self.new_group, self._review_result_rows)
        self._review_result_rows = [self.start_loading(self.new_group, "Generating policy…")]
        self.run_async(
            lambda: selinux.build_policy_review(source=source, since=since), self._on_generate_done
        )

    def _on_generate_done(self, result, error) -> bool:
        for row in self._review_result_rows:
            self.new_group.remove(row)
        self._review_result_rows = []

        if error:
            self.notify(f"Policy generation failed: {error}", is_error=True)
            return False

        for review in result:
            if review.error and not review.te_content:
                subtitle = f"{review.denial_count} denial(s) · {review.error}"
            elif review.pp_path:
                subtitle = f"{review.denial_count} denial(s) · compiled, ready to review"
            else:
                subtitle = f"{review.denial_count} denial(s) · {review.error or 'not compiled'}"

            row = Adw.ActionRow(title=esc(f"Draft: {review.program}"), subtitle=esc(subtitle))
            view_btn = Gtk.Button(label="View", valign=Gtk.Align.CENTER, css_classes=["flat"])
            view_btn.connect("clicked", self._on_view_review, review)
            row.add_suffix(view_btn)
            if review.pp_path:
                install_btn = Gtk.Button(label="Install", valign=Gtk.Align.CENTER)
                install_btn.connect("clicked", self._on_install_review, review)
                row.add_suffix(install_btn)
            self.new_group.add(row)
            self._review_result_rows.append(row)

        self.notify(f"Generated {len(result)} draft module(s)")
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

    # --------------------------------------------------------- undefined-in-policy help --

    def _on_undefined_help_clicked(self, _btn: Gtk.Button, denial) -> None:
        permission = denial.permissions[0] if denial.permissions else ""
        what_text = (
            f"The kernel knows about the '{permission}' permission for the '{denial.tclass}' class, "
            if permission
            else f"The kernel knows about the '{denial.tclass}' class, "
        )
        explanation = (
            f"{what_text}but your compiled policy doesn't define it - this is a policy class/permission "
            "definition gap, not a missing allow rule, so a generated .te module can't fix it.\n\n"
            "Two ways to fix it:\n"
            "1. Rebuild the policy source with UNK_PERMS=allow in build.conf - one line, but treats "
            "ALL undefined permissions (not just this one) as allowed from now on.\n"
            "2. Add the definition properly to the policy source's access_vectors file, rebuild, and "
            "reinstall - more precise, but needs the policy source rebuilt.\n\n"
            "Atropa doesn't ship or edit policy content itself - the check below is read-only, just to "
            "tell you whether your policy source already has this defined before you go looking."
        )

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        path_row = Adw.EntryRow(title="Policy source directory")
        path_row.set_text("/etc/selinux/refpolicy/src/policy")
        check_btn = Gtk.Button(label="Check", valign=Gtk.Align.CENTER)
        path_row.add_suffix(check_btn)
        box.append(path_row)
        result_label = Gtk.Label(label="", wrap=True, xalign=0)
        box.append(result_label)

        def on_check_clicked(_b: Gtk.Button) -> None:
            path = path_row.get_text().strip()
            if not path:
                return
            result_label.set_text("Checking…")
            self.run_async(
                lambda: selinux.check_policy_source_for_permission(path, denial.tclass, permission),
                lambda res, err: self._on_policy_source_checked(res, err, result_label),
            )

        check_btn.connect("clicked", on_check_clicked)

        dialog = Adw.AlertDialog(heading=f"class {denial.tclass}: {permission or '(whole class)'}", body=explanation)
        dialog.set_extra_child(box)
        dialog.add_response("close", "Close")
        dialog.present(self.get_root())

    def _on_policy_source_checked(self, result, error, label: Gtk.Label) -> bool:
        if error:
            label.set_text(f"Couldn't check: {error}")
            return False
        if result["error"]:
            label.set_text(result["error"])
        elif not result["class_found"]:
            label.set_text(f"Class not found in {result['checked_path']} - check the path is right.")
        elif result["permission_found"]:
            inherits_note = f" (via 'inherits {result['inherits']}')" if result["inherits"] else ""
            label.set_text(f"Found in {result['checked_path']}{inherits_note} - may already be fixed here; check manually.")
        else:
            label.set_text(f"Not found in {result['checked_path']} - looks like it genuinely needs adding.")
        return False
