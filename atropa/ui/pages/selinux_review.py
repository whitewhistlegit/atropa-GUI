"""
atropa.ui.pages.selinux_review - SELinux: Denials.

One list of programs (SELinux source domains), each with the single best
next step, and a page per program: what kind of program it is, the
recommended route (boolean, relabel, dontaudit for noise, a module only when
none of those cover it), its drafted module reviewed in place, and the raw
denials. Setup Mode, restorecon, boolean "Turn on" and the undefined-class
help are the same as before; only the layout changed.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import selinux, selinux_programs, te_lint
from atropa.ui import selinux_lint
from atropa.ui.pages import BasePage, esc
from atropa.ui.selinux_module_view import ModuleView

_STEP_CLASS = {
    "dangerous": "error", "review": "warning", "relabel": "accent", "boolean": "accent", "module": "accent",
    "policy_gap": "warning", "noise": "dim-label", "done": "success",
}
_KIND_LABEL = {
    "new": "needs a rule", "already_allowed": "allowed, yet denied - a label problem?", "boolean": "a boolean allows it",
    "noise": "known noise", "undefined_in_policy": "not defined in the policy", "resolved": "stopped recurring",
}
_FILTERS = (("needs_action", "Needs action"), ("noise", "Noise"), ("done", "Done"), ("all", "All"))


def _denial_title(denial) -> str:
    perms = ",".join(denial.permissions) or "?"
    return f"{denial.scontext_type} → {denial.tcontext_type} : {denial.tclass} {{{perms}}}"


class SelinuxReviewPage(BasePage):
    def __init__(self) -> None:
        super().__init__()
        self._programs: list = []
        self._review = None
        self._filter = "needs_action"
        self._program_rows: list = []
        self._content_groups: list = []

        # Programs on the left, the selected program on the right.
        sidebar = Adw.PreferencesPage()
        self.detail = Adw.PreferencesPage()
        self.empty = Adw.StatusPage(
            icon_name="edit-find-symbolic", title="Review your denials",
            description="Fetches the denials since boot (or since Setup Mode started), groups them by program "
                        "and drafts a module for each - nothing is installed until you say so.",
        )
        self.content_stack = Gtk.Stack()
        self.content_stack.add_named(self.empty, "empty")
        self.content_stack.add_named(self.detail, "detail")
        self.split = Adw.NavigationSplitView(min_sidebar_width=300, max_sidebar_width=400, sidebar_width_fraction=0.38)
        self.split.set_sidebar(Adw.NavigationPage(title="Programs", child=sidebar))
        self.content_page = Adw.NavigationPage(title="Program", child=self.content_stack)
        self.split.set_content(self.content_page)
        self.toast_overlay.set_child(self.split)
        self.preferences_page = sidebar  # add_group() fills the sidebar

        setup_group = self.add_group("Setup Mode")
        self.setup_mode_row = Adw.ActionRow(title="Checking Setup Mode status…")
        self.setup_mode_btn = Gtk.Button(label="…", valign=Gtk.Align.CENTER)
        self.setup_mode_btn.connect("clicked", self._on_setup_mode_btn_clicked)
        self.setup_mode_row.add_suffix(self.setup_mode_btn)
        setup_group.add(self.setup_mode_row)

        review_group = self.add_group("Review")
        run_row = Adw.ActionRow(title="Review now")
        journal_btn = Gtk.Button(label="Kernel log", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        journal_btn.connect("clicked", lambda _b: self._on_run_review("journal"))
        audit_btn = Gtk.Button(label="audit.log", valign=Gtk.Align.CENTER, tooltip_text="Asks for your password")
        audit_btn.connect("clicked", lambda _b: self._on_run_review("audit_log"))
        run_row.add_suffix(journal_btn)
        run_row.add_suffix(audit_btn)
        review_group.add(run_row)
        self.summary_row = Adw.ActionRow(title="No review run yet")
        review_group.add(self.summary_row)
        chips = Gtk.Box(css_classes=["linked"], margin_top=8, halign=Gtk.Align.START)
        self._chips: dict[str, Gtk.ToggleButton] = {}
        first = None
        for key, label in _FILTERS:
            chip = Gtk.ToggleButton(label=label, active=key == self._filter)
            if first is None:
                first = chip
            else:
                chip.set_group(first)
            chip.connect("toggled", self._on_filter_toggled, key)
            self._chips[key] = chip
            chips.append(chip)
        review_group.add(chips)

        self.programs_group = self.add_group("Programs")
        self.refresh()

    def refresh(self) -> None:
        self.run_async(selinux.is_in_setup_mode, self._on_setup_mode_status_loaded)

    # --------------------------------------------------------- setup mode --

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
            self.setup_mode_row.set_subtitle("Permissive, recording from a start time")
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

    # --------------------------------------------------------- review --

    def _on_run_review(self, source: str) -> None:
        self.summary_row.set_title("Reviewing…")
        self.summary_row.set_subtitle("Classifying denials and drafting modules")
        self.clear_rows(self.programs_group, self._program_rows)
        self._program_rows = [self.start_loading(self.programs_group, "Reviewing…")]

        def work():
            review = selinux.review_all_denials(source=source)
            drafts = selinux.build_policy_review(
                source="audit_log" if "audit_log" in review.source else "journal", since=review.since,
            ) if review.new or review.noise else []
            return review, selinux_programs.overview(review, drafts)

        self.run_async(work, self._on_review_loaded)

    def _on_review_loaded(self, result, error) -> bool:
        self.clear_rows(self.programs_group, self._program_rows)
        self._program_rows = []
        if error:
            self.summary_row.set_title("Review failed")
            self.summary_row.set_subtitle(esc(error))
            return False
        self._review, self._programs = result
        counts = selinux_programs.counts(self._programs)
        self.summary_row.set_title(f"{len(self._programs)} program(s) · {counts['needs_action']} need action")
        scope = f"since {self._review.since}" if self._review.since else "since boot / all retained"
        checked = "checked against the loaded policy" if self._review.policy_checked else "not checked (needs setools)"
        self.summary_row.set_subtitle(esc(f"{self._review.total_raw_lines} denial line(s) · {scope} · {checked}"))
        for key, label in _FILTERS:
            count = len(self._programs) if key == "all" else counts[key]
            self._chips[key].set_label(f"{label} {count}")
        self._render_programs()
        return False

    def _on_filter_toggled(self, chip: Gtk.ToggleButton, key: str) -> None:
        if chip.get_active():
            self._filter = key
            self._render_programs()

    def _visible(self, program) -> bool:
        if self._filter == "all":
            return True
        if self._filter == "needs_action":
            return program.step in selinux_programs.NEEDS_ACTION
        return program.step == self._filter

    def _render_programs(self) -> None:
        self.clear_rows(self.programs_group, self._program_rows)
        self._program_rows = []
        shown = [p for p in self._programs if self._visible(p)]
        if not shown:
            row = Adw.ActionRow(title="Nothing here" if self._review else "Run a review first")
            self.programs_group.add(row)
            self._program_rows.append(row)
            return
        for program in shown:
            category = te_lint.CATEGORIES.get(program.category, "")
            row = Adw.ActionRow(title=esc(program.title),
                                subtitle=esc(f"{category} · {program.count} denial(s) · {program.domain}"),
                                activatable=True)
            badge = Gtk.Label(label=selinux_programs.STEP_LABELS[program.step], valign=Gtk.Align.CENTER,
                              css_classes=["caption-heading", _STEP_CLASS[program.step]])
            row.add_suffix(badge)
            row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
            row.connect("activated", self._on_program_activated, program)
            self.programs_group.add(row)
            self._program_rows.append(row)

    # --------------------------------------------------------- program page --

    def _on_program_activated(self, _row, program) -> None:
        self._show_program(program)
        self.split.set_show_content(True)

    def _detail_group(self, title: str, description: str = "") -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(title=esc(title))
        if description:
            group.set_description(esc(description))
        self.detail.add(group)
        self._content_groups.append(group)
        return group

    def _show_program(self, program) -> None:
        for group in self._content_groups:
            self.detail.remove(group)
        self._content_groups = []
        self.content_page.set_title(program.title)
        self.content_stack.set_visible_child_name("detail")

        category = te_lint.CATEGORIES.get(program.category, "")
        header = self._detail_group(program.title, f"{program.domain} · {program.count} denial(s) · {category}")
        header.set_header_suffix(Gtk.Label(label=selinux_programs.STEP_LABELS[program.step],
                                           css_classes=["caption-heading", _STEP_CLASS[program.step]]))

        self._render_recommended(program)

        if program.draft is not None:
            draft = program.draft
            group = self._detail_group("Draft module", draft.safe_name)
            if draft.te_content:
                group.add(ModuleView(
                    self, draft.safe_name, draft.te_content, draft.category, draft.category_reason,
                    booleans=draft.booleans, on_done=self._after_change,
                ))
            else:
                group.add(Adw.ActionRow(title="No draft", subtitle=esc(draft.error or "audit2allow produced nothing")))

        self._render_denials(program)

    def _render_recommended(self, program) -> None:
        group = self._detail_group("Recommended", "The policy's own answers first; a module only for what's left.")
        rows = 0
        boolean_rules = self._review.boolean_rules if self._review else {}
        offered: set[str] = set()
        for denial in program.denials:
            for name in denial.booleans[:2]:
                if name in offered:
                    continue
                offered.add(name)
                covers = sum(name in d.booleans for d in program.denials)
                row = Adw.ActionRow(title=esc(f"Turn on the boolean {name}"),
                                    subtitle=esc(f"Covers {covers} of these denials · switches "
                                                 f"{boolean_rules.get(name, '?')} rule(s) in the policy"))
                button = Gtk.Button(label="Turn on", valign=Gtk.Align.CENTER)
                button.connect("clicked", self._on_turn_on_boolean, name, boolean_rules.get(name))
                row.add_suffix(button)
                group.add(row)
                rows += 1
        paths = []
        for denial in program.denials:
            relabel = denial.hint or denial.classification == "already_allowed"
            if relabel and denial.sample_path and denial.sample_path.startswith("/") and denial.sample_path not in paths:
                paths.append(denial.sample_path)
        for path in paths[:5]:
            row = Adw.ActionRow(title=esc(f"Relabel {path}"),
                                subtitle="A label problem, not a missing rule - restorecon puts the right label back")
            button = Gtk.Button(label="restorecon", valign=Gtk.Align.CENTER)
            button.connect("clicked", self._on_try_restorecon, path)
            row.add_suffix(button)
            group.add(row)
            rows += 1
        if program.noise_draft is not None and program.noise_draft.pp_path:
            noise = program.noise_draft
            row = Adw.ActionRow(title="Silence the known noise",
                                subtitle=esc(f"Installs {noise.safe_name}: dontaudit rules, nothing allowed"))
            button = Gtk.Button(label="Install", valign=Gtk.Align.CENTER)
            button.connect("clicked", self._on_install_noise, noise)
            row.add_suffix(button)
            group.add(row)
            rows += 1
        for denial in program.denials:
            if denial.classification == "undefined_in_policy":
                perm = denial.permissions[0] if denial.permissions else "(whole class)"
                row = Adw.ActionRow(title=esc(f"The policy doesn't define {denial.tclass}: {perm}"),
                                    subtitle="Not fixable with a rule - the policy itself needs updating")
                button = Gtk.Button(label="Help", valign=Gtk.Align.CENTER)
                button.connect("clicked", self._on_undefined_help_clicked, denial)
                row.add_suffix(button)
                group.add(row)
                rows += 1
        if program.draft is not None and program.draft.te_content and any(d.classification == "new" for d in program.denials):
            group.add(Adw.ActionRow(title="A module for the rest", subtitle="Review it below before installing"))
            rows += 1
        if not rows:
            group.add(Adw.ActionRow(title="Nothing to do", subtitle="These denials stopped or are already handled"))

    def _render_denials(self, program) -> None:
        group = self._detail_group("Denials")
        for denial in sorted(program.denials, key=lambda d: -d.count):
            expander = Adw.ExpanderRow(title=esc(_denial_title(denial)),
                                       subtitle=esc(f"{_KIND_LABEL.get(denial.classification, denial.classification)}"
                                                    f" · {denial.count}× · {denial.program}"))
            details = [("Sample", denial.sample_line)]
            if denial.sample_path:
                details.append(("Path", denial.sample_path))
            if denial.hint:
                details.append(("Hint", denial.hint))
            if denial.noise_reason:
                details.append(("Noise", denial.noise_reason))
            if denial.matched_module:
                details.append(("Matched module", denial.matched_module))
            for title, value in details:
                row = Adw.ActionRow(title=title, subtitle=esc(value))
                row.set_subtitle_selectable(True)
                expander.add_row(row)
            group.add(expander)
        if program.draft is not None and program.draft.why_text:
            why = Adw.ExpanderRow(title="audit2why explanation")
            row = Adw.ActionRow(subtitle=esc(program.draft.why_text))
            row.set_subtitle_selectable(True)
            why.add_row(row)
            group.add(why)

    def _after_change(self) -> None:
        self.notify("Run the review again to see what's left")

    # --------------------------------------------------------- actions --

    def _on_install_noise(self, _btn: Gtk.Button, noise) -> None:
        selinux_lint.install(
            self, f"Install {noise.safe_name}?",
            "Loads the dontaudit rules for this program's known noise. Nothing is allowed by it.",
            noise.findings,
            lambda acks: selinux.install_pp_file(noise.pp_path, acks),
        )

    def _on_turn_on_boolean(self, _btn: Gtk.Button, name: str, rule_count) -> None:
        scope = f"It switches {rule_count} rule(s) in the policy, not only the one behind this denial. " if rule_count else ""
        self.confirm(
            f"Turn on {name}?",
            f"{scope}Persistent (setsebool -P), so it survives a reboot; turn it off again on the SELinux page.",
            "Turn on",
            lambda: self.run_action(
                lambda: selinux.set_boolean(name, True),
                lambda result, error: self.handle_command_result(result, error, f"{name} is on", refresh=False),
            ),
        )

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
        path_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        path_list.append(path_row)  # rows must be inside a list box, or GTK asserts once one has focus
        box.append(path_list)
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
