"""
atropa.ui.selinux_module_view - one SELinux module, reviewed in place.

Used by the Denials page (a program's draft) and the Modules page (a
pending, installed or loaded-from-disk module): what kind of program it is
for, what the linter found with a one-click safer option where the fix is
mechanical, the source (editable, flagged lines tinted, re-linted as you
type), and Discard / Save for later / Install - Install gated by the
linter the same way the backend gates it.
"""

from __future__ import annotations

from typing import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from atropa.backend import selinux, te_lint
from atropa.ui import selinux_lint
from atropa.ui.pages import esc

_TINTS = {
    te_lint.DANGEROUS: "rgba(224, 27, 36, 0.18)",
    te_lint.REVIEW: "rgba(229, 165, 10, 0.20)",
    te_lint.NOTE: "rgba(53, 132, 228, 0.12)",
}
_BADGE_CLASS = {te_lint.DANGEROUS: "error", te_lint.REVIEW: "warning", te_lint.NOTE: "accent"}
_FIX_LABELS = {"drop": "Drop it", "dontaudit": "Use dontaudit", "boolean": "Turn on"}


class ModuleView(Gtk.Box):
    def __init__(
        self,
        page,
        module_name: str,
        te_text: str,
        category: str = "unsure",
        category_reason: str = "",
        booleans: list[str] | None = None,
        editable_name: bool = False,
        on_done: Callable[[], None] | None = None,
        allow_discard: bool = True,
        allow_save: bool = True,
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        self.page = page
        self.module_name = module_name
        self.category = category if category in te_lint.CATEGORIES else "unsure"
        self.booleans = booleans
        self.on_done = on_done
        self.findings: list = []
        self._relint_source = 0

        if editable_name:
            names = Gtk.ListBox(css_classes=["boxed-list"], selection_mode=Gtk.SelectionMode.NONE)
            self.name_row = Adw.EntryRow(title="Module name")
            self.name_row.set_text(module_name)
            names.append(self.name_row)
            self.append(names)
        else:
            self.name_row = None

        # --- what kind of program -----------------------------------------
        kind = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        kind.append(Gtk.Label(label="What kind of program is this?", xalign=0, css_classes=["heading"]))
        buttons = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, max_children_per_line=6, column_spacing=0,
                              row_spacing=4, homogeneous=False)
        first = None
        self._category_buttons: dict[str, Gtk.ToggleButton] = {}
        for key, label in te_lint.CATEGORIES.items():
            button = Gtk.ToggleButton(label=label)
            if first is None:
                first = button
            else:
                button.set_group(first)
            button.set_active(key == self.category)
            button.connect("toggled", self._on_category_toggled, key)
            self._category_buttons[key] = button
            buttons.append(button)
        kind.append(buttons)
        if category_reason:
            kind.append(Gtk.Label(label=f"Detected: {category_reason}", xalign=0, wrap=True,
                                  css_classes=["dim-label", "caption"]))
        self.append(kind)

        # --- findings --------------------------------------------------------
        self.findings_title = Gtk.Label(xalign=0, css_classes=["heading"])
        self.append(self.findings_title)
        self.findings_list = Gtk.ListBox(css_classes=["boxed-list"], selection_mode=Gtk.SelectionMode.NONE)
        self.findings_list.connect("row-activated", self._on_finding_activated)
        self.append(self.findings_list)

        # --- source ------------------------------------------------------------
        self.buffer = Gtk.TextBuffer()
        for severity, color in _TINTS.items():
            self.buffer.create_tag(severity, paragraph_background=color)
        self.buffer.set_text(te_text)
        self.text_view = Gtk.TextView(buffer=self.buffer, monospace=True, editable=True,
                                      top_margin=8, bottom_margin=8, left_margin=8, right_margin=8)
        self.text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        scroller = Gtk.ScrolledWindow(min_content_height=240, css_classes=["card"])
        scroller.set_child(self.text_view)
        self.append(scroller)
        self.buffer.connect("changed", self._on_buffer_changed)

        # --- bar -------------------------------------------------------------
        bar = Gtk.Box(spacing=8)
        self.status_label = Gtk.Label(xalign=0, hexpand=True, wrap=True)
        bar.append(self.status_label)
        if allow_discard:
            discard = Gtk.Button(label="Discard")
            discard.connect("clicked", self._on_discard)
            bar.append(discard)
        if allow_save:
            save = Gtk.Button(label="Save for later")
            save.connect("clicked", self._on_save)
            bar.append(save)
        self.install_btn = Gtk.Button(label="Install", css_classes=["suggested-action"])
        self.install_btn.connect("clicked", self._on_install)
        bar.append(self.install_btn)
        self.append(bar)

        self._relint()

    # -- state ----------------------------------------------------------------

    def text(self) -> str:
        start, end = self.buffer.get_bounds()
        return self.buffer.get_text(start, end, True)

    def name(self) -> str:
        return self.name_row.get_text().strip() if self.name_row else self.module_name

    def _relint(self) -> bool:
        self._relint_source = 0
        self.findings = te_lint.lint(self.text(), self.category, self.booleans)
        self._show_findings()
        self._tint()
        verdict = te_lint.verdict(self.findings)
        if verdict == te_lint.DANGEROUS:
            count = sum(f.severity == te_lint.DANGEROUS for f in self.findings)
            self.status_label.set_text(f"Install asks you to acknowledge {count} dangerous finding(s)")
            self.status_label.set_css_classes(["error"])
        elif verdict == te_lint.REVIEW:
            self.status_label.set_text("Worth a second look before installing")
            self.status_label.set_css_classes(["warning"])
        else:
            self.status_label.set_text("Looks fine")
            self.status_label.set_css_classes(["success"])
        return False

    def _show_findings(self) -> None:
        while (child := self.findings_list.get_first_child()) is not None:
            self.findings_list.remove(child)
        self.findings_title.set_text(f"What the linter found ({len(self.findings)})" if self.findings
                                     else "What the linter found")
        if not self.findings:
            self.findings_list.append(Adw.ActionRow(title="Nothing - these rules look ordinary"))
            return
        for finding in self.findings:
            where = f"line {finding.line} · " if finding.line else ""
            row = Adw.ActionRow(title=esc(finding.message), subtitle=esc(f"{where}{finding.why}"))
            row.set_activatable(bool(finding.line))
            row.finding = finding
            badge = Gtk.Label(label=selinux_lint._SEVERITY_LABEL[finding.severity], valign=Gtk.Align.CENTER,
                              css_classes=["caption", _BADGE_CLASS[finding.severity]])
            row.add_prefix(badge)
            label = _FIX_LABELS.get(finding.fix)
            if label and (finding.fix != "drop" or finding.perms) and (finding.fix != "boolean" or finding.detail):
                button = Gtk.Button(label=f"{label} {finding.detail}".strip(), valign=Gtk.Align.CENTER)
                button.connect("clicked", self._on_fix_clicked, finding)
                row.add_suffix(button)
            elif finding.fix == "permissive":
                row.set_tooltip_text("semanage permissive -a <domain> while you investigate, then remove it")
            self.findings_list.append(row)

    def _tint(self) -> None:
        start, end = self.buffer.get_bounds()
        for severity in _TINTS:
            self.buffer.remove_tag_by_name(severity, start, end)
        for finding in reversed(self.findings):  # most severe applied last, so it shows
            if not finding.line or finding.line > self.buffer.get_line_count():
                continue
            ok_start, line_start = self.buffer.get_iter_at_line(finding.line - 1)
            line_end = line_start.copy()
            if not line_end.ends_line():
                line_end.forward_to_line_end()
            if ok_start:
                self.buffer.apply_tag_by_name(finding.severity, line_start, line_end)

    # -- events -----------------------------------------------------------------

    def _on_buffer_changed(self, _buffer) -> None:
        if self._relint_source:
            GLib.source_remove(self._relint_source)
        self._relint_source = GLib.timeout_add(600, self._relint)

    def _on_category_toggled(self, button: Gtk.ToggleButton, key: str) -> None:
        if not button.get_active() or key == self.category:
            return
        self.category = key
        try:
            selinux.set_module_category(self.name(), key)
        except (ValueError, OSError):
            pass  # not saved yet: the category is written when it is
        self._relint()

    def _on_finding_activated(self, _list, row) -> None:
        finding = getattr(row, "finding", None)
        if finding is None or not finding.line:
            return
        ok, where = self.buffer.get_iter_at_line(finding.line - 1)
        if ok:
            self.buffer.place_cursor(where)
            self.text_view.scroll_to_iter(where, 0.2, False, 0, 0)
            self.text_view.grab_focus()

    def _on_fix_clicked(self, _btn, finding) -> None:
        if finding.fix == "drop":
            self.buffer.set_text(te_lint.drop_perms(self.text(), finding))
        elif finding.fix == "dontaudit":
            self.buffer.set_text(te_lint.to_dontaudit(self.text(), finding))
        elif finding.fix == "boolean":
            name = finding.detail
            self.page.confirm(
                f"Turn on {name}?",
                "Persistent (setsebool -P). It switches every rule behind that boolean, not only these; "
                "turn it off again on the SELinux page.",
                "Turn on",
                lambda: self.page.run_action(
                    lambda: selinux.set_boolean(name, True),
                    lambda r, e: self.page.handle_command_result(r, e, f"{name} is on", refresh=False),
                ),
            )
            return
        self._relint()

    def _remember_category(self) -> None:
        try:
            selinux.set_module_category(self.name(), self.category)
        except (ValueError, OSError) as exc:
            raise ValueError(str(exc)) from exc

    def _on_install(self, _btn) -> None:
        name, text = self.name(), self.text()
        try:
            self._remember_category()
        except ValueError as exc:
            self.page.notify(str(exc), is_error=True)
            return
        findings = te_lint.lint(text, self.category, self.booleans)

        def install(acks):
            result = selinux.compile_and_load_te(text, name, acks)
            if result.ok and self.on_done:
                GLib.idle_add(self.on_done)
            return result

        selinux_lint.install(
            self.page, f"Install {name}?",
            "Compiles it and loads it into the running policy with semodule -i. It takes effect immediately.",
            findings, install,
        )

    def _on_save(self, _btn) -> None:
        name, text, category = self.name(), self.text(), self.category

        def done(result, error) -> bool:
            if error:
                self.page.notify(f"Couldn't save {name}: {error}", is_error=True)
            else:
                self.page.notify(f"{name} saved to Pending (SELinux: Modules)")
                if self.on_done:
                    self.on_done()
            return False

        self.page.run_action(lambda: selinux.save_draft(text, name, category), done)

    def _on_discard(self, _btn) -> None:
        name = self.name()

        def discard() -> None:
            try:
                selinux.discard_draft(name)
            except (ValueError, OSError) as exc:
                self.page.notify(f"Couldn't discard {name}: {exc}", is_error=True)
                return
            self.page.notify(f"{name} discarded")
            if self.on_done:
                self.on_done()

        self.page.confirm(f"Discard {name}?", "Deletes the draft's files from Pending. Nothing installed changes.",
                          "Discard", discard)
