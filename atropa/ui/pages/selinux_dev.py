"""
atropa.ui.pages.selinux_dev
-----------------------------
SELinux: Dev - experimental drafting against the running policy's own
source, ported from atropa-scratch. Denials are grouped by program; each
rule can be written as a plain allow, a dontaudit, an interface call the
policy source offers, or skipped, and the module is compiled (and, against
a tree, linked) to check it. Nothing here installs anything: the Denials
page remains the way modules get onto the system.
"""

from __future__ import annotations

import os

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from atropa.backend import policy_draft, policy_source, selinux
from atropa.ui.pages import BasePage, esc

_DECISION_LABELS = {
    policy_draft.ALLOW: "allow",
    policy_draft.DONTAUDIT: "dontaudit",
    policy_draft.SKIP: "skip",
}


def _rule_title(rule: policy_draft.Rule) -> str:
    return f"{rule.tgt}:{rule.tclass} {policy_draft.render_perms(rule.perms)}"


def _choice_options(rule: policy_draft.Rule) -> list[tuple[str, str, str]]:
    """[(label, decision, interface)] for a rule's dropdown, interfaces after the plain choices."""
    options = [("allow" + (f" ({rule.perm_set})" if rule.perm_set else ""), policy_draft.ALLOW, ""),
               ("dontaudit", policy_draft.DONTAUDIT, ""),
               ("skip", policy_draft.SKIP, "")]
    options += [(f"{name}() +{extra}", policy_draft.IFACE, name) for name, extra in rule.choices]
    return options


class SelinuxDevPage(BasePage):
    def __init__(self) -> None:
        super().__init__()
        self._source: policy_source.PolicySource | None = None
        self._kb: policy_source.PolicyKB | None = None
        self._by_domain: dict[str, list[policy_draft.Rule]] = {}
        self._domain = ""
        self._domain_rows: list = []
        self._content_groups: list = []
        self._te_buffer: Gtk.TextBuffer | None = None
        self._build_row: Adw.ActionRow | None = None
        self._last_build: policy_draft.BuildResult | None = None

        sidebar = Adw.PreferencesPage()
        self.detail = Adw.PreferencesPage()
        self.empty = Adw.StatusPage(
            icon_name="applications-engineering-symbolic", title="Experimental drafting",
            description="Reads denials, suggests the policy source's own interfaces for each rule, and compiles "
                        "the module against that source to check it. Nothing here is installed.",
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

        source_group = self.add_group(
            "Policy source",
            "Only a source that builds the running policy is used: its interfaces and build are what a module "
            "will be loaded against.",
        )
        self.source_row = Adw.ActionRow(title="Looking for a policy source…")
        self.source_row.set_subtitle_lines(4)
        pick_btn = Gtk.Button(label="Choose…", valign=Gtk.Align.CENTER,
                              tooltip_text="A Reference Policy source tree or headers directory")
        pick_btn.connect("clicked", lambda _b: self._on_pick_tree())
        self.source_row.add_suffix(pick_btn)
        source_group.add(self.source_row)

        denials_group = self.add_group("Denials")
        read_row = Adw.ActionRow(title="Read denials")
        journal_btn = Gtk.Button(label="Kernel log", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        journal_btn.connect("clicked", lambda _b: self._on_read("journal"))
        audit_btn = Gtk.Button(label="audit.log", valign=Gtk.Align.CENTER, tooltip_text="Asks for your password")
        audit_btn.connect("clicked", lambda _b: self._on_read("audit_log"))
        read_row.add_suffix(journal_btn)
        read_row.add_suffix(audit_btn)
        denials_group.add(read_row)
        self.summary_row = Adw.ActionRow(title="No denials read yet")
        denials_group.add(self.summary_row)

        self.programs_group = self.add_group("Programs")
        self.refresh()

    # ------------------------------------------------------------ source --

    def refresh(self) -> None:
        self.run_async(self._load_source, self._on_source_loaded)

    @staticmethod
    def _load_source():
        source = policy_source.find_source()
        kb = policy_source.load(source) if source.usable else None
        return source, kb

    def _on_source_loaded(self, result, error) -> None:
        if error:
            self._source, self._kb = None, None
            self.source_row.set_title("Couldn't read the policy source")
            self.source_row.set_subtitle(esc(error))
            return
        self._source, self._kb = result
        if self._kb is None:
            self.source_row.set_title("No policy source")
            self.source_row.set_subtitle(esc(self._source.note + ". Choose the tree the running policy is built "
                                                                  "from to get suggestions."))
        else:
            kind = "Source tree" if self._source.kind == "tree" else "Installed headers"
            self.source_row.set_title(esc(f"{kind} · {self._source.name}"))
            self.source_row.set_subtitle(esc(
                f"{self._source.root}\n{len(self._kb.interfaces)} interfaces · {len(self._kb.perm_sets)} permission "
                f"sets · {len(self._kb.classes)} classes"
            ))
        self._annotate_all()
        if self._domain:
            self._show_domain(self._domain)

    def _on_pick_tree(self) -> None:
        dialog = Gtk.FileDialog(title="Choose the running policy's source tree or headers")
        start = (self._source.root if self._source and self._source.root else "") or os.path.expanduser("~")
        if os.path.isdir(start):
            dialog.set_initial_folder(Gio.File.new_for_path(start))
        dialog.select_folder(self.get_root(), None, self._on_tree_chosen)

    def _on_tree_chosen(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            folder = dialog.select_folder_finish(result)
        except GLib.Error:
            return  # cancelled
        try:
            root = policy_source.remember_tree(folder.get_path())
        except (ValueError, OSError) as exc:
            self.notify(str(exc), is_error=True)
            return
        kind, _ = policy_source.detect_layout(root)
        name = policy_source.source_name(kind, root)
        running = policy_source.running_policy_name()
        if name != running:
            self.notify(f"{root} builds {name or 'an unnamed policy'}, not {running} - saved, but not used",
                        is_error=True)
        self.source_row.set_title("Reading the policy source…")
        self.source_row.set_subtitle("")
        self.refresh()

    # ----------------------------------------------------------- denials --

    def _on_read(self, source: str) -> None:
        self.summary_row.set_title("Reading denials…")
        self.summary_row.set_subtitle("")
        self.clear_rows(self.programs_group, self._domain_rows)
        self._domain_rows = [self.start_loading(self.programs_group, "Reading…")]

        def work():
            lines = selinux.list_all_denials(since=selinux.get_setup_mode_started_at(), source=source)
            return len(lines), policy_draft.rules_from_denials(lines)

        self.run_async(work, self._on_denials_read)

    def _on_denials_read(self, result, error) -> None:
        self.clear_rows(self.programs_group, self._domain_rows)
        self._domain_rows = []
        if error:
            self.summary_row.set_title("Couldn't read denials")
            self.summary_row.set_subtitle(esc(error))
            return
        count, self._by_domain = result
        self.summary_row.set_title(f"{len(self._by_domain)} program(s) · {count} denial line(s)")
        self._annotate_all()
        self._render_domains()

    def _annotate_all(self) -> None:
        if self._kb is None:
            return
        for rules in self._by_domain.values():
            policy_draft.annotate(rules, self._kb)

    def _render_domains(self) -> None:
        self.clear_rows(self.programs_group, self._domain_rows)
        self._domain_rows = []
        if not self._by_domain:
            row = Adw.ActionRow(title="No denials")
            self.programs_group.add(row)
            self._domain_rows.append(row)
            return
        order = sorted(self._by_domain, key=lambda d: (-sum(r.count for r in self._by_domain[d]), d))
        for domain in order:
            rules = self._by_domain[domain]
            names = []
            for rule in rules:
                names += [n for n in rule.programs if n not in names]
            row = Adw.ActionRow(title=esc(", ".join(names[:3]) or domain),
                                subtitle=esc(f"{domain} · {len(rules)} rule(s) · {sum(r.count for r in rules)} denial(s)"),
                                activatable=True)
            row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
            row.connect("activated", self._on_domain_activated, domain)
            self.programs_group.add(row)
            self._domain_rows.append(row)

    def _on_domain_activated(self, _row, domain: str) -> None:
        self._show_domain(domain)
        self.split.set_show_content(True)

    # ------------------------------------------------------------ detail --

    def _detail_group(self, title: str, description: str = "") -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(title=esc(title))
        if description:
            group.set_description(esc(description))
        self.detail.add(group)
        self._content_groups.append(group)
        return group

    def _module_name(self) -> str:
        return policy_draft.module_name_for(self._domain, self._kb)

    def _show_domain(self, domain: str) -> None:
        if domain not in self._by_domain:
            return
        for group in self._content_groups:
            self.detail.remove(group)
        self._content_groups = []
        self._domain = domain
        self._last_build = None
        rules = self._by_domain[domain]
        self.content_page.set_title(domain)
        self.content_stack.set_visible_child_name("detail")

        rules_group = self._detail_group(
            "Rules", "One per target and class. Interfaces are the policy source's own, tightest first: "
                     "+N is how many more permissions the interface grants in all.",
        )
        if self._kb is not None:
            tight = Gtk.Button(label="Use tight interfaces", valign=Gtk.Align.CENTER,
                               tooltip_text=f"Switch each allow rule to its tightest interface, if it grants at most "
                                            f"{policy_draft.TIGHT_EXTRA} more permissions")
            tight.connect("clicked", self._on_use_tight)
            rules_group.set_header_suffix(tight)
        for rule in rules:
            rules_group.add(self._rule_row(rule))

        module_group = self._detail_group(self._module_name(), "Refpolicy style - only the policy's own build "
                                                                 "compiles it.")
        self._te_buffer = Gtk.TextBuffer()
        view = Gtk.TextView(buffer=self._te_buffer, editable=False, monospace=True, cursor_visible=False,
                            top_margin=8, bottom_margin=8, left_margin=8, right_margin=8)
        view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        scroller = Gtk.ScrolledWindow(min_content_height=200, css_classes=["card"])
        scroller.set_child(view)
        module_group.add(scroller)

        actions = Gtk.ListBox(css_classes=["boxed-list"], selection_mode=Gtk.SelectionMode.NONE, margin_top=12)
        self._build_row = Adw.ActionRow(title="Not built yet")
        self._build_row.set_subtitle_lines(3)
        build_btn = Gtk.Button(label="Build", valign=Gtk.Align.CENTER, css_classes=["suggested-action"],
                               sensitive=self._kb is not None,
                               tooltip_text="Compiles the module against the policy source - installs nothing")
        build_btn.connect("clicked", self._on_build)
        log_btn = Gtk.Button(label="Log", valign=Gtk.Align.CENTER)
        log_btn.connect("clicked", self._on_show_log)
        copy_btn = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Copy the .te")
        copy_btn.connect("clicked", self._on_copy)
        for button in (copy_btn, log_btn, build_btn):
            self._build_row.add_suffix(button)
        actions.append(self._build_row)
        module_group.add(actions)
        self._update_te()

    def _rule_row(self, rule: policy_draft.Rule) -> Adw.ActionRow:
        where = ", ".join(rule.programs[:3])
        if rule.path:
            where += f" · {rule.path}"
        row = Adw.ActionRow(title=esc(_rule_title(rule)), subtitle=esc(f"{rule.count}× · {where}".strip(" ·")))
        options = _choice_options(rule)
        dropdown = Gtk.DropDown.new_from_strings([label for label, _, _ in options])
        dropdown.set_valign(Gtk.Align.CENTER)
        current = next((i for i, (_, d, name) in enumerate(options)
                        if d == rule.decision and name == (rule.iface if d == policy_draft.IFACE else "")), 0)
        dropdown.set_selected(current)
        if rule.choices:
            tips = []
            for name, extra in rule.choices:
                iface = self._kb.interfaces.get(name) if self._kb else None
                tips.append(f"{name} (+{extra})" + (f": {iface.summary}" if iface and iface.summary else ""))
            dropdown.set_tooltip_text("\n".join(tips))
        dropdown.connect("notify::selected", self._on_decision_changed, rule, options)
        row.add_suffix(dropdown)
        return row

    def _on_decision_changed(self, dropdown: Gtk.DropDown, _pspec, rule, options) -> None:
        _, rule.decision, rule.iface = options[dropdown.get_selected()]
        self._update_te()

    def _on_use_tight(self, _btn) -> None:
        changed = policy_draft.use_tight_interfaces(self._by_domain.get(self._domain, []))
        self.notify(f"{changed} rule(s) switched to an interface" if changed else "No close-fitting interfaces")
        self._show_domain(self._domain)

    def _te(self) -> str:
        return policy_draft.gen_te(self._module_name(), self._by_domain.get(self._domain, []))

    def _update_te(self) -> None:
        if self._te_buffer is not None:
            self._te_buffer.set_text(self._te())
        if self._build_row is not None:
            self._last_build = None
            self._build_row.set_title("Not built yet" if self._kb else "No policy source to build against")
            self._build_row.set_subtitle("")

    def _on_copy(self, _btn) -> None:
        Gdk.Display.get_default().get_clipboard().set(self._te())
        self.notify("Copied the .te")

    def _on_build(self, _btn) -> None:
        if self._kb is None:
            return
        module, te, kb, domain = self._module_name(), self._te(), self._kb, self._domain
        self._build_row.set_title("Building…")
        self._build_row.set_subtitle("")

        def done(result, error) -> None:
            if domain != self._domain or self._build_row is None:
                return
            if error:
                self._build_row.set_title("Build failed to run")
                self._build_row.set_subtitle(esc(error))
                return
            self._last_build = result
            self._build_row.set_title("Builds" if result.ok else "Doesn't build")
            self._build_row.set_subtitle(esc(result.summary))

        self.run_async(lambda: policy_draft.build(module, te, kb), done)

    def _on_show_log(self, _btn) -> None:
        text = self._last_build.log() + f"\nbuild dir: {self._last_build.workdir}\n" if self._last_build \
            else "Build the module first."
        view = Gtk.TextView(editable=False, monospace=True, top_margin=10, bottom_margin=10, left_margin=10,
                            right_margin=10)
        view.get_buffer().set_text(text)
        toolbar = Adw.ToolbarView(content=Gtk.ScrolledWindow(child=view, vexpand=True))
        toolbar.add_top_bar(Adw.HeaderBar())
        dialog = Adw.Dialog(title="Build log", content_width=760, content_height=520)
        dialog.set_child(toolbar)
        dialog.present(self.get_root())
