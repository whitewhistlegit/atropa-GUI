"""
atropa.ui.pages.selinux_load - SELinux: Modules.

Every module Atropa knows about, linted: the ones it installed (active or
not), the ones waiting in Pending, and any .te loaded from disk or written
here. Opening one shows the same module view as the Denials page - category,
findings with safer options, editable source, gated Install - so a
hand-loaded .te gets the same checks as a draft. Everything loaded in the
policy, Atropa's or not, is listed at the bottom.
"""

from __future__ import annotations

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, Gtk  # noqa: E402

from atropa.backend import selinux, te_lint
from atropa.ui import selinux_lint
from atropa.ui.pages import BasePage, esc
from atropa.ui.selinux_module_view import ModuleView

TE_TEMPLATE = """module local_policy 1.0;

require {
    type unconfined_t;
    class file { read write };
}

# Example - replace with the rule(s) you actually need:
# allow unconfined_t self:file { read write };
"""


def _module_findings(directory: Path, name: str) -> tuple[str, str, list]:
    """(source text, category, findings) for a module's .te in `directory`."""
    source = directory / f"{name}.te"
    try:
        text = source.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "", "unsure", []
    category = te_lint.read_meta(directory, name)["category"]
    return text, category, te_lint.lint(text, category)


class SelinuxLoadPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self.installed_group = self.add_group(
            "Installed by Atropa",
            "Every module installed here. Inactive means it was removed, or the policy store changed "
            "(each SELINUXTYPE has its own module list).",
        )
        self.reinstall_all_btn = Gtk.Button(label="Reinstall all inactive", valign=Gtk.Align.CENTER)
        self.reinstall_all_btn.connect("clicked", self._on_reinstall_all_clicked)
        self.installed_group.set_header_suffix(self.reinstall_all_btn)

        self.pending_group = self.add_group(
            "Pending", "Compiled, not installed: drafts saved for later, imports, earlier sessions.",
        )

        write_group = self.add_group("Write or load a module")
        new_row = Adw.ActionRow(title="New module", subtitle="Start from an empty template")
        new_btn = Gtk.Button(label="New…", valign=Gtk.Align.CENTER)
        new_btn.connect("clicked", lambda _b: self.load_te_text(TE_TEMPLATE, "local_policy"))
        new_row.add_suffix(new_btn)
        write_group.add(new_row)
        file_row = Adw.ActionRow(title="Load a .te file", subtitle="Opens it here to review and install")
        file_btn = Gtk.Button(label="Choose…", valign=Gtk.Align.CENTER)
        file_btn.connect("clicked", self._on_load_file)
        file_row.add_suffix(file_btn)
        write_group.add(file_row)
        import_row = Adw.ActionRow(title="Import several .te files",
                                   subtitle="Each is compiled into Pending for review; nothing is installed")
        import_btn = Gtk.Button(label="Choose…", valign=Gtk.Align.CENTER)
        import_btn.connect("clicked", self._on_import_files)
        import_row.add_suffix(import_btn)
        write_group.add(import_row)

        self.loaded_group = self.add_group("Loaded in the policy")
        self.loaded_expander = Adw.ExpanderRow(title="Loaded modules", subtitle="Loading…")
        self.loaded_group.add(self.loaded_expander)
        self._loaded_rows: list = []
        self._installed_rows: list = []
        self._pending_rows: list = []

        self.refresh()

    def refresh(self) -> None:
        self.clear_rows(self.installed_group, self._installed_rows)
        self._installed_rows = [self.start_loading(self.installed_group, "Loading…")]
        self.run_async(selinux.list_approved_modules, self._on_approved_loaded)
        self.clear_rows(self.pending_group, self._pending_rows)
        self._pending_rows = [self.start_loading(self.pending_group, "Loading…")]
        self.run_async(selinux.list_pending_modules, self._on_pending_loaded)
        self.run_async(selinux.list_semodules, self._on_modules_loaded)

    # -- the module view -------------------------------------------------------

    def load_te_text(self, text: str, module_name: str, category: str = "unsure", allow_discard: bool = False) -> None:
        """Open a module in the module view (also what other pages call to hand one over)."""
        dialog = Adw.Dialog(title=module_name, content_width=760, content_height=720)
        view = ModuleView(self, module_name, text, category, editable_name=True, allow_discard=allow_discard,
                          on_done=lambda: (dialog.close(), self.refresh()))
        view.set_margin_top(12)
        view.set_margin_bottom(12)
        view.set_margin_start(12)
        view.set_margin_end(12)
        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_child(view)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        toolbar.set_content(scroller)
        dialog.set_child(toolbar)
        dialog.present(self.get_root())

    def _open_module(self, _btn, directory: Path, name: str, allow_discard: bool) -> None:
        text, category, _findings = _module_findings(directory, name)
        if not text:
            self.notify(f"{name} has no .te source to show", is_error=True)
            return
        self.load_te_text(text, name, category, allow_discard)

    # -- installed ---------------------------------------------------------------

    def _on_approved_loaded(self, result, error) -> bool:
        self.clear_rows(self.installed_group, self._installed_rows)
        self._installed_rows = []
        if error:
            self.notify(f"Couldn't list installed modules: {error}", is_error=True)
            return False
        if not result:
            self._add(self.installed_group, self._installed_rows, Adw.ActionRow(title="Nothing installed yet"))
            self.reinstall_all_btn.set_visible(False)
            return False
        self.reinstall_all_btn.set_visible(any(not entry["active"] for entry in result))
        for entry in result:
            _text, category, findings = _module_findings(selinux.APPROVED_MODULES_DIR, entry["name"])
            state = "Active" if entry["active"] else "Inactive"
            row = Adw.ActionRow(title=esc(entry["name"]), subtitle=esc(
                f"{state} · {selinux_lint.badge(findings)} · {te_lint.CATEGORIES.get(category, '')}"))
            open_btn = Gtk.Button(label="Open", valign=Gtk.Align.CENTER, css_classes=["flat"])
            open_btn.connect("clicked", self._open_module, selinux.APPROVED_MODULES_DIR, entry["name"], False)
            row.add_suffix(open_btn)
            if entry["active"]:
                remove = Gtk.Button(label="Remove", valign=Gtk.Align.CENTER)
                remove.connect("clicked", self._on_remove_module, entry["name"])
                row.add_suffix(remove)
            else:
                reinstall = Gtk.Button(label="Reinstall", valign=Gtk.Align.CENTER)
                reinstall.connect("clicked", self._on_install_pp, entry["name"], entry["path"], findings)
                row.add_suffix(reinstall)
            self._add(self.installed_group, self._installed_rows, row)
        return False

    def _on_remove_module(self, _btn: Gtk.Button, module_name: str) -> None:
        self.confirm(
            f"Remove policy module '{module_name}'?",
            "Anything it allowed will go back to being denied. Its files stay, so it can be reinstalled.",
            "Remove",
            lambda: self.run_action(lambda: selinux.remove_semodule(module_name), self.handle_command_result),
        )

    def _on_reinstall_all_clicked(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Reinstall every inactive module?",
            "One semodule call, one password prompt. Modules with dangerous findings you haven't "
            "acknowledged are held back - reinstall those one at a time.",
            "Reinstall all",
            lambda: self.run_action(selinux.reinstall_all_approved_modules, self.handle_command_result),
            destructive=False,
        )

    # -- pending -----------------------------------------------------------------

    def _on_pending_loaded(self, result, error) -> bool:
        self.clear_rows(self.pending_group, self._pending_rows)
        self._pending_rows = []
        if error:
            self.notify(f"Couldn't list pending modules: {error}", is_error=True)
            return False
        if not result:
            self._add(self.pending_group, self._pending_rows, Adw.ActionRow(title="Nothing pending"))
            return False
        for name, pp_path in result:
            _text, category, findings = _module_findings(Path(pp_path).parent, name)
            row = Adw.ActionRow(title=esc(name), subtitle=esc(
                f"{selinux_lint.badge(findings)} · {te_lint.CATEGORIES.get(category, '')}"))
            open_btn = Gtk.Button(label="Open", valign=Gtk.Align.CENTER, css_classes=["flat"])
            open_btn.connect("clicked", self._open_module, Path(pp_path).parent, name, True)
            row.add_suffix(open_btn)
            install = Gtk.Button(label="Install", valign=Gtk.Align.CENTER)
            install.connect("clicked", self._on_install_pp, name, pp_path, findings)
            row.add_suffix(install)
            discard = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"],
                                 tooltip_text="Discard")
            discard.connect("clicked", self._on_discard_pending, name)
            row.add_suffix(discard)
            self._add(self.pending_group, self._pending_rows, row)
        return False

    def _on_install_pp(self, _btn: Gtk.Button, module_name: str, pp_path: str, findings: list) -> None:
        selinux_lint.install(
            self, f"Install {module_name}?",
            f"Loads {pp_path} into the running SELinux policy with semodule -i.",
            findings,
            lambda acks: selinux.install_pp_file(pp_path, acks),
        )

    def _on_discard_pending(self, _btn: Gtk.Button, module_name: str) -> None:
        try:
            selinux.discard_draft(module_name)
        except (ValueError, OSError) as exc:
            self.notify(f"Couldn't discard: {exc}", is_error=True)
            return
        self.refresh()

    # -- loaded ------------------------------------------------------------------

    def _on_modules_loaded(self, result, error) -> bool:
        for row in self._loaded_rows:
            self.loaded_expander.remove(row)
        self._loaded_rows = []
        if error:
            self.loaded_expander.set_subtitle(esc(f"Couldn't list them: {error}"))
            return False
        self.loaded_expander.set_subtitle(f"{len(result)} module(s)")
        for name in result:
            row = Adw.ActionRow(title=esc(name))
            remove = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"],
                                tooltip_text="Remove from the policy")
            remove.connect("clicked", self._on_remove_module, name)
            row.add_suffix(remove)
            self.loaded_expander.add_row(row)
            self._loaded_rows.append(row)
        return False

    # -- files -------------------------------------------------------------------

    def _te_dialog(self) -> Gtk.FileDialog:
        dialog = Gtk.FileDialog()
        filt = Gtk.FileFilter()
        filt.set_name("SELinux policy source (.te)")
        filt.add_pattern("*.te")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filt)
        dialog.set_filters(filters)
        return dialog

    def _on_load_file(self, _btn: Gtk.Button) -> None:
        self._te_dialog().open(self.get_root(), None, self._on_file_chosen)

    def _on_file_chosen(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            gfile = dialog.open_finish(result)
        except Exception:  # noqa: BLE001 - cancelled
            return
        path = gfile.get_path() if gfile else None
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self.notify(f"Couldn't read file: {exc}", is_error=True)
            return
        self.load_te_text(content, selinux._module_name_from_te(content, Path(path).stem))

    def _on_import_files(self, _btn: Gtk.Button) -> None:
        self._te_dialog().open_multiple(self.get_root(), None, self._on_import_files_chosen)

    def _on_import_files_chosen(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            gfiles = dialog.open_multiple_finish(result)
        except Exception:  # noqa: BLE001 - cancelled
            return
        paths = [gfiles.get_item(i).get_path() for i in range(gfiles.get_n_items())] if gfiles else []
        paths = [p for p in paths if p]
        if not paths:
            return
        self.confirm(
            f"Import {len(paths)} .te file(s)?",
            "Each one is compiled into Pending for review - nothing is installed. A file that fails to "
            "compile is reported and skipped.",
            "Import",
            lambda: self.run_async(lambda: selinux.import_te_files(paths), self._on_import_done),
            destructive=False,
        )

    def _on_import_done(self, result, error) -> bool:
        if error:
            self.notify(f"Import failed: {error}", is_error=True)
            return False
        failed = [r for r in result if r.error is not None]
        ok = len(result) - len(failed)
        if failed:
            detail = "; ".join(f"{Path(r.source_path).name}: {r.error}" for r in failed[:3])
            self.notify(f"{ok} imported, {len(failed)} failed - {detail}", is_error=not ok)
        else:
            self.notify(f"{ok} module(s) imported into Pending")
        self.refresh()
        return False

    def _add(self, group, rows: list, row) -> None:
        group.add(row)
        rows.append(row)
