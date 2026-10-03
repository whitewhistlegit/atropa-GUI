"""atropa.ui.pages.selinux_load - Compile and load a SELinux .te policy module."""

from __future__ import annotations

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, Gtk  # noqa: E402

from atropa.backend import selinux
from atropa.ui.pages import BasePage, esc

TE_TEMPLATE = """module local_policy 1.0;

require {
    type unconfined_t;
    class file { read write };
}

# Example - replace with the rule(s) you actually need:
# allow unconfined_t self:file { read write };
"""


class SelinuxLoadPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        intro_group = self.add_group(
            "Load a Policy Module",
            "Paste .te text, load one from disk, or send one over from a 'Generate .te' "
            "denial on the SELinux page, then compile and install it - or import a whole batch "
            "of already-written .te files at once (they go to Pending below for individual "
            "review and install, rather than installing immediately).",
        )

        self.module_name_row = Adw.EntryRow(title="Module name")
        self.module_name_row.set_text("local_policy")
        intro_group.add(self.module_name_row)

        load_file_btn = Gtk.Button(label="Load .te file from disk…")
        load_file_btn.connect("clicked", self._on_load_file)
        intro_group.add(load_file_btn)

        import_files_btn = Gtk.Button(label="Import .te files… (batch, goes to Pending for review)")
        import_files_btn.connect("clicked", self._on_import_files)
        intro_group.add(import_files_btn)

        editor_group = self.add_group(".te Contents")
        self.buffer = Gtk.TextBuffer()
        self.buffer.set_text(TE_TEMPLATE)
        text_view = Gtk.TextView(buffer=self.buffer, monospace=True)
        text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        text_view.set_top_margin(8)
        text_view.set_bottom_margin(8)
        text_view.set_left_margin(8)
        text_view.set_right_margin(8)
        scroller = Gtk.ScrolledWindow(min_content_height=280)
        scroller.set_child(text_view)
        scroller.add_css_class("card")
        editor_group.add(scroller)

        compile_btn = Gtk.Button(label="Compile & Load", css_classes=["suggested-action"])
        compile_btn.set_margin_top(8)
        compile_btn.connect("clicked", self._on_compile_clicked)
        editor_group.add(compile_btn)

        modules_group = self.add_group("Loaded Policy Modules")
        self.modules_group = modules_group

        approved_group = self.add_group(
            "Approved (Installed History)",
            "Everything ever installed via this app. 'Inactive' means it was later removed, or that the "
            "active policy store changed (each SELINUXTYPE has its own module list) - reinstall one at a "
            "time, or all at once below in a single authentication prompt.",
        )
        self.approved_group = approved_group
        reinstall_all_row = Adw.ActionRow(title="Reinstall every inactive approved module")
        self.reinstall_all_btn = Gtk.Button(label="Reinstall All Inactive", valign=Gtk.Align.CENTER)
        self.reinstall_all_btn.connect("clicked", self._on_reinstall_all_clicked)
        reinstall_all_row.add_suffix(self.reinstall_all_btn)
        approved_group.add(reinstall_all_row)

        pending_group = self.add_group(
            "Pending (Compiled, Not Installed)",
            "From a review batch on the SELinux page - or a previous session. Nothing here is active yet.",
        )
        self.pending_group = pending_group

        self.refresh()

    def refresh(self) -> None:
        self.clear_rows(self.modules_group, getattr(self, "_module_rows", []))
        self._module_rows = [self.start_loading(self.modules_group, "Loading loaded modules…")]
        self.run_async(selinux.list_semodules, self._on_modules_loaded)
        self.clear_rows(self.pending_group, getattr(self, "_pending_rows", []))
        self._pending_rows = [self.start_loading(self.pending_group, "Loading pending modules…")]
        self.run_async(selinux.list_pending_modules, self._on_pending_loaded)
        self.clear_rows(self.approved_group, getattr(self, "_approved_rows", []))
        self._approved_rows = [self.start_loading(self.approved_group, "Loading approved modules…")]
        self.run_async(selinux.list_approved_modules, self._on_approved_loaded)

    def load_te_text(self, text: str, module_name: str) -> None:
        """Called from the SELinux page's 'Generate .te' dialog to hand off generated text here."""
        self.buffer.set_text(text)
        self.module_name_row.set_text(module_name)

    def _on_load_file(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileDialog()
        filt = Gtk.FileFilter()
        filt.set_name("SELinux policy source (.te)")
        filt.add_pattern("*.te")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filt)
        dialog.set_filters(filters)
        dialog.open(self.get_root(), None, self._on_file_chosen)

    def _on_file_chosen(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            gfile = dialog.open_finish(result)
        except Exception:  # noqa: BLE001 - user cancelled or dialog error, nothing to do
            return
        if not gfile:
            return
        path = gfile.get_path()
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as exc:
            self.notify(f"Couldn't read file: {exc}", is_error=True)
            return
        self.buffer.set_text(content)
        stem = path.rsplit("/", 1)[-1].removesuffix(".te")
        if stem:
            self.module_name_row.set_text(stem)

    def _on_import_files(self, _btn: Gtk.Button) -> None:
        """
        Batch import - e.g. a folder of hand-kept or third-party .te files,
        as opposed to the single paste/load-then-Compile-&-Load flow above,
        which installs directly. Deliberately routes through
        import_te_files() -> Pending instead: a batch of files that may
        never have been individually opened doesn't get the same "the
        person clicking the button just read this" assumption a single
        loaded-into-the-editor file does.
        """
        dialog = Gtk.FileDialog()
        filt = Gtk.FileFilter()
        filt.set_name("SELinux policy source (.te)")
        filt.add_pattern("*.te")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filt)
        dialog.set_filters(filters)
        dialog.open_multiple(self.get_root(), None, self._on_import_files_chosen)

    def _on_import_files_chosen(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            gfiles = dialog.open_multiple_finish(result)
        except Exception:  # noqa: BLE001 - user cancelled or dialog error, nothing to do
            return
        if gfiles is None:
            return

        paths = []
        for i in range(gfiles.get_n_items()):
            gfile = gfiles.get_item(i)
            path = gfile.get_path()
            if path:
                paths.append(path)
        if not paths:
            return

        self.confirm(
            f"Import {len(paths)} .te file(s)?",
            "Each one is compiled and added to Pending below for individual review and install - "
            "nothing here installs anything into the running policy directly. A file that fails to "
            "compile is reported and skipped rather than blocking the rest of the batch.",
            "Import",
            lambda: self.run_async(lambda: selinux.import_te_files(paths), self._on_import_done),
        )

    def _on_import_done(self, result, error) -> bool:
        if error:
            self.notify(f"Import failed: {error}", is_error=True)
            return False

        succeeded = [r for r in result if r.error is None]
        failed = [r for r in result if r.error is not None]

        if failed:
            detail = "; ".join(f"{Path(r.source_path).name}: {r.error}" for r in failed[:3])
            if len(failed) > 3:
                detail += f"; +{len(failed) - 3} more"
            self.notify(
                f"{len(succeeded)} imported, {len(failed)} failed - {detail}",
                is_error=not succeeded,
            )
        else:
            self.notify(f"{len(succeeded)} module(s) imported - review them in Pending below")

        self.refresh()
        return False

    def _on_compile_clicked(self, _btn: Gtk.Button) -> None:
        module_name = self.module_name_row.get_text().strip()
        start, end = self.buffer.get_bounds()
        te_content = self.buffer.get_text(start, end, True)

        if not module_name:
            self.notify("Enter a module name first", is_error=True)
            return
        if not te_content.strip():
            self.notify("The .te content is empty", is_error=True)
            return

        self.confirm(
            f"Compile and load '{module_name}'?",
            "This compiles the policy text and installs it into the running SELinux "
            "policy with semodule -i. Review the .te content carefully before continuing - "
            "it takes effect immediately.",
            "Compile & Load",
            lambda: self.run_async(lambda: selinux.compile_and_load_te(te_content, module_name), self.handle_command_result),
        )

    def _on_modules_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_module_rows", [])):
            self.modules_group.remove(row)
        self._module_rows = []

        if error:
            self.notify(f"Couldn't list policy modules: {error}", is_error=True)
            return False

        if not result:
            row = Adw.ActionRow(title="No custom policy modules loaded")
            self.modules_group.add(row)
            self._module_rows.append(row)
            return False

        for name in result:
            row = Adw.ActionRow(title=esc(name))
            remove_btn = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"])
            remove_btn.connect("clicked", self._on_remove_module, name)
            row.add_suffix(remove_btn)
            self.modules_group.add(row)
            self._module_rows.append(row)
        return False

    def _on_remove_module(self, _btn: Gtk.Button, module_name: str) -> None:
        self.confirm(
            f"Remove policy module '{module_name}'?",
            "Anything it allowed will go back to being denied.",
            "Remove",
            lambda: self.run_async(lambda: selinux.remove_semodule(module_name), self.handle_command_result),
        )

    def _on_approved_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_approved_rows", [])):
            self.approved_group.remove(row)
        self._approved_rows = []

        if error:
            self.notify(f"Couldn't list approved modules: {error}", is_error=True)
            return False

        if not result:
            row = Adw.ActionRow(title="Nothing approved yet")
            self.approved_group.add(row)
            self._approved_rows.append(row)
            return False

        for entry in result:
            status = "Active" if entry["active"] else "Inactive (removed from policy)"
            row = Adw.ActionRow(title=esc(entry["name"]), subtitle=esc(status))
            if not entry["active"]:
                reinstall_btn = Gtk.Button(label="Reinstall", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
                reinstall_btn.connect("clicked", self._on_install_pending, entry["name"], entry["path"])
                row.add_suffix(reinstall_btn)
            self.approved_group.add(row)
            self._approved_rows.append(row)
        return False

    def _on_reinstall_all_clicked(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Reinstall every inactive approved module?",
            "Installs all of them in a single semodule call - one authentication prompt total, "
            "instead of one per module. Common right after switching SELINUXTYPE, where a whole "
            "batch can go inactive at once for a reason that has nothing to do with any single "
            "module being untrustworthy.",
            "Reinstall All",
            lambda: self.run_async(selinux.reinstall_all_approved_modules, self.handle_command_result),
        )

    def _on_pending_loaded(self, result, error) -> bool:
        for row in list(getattr(self, "_pending_rows", [])):
            self.pending_group.remove(row)
        self._pending_rows = []

        if error:
            self.notify(f"Couldn't list pending modules: {error}", is_error=True)
            return False

        if not result:
            row = Adw.ActionRow(title="Nothing pending")
            self.pending_group.add(row)
            self._pending_rows.append(row)
            return False

        for name, pp_path in result:
            row = Adw.ActionRow(title=esc(name), subtitle=esc(pp_path))

            install_btn = Gtk.Button(label="Install", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
            install_btn.connect("clicked", self._on_install_pending, name, pp_path)
            row.add_suffix(install_btn)

            discard_btn = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, css_classes=["flat"])
            discard_btn.connect("clicked", self._on_discard_pending, pp_path)
            row.add_suffix(discard_btn)

            self.pending_group.add(row)
            self._pending_rows.append(row)
        return False

    def _on_install_pending(self, _btn: Gtk.Button, module_name: str, pp_path: str) -> None:
        self.confirm(
            f"Install policy module '{module_name}'?",
            f"Loads {pp_path} into the running SELinux policy with semodule -i.",
            "Install",
            lambda: self.run_async(lambda: selinux.install_pp_file(pp_path), self.handle_command_result),
        )

    def _on_discard_pending(self, _btn: Gtk.Button, pp_path: str) -> None:
        try:
            Path(pp_path).unlink(missing_ok=True)
        except OSError as exc:
            self.notify(f"Couldn't delete: {exc}", is_error=True)
            return
        self.refresh()
