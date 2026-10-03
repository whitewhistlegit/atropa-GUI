"""atropa.ui.pages.quicksetup - Security Quick Setup: a checklist + guided wizard for a recommended security baseline."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import quicksetup
from atropa.ui.pages import BasePage, esc


class QuickSetupPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        intro_group = self.add_group(
            "Security Quick Setup",
            "A recommended baseline across every security module at once - installs anything "
            "missing from scratch, then applies conservative defaults. Uncheck anything you'd "
            "rather configure by hand, then either apply everything selected in one batch, or "
            "walk through it step by step with a chance to skip each one.",
        )

        button_row = Adw.ActionRow(title="Selected items")
        self.selected_count_label = Gtk.Label(label="", css_classes=["dim-label"])
        button_row.add_suffix(self.selected_count_label)
        wizard_btn = Gtk.Button(label="Guided Setup…", valign=Gtk.Align.CENTER)
        wizard_btn.connect("clicked", self._on_start_wizard)
        button_row.add_suffix(wizard_btn)
        apply_btn = Gtk.Button(label="Apply Selected", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        apply_btn.connect("clicked", self._on_apply_selected)
        button_row.add_suffix(apply_btn)
        intro_group.add(button_row)

        self.checklist_group = self.add_group(
            "Checklist",
            "Checked items are included in both 'Apply Selected' and 'Guided Setup' below.",
        )
        self._checkboxes: dict[str, Gtk.CheckButton] = {}
        self._status_labels: dict[str, Gtk.Label] = {}
        for item in quicksetup.CATALOG:
            row = Adw.ActionRow(title=esc(item.title), subtitle=esc(item.description))
            check = Gtk.CheckButton(active=item.default_selected, valign=Gtk.Align.CENTER)
            check.connect("toggled", lambda _c: self._update_selected_count())
            row.add_prefix(check)
            self._checkboxes[item.key] = check

            if item.risk_note:
                warning_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
                warning_icon.set_tooltip_text(item.risk_note)
                row.add_suffix(warning_icon)

            status_label = Gtk.Label(label="…", css_classes=["dim-label"])
            row.add_suffix(status_label)
            self._status_labels[item.key] = status_label

            self.checklist_group.add(row)

        self._update_selected_count()
        self.refresh()

    def _update_selected_count(self) -> None:
        n = sum(1 for cb in self._checkboxes.values() if cb.get_active())
        self.selected_count_label.set_label(f"{n} of {len(self._checkboxes)}")

    def refresh(self) -> None:
        self.run_async(quicksetup.status_summary, self._on_status_loaded)

    def _on_status_loaded(self, result, error) -> bool:
        if error:
            self.notify(f"Couldn't check current status: {error}", is_error=True)
            return False
        for key, label in self._status_labels.items():
            label.set_label(result.get(key, "?"))
        return False

    def _selected_keys(self) -> list[str]:
        return [key for key, cb in self._checkboxes.items() if cb.get_active()]

    # --------------------------------------------------------- batch apply --

    def _on_apply_selected(self, _btn: Gtk.Button) -> None:
        keys = self._selected_keys()
        if not keys:
            self.notify("Nothing selected", is_error=True)
            return
        titles = ", ".join(item.title for item in quicksetup.CATALOG if item.key in keys)
        self.confirm(
            "Apply the selected security baseline?",
            f"This will set up: {titles}. Anything not installed yet gets installed from "
            "scratch first. Progress is shown live.",
            "Apply",
            lambda: self.run_streaming_operation(
                "Applying Security Baseline",
                lambda on_line: quicksetup.apply_items(keys, on_line),
                self._on_batch_done,
            ),
        )

    def _on_batch_done(self, result, error) -> bool:
        if error:
            self.notify(f"Error: {error}", is_error=True)
        elif result is not None:
            failed = [key for key, res in result.items() if not res.ok]
            if failed:
                self.notify(f"Finished with issues: {', '.join(failed)}", is_error=True)
            else:
                self.notify("Security baseline applied")
        self.refresh()
        return False

    # --------------------------------------------------------- guided wizard --

    def _on_start_wizard(self, _btn: Gtk.Button) -> None:
        keys = self._selected_keys()
        if not keys:
            self.notify("Nothing selected", is_error=True)
            return
        order = {item.key: i for i, item in enumerate(quicksetup.CATALOG)}
        self._wizard_queue = sorted(keys, key=lambda k: order[k])
        self._run_next_wizard_step()

    def _run_next_wizard_step(self) -> None:
        if not getattr(self, "_wizard_queue", None):
            self.notify("Guided setup complete")
            self.refresh()
            return

        key = self._wizard_queue.pop(0)
        item = next(i for i in quicksetup.CATALOG if i.key == key)

        body = item.description
        if item.risk_note:
            body = f"{body}\n\n⚠ {item.risk_note}"

        dialog = Adw.AlertDialog(heading=f"Step: {item.title}", body=body)
        dialog.add_response("skip", "Skip")
        dialog.add_response("apply", "Apply")
        dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("apply")
        dialog.set_close_response("skip")

        def on_response(_dialog, response: str) -> None:
            if response == "apply":
                self._apply_wizard_step(key, item.title)
            else:
                self._run_next_wizard_step()

        dialog.connect("response", on_response)
        dialog.present(self.get_root())

    def _apply_wizard_step(self, key: str, title: str) -> None:
        self.run_streaming_operation(
            f"Setting up: {title}",
            lambda on_line: quicksetup.apply_single(key, on_line),
            lambda _result, _error: self._run_next_wizard_step(),
        )
