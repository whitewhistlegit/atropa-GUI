"""atropa.ui.pages.quicksetup - Security Quick Setup: a checklist + guided wizard for a recommended security baseline."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import pacman, privilege, quicksetup
from atropa.ui.pages import BasePage, esc

_LOCKED_TOOLTIP = "Unlock with the administrator password before selecting this"


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
        self._lock_buttons: dict[str, Gtk.Button] = {}
        self._unlocked: set[str] = set()
        for item in quicksetup.CATALOG:
            row = Adw.ActionRow(title=esc(item.title), subtitle=esc(item.description))
            # A locked item's box can't be ticked at all until the lock next to
            # it has been opened with the administrator password - so it can't
            # end up in a batch by a stray click.
            check = Gtk.CheckButton(
                active=item.default_selected and not item.locked, valign=Gtk.Align.CENTER, sensitive=not item.locked
            )
            check.connect("toggled", lambda _c: self._update_selected_count())
            row.add_prefix(check)
            self._checkboxes[item.key] = check

            if item.risk_note:
                warning_icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
                warning_icon.set_tooltip_text(item.risk_note)
                row.add_suffix(warning_icon)

            if item.key == "selinux_repo":
                # The way back, next to the way in. Shown only while the
                # repository is in pacman.conf, usable only while unlocked.
                self.repo_remove_btn = Gtk.Button(
                    label="Remove", valign=Gtk.Align.CENTER, visible=False, sensitive=False
                )
                self.repo_remove_btn.connect("clicked", self._on_remove_repo_clicked)
                row.add_suffix(self.repo_remove_btn)

            if item.locked:
                lock_btn = Gtk.Button(valign=Gtk.Align.CENTER, css_classes=["flat"])
                lock_btn.set_icon_name("changes-prevent-symbolic")
                lock_btn.set_tooltip_text(_LOCKED_TOOLTIP)
                lock_btn.connect("clicked", self._on_lock_clicked, item.key)
                row.add_suffix(lock_btn)
                self._lock_buttons[item.key] = lock_btn

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
        self.run_async(lambda: (quicksetup.status_summary(), pacman.selinux_repo_enabled()), self._on_status_loaded)

    def _on_status_loaded(self, result, error) -> bool:
        if error:
            self.notify(f"Couldn't check current status: {error}", is_error=True)
            return False
        summary, repo_enabled = result
        for key, label in self._status_labels.items():
            label.set_label(summary.get(key, "?"))
        self.repo_remove_btn.set_visible(repo_enabled)
        return False

    def _selected_keys(self) -> list[str]:
        return [key for key, cb in self._checkboxes.items() if cb.get_active()]

    # ---------------------------------------------------------------- locks --

    def _set_locked(self, key: str, locked: bool) -> None:
        check = self._checkboxes[key]
        if locked:
            self._unlocked.discard(key)
            check.set_active(False)
        else:
            self._unlocked.add(key)
        check.set_sensitive(not locked)
        button = self._lock_buttons[key]
        button.set_icon_name("changes-prevent-symbolic" if locked else "changes-allow-symbolic")
        button.set_tooltip_text(_LOCKED_TOOLTIP if locked else "Unlocked - click to lock it again")
        if key == "selinux_repo":
            self.repo_remove_btn.set_sensitive(not locked)
        self._update_selected_count()

    def _lock_everything(self) -> None:
        for key in list(self._unlocked):
            self._set_locked(key, True)

    def _on_lock_clicked(self, _btn: Gtk.Button, key: str) -> None:
        if key in self._unlocked:
            self._set_locked(key, True)
            return

        def on_done(result, error) -> bool:
            if error is None and getattr(result, "ok", False):
                self._set_locked(key, False)
            else:
                self.notify("Still locked - unlocking takes the administrator password", is_error=True)
            return False

        self.run_action(privilege.authenticate, on_done)

    def _on_remove_repo_clicked(self, _btn: Gtk.Button) -> None:
        self.confirm(
            "Remove the SELinux package repository?",
            f"Takes [{pacman.SELINUX_REPO_NAME}] back out of pacman.conf (backed up first). Packages already "
            "installed from it stay installed; pacman just stops looking there, so they no longer get updates.",
            "Remove",
            lambda: self.run_action(
                pacman.disable_selinux_repo,
                lambda result, error: self.handle_command_result(result, error, "Repository removed"),
            ),
        )

    # --------------------------------------------------------- batch apply --

    def _on_apply_selected(self, _btn: Gtk.Button) -> None:
        keys = self._selected_keys()
        if not keys:
            self.notify("Nothing selected", is_error=True)
            return
        selected = [item for item in quicksetup.CATALOG if item.key in keys]
        titles = ", ".join(item.title for item in selected)
        body = (
            f"This will set up: {titles}. Anything not installed yet gets installed from "
            "scratch first. Progress is shown live."
        )
        # What a locked item does is said here too, not only in its tooltip.
        for item in selected:
            if item.locked and item.risk_note:
                body += f"\n\n⚠ {item.title}: {item.risk_note}"
        unlocked = set(self._unlocked)
        self.confirm(
            "Apply the selected security baseline?",
            body,
            "Apply",
            lambda: self.run_streaming_operation(
                "Applying Security Baseline",
                lambda on_line: quicksetup.apply_items(keys, on_line, unlocked=unlocked),
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
        self._lock_everything()
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
            self._lock_everything()
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
        unlocked = set(self._unlocked)
        self.run_streaming_operation(
            f"Setting up: {title}",
            lambda on_line: quicksetup.apply_single(key, on_line, unlocked=unlocked),
            lambda _result, _error: self._run_next_wizard_step(),
        )
