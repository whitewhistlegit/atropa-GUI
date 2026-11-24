"""atropa.ui.pages.bootloader - Bootloader module (GRUB / systemd-boot)."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import bootloader, kernel_params
from atropa.ui.pages import BasePage, esc


class BootloaderPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self.status_group = self.add_group("Bootloader")
        self.status_row = Adw.ActionRow(title="Detecting bootloader…")
        self.status_group.add(self.status_row)

        self.timeout_row = Adw.SpinRow.new_with_range(0, 60, 1)
        self.timeout_row.set_title("Boot menu timeout (seconds)")
        apply_timeout_btn = Gtk.Button(label="Apply", valign=Gtk.Align.CENTER)
        apply_timeout_btn.connect("clicked", self._on_apply_timeout)
        self.timeout_row.add_suffix(apply_timeout_btn)
        self.status_group.add(self.timeout_row)

        regen_row = Adw.ActionRow(title="Regenerate boot configuration", subtitle="Run after kernel/initramfs changes")
        regen_btn = Gtk.Button(label="Regenerate")
        regen_btn.set_valign(Gtk.Align.CENTER)
        regen_btn.connect("clicked", self._on_regenerate)
        regen_row.add_suffix(regen_btn)
        self.status_group.add(regen_row)

        self.entries_group = self.add_group("Boot Entries")

        # --- kernel parameters ---------------------------------------------
        self.params_group = self.add_group(
            "Kernel parameters",
            "Before every change, the current boot entry is kept with its current parameters, "
            "so a parameter that stops the machine booting can be undone from the boot menu.",
        )
        self.params_apply_btn = Gtk.Button(label="Apply", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        self.params_apply_btn.connect("clicked", self._on_apply_params)
        self.params_group.set_header_suffix(self.params_apply_btn)
        self._param_rows: list = []
        self._param_switches: dict[str, Adw.SwitchRow] = {}
        self._params: kernel_params.KernelParams | None = None
        self._pending_add: list[str] = []
        self._pending_remove: list[str] = []

        self.refresh()

    def refresh(self) -> None:
        self.clear_rows(self.entries_group, getattr(self, "_entry_rows", []))
        self._entry_rows = [self.start_loading(self.entries_group, "Loading boot entries…")]
        self.run_async(bootloader.get_info, self._on_loaded)
        self.clear_rows(self.params_group, self._param_rows)
        self._param_rows = [self.start_loading(self.params_group, "Reading kernel parameters…")]
        self._param_switches = {}
        self._pending_add, self._pending_remove = [], []
        self.params_apply_btn.set_sensitive(False)
        self.run_async(kernel_params.read, self._on_params_loaded)

    # -- kernel parameters ----------------------------------------------------

    def _param_row(self, row) -> None:
        self.params_group.add(row)
        self._param_rows.append(row)

    def _on_params_loaded(self, state, error) -> bool:
        self.clear_rows(self.params_group, self._param_rows)
        self._param_rows = []
        if error or not state.supported:
            self._param_row(Adw.ActionRow(title="Kernel parameters can't be changed here",
                                          subtitle=esc(str(error) if error else state.reason)))
            return False
        self._params = state
        configured = " ".join(state.configured) or "(none)"
        differs = sorted(state.running) != sorted(state.configured) and state.bootloader == "systemd-boot"
        row = Adw.ActionRow(title="Configured", subtitle=esc(configured))
        row.set_subtitle_selectable(True)
        self._param_row(row)
        running_row = Adw.ActionRow(title="Running with", subtitle=esc(" ".join(state.running)))
        running_row.set_subtitle_selectable(True)
        if differs:
            running_row.set_title("Running with (differs - reboot to apply)")
        self._param_row(running_row)

        for preset in kernel_params.PRESETS:
            switch = Adw.SwitchRow(title=preset.title, subtitle=esc(f"{preset.detail} · {preset.param}"))
            switch.set_active(preset.param in state.configured)
            switch.connect("notify::active", self._on_preset_toggled, preset)
            self._param_switches[preset.key] = switch
            self._param_row(switch)

        presets = {p.param for p in kernel_params.PRESETS}
        others = [p for p in state.configured if p not in presets]
        if others:
            other_row = Adw.ExpanderRow(title="Other parameters", subtitle=esc(" ".join(others)))
            for param in others:
                inner = Adw.ActionRow(title=esc(param))
                remove = Gtk.Button(icon_name="list-remove-symbolic", valign=Gtk.Align.CENTER,
                                    css_classes=["flat"], tooltip_text=f"Remove {param}")
                remove.connect("clicked", self._on_remove_other, param, inner)
                inner.add_suffix(remove)
                other_row.add_row(inner)
            self._param_row(other_row)

        self.add_param_row = Adw.EntryRow(title="Add a parameter (one word, e.g. mitigations=auto)")
        self.add_param_row.set_show_apply_button(True)
        self.add_param_row.connect("apply", self._on_add_param)
        self._param_row(self.add_param_row)

        if state.previous_entry:
            prev = Adw.ActionRow(title="A boot entry with the previous parameters is kept",
                                 subtitle=esc(state.previous_entry))
            forget = Gtk.Button(label="Remove it", valign=Gtk.Align.CENTER)
            forget.connect("clicked", self._on_forget_previous)
            prev.add_suffix(forget)
            self._param_row(prev)
        return False

    def _mark_pending(self) -> None:
        self.params_apply_btn.set_sensitive(bool(self._pending_add or self._pending_remove))

    def _on_preset_toggled(self, switch: Adw.SwitchRow, _pspec, preset) -> None:
        if switch.get_active():
            # One lsm= list: switching one on switches the other off.
            for other in kernel_params.PRESETS:
                if other is not preset and other.param.split("=")[0] == preset.param.split("=")[0] == "lsm":
                    self._param_switches[other.key].set_active(False)
            if preset.param in self._pending_remove:
                self._pending_remove.remove(preset.param)
            elif preset.param not in self._params.configured:
                self._pending_add.append(preset.param)
        else:
            if preset.param in self._pending_add:
                self._pending_add.remove(preset.param)
            elif preset.param in self._params.configured:
                self._pending_remove.append(preset.param)
        self._mark_pending()

    def _on_remove_other(self, _btn: Gtk.Button, param: str, row: Adw.ActionRow) -> None:
        if param not in self._pending_remove:
            self._pending_remove.append(param)
        row.set_sensitive(False)
        row.set_subtitle("removed when you apply")
        self._mark_pending()

    def _on_add_param(self, entry: Adw.EntryRow) -> None:
        param = entry.get_text().strip()
        try:
            kernel_params.check_param(param)
        except ValueError as exc:
            self.notify(str(exc), is_error=True)
            return
        if param not in self._pending_add:
            self._pending_add.append(param)
        entry.set_text("")
        self.notify(f"{param} is added when you apply")
        self._mark_pending()

    def _on_apply_params(self, _btn: Gtk.Button) -> None:
        add, remove = list(self._pending_add), list(self._pending_remove)
        changes = [f"+ {p}" for p in add] + [f"- {p}" for p in remove]
        keep = ("custom.cfg, which GRUB shows" if self._params and self._params.bootloader == "grub"
                else "an atropa-previous entry, which systemd-boot shows")
        self.confirm(
            "Change the kernel parameters?",
            "\n".join(changes) + f"\n\nThe current boot entry is kept first in {keep} as "
            "\u201c… (kernel parameters before today)\u201d. If the next boot fails, pick that entry, then undo "
            "the change here. Takes effect after a reboot.",
            "Apply",
            lambda: self.run_action(lambda: kernel_params.apply(add, remove),
                                    lambda r, e: self.handle_command_result(r, e, "Kernel parameters changed - reboot to use them")),
            destructive=False,
        )

    def _on_forget_previous(self, _btn: Gtk.Button) -> None:
        self.run_action(kernel_params.forget_previous,
                        lambda r, e: self.handle_command_result(r, e, "Previous-parameters entry removed"))

    def _on_loaded(self, result, error) -> bool:
        if error:
            self.status_row.set_title("Could not read bootloader configuration")
            self.status_row.set_subtitle(esc(error))
            return False

        info = result
        if info.kind == "unknown":
            self.status_row.set_title("No supported bootloader detected")
            self.status_row.set_subtitle("Looked for GRUB and systemd-boot")
        else:
            self.status_row.set_title(f"Using {info.kind}")

        if info.default_timeout.isdigit():
            self.timeout_row.set_value(int(info.default_timeout))

        for row in list(getattr(self, "_entry_rows", [])):
            self.entries_group.remove(row)
        self._entry_rows = []

        for entry in info.entries:
            row = Adw.ActionRow(title=esc(entry.title), subtitle=esc(entry.identifier))
            self.entries_group.add(row)
            self._entry_rows.append(row)

        if info.entries_error:
            row = Adw.ActionRow(title="Couldn't read the boot entries", subtitle=esc(info.entries_error))
            self.entries_group.add(row)
            self._entry_rows.append(row)

        return False

    def _on_apply_timeout(self, _btn: Gtk.Button) -> None:
        seconds = int(self.timeout_row.get_value())
        self.notify("Applying timeout and regenerating config…")
        self.run_async(lambda: bootloader.set_timeout(seconds), self.handle_command_result)

    def _on_regenerate(self, _btn: Gtk.Button) -> None:
        self.notify("Regenerating boot configuration…")
        self.run_async(bootloader.regenerate_config, self.handle_command_result)
