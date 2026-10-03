"""atropa.ui.pages.addons - Add-ons: browse and enable/disable discovered plugins."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import plugins
from atropa.ui.pages import BasePage, esc


class AddonsPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self.add_group(
            "Add-ons",
            "Plugins are declarative TOML manifests, never code - a plugin can only reference "
            "pre-approved actions, never run an arbitrary command. Manifest files live under "
            "/etc/atropa/plugins/, which only root can write to, so placing, editing, AND "
            "enabling a plugin all require root authentication - the same barrier as any other "
            "privileged action here. Restart Atropa after enabling or disabling a plugin for "
            "the sidebar to reflect the change.",
        )

        self.list_group = self.add_group("Discovered Plugins")
        self._rows: list = []
        self.refresh()

    def refresh(self) -> None:
        self.clear_rows(self.list_group, self._rows)
        self._rows = [self.start_loading(self.list_group, "Scanning /etc/atropa/plugins…")]
        self.run_async(plugins.discover_plugins, self._on_loaded)

    def _on_loaded(self, result, error) -> bool:
        self.clear_rows(self.list_group, self._rows)
        self._rows = []

        if error:
            self.notify(f"Couldn't scan plugins: {error}", is_error=True)
            return False

        if not result:
            row = Adw.ActionRow(title="No plugins found", subtitle="Nothing in /etc/atropa/plugins/")
            self.list_group.add(row)
            self._rows.append(row)
            return False

        for plugin in result:
            row = self._build_plugin_row(plugin)
            self.list_group.add(row)
            self._rows.append(row)
        return False

    def _build_plugin_row(self, plugin) -> Adw.ActionRow:
        if plugin.manifest is None:
            row = Adw.ActionRow(title=esc(plugin.plugin_id), subtitle=esc("Invalid: " + "; ".join(plugin.errors)))
            row.add_prefix(Gtk.Image.new_from_icon_name("dialog-error-symbolic"))
            return row

        subtitle = plugin.manifest.description or plugin.path
        if plugin.enabled:
            subtitle = f"Enabled · {subtitle}"
        row = Adw.ActionRow(title=esc(plugin.manifest.title), subtitle=esc(subtitle))
        row.add_prefix(
            Gtk.Image.new_from_icon_name("emblem-ok-symbolic" if plugin.enabled else "dialog-warning-symbolic")
        )

        toggle_btn = Gtk.Button(label="Disable" if plugin.enabled else "Enable", valign=Gtk.Align.CENTER)
        if not plugin.enabled:
            toggle_btn.add_css_class("suggested-action")
        toggle_btn.connect("clicked", self._on_toggle_clicked, plugin)
        row.add_suffix(toggle_btn)
        return row

    def _on_toggle_clicked(self, _btn: Gtk.Button, plugin) -> None:
        new_state = not plugin.enabled
        verb = "Enable" if new_state else "Disable"
        body = (
            "This requires administrator authentication, since plugin state lives in a "
            "root-owned file. Restart Atropa afterward for the sidebar to reflect the change."
        )
        if new_state:
            body += (
                "\n\nOnce enabled, every action this plugin runs still shows its real "
                "underlying call in a confirm dialog before running - the plugin's own labels "
                "are never the final word on what a button does."
            )

        self.confirm(
            f"{verb} '{plugin.manifest.title}'?",
            body,
            verb,
            lambda: self.run_async(
                lambda: plugins.set_plugin_enabled(plugin.plugin_id, new_state),
                lambda result, error: self.handle_command_result(
                    result, error, success_message=f"{verb}d - restart Atropa to apply"
                ),
            ),
        )
