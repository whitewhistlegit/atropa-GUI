"""atropa.ui.pages.plugin_page - Generic renderer for one enabled plugin's manifest."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import plugin_registry, plugins
from atropa.ui.pages import BasePage, esc


def _summarize_result(result) -> str:
    if hasattr(result, "ok"):  # CommandResult-like
        if result.ok:
            return "OK" + (f" - {result.stdout.strip()[:150]}" if getattr(result, "stdout", "") else "")
        return f"Failed: {(getattr(result, 'stderr', '') or getattr(result, 'stdout', '')).strip()[:150]}"
    if isinstance(result, list):
        return f"{len(result)} item(s)"
    return str(result)[:200]


class PluginPage(BasePage):
    """Renders exactly one plugin's manifest into a page. Every row's
    button, whichever label the plugin gave it, always shows the real
    registry action being called in a confirm dialog before a mutating
    action runs - a plugin's own wording is never the final word on what
    a button does."""

    def __init__(self, manifest) -> None:
        super().__init__()
        self.manifest = manifest

        intro = self.add_group(
            manifest.title,
            manifest.description or "A plugin page (declarative - see the Add-ons page for details).",
        )
        meta_bits = []
        if manifest.author:
            meta_bits.append(f"by {manifest.author}")
        if manifest.version:
            meta_bits.append(f"v{manifest.version}")
        if meta_bits:
            intro.add(Adw.ActionRow(title=" · ".join(meta_bits)))

        for group_spec in manifest.groups:
            group = self.add_group(group_spec.title, group_spec.description)
            for row_spec in group_spec.rows:
                group.add(self._build_row(row_spec))

    def refresh(self) -> None:
        pass  # plugin rows act on demand via their own buttons, nothing to auto-refresh

    def _build_row(self, row_spec) -> Adw.ActionRow:
        action = plugin_registry.get_action(row_spec.action_key)
        subtitle = action.description if action else "Unknown action (registry may have changed)"
        row = Adw.ActionRow(title=esc(row_spec.title), subtitle=esc(subtitle))

        label = row_spec.button_label or "Run"
        btn = Gtk.Button(label=esc(label), valign=Gtk.Align.CENTER)
        if action is not None and action.mutating:
            btn.add_css_class("destructive-action" if "remove" in row_spec.action_key or "disable" in row_spec.action_key else "suggested-action")
        btn.connect("clicked", self._on_row_clicked, row_spec, row)
        row.add_suffix(btn)
        return row

    def _on_row_clicked(self, _btn: Gtk.Button, row_spec, row: Adw.ActionRow) -> None:
        action = plugin_registry.get_action(row_spec.action_key)
        real_call = plugin_registry.describe_call(row_spec.action_key, row_spec.params)

        def run() -> None:
            self.run_async(
                lambda: plugins.run_plugin_action(row_spec.action_key, row_spec.params),
                lambda result, error: self._on_action_done(result, error, row),
            )

        if action is not None and action.mutating:
            self.confirm(
                f"Run: {row_spec.title}?",
                f"This runs:\n\n{real_call}\n\nShown regardless of this plugin's own labeling, "
                "so you always know exactly what a plugin button does before it runs.",
                "Run",
                run,
            )
        else:
            run()

    def _on_action_done(self, result, error, row: Adw.ActionRow) -> bool:
        if error:
            self.notify(f"Error: {error}", is_error=True)
            row.set_subtitle(esc(f"Error: {error}"))
        else:
            self.notify("Done")
            row.set_subtitle(esc(_summarize_result(result)))
        return False
