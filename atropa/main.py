#!/usr/bin/env python3
"""
Atropa - a YaST-inspired system control center for Arch Linux.

Run with:  python3 -m atropa.main
"""

from __future__ import annotations

import sys
from pathlib import Path

import gi

gi.require_version("Gdk", "4.0")
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gio, Gtk  # noqa: E402

from atropa.ui.main_window import AtropaWindow  # noqa: E402

APP_ID = "org.atropa.Atropa"

# The logo as a hicolor icon tree, named after APP_ID. install.sh copies the
# same tree into ~/.local/share/icons for the launcher.
ICONS_DIR = Path(__file__).resolve().parent / "resources" / "icons"


class AtropaApplication(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("startup", self.on_startup)
        self.connect("activate", self.on_activate)

    def on_startup(self, app: Adw.Application) -> None:
        # GTK4 only takes a window icon by theme name, never from a file, so
        # the packaged icons go on the theme's search path first. That makes
        # the name resolve when running straight from source too, not only
        # once install.sh has copied the icons into the user's icon theme.
        display = Gdk.Display.get_default()
        if display is not None:
            Gtk.IconTheme.get_for_display(display).add_search_path(str(ICONS_DIR))
        Gtk.Window.set_default_icon_name(APP_ID)

    def on_activate(self, app: Adw.Application) -> None:
        win = self.props.active_window
        if not win:
            win = AtropaWindow(application=app)
        win.present()


def main() -> int:
    Adw.init()
    app = AtropaApplication()
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
