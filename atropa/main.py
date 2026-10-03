#!/usr/bin/env python3
"""
Atropa - a YaST-inspired system control center for Arch Linux.

Run with:  python3 -m atropa.main
"""

from __future__ import annotations

import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio  # noqa: E402

from atropa.ui.main_window import AtropaWindow  # noqa: E402

APP_ID = "org.atropa.Atropa"


class AtropaApplication(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", self.on_activate)

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
