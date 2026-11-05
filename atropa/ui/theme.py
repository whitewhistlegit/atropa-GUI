"""
atropa.ui.theme
-----------------
Loads Atropa's stylesheet. The CSS is a refinement layer on top of stock
libadwaita: it only uses Adwaita's named colours (@accent_bg_color,
@window_fg_color, ...), so light/dark and the desktop's accent colour all
keep working without Atropa choosing a palette of its own.

The UI stays fully usable if this file is missing or malformed - a theme
problem is reported on stderr and the app falls back to stock libadwaita.
tests/test_resources.py checks that style.css really is shipped in the wheel,
so a packaging mistake fails CI instead of quietly shipping an unstyled app.
"""

from __future__ import annotations

import sys
from pathlib import Path

from gi.repository import Gdk, GLib, Gtk

# atropa/ui/theme.py -> atropa/resources/style.css
STYLESHEET = Path(__file__).resolve().parent.parent / "resources" / "style.css"


def load_stylesheet(display: Gdk.Display) -> None:
    """Attach style.css to `display` at application priority."""
    if not STYLESHEET.is_file():
        return

    provider = Gtk.CssProvider()
    try:
        provider.load_from_path(str(STYLESHEET))
    except (GLib.Error, OSError) as error:
        print(f"Atropa: could not load {STYLESHEET}: {error}", file=sys.stderr)
        return

    Gtk.StyleContext.add_provider_for_display(display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
