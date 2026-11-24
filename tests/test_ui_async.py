"""
BasePage.run_async delivers its result exactly once.

GLib runs an idle callback again while it returns something truthy, and a
page callback written as a lambda returning a tuple did: after installing
an SELinux module the Modules page refreshed (a pkexec semodule -l each
time) about a hundred times in two seconds.
"""

from __future__ import annotations

import pytest

try:
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import GLib

    from atropa.ui import pages
except (ImportError, ValueError) as exc:  # pragma: no cover - backend CI has no GTK
    pytest.skip(f"GTK4/libadwaita isn't available: {exc}", allow_module_level=True)


def test_run_async_calls_on_done_once_even_if_it_returns_truthy(monkeypatch):
    monkeypatch.setattr(pages, "smoke_mode", lambda: False)
    loop = GLib.MainLoop()
    calls = []

    def on_done(result, error):
        calls.append((result, error))
        return ("truthy", "tuple")

    pages.BasePage.run_async(None, lambda: 42, on_done)
    GLib.timeout_add(300, loop.quit)
    loop.run()

    assert calls == [(42, None)]
