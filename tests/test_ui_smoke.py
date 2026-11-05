"""
Construct every built-in page under a real (virtual) display.

This is the one thing the backend suite cannot check: whether the GTK code
actually builds. Run it under `xvfb-run` in CI (see ci.yml); locally any
desktop session works. Pages normally start backend calls from __init__, so
the smoke mode in atropa.ui.pages makes run_async a no-op - this test is
about widget construction, not about shelling out to pkexec on a build host.
"""

from __future__ import annotations

import os

os.environ.setdefault("ATROPA_UI_SMOKE", "1")

import pytest

try:
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gtk
except (ImportError, ValueError) as exc:  # pragma: no cover - backend CI has no GTK
    pytest.skip(f"GTK4/libadwaita isn't available: {exc}", allow_module_level=True)

if not os.environ.get("DISPLAY"):
    pytest.skip("needs a display; CI runs this file under xvfb-run", allow_module_level=True)


def _built_in_modules():
    from atropa.ui.main_window import MODULES

    # Plugin pages are built from manifests on the host and are deliberately
    # not part of the built-in surface this test covers.
    return [module for module in MODULES if not module.key.startswith("plugin_")]


@pytest.fixture(scope="module", autouse=True)
def display():
    from unittest.mock import patch

    from atropa.backend.privilege import PrivilegeError

    def no_privileged_command():
        # Belt and braces: construction must never raise a polkit dialog on
        # a developer's desktop (or hang on a CI runner).
        raise PrivilegeError("privileged commands are disabled in the UI smoke test")

    with patch("atropa.backend.privilege._resolve_privileged_prefix", no_privileged_command):
        Adw.init()
        Gtk.init()
        yield


@pytest.mark.parametrize("module", _built_in_modules(), ids=lambda module: module.key)
def test_every_page_constructs(module):
    page = module.page()

    assert page.get_first_child() is not None, "page has no toast overlay content"
    assert page.preferences_page.get_first_child() is not None, "page has no groups"


def test_the_module_list_has_no_duplicate_keys():
    keys = [module.key for module in _built_in_modules()]
    assert len(keys) == len(set(keys))


def test_smoke_mode_is_on():
    from atropa.ui.pages import smoke_mode

    assert smoke_mode() is True
