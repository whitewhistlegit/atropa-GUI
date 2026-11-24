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

    def no_privileged_command(*_argv):
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


def test_selinux_module_view_lints_and_fixes_in_place():
    """The module view used by Denials and Modules: lint, tint, and a one-click drop."""
    from atropa.backend import te_lint
    from atropa.ui.pages.selinux_load import SelinuxLoadPage
    from atropa.ui.selinux_module_view import ModuleView

    page = SelinuxLoadPage()
    text = "module m 1.0;\nallow a_t self:capability { sys_admin chown };\nallow a_t shadow_t:file read;\n"
    view = ModuleView(page, "atropa_m", text, "desktop_app", "a test")
    assert te_lint.verdict(view.findings) == te_lint.DANGEROUS
    shadow = next(f for f in view.findings if f.rule_id == "shadow")
    view._on_fix_clicked(None, shadow)
    assert "shadow_t" not in view.text().split("\n", 1)[1]
    assert all(f.rule_id != "shadow" for f in view.findings)


def test_selinux_denials_page_shows_a_program():
    from types import SimpleNamespace

    from atropa.backend import selinux, selinux_programs, te_lint
    from atropa.ui.pages.selinux_review import SelinuxReviewPage

    denial = selinux.GroupedDenial(key="k", scontext_type="a_t", tcontext_type="shadow_t", tclass="file",
                                   permissions=["read"], program="a", sample_line="avc", sample_path="/x", count=3,
                                   hint="label?", booleans=["a_bool"])
    review = SimpleNamespace(new=[denial], needs_boolean=[], noise=[], already_allowed=[], undefined_in_policy=[],
                             resolved=[], boolean_rules={"a_bool": 2}, since=None, total_raw_lines=3,
                             policy_checked=True)
    te = "module atropa_a_t 1.0;\nallow a_t shadow_t:file read;\n"
    draft = selinux.ProgramPolicyReview(program="a", safe_name="atropa_a_t", denial_count=3, domain="a_t",
                                        te_content=te, findings=te_lint.lint(te))
    programs = selinux_programs.overview(review, [draft])
    page = SelinuxReviewPage()
    page._on_review_loaded((review, programs), None)
    page._on_program_activated(None, programs[0])
    assert page.content_stack.get_visible_child_name() == "detail"
