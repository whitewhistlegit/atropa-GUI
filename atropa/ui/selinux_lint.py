"""
atropa.ui.selinux_lint - what te_lint found, shown the same way on every
SELinux page: a badge, the findings as text, and an install dialog that asks
for each dangerous finding to be acknowledged before installing.
"""

from __future__ import annotations

from typing import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import te_lint

_SEVERITY_LABEL = {te_lint.DANGEROUS: "Dangerous", te_lint.REVIEW: "Review", te_lint.NOTE: "Note"}


def badge(findings: list) -> str:
    """'Dangerous (2)', 'Review (3)' or 'Looks fine', for a row subtitle."""
    verdict = te_lint.verdict(findings)
    if verdict == "fine":
        return "Looks fine"
    count = sum(1 for f in findings if f.severity == verdict)
    return f"{_SEVERITY_LABEL[verdict]} ({count})"


def install(page, heading: str, body: str, findings: list, install_fn: Callable[[list[str]], object]) -> None:
    """
    Confirm, then run install_fn(acknowledged_keys) as the page's action.
    Without dangerous findings this is a normal confirm (listing the Review
    ones); with them, Install stays disabled until each one is ticked.
    """
    dangerous = [f for f in findings if f.severity == te_lint.DANGEROUS]
    review = [f for f in findings if f.severity == te_lint.REVIEW]

    def run(acks: list[str]) -> None:
        page.run_action(lambda: install_fn(acks), page.handle_command_result)

    if not dangerous:
        extra = ""
        if review:
            extra = "\n\nWorth a second look:\n" + "\n".join(f"• {f.message}" for f in review)
        page.confirm(heading, body + extra, "Install", lambda: run([]), destructive=False)
        return

    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    checks: list[tuple[Gtk.CheckButton, object]] = []
    for finding in dangerous:
        check = Gtk.CheckButton()
        label = Gtk.Label(
            label=f"{finding.message}\n{finding.why}", wrap=True, xalign=0, max_width_chars=60,
        )
        check.set_child(label)
        box.append(check)
        checks.append((check, finding))

    dialog = Adw.AlertDialog(
        heading=heading,
        body=body + "\n\nThis module grants dangerous access. Tick each one you understand and still want:",
    )
    dialog.set_extra_child(box)
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("install", "Install anyway")
    dialog.set_response_appearance("install", Adw.ResponseAppearance.DESTRUCTIVE)
    dialog.set_response_enabled("install", False)
    dialog.set_close_response("cancel")

    def on_toggled(_check) -> None:
        dialog.set_response_enabled("install", all(c.get_active() for c, _f in checks))

    for check, _finding in checks:
        check.connect("toggled", on_toggled)

    def on_response(_dialog, response: str) -> None:
        if response == "install":
            run([finding.key for _check, finding in checks])

    dialog.connect("response", on_response)
    dialog.present(page.get_root())
