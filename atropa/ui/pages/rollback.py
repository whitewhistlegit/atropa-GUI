"""atropa.ui.pages.rollback - Package History: undo a recent pacman transaction from the cache."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import rollback
from atropa.ui.pages import BasePage, esc

# A transaction can touch hundreds of packages; the expander lists this
# many and summarizes the rest.
_MAX_CHANGE_ROWS = 40
_ARROWS = {"upgraded": "↑", "downgraded": "↓", "installed": "+", "removed": "−", "reinstalled": "↻"}


def _command(transaction: rollback.Transaction) -> str:
    """The command as typed: Atropa's helper runs pacman by its resolved path."""
    head, _sep, rest = transaction.command.partition(" ")
    return f"{head.rsplit('/', 1)[-1]} {rest}".strip() or "pacman transaction"


def _summary(transaction: rollback.Transaction) -> str:
    parts = [
        f"{transaction.count(action)} {action}"
        for action in ("upgraded", "downgraded", "installed", "removed")
        if transaction.count(action)
    ]
    return ", ".join(parts)


class RollbackPage(BasePage):
    def __init__(self) -> None:
        super().__init__()
        self.group = self.add_group(
            "Recent pacman transactions",
            "Rolling back reinstalls the versions a transaction replaced, from the package cache, in one "
            "pacman run - the usual way to undo an upgrade that broke something. Packages it newly "
            "installed stay installed, and the next full upgrade upgrades everything again.",
        )
        self._rows: list = []
        self.refresh()

    def refresh(self) -> None:
        self.clear_rows(self.group, self._rows)
        self._rows = [self.start_loading(self.group, "Reading pacman's log…")]
        self.run_async(self._load, self._on_loaded)

    @staticmethod
    def _load():
        transactions = rollback.transactions()
        installed = rollback.installed_versions()
        return [(transaction, rollback.plan(transaction, installed)) for transaction in transactions]

    def _on_loaded(self, result, error) -> bool:
        self.clear_rows(self.group, self._rows)
        self._rows = []
        if error:
            row = Adw.ActionRow(title="Couldn't read the package history", subtitle=esc(error))
            self.group.add(row)
            self._rows.append(row)
            return False
        if not result:
            row = Adw.ActionRow(title="No pacman transactions in the log yet")
            self.group.add(row)
            self._rows.append(row)
            return False
        for transaction, plan in result:
            self._add_transaction(transaction, plan)
        return False

    def _add_transaction(self, transaction: rollback.Transaction, plan: rollback.RollbackPlan) -> None:
        row = Adw.ExpanderRow(title=esc(_command(transaction)))
        when = transaction.time.replace("T", " ")[:16]
        row.set_subtitle(esc(f"{when} · {_summary(transaction)}" + (f" · {plan.reason}" if plan.reason else "")))

        button = Gtk.Button(label="Roll back", valign=Gtk.Align.CENTER)
        if plan.possible:
            button.connect("clicked", lambda _b: self._on_roll_back(plan))
        else:
            button.set_sensitive(False)
            button.set_tooltip_text(plan.reason)
        row.add_suffix(button)

        for change in transaction.changes[:_MAX_CHANGE_ROWS]:
            if change.action in {"upgraded", "downgraded"}:
                versions = f"{change.old} → {change.new}"
            else:
                versions = change.new or change.old or ""
            child = Adw.ActionRow(
                title=esc(f"{_ARROWS.get(change.action, '')} {change.name}"),
                subtitle=esc(f"{change.action} {versions}"),
            )
            row.add_row(child)
        hidden = len(transaction.changes) - _MAX_CHANGE_ROWS
        if hidden > 0:
            row.add_row(Adw.ActionRow(title=esc(f"… and {hidden} more")))

        self.group.add(row)
        self._rows.append(row)

    def _on_roll_back(self, plan: rollback.RollbackPlan) -> None:
        notes = []
        if plan.kept:
            notes.append(f"{len(plan.kept)} package(s) it installed stay installed.")
        if plan.gone:
            notes.append(f"{len(plan.gone)} package(s) removed since are skipped.")
        notes.append(
            "The next full upgrade upgrades them again; add a package to IgnorePkg in pacman.conf to hold it back."
        )
        self.confirm(
            f"Roll back {len(plan.files)} package(s)?",
            f"Reinstalls the versions from before \"{_command(plan.transaction)}\" "
            f"({plan.transaction.time[:16].replace('T', ' ')}) from the package cache, in one pacman run. "
            + " ".join(notes),
            "Roll back",
            lambda: self.run_streaming_operation(
                "Rolling back packages",
                lambda on_line: rollback.apply(plan, on_line),
                self._on_done,
            ),
        )

    def _on_done(self, result, error) -> None:
        self.handle_command_result(result, error, "Rolled back")
        self.refresh()
