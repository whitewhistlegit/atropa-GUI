"""atropa.ui.pages.mirrors - Mirror ranking with reflector."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from atropa.backend import mirrors
from atropa.ui.pages import BasePage, esc


class MirrorsPage(BasePage):
    def __init__(self) -> None:
        super().__init__()

        self.current_group = self.add_group("Current mirrorlist")
        self.rank_group = self.add_group("Rank mirrors")

        self.count_row = Adw.SpinRow.new_with_range(3, 50, 1)
        self.count_row.set_title("How many to keep")
        self.count_row.set_value(10)
        self.rank_group.add(self.count_row)

        # Adw.EntryRow has no subtitle property, so the hint goes in the
        # title like every other single-field row in Atropa.
        self.country_row = Adw.EntryRow(title="Country (e.g. Netherlands - leave empty for worldwide)")
        self.rank_group.add(self.country_row)

        rank_row = Adw.ActionRow(title="Find the fastest mirrors", subtitle="Asks reflector to test and sort them")
        rank_btn = Gtk.Button(label="Rank", valign=Gtk.Align.CENTER)
        rank_btn.connect("clicked", self._on_rank)
        rank_row.add_suffix(rank_btn)
        self.rank_group.add(rank_row)

        self._current_rows: list = []
        self._rank_rows: list = []
        self._ranked: list[str] = []
        self.refresh()

    def refresh(self) -> None:
        self.clear_rows(self.current_group, self._current_rows)
        self._current_rows = [self.start_loading(self.current_group, "Reading the mirrorlist…")]
        self.run_async(mirrors.current_mirrors, self._on_current_loaded)

    def _on_current_loaded(self, result, error) -> bool:
        self.clear_rows(self.current_group, self._current_rows)
        self._current_rows = []

        row = Adw.ActionRow()
        if error:
            row.set_title("Couldn't read the mirrorlist")
            row.set_subtitle(esc(error))
        elif not result:
            row.set_title("No mirrors configured")
            row.set_subtitle(esc(f"{mirrors.MIRRORLIST} has no active Server lines"))
        else:
            row.set_title(esc(f"{len(result)} mirrors configured"))
            row.set_subtitle(esc(result[0].url))

        self.current_group.add(row)
        self._current_rows.append(row)
        return False

    def _on_rank(self, _btn: Gtk.Button) -> None:
        count = int(self.count_row.get_value())
        country = self.country_row.get_text().strip()
        self.clear_rows(self.rank_group, self._rank_rows)
        self._rank_rows = [self.start_loading(self.rank_group, "Ranking mirrors with reflector…")]
        self._ranked = []
        self.run_async(lambda: mirrors.rank_mirrors(count, country), self._on_ranked)

    def _on_ranked(self, result, error) -> bool:
        self.clear_rows(self.rank_group, self._rank_rows)
        self._rank_rows = []

        if error:
            self._ranked = []
            row = Adw.ActionRow(title="Couldn't rank mirrors", subtitle=esc(error))
            self.rank_group.add(row)
            self._rank_rows.append(row)
            return False

        self._ranked = list(result)
        for url in result:
            row = Adw.ActionRow(title=esc(url))
            self.rank_group.add(row)
            self._rank_rows.append(row)

        # One button for the whole list: reflector's order is the point, so
        # there's no per-row "Use" that would silently drop the ranking.
        apply_row = Adw.ActionRow(
            title="Use the ranked list", subtitle=esc(f"{len(result)} mirrors, fastest first")
        )
        apply_btn = Gtk.Button(label="Use these mirrors", valign=Gtk.Align.CENTER)
        apply_btn.add_css_class("suggested-action")
        apply_btn.connect("clicked", self._on_use_ranked)
        apply_row.add_suffix(apply_btn)
        self.rank_group.add(apply_row)
        self._rank_rows.append(apply_row)
        return False

    def _on_use_ranked(self, _btn: Gtk.Button) -> None:
        if not self._ranked:
            self.notify("Rank some mirrors first")
            return
        urls = list(self._ranked)
        self.confirm(
            "Replace the mirrorlist?",
            "Writes the ranked list to /etc/pacman.d/mirrorlist after backing it up.",
            "Replace",
            lambda: self.run_action(
                lambda: mirrors.write_mirrorlist(urls),
                lambda result, error: self.handle_command_result(result, error, "Mirrorlist replaced"),
            ),
        )
