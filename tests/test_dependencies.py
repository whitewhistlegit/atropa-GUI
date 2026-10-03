"""Tests for atropa.backend.dependencies."""
from __future__ import annotations

from atropa.backend import dependencies


def test_catalog_entries_have_unique_names():
    names = [dep.name for dep in dependencies.CATALOG]
    assert len(names) == len(set(names))


def test_catalog_every_entry_has_module_and_description():
    for dep in dependencies.CATALOG:
        assert dep.name
        assert dep.module
        assert dep.description


def test_catalog_non_installable_entries_have_a_note():
    """Any entry with package=None (can't offer an Install button) must
    explain why, so the UI has something to show instead."""
    for dep in dependencies.CATALOG:
        if dep.package is None:
            assert dep.note, f"{dep.name} has no package but also no note"


def test_check_all_reports_status_for_every_entry(fake_which):
    fake_which.add("pkexec")
    statuses = dependencies.check_all()
    assert len(statuses) == len(dependencies.CATALOG)
    by_name = {s.dependency.name: s.installed for s in statuses}
    assert by_name["pkexec"] is True
    assert by_name["semodule"] is False


def test_check_all_reflects_multiple_installed_tools(fake_which):
    fake_which.update({"pkexec", "pacman", "systemctl", "sestatus"})
    statuses = dependencies.check_all()
    by_name = {s.dependency.name: s.installed for s in statuses}
    assert by_name["pkexec"] is True
    assert by_name["pacman"] is True
    assert by_name["systemctl"] is True
    assert by_name["sestatus"] is True
    assert by_name["ufw"] is False


def test_missing_required_empty_when_all_required_tools_present(fake_which):
    fake_which.update({"pkexec", "pacman", "systemctl"})
    assert dependencies.missing_required() == []


def test_missing_required_lists_absent_required_tools(fake_which):
    # default fake_which only has pkexec - pacman and systemctl are "missing"
    missing = dependencies.missing_required()
    missing_names = {dep.name for dep in missing}
    assert "pacman" in missing_names
    assert "systemctl" in missing_names
    assert "pkexec" not in missing_names  # present in this test's fake_which


def test_missing_required_never_includes_optional_tools(fake_which):
    # nothing optional is installed in the default fake_which fixture
    missing = dependencies.missing_required()
    assert all(dep.required for dep in missing)


def test_summary_counts_matches_catalog_size(fake_which):
    counts = dependencies.summary_counts()
    assert counts["total"] == len(dependencies.CATALOG)
    assert counts["installed"] + counts["missing"] == counts["total"]


def test_summary_counts_all_missing_except_default_pkexec(fake_which):
    counts = dependencies.summary_counts()
    assert counts["installed"] == 1  # only pkexec, from the default fake_which fixture


def test_summary_counts_updates_as_more_tools_appear(fake_which):
    fake_which.update({"pacman", "systemctl", "ufw"})
    counts = dependencies.summary_counts()
    assert counts["installed"] == 4  # pkexec + the three added above
