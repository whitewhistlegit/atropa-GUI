"""
The app icon is wired by name in three places that have to agree: APP_ID in
main.py (the window icon), Icon= in the desktop launcher, and the file names
in the packaged hicolor tree. A mismatch shows a generic icon with no error,
so it's checked here instead of being found by eye.
"""
from __future__ import annotations

import re
import struct
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESOURCES = ROOT / "atropa" / "resources"
ICONS = RESOURCES / "icons" / "hicolor"


def _app_id() -> str:
    # main.py imports GTK, which the test environment doesn't have, so read it as text.
    source = (ROOT / "atropa" / "main.py").read_text(encoding="utf-8")
    match = re.search(r'^APP_ID = "([^"]+)"$', source, re.MULTILINE)
    assert match, "APP_ID not found in main.py"
    return match.group(1)


def _desktop_entry() -> dict[str, str]:
    lines = (RESOURCES / "atropa.desktop").read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines if "=" in line)


def _png_size(path: Path) -> tuple[int, int]:
    header = path.read_bytes()[:24]
    assert header[:8] == b"\x89PNG\r\n\x1a\n", f"{path} is not a PNG"
    return struct.unpack(">II", header[16:24])


def _icons() -> list[Path]:
    return sorted(ICONS.glob("*/apps/*.png"))


def test_launcher_uses_the_app_id_as_its_icon_and_window_class():
    entry = _desktop_entry()
    assert entry["Icon"] == _app_id()
    # Wayland desktops match a running window to its launcher by app ID.
    assert entry["StartupWMClass"] == _app_id()


def test_every_icon_is_a_square_png_of_its_directory_size():
    assert _icons(), "no packaged icons found"
    for icon in _icons():
        assert icon.stem == _app_id(), icon
        size = int(icon.parent.parent.name.split("x")[0])
        assert _png_size(icon) == (size, size), icon


def test_icons_are_shipped_as_package_data():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = pyproject["tool"]["setuptools"]["package-data"]["atropa"]
    packaged = {path for pattern in patterns for path in (ROOT / "atropa").glob(pattern)}
    assert set(_icons()) <= packaged
