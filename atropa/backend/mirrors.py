"""
atropa.backend.mirrors
--------------------------
Ranking pacman mirrors with reflector, and replacing
/etc/pacman.d/mirrorlist with the ranked result.

`reflector --print` is only the read-only half. The write goes through
backup_file() and a privileged `tee`, the same path every other config edit
in Atropa takes, so a bad mirrorlist can always be restored from Activity.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from .privilege import CommandResult, backup_file, run_privileged, run_unprivileged

MIRRORLIST = Path("/etc/pacman.d/mirrorlist")

# Pacman's own line format; bare URLs are accepted too because reflector's
# --print output differs between versions.
_SERVER_RE = re.compile(r"^\s*Server\s*=\s*(\S+)\s*$")
_BARE_URL_RE = re.compile(r"^\s*(https?://\S+)\s*$")


@dataclass
class Mirror:
    url: str


def current_mirrors() -> list[Mirror]:
    """Active ``Server =`` entries, in the order pacman will try them."""
    try:
        text = MIRRORLIST.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise RuntimeError(f"Couldn't read {MIRRORLIST}: {exc}") from exc

    mirrors = []
    for line in text.splitlines():
        match = _SERVER_RE.match(line)
        if match:
            mirrors.append(Mirror(match.group(1)))
    return mirrors


def rank_mirrors(count: int = 10, country: str = "") -> list[str]:
    """
    Ask reflector for the fastest `count` mirrors. Kept read-only: reflector
    writes the mirrorlist itself unless --print is given, and Atropa wants
    backup_file() in front of that write.
    """
    if shutil.which("reflector") is None:
        raise RuntimeError("reflector isn't installed - install it with: pacman -S reflector")

    argv = ["reflector", "--score", "20", "--latest", "30", "--sort", "rate", "--number", str(count)]
    if country:
        argv += ["--country", country]
    argv.append("--print")

    result = run_unprivileged(argv, timeout=180)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or f"reflector exited with status {result.returncode}")

    urls: list[str] = []
    for raw in result.stdout.splitlines():
        match = _SERVER_RE.match(raw) or _BARE_URL_RE.match(raw)
        if match is None:
            continue
        url = match.group(1)
        if url not in urls:  # reflector can list the same mirror twice
            urls.append(url)

    if not urls:
        snippet = " ".join(result.stdout.split())[:160]
        raise RuntimeError(f"reflector printed no usable mirrors: {snippet or '(no output)'}")
    return urls


def write_mirrorlist(urls: list[str]) -> CommandResult:
    """Back up the current mirrorlist, then replace it with one Server line per URL."""
    if not urls:
        raise ValueError("No mirrors to write")
    for url in urls:
        if not url.startswith(("http://", "https://")) or any(char.isspace() for char in url):
            raise ValueError(f"{url!r} isn't an http(s) mirror URL")

    backup_file(str(MIRRORLIST))
    content = "# /etc/pacman.d/mirrorlist - written by Atropa\n\n" + "".join(f"Server = {url}\n" for url in urls)
    return run_privileged(["tee", str(MIRRORLIST)], input_text=content)
