"""
atropa.backend.news
-------------------
"Read the news before -Syu": the Arch news feed, narrowed down to the items
that may need manual steps for the upgrade the user is about to run.

- ``fetch_feed()`` / ``parse_feed()`` turn https://archlinux.org/feeds/news/
  into :class:`NewsItem` objects (title, link, published, summary).
- ``last_upgrade_time()`` reads the last ``starting full system upgrade``
  line out of ``/var/log/pacman.log``, so only news published *since* that
  upgrade is worth showing - everything older has already been dealt with
  by an earlier ``-Syu``.
- ``check()`` glues the two together and never raises: whatever went wrong
  (offline, DNS, a truncated feed) lands in :attr:`NewsReport.error`, so the
  UI can show the page with a one-line explanation instead of a blank
  screen.

Read-only, and no network access unless ``fetch_feed()`` (or ``check()``
without an injected ``fetch``) is actually called. Nothing here runs as
root and nothing is fetched on import.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Callable

from .. import __version__

FEED_URL = "https://archlinux.org/feeds/news/"
PACMAN_LOG = Path("/var/log/pacman.log")

USER_AGENT = f"atropa/{__version__}"

# pacman's own line, e.g.
#   [2026-11-05T03:00:00+0100] [PACMAN] starting full system upgrade
# Anchored at the start of a line: the log is append-only, so the last
# match is the most recent upgrade.
UPGRADE_PATTERN = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+\[PACMAN\]\s+starting full system upgrade",
    re.MULTILINE,
)


@dataclass
class NewsItem:
    title: str
    link: str
    published: datetime
    summary: str = ""


@dataclass
class NewsReport:
    items: list[NewsItem] = field(default_factory=list)
    # The full-upgrade timestamp the items were filtered against; None when
    # there is no (readable) pacman log yet, i.e. "show the newest items".
    since: datetime | None = None
    error: str = ""
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _aware(moment: datetime) -> datetime:
    """A timezone-aware copy of ``moment``; a naive value is taken as UTC."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


def _parse_timestamp(raw: str) -> datetime | None:
    """datetime.fromisoformat, or None for a line we can't read."""
    try:
        stamp = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return None
    return _aware(stamp)


def _parse_date(raw: str) -> datetime | None:
    """RSS pubDate (RFC 822) -> aware datetime; None when it's unparsable."""
    if not raw:
        return None
    try:
        stamp = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if stamp is None:  # parsedate_to_datetime() can answer None for some junk
        return None
    return _aware(stamp)


def _clean_summary(raw: str) -> str:
    """Descriptions are HTML: drop the tags and collapse the whitespace."""
    return " ".join(re.sub(r"<[^>]+>", "", raw).split())


def _child_text(node: ET.Element, tag: str) -> str:
    child = node.find(tag)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def fetch_feed(timeout: int = 15) -> str:
    """
    Download the Arch news RSS feed as text (UTF-8, undecodable bytes
    replaced rather than fatal). Raises RuntimeError with a readable
    message when the network, DNS or the server can't answer.
    """
    request = urllib.request.Request(FEED_URL, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"The Arch news feed returned HTTP {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Couldn't reach the Arch news feed: {exc.reason}") from exc
    except OSError as exc:
        raise RuntimeError(f"Couldn't read the Arch news feed: {exc}") from exc


def parse_feed(text: str) -> list[NewsItem]:
    """
    Parse the RSS 2.0 document into newest-first ``NewsItem`` objects.

    Items without a title or link, and items whose pubDate isn't a date we
    understand, are skipped instead of failing the whole page. Raises
    ValueError when ``text`` isn't XML at all (or isn't an RSS feed) - the
    caller (``check()``) turns that into ``NewsReport.error``.
    """
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Couldn't parse the Arch news feed: {exc}") from exc

    channel = root.find("channel")
    if channel is None:
        raise ValueError("The Arch news feed has no <channel>; is this really the news feed?")

    items = []
    for node in channel.findall("item"):
        title = _child_text(node, "title")
        link = _child_text(node, "link")
        published = _parse_date(_child_text(node, "pubDate"))
        if not title or not link or published is None:
            continue
        items.append(NewsItem(title, link, published, _clean_summary(_child_text(node, "description"))))

    items.sort(key=lambda item: item.published, reverse=True)
    return items


def last_upgrade_time(log_text: str | None = None) -> datetime | None:
    """
    Timestamp of the most recent full system upgrade in pacman's log, or
    None when there is no log (missing, unreadable, or simply no upgrade in
    it yet). The log is append-only, so the last match wins.
    """
    if log_text is None:
        try:
            log_text = PACMAN_LOG.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    found = None
    for match in UPGRADE_PATTERN.finditer(log_text):
        stamp = _parse_timestamp(match.group("ts"))
        if stamp is not None:
            found = stamp
    return found


def relevant_news(items: list[NewsItem], since: datetime | None, limit: int = 10) -> list[NewsItem]:
    """
    Newest ``limit`` items published strictly after ``since`` (or simply the
    newest ``limit`` when ``since`` is None). A naive ``since`` is read as
    UTC, the same way naive feed dates are.
    """
    if limit <= 0:
        return []

    ordered = sorted(items, key=lambda item: _aware(item.published), reverse=True)
    if since is None:
        return ordered[:limit]

    cutoff = _aware(since)
    return [item for item in ordered if _aware(item.published) > cutoff][:limit]


def check(fetch: Callable[[], str] | None = None) -> NewsReport:
    """
    Fetch + parse the feed, then keep the items newer than the last full
    upgrade. Injecting ``fetch`` (a zero-argument callable returning the
    feed text) keeps this offline in tests; it defaults to fetch_feed().

    Never raises: a failure is reported in ``NewsReport.error`` with
    ``items`` left empty, so the Packages page can still render.
    """
    report = NewsReport(checked_at=datetime.now(timezone.utc))
    try:
        text = (fetch or fetch_feed)()
        items = parse_feed(text)
        since = last_upgrade_time()
        report.since = since
        report.items = relevant_news(items, since)
    except Exception as exc:  # noqa: BLE001 - the news check must never take the page down
        report.error = str(exc) or exc.__class__.__name__
    return report
