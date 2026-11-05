"""Tests for atropa.backend.news - hermetic: no network, no real pacman log."""

from __future__ import annotations

import urllib.error
from datetime import datetime, timedelta, timezone

import pytest

from atropa.backend import news

# --------------------------------------------------------------- sample feed --

FEED = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Arch Linux: Recent news updates</title>
    <link>https://archlinux.org/news/</link>
    <description>The latest news from the Arch Linux team</description>
    <item>
      <title>pacman 7 requires manual intervention</title>
      <link>https://archlinux.org/news/pacman-7/</link>
      <pubDate>Thu, 01 Oct 2026 12:00:00 GMT</pubDate>
      <description>&lt;p&gt;The local database needs a one-time
        migration.&lt;/p&gt;</description>
    </item>
    <item>
      <title>New mirror layout</title>
      <link>https://archlinux.org/news/mirror-layout/</link>
      <pubDate>Sat, 07 Nov 2026 09:30:00 +0100</pubDate>
      <description>&lt;p&gt;Mirrors move to &lt;b&gt;mirror.archlinux.org&lt;/b&gt;.&lt;/p&gt;</description>
    </item>
    <item>
      <title>Kernel firmware split</title>
      <link>https://archlinux.org/news/firmware-split/</link>
      <pubDate>Wed, 05 Nov 2026 02:00:00 +0000</pubDate>
      <description>&lt;p&gt;linux-firmware is now split by vendor.&lt;/p&gt;</description>
    </item>
  </channel>
</rss>
"""


def _item(
    title: str = "A news item",
    link: str = "https://archlinux.org/news/a/",
    pub_date: str | None = "Wed, 05 Nov 2026 02:00:00 +0000",
    description: str | None = "Something happened.",
) -> str:
    parts = []
    if title:
        parts.append(f"<title>{title}</title>")
    if link:
        parts.append(f"<link>{link}</link>")
    if pub_date:
        parts.append(f"<pubDate>{pub_date}</pubDate>")
    if description is not None:
        parts.append(f"<description>{description}</description>")
    return "<item>" + "".join(parts) + "</item>"


def _feed(*items: str) -> str:
    return '<rss version="2.0"><channel>' + "".join(items) + "</channel></rss>"


# -------------------------------------------------------------------- parsing --


def test_parse_feed_returns_newest_first_with_clean_fields():
    items = news.parse_feed(FEED)

    assert [item.title for item in items] == [
        "New mirror layout",
        "Kernel firmware split",
        "pacman 7 requires manual intervention",
    ]
    assert [item.link for item in items] == [
        "https://archlinux.org/news/mirror-layout/",
        "https://archlinux.org/news/firmware-split/",
        "https://archlinux.org/news/pacman-7/",
    ]
    # The feed's own order (Oct 1, Nov 7, Nov 5) is not trusted.
    assert items[0].published == datetime(2026, 11, 7, 9, 30, tzinfo=timezone(timedelta(hours=1)))
    assert items[0].published.utcoffset() == timedelta(hours=1)
    assert items[0].summary == "Mirrors move to mirror.archlinux.org."
    assert items[2].summary == "The local database needs a one-time migration."
    # Everything is timezone-aware, even the items published in UTC.
    assert all(item.published.tzinfo is not None for item in items)


def test_parse_feed_collapses_whitespace_and_strips_html_tags():
    description = (
        '&lt;p&gt;Read the &lt;a href="https://archlinux.org/news/"&gt;news&lt;/a&gt;.\n'
        "   Then run   &lt;code&gt;pacman -Syu&lt;/code&gt;.&lt;/p&gt;"
    )
    items = news.parse_feed(_feed(_item(description=description)))
    assert items[0].summary == "Read the news. Then run pacman -Syu."


def test_parse_feed_skips_items_missing_a_title_link_or_usable_date():
    feed = _feed(
        _item(title="Kept"),
        _item(title="", link="https://archlinux.org/news/no-title/"),
        _item(title="No link", link=""),
        _item(title="No pubDate", pub_date=None),
        _item(title="Unparsable date", pub_date="some time after lunch"),
    )
    assert [item.title for item in news.parse_feed(feed)] == ["Kept"]


def test_parse_feed_raises_value_error_on_malformed_xml():
    with pytest.raises(ValueError, match="Arch news feed"):
        news.parse_feed("<rss><channel><item></channel>")


def test_parse_feed_raises_value_error_when_there_is_no_channel():
    with pytest.raises(ValueError, match="channel"):
        news.parse_feed("<html><body>not a feed</body></html>")


@pytest.mark.parametrize(
    ("pub_date", "expected"),
    [
        ("Wed, 05 Nov 2026 02:00:00 +0000", datetime(2026, 11, 5, 2, 0, tzinfo=timezone.utc)),
        ("Wed, 05 Nov 2026 02:00:00 +0100", datetime(2026, 11, 5, 2, 0, tzinfo=timezone(timedelta(hours=1)))),
        ("Wed, 05 Nov 2026 02:00:00 GMT", datetime(2026, 11, 5, 2, 0, tzinfo=timezone.utc)),
        # No zone at all: RSS readers assume UTC, so do we.
        ("Wed, 05 Nov 2026 02:00:00", datetime(2026, 11, 5, 2, 0, tzinfo=timezone.utc)),
    ],
)
def test_parse_feed_parses_common_rss_date_forms(pub_date, expected):
    item = news.parse_feed(_feed(_item(pub_date=pub_date)))[0]
    assert item.published == expected
    assert item.published.tzinfo is not None


# -------------------------------------------------------------------- fetching --


class _FakeResponse:
    def __init__(self, body: bytes):
        self.body = body
        self.closed = False

    def read(self) -> bytes:
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.closed = True
        return False


def test_fetch_feed_requests_the_feed_with_an_atropa_user_agent(monkeypatch):
    seen: dict[str, object] = {}

    def fake_urlopen(request, timeout=None):
        seen["url"] = request.full_url
        seen["user_agent"] = request.get_header("User-agent")
        seen["timeout"] = timeout
        return _FakeResponse(b"<rss/>")

    monkeypatch.setattr(news.urllib.request, "urlopen", fake_urlopen)

    assert news.fetch_feed(timeout=3) == "<rss/>"
    assert seen["url"] == news.FEED_URL
    assert seen["user_agent"] == news.USER_AGENT
    assert seen["timeout"] == 3


def test_fetch_feed_replaces_undecodable_bytes(monkeypatch):
    monkeypatch.setattr(news.urllib.request, "urlopen", lambda request, timeout=None: _FakeResponse(b"caf\xe9"))
    assert news.fetch_feed() == "caf\ufffd"


def test_fetch_feed_reports_an_http_error_as_runtime_error(monkeypatch):
    def fake_urlopen(request, timeout=None):
        raise urllib.error.HTTPError(news.FEED_URL, 503, "Service Unavailable", None, None)

    monkeypatch.setattr(news.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="503"):
        news.fetch_feed()


def test_fetch_feed_reports_an_unreachable_host_as_runtime_error(monkeypatch):
    def fake_urlopen(request, timeout=None):
        raise urllib.error.URLError("Name or service not known")

    monkeypatch.setattr(news.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="Couldn't reach"):
        news.fetch_feed()


# -------------------------------------------------------------- pacman log --

PACMAN_LOG_TEXT = """\
[2026-10-01T10:00:00+0200] [PACMAN] Running 'pacman -Syu'
[2026-10-01T10:00:01+0200] [PACMAN] synchronizing package lists
[2026-10-01T10:00:02+0200] [PACMAN] starting full system upgrade
[2026-10-01T10:05:00+0200] [ALPM] transaction started
[2026-10-01T10:06:00+0200] [ALPM] installed linux (6.11.1.arch1-1)
[2026-11-04T08:00:00+0100] [PACMAN] Running 'pacman -Syu'
[2026-11-05T03:00:00+0100] [PACMAN] starting full system upgrade
[2026-11-05T03:00:04+0100] [ALPM] installed linux (6.12.1.arch1-1)
"""


def test_last_upgrade_time_returns_the_last_full_upgrade_and_keeps_its_zone():
    stamp = news.last_upgrade_time(PACMAN_LOG_TEXT)
    assert stamp == datetime(2026, 11, 5, 3, 0, tzinfo=timezone(timedelta(hours=1)))
    assert stamp.utcoffset() == timedelta(hours=1)
    assert stamp.tzinfo is not None


def test_last_upgrade_time_is_none_without_an_upgrade_line():
    assert news.last_upgrade_time("[2026-10-01T10:00:01+0200] [PACMAN] synchronizing package lists\n") is None


def test_last_upgrade_time_is_none_when_the_log_is_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(news, "PACMAN_LOG", tmp_path / "no-such-pacman.log")
    assert news.last_upgrade_time() is None


def test_last_upgrade_time_is_none_when_the_log_cannot_be_read(monkeypatch, tmp_path):
    # A directory at the log's path makes read_text() raise OSError.
    unreadable = tmp_path / "pacman.log"
    unreadable.mkdir()
    monkeypatch.setattr(news, "PACMAN_LOG", unreadable)
    assert news.last_upgrade_time() is None


def test_last_upgrade_time_reads_the_monkeypatched_log_file(monkeypatch, tmp_path):
    log = tmp_path / "pacman.log"
    log.write_text(PACMAN_LOG_TEXT, encoding="utf-8")
    monkeypatch.setattr(news, "PACMAN_LOG", log)
    assert news.last_upgrade_time() == datetime(2026, 11, 5, 2, 0, tzinfo=timezone.utc)


def test_last_upgrade_time_reads_a_naive_timestamp_as_utc():
    stamp = news.last_upgrade_time("[2026-11-05T03:00:00] [PACMAN] starting full system upgrade\n")
    assert stamp == datetime(2026, 11, 5, 3, 0, tzinfo=timezone.utc)
    assert stamp.tzinfo is not None


def test_last_upgrade_time_skips_lines_with_an_unparsable_timestamp():
    text = (
        "[not a timestamp] [PACMAN] starting full system upgrade\n"
        "[2026-11-05T03:00:00+0100] [PACMAN] starting full system upgrade\n"
    )
    assert news.last_upgrade_time(text) == datetime(2026, 11, 5, 3, 0, tzinfo=timezone(timedelta(hours=1)))


# ------------------------------------------------------------- relevant news --


def _news_items() -> list[news.NewsItem]:
    # Deliberately not in feed order: relevant_news() sorts newest-first.
    return [
        news.NewsItem("Oldest", "https://archlinux.org/news/old/", datetime(2026, 10, 1, tzinfo=timezone.utc)),
        news.NewsItem("Newest", "https://archlinux.org/news/new/", datetime(2026, 11, 7, tzinfo=timezone.utc)),
        news.NewsItem("Middle", "https://archlinux.org/news/mid/", datetime(2026, 11, 5, tzinfo=timezone.utc)),
    ]


def test_relevant_news_without_since_returns_the_newest_limit():
    picked = news.relevant_news(_news_items(), None, limit=2)
    assert [item.title for item in picked] == ["Newest", "Middle"]


def test_relevant_news_keeps_only_items_strictly_after_since():
    picked = news.relevant_news(_news_items(), datetime(2026, 11, 5, tzinfo=timezone.utc))
    # "Middle" is exactly at `since`, so it doesn't count as news.
    assert [item.title for item in picked] == ["Newest"]


def test_relevant_news_caps_to_limit_even_with_since():
    picked = news.relevant_news(_news_items(), datetime(2026, 1, 1, tzinfo=timezone.utc), limit=2)
    assert [item.title for item in picked] == ["Newest", "Middle"]


def test_relevant_news_reads_a_naive_since_as_utc():
    picked = news.relevant_news(_news_items(), datetime(2026, 11, 5))
    assert [item.title for item in picked] == ["Newest"]


def test_relevant_news_with_a_non_positive_limit_is_empty():
    assert news.relevant_news(_news_items(), None, limit=0) == []


# ---------------------------------------------------------------------- check --


def test_check_filters_the_feed_by_the_last_full_upgrade(monkeypatch, tmp_path):
    log = tmp_path / "pacman.log"
    log.write_text("[2026-11-04T00:00:00+0000] [PACMAN] starting full system upgrade\n", encoding="utf-8")
    monkeypatch.setattr(news, "PACMAN_LOG", log)

    report = news.check(fetch=lambda: FEED)

    assert report.error == ""
    assert report.since == datetime(2026, 11, 4, tzinfo=timezone.utc)
    # New mirror layout (Nov 7) and Kernel firmware split (Nov 5), not pacman 7 (Oct 1).
    assert [item.title for item in report.items] == ["New mirror layout", "Kernel firmware split"]
    assert report.checked_at.tzinfo is not None


def test_check_without_a_pacman_log_shows_the_newest_items(monkeypatch, tmp_path):
    monkeypatch.setattr(news, "PACMAN_LOG", tmp_path / "no-such-pacman.log")

    report = news.check(fetch=lambda: FEED)

    assert report.error == ""
    assert report.since is None
    assert [item.title for item in report.items] == [
        "New mirror layout",
        "Kernel firmware split",
        "pacman 7 requires manual intervention",
    ]


def test_check_puts_a_fetch_failure_in_the_report_instead_of_raising(monkeypatch, tmp_path):
    monkeypatch.setattr(news, "PACMAN_LOG", tmp_path / "no-such-pacman.log")

    def boom():
        raise RuntimeError("network is unreachable")

    report = news.check(fetch=boom)

    assert report.items == []
    assert "network is unreachable" in report.error
    assert report.checked_at.tzinfo is not None


def test_check_puts_a_malformed_feed_in_the_report(monkeypatch, tmp_path):
    monkeypatch.setattr(news, "PACMAN_LOG", tmp_path / "no-such-pacman.log")

    report = news.check(fetch=lambda: "<rss><channel><item></channel>")

    assert report.items == []
    assert "Arch news feed" in report.error
