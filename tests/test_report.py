from datetime import datetime, timezone

from soc_news_parser.parser import ParseError, ParsedArticle
from soc_news_parser.report import collect_report, render_markdown


def parsed_article(source: str, title: str, body: str) -> ParsedArticle:
    return ParsedArticle(
        source=source,
        title=title,
        url=f"https://example.test/{title.lower().replace(' ', '-')}",
        published_at="2026-08-29T12:00:00+00:00",
        body=body,
        extraction_method="feed:content",
        body_characters=len(body),
        warnings=[],
    )


class FakeParser:
    def parse_feed(self, source: object, **_: object) -> list[ParsedArticle]:
        name = getattr(source, "name")
        if name == "BleepingComputer":
            raise ParseError("simulated source failure")
        if name == "The Hacker News":
            return [
                parsed_article(
                    name,
                    "First report",
                    """Indicators of Compromise
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
evil[.]example
payload.exe
""",
                ),
                parsed_article(
                    name,
                    "Second report",
                    """Security analysis
The report mentions evil[.]example without characterizing it.
""",
                ),
            ]
        return []


def test_report_counts_unique_confirmed_values_and_failures() -> None:
    generated = datetime(2026, 8, 30, 1, 21, tzinfo=timezone.utc)
    report = collect_report(
        FakeParser(),  # type: ignore[arg-type]
        ["the-hacker-news", "bleepingcomputer"],
        since=datetime(2026, 8, 29, 1, 21, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
    )

    assert report.article_count == 2
    assert report.confirmed_ioc_count == 2
    assert report.confirmed_filename_count == 1
    assert report.subject.endswith("文章數 2 / IoC數 2")
    assert len(report.source_failures) == 1

    markdown = render_markdown(report)
    assert "simulated source failure" in markdown
    assert "Candidate 唯一值：1" in markdown
    assert "正文 SHA-256" in markdown
    assert "不納入主旨統計" in markdown
