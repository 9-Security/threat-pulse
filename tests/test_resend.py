import base64
import json
from pathlib import Path

import httpx
import pytest

from soc_news_parser.resend import (
    RESEND_ENDPOINT,
    ReportEmail,
    ResendClient,
    ResendError,
    build_report_email,
)


REPORT_ID = "a" * 64


def report_pair(tmp_path: Path) -> tuple[str, str]:
    json_path = tmp_path / "daily-evidence.json"
    markdown_path = tmp_path / "daily-report.md"
    json_path.write_text(
        json.dumps(
            {
                "report_id": REPORT_ID,
                "subject": "[SOC] 每日資安新聞 IoC 彙整報告 - 文章數 2 / IoC數 3",
            }
        ),
        encoding="utf-8",
    )
    markdown_path.write_text(
        f"# Report\n\n- Report ID：`{REPORT_ID}`\n\n<script>alert(1)</script>",
        encoding="utf-8",
    )
    return str(json_path), str(markdown_path)


def test_build_report_email_validates_pair_and_attaches_both_files(
    tmp_path: Path,
) -> None:
    json_path, markdown_path = report_pair(tmp_path)
    email = build_report_email(
        json_path=json_path,
        markdown_path=markdown_path,
        sender="SOC <reports@example.com>",
        recipients=["analyst@example.com"],
    )

    assert email.report_id == REPORT_ID
    assert email.payload["to"] == ["analyst@example.com"]
    assert email.payload["subject"].startswith("[SOC]")
    assert len(email.payload["attachments"]) == 2
    assert base64.b64decode(email.payload["attachments"][0]["content"]).startswith(
        b"# Report"
    )
    assert "<script>" not in email.payload["html"]
    assert len(email.idempotency_key) <= 256


def test_report_pair_mismatch_is_rejected(tmp_path: Path) -> None:
    json_path, markdown_path = report_pair(tmp_path)
    Path(markdown_path).write_text("# Wrong report", encoding="utf-8")

    with pytest.raises(ResendError, match="do not match"):
        build_report_email(
            json_path=json_path,
            markdown_path=markdown_path,
            sender="reports@example.com",
            recipients=["analyst@example.com"],
        )


def test_idempotency_key_changes_with_recipient(tmp_path: Path) -> None:
    json_path, markdown_path = report_pair(tmp_path)
    first = build_report_email(
        json_path=json_path,
        markdown_path=markdown_path,
        sender="reports@example.com",
        recipients=["first@example.com"],
    )
    second = build_report_email(
        json_path=json_path,
        markdown_path=markdown_path,
        sender="reports@example.com",
        recipients=["second@example.com"],
    )

    assert first.idempotency_key != second.idempotency_key


def test_resend_client_retries_and_returns_email_id() -> None:
    attempts = 0
    delays: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        assert str(request.url) == RESEND_ENDPOINT
        assert request.headers["authorization"] == "Bearer re_secret"
        assert request.headers["idempotency-key"] == "soc-report/test"
        if attempts == 1:
            return httpx.Response(
                429, headers={"retry-after": "0"}, json={"message": "slow down"}
            )
        return httpx.Response(200, json={"id": "email_123"})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    email = ReportEmail(
        payload={
            "from": "reports@example.com",
            "to": ["analyst@example.com"],
            "subject": "test",
            "text": "test",
        },
        idempotency_key="soc-report/test",
        report_id=REPORT_ID,
    )

    with ResendClient(
        "re_secret", client=client, sleeper=delays.append
    ) as resend:
        result = resend.send(email)

    assert attempts == 2
    assert delays == [0.0]
    assert result.email_id == "email_123"
    assert result.report_id == REPORT_ID


def test_resend_client_reports_non_retryable_error() -> None:
    transport = httpx.MockTransport(
        lambda _: httpx.Response(422, json={"message": "invalid sender"})
    )
    with ResendClient("re_secret", client=httpx.Client(transport=transport)) as client:
        with pytest.raises(ResendError, match="422"):
            client.send(
                ReportEmail(
                    payload={},
                    idempotency_key="soc-report/test",
                    report_id=REPORT_ID,
                )
            )
