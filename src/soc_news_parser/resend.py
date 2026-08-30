from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from email.utils import parseaddr
from pathlib import Path
from typing import Any, Callable

import httpx
from bs4 import BeautifulSoup
from markdown import markdown as render_markdown_html


RESEND_ENDPOINT = "https://api.resend.com/emails"
MAX_RAW_ATTACHMENT_BYTES = 28 * 1024 * 1024
MAX_REQUEST_BYTES = 38 * 1024 * 1024


class ResendError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReportEmail:
    payload: dict[str, Any]
    idempotency_key: str
    report_id: str


@dataclass(frozen=True)
class SendResult:
    email_id: str
    report_id: str
    idempotency_key: str


def _sanitize_rendered_html(value: str) -> str:
    soup = BeautifulSoup(value, "html.parser")
    for node in soup.select("script, style, iframe, object, embed, link, meta, img"):
        node.decompose()
    for node in soup.find_all(True):
        href = node.get("href")
        node.attrs = {}
        if node.name == "a" and isinstance(href, str):
            if href.startswith(("https://", "http://")):
                node["href"] = href
                node["rel"] = "noopener noreferrer"
    return str(soup)


def _valid_address(value: str, *, allow_display_name: bool = False) -> str:
    if "\r" in value or "\n" in value:
        raise ResendError("email addresses cannot contain line breaks")
    display_name, address = parseaddr(value)
    if not address or "@" not in address or address.startswith("@"):
        raise ResendError(f"invalid email address: {value!r}")
    local, domain = address.rsplit("@", 1)
    if not local or "." not in domain or any(char.isspace() for char in address):
        raise ResendError(f"invalid email address: {value!r}")
    if display_name and not allow_display_name:
        raise ResendError(f"recipient display names are not allowed: {value!r}")
    return value


def _load_report_pair(
    json_path: str, markdown_path: str
) -> tuple[dict[str, Any], str, bytes, bytes]:
    json_file = Path(json_path).expanduser().resolve()
    markdown_file = Path(markdown_path).expanduser().resolve()
    try:
        json_bytes = json_file.read_bytes()
        markdown_bytes = markdown_file.read_bytes()
        report = json.loads(json_bytes)
        markdown = markdown_bytes.decode("utf-8")
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ResendError(f"could not read report pair: {error}") from error

    report_id = report.get("report_id")
    subject = report.get("subject")
    if not isinstance(report_id, str) or len(report_id) != 64:
        raise ResendError("JSON report has no valid report_id")
    if not isinstance(subject, str) or not subject.startswith("[SOC]"):
        raise ResendError("JSON report has no valid SOC subject")
    if report_id not in markdown:
        raise ResendError("JSON and Markdown Report IDs do not match")
    if len(json_bytes) + len(markdown_bytes) > MAX_RAW_ATTACHMENT_BYTES:
        raise ResendError("report attachments exceed the safe 28 MiB raw-size limit")
    return report, markdown, json_bytes, markdown_bytes


def build_report_email(
    *,
    json_path: str,
    markdown_path: str,
    sender: str,
    recipients: list[str],
) -> ReportEmail:
    if not recipients:
        raise ResendError("at least one recipient is required")
    sender = _valid_address(sender, allow_display_name=True)
    normalized_recipients = [_valid_address(value) for value in recipients]
    report, markdown, json_bytes, markdown_bytes = _load_report_pair(
        json_path, markdown_path
    )
    report_id = report["report_id"]
    recipient_digest = hashlib.sha256(
        "\n".join(sorted(normalized_recipients)).encode()
    ).hexdigest()[:16]
    idempotency_key = f"soc-report/{report_id}/{recipient_digest}"
    rendered_report = render_markdown_html(
        markdown,
        extensions=["sane_lists"],
        output_format="html",
    )
    rendered_report = _sanitize_rendered_html(rendered_report)
    payload = {
        "from": sender,
        "to": normalized_recipients,
        "subject": report["subject"],
        "text": markdown,
        "html": (
            "<html><head><style>"
            "body{font-family:Arial,'Noto Sans TC',sans-serif;line-height:1.6;"
            "color:#17202a;max-width:860px;margin:24px auto;padding:0 20px}"
            "h1{font-size:26px;border-bottom:2px solid #1f618d;padding-bottom:10px}"
            "h2{font-size:20px;margin-top:30px;color:#154360}"
            "h3{font-size:16px;color:#1f618d}"
            "code{background:#f2f4f4;padding:2px 5px;border-radius:3px;"
            "overflow-wrap:anywhere}"
            "li{margin:5px 0}a{color:#1a5276}"
            "</style></head><body>"
            f"{rendered_report}"
            "</body></html>"
        ),
        "attachments": [
            {
                "filename": Path(markdown_path).name,
                "content": base64.b64encode(markdown_bytes).decode("ascii"),
                "content_type": "text/markdown; charset=utf-8",
            },
            {
                "filename": Path(json_path).name,
                "content": base64.b64encode(json_bytes).decode("ascii"),
                "content_type": "application/json",
            },
        ],
        "tags": [{"name": "report_id", "value": report_id}],
    }
    request_size = len(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )
    if request_size > MAX_REQUEST_BYTES:
        raise ResendError("encoded email request exceeds the safe 38 MiB limit")
    return ReportEmail(payload, idempotency_key, report_id)


class ResendClient:
    def __init__(
        self,
        api_key: str,
        *,
        client: httpx.Client | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if not api_key:
            raise ResendError("RESEND_API_KEY is required")
        self.api_key = api_key
        self.client = client or httpx.Client(timeout=30.0)
        self._owns_client = client is None
        self.sleeper = sleeper

    @classmethod
    def from_environment(cls) -> ResendClient:
        return cls(os.environ.get("RESEND_API_KEY", ""))

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def __enter__(self) -> ResendClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def send(self, email: ReportEmail) -> SendResult:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Idempotency-Key": email.idempotency_key,
        }
        for attempt in range(3):
            try:
                response = self.client.post(
                    RESEND_ENDPOINT, headers=headers, json=email.payload
                )
            except httpx.HTTPError as error:
                if attempt == 2:
                    raise ResendError(f"Resend request failed: {error}") from error
                self.sleeper(2**attempt)
                continue

            if response.status_code < 400:
                try:
                    email_id = response.json()["id"]
                except (ValueError, KeyError, TypeError) as error:
                    raise ResendError("Resend returned no email id") from error
                if not isinstance(email_id, str) or not email_id:
                    raise ResendError("Resend returned an invalid email id")
                return SendResult(email_id, email.report_id, email.idempotency_key)

            retryable = response.status_code == 429 or response.status_code >= 500
            if retryable and attempt < 2:
                retry_after = response.headers.get("retry-after")
                try:
                    delay = min(float(retry_after), 10.0) if retry_after else 2**attempt
                except ValueError:
                    delay = 2**attempt
                self.sleeper(delay)
                continue
            try:
                detail = response.json()
            except ValueError:
                detail = response.text[:500]
            raise ResendError(
                f"Resend rejected the request ({response.status_code}): {detail}"
            )
        raise ResendError("Resend request failed after retries")
