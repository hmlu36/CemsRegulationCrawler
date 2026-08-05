#!/usr/bin/env python3
"""Periodic CEMS regulation webpage and document change monitor."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import smtplib
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup

VOLATILE_QUERY_KEYS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "ved", "sourceid",
}
DOCUMENT_EXTENSIONS = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_url(url: str) -> str:
    parts = urlsplit(url)
    pairs = []
    for chunk in parts.query.split("&"):
        if not chunk:
            continue
        key = chunk.split("=", 1)[0].lower()
        if key not in VOLATILE_QUERY_KEYS:
            pairs.append(chunk)
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path, "&".join(pairs), "")
    )


def normalize_html(content: bytes, base_url: str) -> tuple[bytes, list[str], str]:
    soup = BeautifulSoup(content, "html.parser")
    for node in soup(["script", "style", "noscript", "svg"]):
        node.decompose()
    for selector in (
        "header", "footer", "nav", ".cookie", ".cookies", ".breadcrumb",
        ".social", ".share", "[aria-label*=cookie i]",
    ):
        for node in soup.select(selector):
            node.decompose()
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))
    links = set()
    for anchor in soup.select("a[href]"):
        absolute = canonical_url(urljoin(base_url, anchor.get("href", "")))
        if urlsplit(absolute).path.lower().endswith(DOCUMENT_EXTENSIONS):
            links.add(absolute)
    fingerprint_input = (title + "\n" + text + "\n" + "\n".join(sorted(links))).encode()
    return fingerprint_input, sorted(links), title


@dataclass
class CheckResult:
    source_id: str
    name: str
    url: str
    status: str
    detail: str
    checked_at: str
    http_status: int | None = None
    downloaded: str | None = None


class Monitor:
    def __init__(self, root: Path, config: dict):
        self.root = root
        self.config = config
        self.archive = root / "archive"
        self.archive.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(root / "monitor_state.sqlite3")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS state (
               source_id TEXT PRIMARY KEY, url TEXT NOT NULL, content_hash TEXT,
               etag TEXT, last_modified TEXT, document_links TEXT,
               last_status INTEGER, last_checked TEXT, last_changed TEXT)"""
        )
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS events (
               id INTEGER PRIMARY KEY, source_id TEXT, checked_at TEXT,
               event_type TEXT, detail TEXT)"""
        )
        defaults = config.get("defaults", {})
        raw_timeout = defaults.get("timeout_seconds", 30)
        self.timeout = (min(10, raw_timeout), raw_timeout)
        self.session = requests.Session()
        self.session.headers["User-Agent"] = defaults.get(
            "user_agent", "CEMS-Regulation-Monitor/1.0"
        )

    def previous(self, source_id: str):
        return self.db.execute(
            "SELECT content_hash, etag, last_modified, document_links, last_status "
            "FROM state WHERE source_id=?", (source_id,)
        ).fetchone()

    def record(self, source: dict, digest: str, response: requests.Response,
               links: list[str], changed: bool, event: str, detail: str) -> None:
        checked = now_iso()
        self.db.execute(
            """INSERT INTO state
               (source_id,url,content_hash,etag,last_modified,document_links,
                last_status,last_checked,last_changed)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(source_id) DO UPDATE SET
                 url=excluded.url, content_hash=excluded.content_hash,
                 etag=excluded.etag, last_modified=excluded.last_modified,
                 document_links=excluded.document_links,
                 last_status=excluded.last_status, last_checked=excluded.last_checked,
                 last_changed=CASE WHEN ? THEN excluded.last_changed
                                   ELSE state.last_changed END""",
            (
                source["id"], source["url"], digest, response.headers.get("ETag"),
                response.headers.get("Last-Modified"), json.dumps(links),
                response.status_code, checked, checked if changed else None, changed,
            ),
        )
        self.db.execute(
            "INSERT INTO events(source_id,checked_at,event_type,detail) VALUES(?,?,?,?)",
            (source["id"], checked, event, detail),
        )
        self.db.commit()

    def archive_bytes(self, source: dict, content: bytes, response: requests.Response) -> str:
        date_dir = self.archive / source["id"] / datetime.now().strftime("%Y%m%d-%H%M%S")
        date_dir.mkdir(parents=True, exist_ok=True)
        suffix = Path(urlsplit(response.url).path).suffix.lower()
        if not suffix:
            ctype = response.headers.get("Content-Type", "").lower()
            suffix = ".pdf" if "pdf" in ctype else ".html"
        target = date_dir / f"content{suffix[:8]}"
        target.write_bytes(content)
        (date_dir / "metadata.json").write_text(
            json.dumps(
                {
                    "source_url": source["url"], "final_url": response.url,
                    "downloaded_at": now_iso(), "sha256": sha256(content),
                    "content_type": response.headers.get("Content-Type"),
                    "etag": response.headers.get("ETag"),
                    "last_modified": response.headers.get("Last-Modified"),
                },
                ensure_ascii=False, indent=2,
            ),
            encoding="utf-8",
        )
        return str(target.relative_to(self.root))

    def check_one(self, source: dict) -> CheckResult:
        checked = now_iso()
        previous = self.previous(source["id"])
        headers = {}
        if previous:
            if previous[1]:
                headers["If-None-Match"] = previous[1]
            if previous[2]:
                headers["If-Modified-Since"] = previous[2]
        try:
            response = self.session.get(
                source["url"], headers=headers, timeout=self.timeout,
                allow_redirects=True,
            )
            if response.status_code == 304:
                self.record(source, previous[0], response,
                            json.loads(previous[3] or "[]"), False,
                            "unchanged", "HTTP 304 Not Modified")
                return CheckResult(source["id"], source["name"], source["url"],
                                   "unchanged", "伺服器回覆未變更", checked, 304)
            response.raise_for_status()
            ctype = response.headers.get("Content-Type", "").lower()
            is_document = source.get("kind") == "document" or any(
                token in ctype for token in ("application/pdf", "application/msword",
                                             "officedocument", "application/zip")
            )
            if is_document:
                fingerprint, links, title = response.content, [], ""
            else:
                fingerprint, links, title = normalize_html(response.content, response.url)
            digest = sha256(fingerprint)
            is_first = previous is None
            changed = bool(previous and previous[0] != digest)
            new_links = []
            if previous:
                old_links = set(json.loads(previous[3] or "[]"))
                new_links = sorted(set(links) - old_links)
                changed = changed or bool(new_links)
            downloaded = None
            if (is_first and source.get("download_on_first_seen")) or (
                changed and source.get("download_on_change", is_document)
            ):
                downloaded = self.archive_bytes(source, response.content, response)
            event = "first_seen" if is_first else ("changed" if changed else "unchanged")
            detail = title or response.url
            if new_links:
                detail += f"; 新增附件 {len(new_links)} 個"
            self.record(source, digest, response, links, changed, event, detail)
            status = event
            return CheckResult(source["id"], source["name"], source["url"], status,
                               detail, checked, response.status_code, downloaded)
        except Exception as exc:
            detail = f"{type(exc).__name__}: {exc}"
            self.db.execute(
                "INSERT INTO events(source_id,checked_at,event_type,detail) VALUES(?,?,?,?)",
                (source["id"], checked, "error", detail),
            )
            self.db.commit()
            return CheckResult(source["id"], source["name"], source["url"],
                               "error", detail, checked)

    def run(self, priority: str | None = None) -> list[CheckResult]:
        rows = []
        for source in self.config["sources"]:
            if not source.get("enabled", True):
                continue
            if priority and source.get("priority") != priority:
                continue
            rows.append(self.check_one(source))
            time.sleep(float(os.getenv("CEMS_REQUEST_DELAY", "0.5")))
        return rows


def make_report(results: list[CheckResult], path: Path) -> None:
    counts = {key: sum(r.status == key for r in results)
              for key in ("changed", "first_seen", "unchanged", "error")}
    lines = [
        "# CEMS 法規網址監測報告", "",
        f"- 產生時間：{now_iso()}",
        f"- 變更：{counts['changed']}；首次建立基準：{counts['first_seen']}；"
        f"未變更：{counts['unchanged']}；錯誤：{counts['error']}", "",
        "| 狀態 | 名稱 | HTTP | 說明 |",
        "|---|---|---:|---|",
    ]
    order = {"changed": 0, "error": 1, "first_seen": 2, "unchanged": 3}
    for item in sorted(results, key=lambda row: order[row.status]):
        label = {"changed": "有變更", "error": "錯誤", "first_seen": "建立基準",
                 "unchanged": "無變更"}[item.status]
        name = item.name.replace("|", "／")[:90]
        detail = item.detail.replace("|", "／")[:180]
        lines.append(
            f"| {label} | [{name}]({item.url}) | {item.http_status or ''} | {detail} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def send_notifications(results: list[CheckResult], report: Path) -> None:
    important = [r for r in results if r.status in {"changed", "error"}]
    if not important:
        return
    summary = "\n".join(
        f"- {r.status}: {r.name[:80]} — {r.url}" for r in important[:30]
    )
    webhook = os.getenv("CEMS_WEBHOOK_URL")
    if webhook:
        requests.post(webhook, json={"text": "CEMS 法規監測結果\n" + summary}, timeout=20)
    if all(os.getenv(key) for key in ("SMTP_HOST", "SMTP_FROM", "SMTP_TO")):
        message = EmailMessage()
        message["Subject"] = f"CEMS 法規監測：{len(important)} 項需注意"
        message["From"] = os.environ["SMTP_FROM"]
        message["To"] = os.environ["SMTP_TO"]
        message.set_content("CEMS 法規監測結果\n\n" + summary)
        message.add_attachment(report.read_bytes(), maintype="text",
                               subtype="markdown", filename=report.name)
        port = int(os.getenv("SMTP_PORT", "587"))
        with smtplib.SMTP(os.environ["SMTP_HOST"], port) as smtp:
            smtp.starttls()
            if os.getenv("SMTP_USER"):
                smtp.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
            smtp.send_message(message)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("sources.json"))
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--priority", choices=("official", "review", "reference"))
    parser.add_argument("--notify", action="store_true")
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    monitor = Monitor(args.root, config)
    results = monitor.run(args.priority)
    report = args.root / "latest_report.md"
    make_report(results, report)
    if args.notify:
        send_notifications(results, report)
    changed = sum(row.status == "changed" for row in results)
    errors = sum(row.status == "error" for row in results)
    print(f"Checked {len(results)} sources; changed={changed}; errors={errors}")
    print(report)
    return 0  # 網路錯誤已記錄於報告，不視為流程失敗


if __name__ == "__main__":
    sys.exit(main())
