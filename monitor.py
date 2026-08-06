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
            if is_first or (
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


def generate_index(monitor: Monitor, config: dict, results: list[CheckResult], root: Path) -> None:
    """產生 index.html — 可瀏覽所有來源、下載檔案與監測歷史"""
    import html as _html
    archive_dir = root / "archive"
    sources_map = {s["id"]: s for s in config["sources"]}

    # ── 蒐集 archive 中的下載紀錄 ──
    archive_entries: list[dict] = []
    if archive_dir.exists():
        for src_dir in sorted(archive_dir.iterdir()):
            if not src_dir.is_dir():
                continue
            for snap_dir in sorted(src_dir.iterdir(), reverse=True):
                if not snap_dir.is_dir():
                    continue
                meta = {}
                meta_file = snap_dir / "metadata.json"
                if meta_file.exists():
                    try:
                        meta = json.loads(meta_file.read_text(encoding="utf-8"))
                    except Exception:
                        pass
                content_files = sorted(
                    str(f.relative_to(root)) for f in snap_dir.iterdir()
                    if f.name != "metadata.json"
                )
                archive_entries.append({
                    "source_id": src_dir.name,
                    "snapshot": snap_dir.name,
                    "snap_rel": str(snap_dir.relative_to(root)),
                    "files": content_files,
                    "meta": meta,
                })

    # ── 依 snapshot 分組 ──
    snap_map: dict[str, list[dict]] = {}
    for e in archive_entries:
        snap_map.setdefault(e["source_id"], []).append(e)

    # ── 來源狀態 ──
    order = {"changed": 0, "error": 1, "first_seen": 2, "unchanged": 3}
    rows_data = []
    for item in sorted(results, key=lambda r: order.get(r.status, 9)):
        label = {"changed": "有變更", "error": "錯誤",
                 "first_seen": "建立基準", "unchanged": "無變更"}[item.status]
        tag = {"changed": "danger", "error": "warning",
               "first_seen": "info", "unchanged": "success"}[item.status]
        snapshots = snap_map.get(item.source_id, [])
        rows_data.append({
            "id": item.source_id,
            "name": item.name[:120],
            "url": item.url,
            "status": item.status,
            "label": label,
            "tag": tag,
            "detail": item.detail[:200],
            "http": item.http_status or "",
            "downloaded": item.downloaded or "",
            "checked_at": item.checked_at,
            "snapshots": snapshots,
            "snap_count": len(snapshots),
            "tags": sources_map.get(item.source_id, {}).get("tags", []),
            "priority": sources_map.get(item.source_id, {}).get("priority", ""),
        })

    # ── 統計 ──
    counts = {k: sum(1 for r in rows_data if r["status"] == k)
              for k in ("changed", "first_seen", "unchanged", "error")}

    # ── 產生 JSON 內嵌資料 ──
    data_json = json.dumps({
        "generated_at": now_iso(),
        "stats": counts,
        "total_sources": len(rows_data),
        "total_snapshots": len(archive_entries),
        "sources": rows_data,
    }, ensure_ascii=False)

    html_text = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CEMS 法規監測儀表板</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,'Microsoft JhengHei',sans-serif;background:#f0f2f5;color:#1a1a2e}}
.header{{background:linear-gradient(135deg,#0f3460,#16213e);color:#fff;padding:28px 32px}}
.header h1{{font-size:1.6rem;font-weight:600}}
.header .sub{{opacity:.75;margin-top:4px;font-size:.85rem}}
.stats{{display:flex;gap:14px;padding:20px 32px;flex-wrap:wrap}}
.stat-card{{background:#fff;border-radius:12px;padding:16px 22px;min-width:120px;box-shadow:0 1px 4px rgba(0,0,0,.06)}}
.stat-card .num{{font-size:1.8rem;font-weight:700}}
.stat-card .lbl{{font-size:.8rem;color:#666;margin-top:2px}}
.stat-card.danger .num{{color:#e74c3c}}
.stat-card.warning .num{{color:#f39c12}}
.stat-card.info .num{{color:#3498db}}
.stat-card.success .num{{color:#27ae60}}
.container{{padding:0 32px 40px}}
.toolbar{{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap}}
.toolbar input,.toolbar select{{padding:8px 14px;border:1px solid #d0d5dd;border-radius:8px;font-size:.88rem;outline:none}}
.toolbar input:focus,.toolbar select:focus{{border-color:#3498db;box-shadow:0 0 0 3px rgba(52,152,219,.15)}}
.toolbar input{{flex:1;min-width:200px}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.06)}}
th,td{{padding:11px 14px;text-align:left;font-size:.88rem;border-bottom:1px solid #eee}}
th{{background:#f8f9fa;font-weight:600;color:#555;white-space:nowrap}}
tr:hover{{background:#f0f7ff}}
.badge{{display:inline-block;padding:3px 10px;border-radius:20px;font-size:.76rem;font-weight:600}}
.badge-danger{{background:#fde8e8;color:#c0392b}}
.badge-warning{{background:#fef3e2;color:#e67e22}}
.badge-info{{background:#e3f0fc;color:#2471a3}}
.badge-success{{background:#e6f9ee;color:#1e8449}}
.badge-priority{{font-size:.7rem;padding:2px 7px;border-radius:10px;margin-left:6px}}
.prio-official{{background:#d4edda;color:#155724}}
.prio-review{{background:#fff3cd;color:#856404}}
.prio-reference{{background:#e2e3e5;color:#383d41}}
a{{color:#2980b9;text-decoration:none}}
a:hover{{text-decoration:underline}}
.file-list{{font-size:.82rem}}
.file-list a{{margin-right:8px;white-space:nowrap}}
.snap-toggle{{cursor:pointer;color:#3498db;font-size:.82rem;user-select:none}}
.snap-detail{{display:none;margin-top:6px;padding:8px 12px;background:#f8f9fa;border-radius:8px;font-size:.8rem}}
.snap-detail.open{{display:block}}
.snap-row{{padding:2px 0}}
.snap-row .ts{{color:#888;margin-right:8px}}
.empty{{text-align:center;padding:40px;color:#999}}
.footer{{text-align:center;padding:16px;color:#999;font-size:.78rem}}
.url-cell{{max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.tag-chip{{display:inline-block;padding:1px 6px;margin:1px 3px;background:#eef2f7;border-radius:6px;font-size:.7rem;color:#555}}
</style>
</head>
<body>
<div class="header">
<h1>🌐 CEMS 各國法規監測儀表板</h1>
<div class="sub">自動化監測 · 版本比對 · 檔案歸檔</div>
</div>
<div class="stats" id="stats"></div>
<div class="container">
<div class="toolbar">
<input type="text" id="search" placeholder="🔍 搜尋來源名稱或網址..." oninput="renderTable()">
<select id="statusFilter" onchange="renderTable()">
<option value="">全部狀態</option>
<option value="changed">有變更</option>
<option value="error">錯誤</option>
<option value="first_seen">建立基準</option>
<option value="unchanged">無變更</option>
</select>
<select id="priorityFilter" onchange="renderTable()">
<option value="">全部優先級</option>
<option value="official">官方</option>
<option value="review">待確認</option>
<option value="reference">參考</option>
</select>
</div>
<table>
<thead><tr>
<th>狀態</th><th>來源名稱</th><th>標籤</th><th>HTTP</th>
<th>下載檔案</th><th>最近檢查</th>
</tr></thead>
<tbody id="tbody"></tbody>
</table>
<div class="empty" id="emptyMsg" style="display:none">沒有符合條件的來源</div>
</div>
<div class="footer">產生時間：<span id="genTime"></span> · CemsRegulationCrawler</div>

<script>
const DATA = {data_json};

function esc(s) {{
    const d = document.createElement("div");
    d.textContent = s || "";
    return d.innerHTML;
}}

function renderTable() {{
    const search = (document.getElementById("search").value || "").toLowerCase();
    const sf = document.getElementById("statusFilter").value;
    const pf = document.getElementById("priorityFilter").value;
    const filtered = DATA.sources.filter(r => {{
        if (sf && r.status !== sf) return false;
        if (pf && r.priority !== pf) return false;
        if (search) {{
            const hay = (r.name + r.url + r.tags.join(" ")).toLowerCase();
            if (!hay.includes(search)) return false;
        }}
        return true;
    }});
    const tbody = document.getElementById("tbody");
    const empty = document.getElementById("emptyMsg");
    if (filtered.length === 0) {{
        tbody.innerHTML = "";
        empty.style.display = "block";
        return;
    }}
    empty.style.display = "none";
    let html = "";
    filtered.forEach(r => {{
        const tagClass = "badge-" + r.tag;
        const prioClass = "prio-" + r.priority;
        let snapHtml = "";
        if (r.snapshots.length > 0) {{
            const sid = r.id.replace(/[^a-zA-Z0-9]/g, "_");
            snapHtml = '<span class="snap-toggle" onclick="toggleSnap(\'' + sid + '\')">\u{1F4E6} ' + r.snap_count + ' 個版本 \u25B8</span>';
            snapHtml += '<div class="snap-detail" id="snap_' + sid + '">';
            r.snapshots.forEach(s => {{
                snapHtml += '<div class="snap-row"><span class="ts">' + esc(s.snapshot) + '</span>';
                s.files.forEach(f => {{
                    const label = f.split("/").pop();
                    snapHtml += '<a href="' + esc(f) + '" target="_blank" title="' + esc(f) + '">\u{1F4C4} ' + esc(label) + '</a> ';
                }});
                if (s.meta && s.meta.sha256) {{
                    snapHtml += '<span style="color:#999;font-size:.72rem">SHA-256: ' + esc(s.meta.sha256.substring(0,16)) + '...</span>';
                }}
                snapHtml += '</div>';
            }});
            snapHtml += '</div>';
        }} else if (r.downloaded) {{
            snapHtml = '<a href="' + esc(r.downloaded) + '" class="file-list">\u{1F4C4} 下載</a>';
        }} else {{
            snapHtml = '<span style="color:#aaa">—</span>';
        }}
        const tagsHtml = r.tags.slice(0,3).map(t => '<span class="tag-chip">' + esc(t) + '</span>').join("");
        html += '<tr>' +
            '<td><span class="badge ' + tagClass + '">' + esc(r.label) + '</span>' +
            '<span class="badge-priority ' + prioClass + '">' + esc(r.priority) + '</span></td>' +
            '<td><a href="' + esc(r.url) + '" target="_blank" title="' + esc(r.url) + '">' + esc(r.name) + '</a></td>' +
            '<td>' + tagsHtml + '</td>' +
            '<td>' + esc(String(r.http)) + '</td>' +
            '<td>' + snapHtml + '</td>' +
            '<td style="white-space:nowrap;font-size:.8rem">' + esc(r.checked_at.replace("T"," ").substring(0,16)) + '</td>' +
            '</tr>';
    }});
    tbody.innerHTML = html;
}}

function toggleSnap(id) {{
    const el = document.getElementById("snap_" + id);
    if (el) el.classList.toggle("open");
}}

// ── 統計卡片 ──
(function() {{
    document.getElementById("genTime").textContent = DATA.generated_at.replace("T"," ").substring(0,19);
    const st = DATA.stats;
    const cards = [
        {{cls:"danger",num:st.changed,lbl:"有變更"}},
        {{cls:"warning",num:st.error,lbl:"錯誤"}},
        {{cls:"info",num:st.first_seen,lbl:"建立基準"}},
        {{cls:"success",num:st.unchanged,lbl:"無變更"}},
        {{cls:"",num:DATA.total_sources,lbl:"來源總數"}},
        {{cls:"",num:DATA.total_snapshots,lbl:"歸檔版本"}},
    ];
    document.getElementById("stats").innerHTML = cards.map(c =>
        '<div class="stat-card ' + c.cls + '"><div class="num">' + c.num + '</div><div class="lbl">' + c.lbl + '</div></div>'
    ).join("");
    renderTable();
}})();
</script>
</body>
</html>"""

    (root / "index.html").write_text(html_text, encoding="utf-8")


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
    generate_index(monitor, config, results, args.root)
    if args.notify:
        send_notifications(results, report)
    changed = sum(row.status == "changed" for row in results)
    errors = sum(row.status == "error" for row in results)
    print(f"Checked {len(results)} sources; changed={changed}; errors={errors}")
    print(report)
    return 0  # 網路錯誤已記錄於報告，不視為流程失敗


if __name__ == "__main__":
    sys.exit(main())
