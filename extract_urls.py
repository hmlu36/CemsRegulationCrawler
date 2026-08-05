#!/usr/bin/env python3
"""Extract hyperlinks and visible URLs from a DOCX into monitor configuration."""

from __future__ import annotations

import argparse
import json
import re
import zipfile
from pathlib import Path
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "pr": "http://schemas.openxmlformats.org/package/2006/relationships",
}
URL_RE = re.compile(r"https?://[^\s<>\]）)\"']+")
NON_OFFICIAL_HINTS = {
    "google.com", "youtube.com", "sciencedirect.com", "researchgate.net",
    "envirotech-online.com", "ektimo.com.au", "apexioindustrial.com.au",
    "qhsealert.com", "sustainabilitycloud.com", "zhiyanbao.cn",
}


def clean_url(value: str) -> str:
    return value.rstrip(".,;:!?，。；：、")


def infer_kind(url: str) -> str:
    path = urlparse(url).path.lower()
    if path.endswith(".pdf"):
        return "document"
    if path.endswith((".doc", ".docx", ".xls", ".xlsx", ".zip")):
        return "document"
    return "page"


def infer_priority(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if any(host == h or host.endswith("." + h) for h in NON_OFFICIAL_HINTS):
        return "reference"
    official_markers = (
        ".gov", ".gov.", ".go.", ".gob.", ".gc.ca", ".europa.eu", ".nic.in",
        ".gov.in", ".gov.uk", ".epa.", ".emb.gov.ph", ".doe.gov.my",
    )
    return "official" if any(marker in host for marker in official_markers) else "review"


def extract(docx: Path) -> list[dict]:
    with zipfile.ZipFile(docx) as archive:
        document = ET.fromstring(archive.read("word/document.xml"))
        rels_root = ET.fromstring(archive.read("word/_rels/document.xml.rels"))
        rels = {
            item.attrib["Id"]: item.attrib.get("Target", "")
            for item in rels_root.findall("pr:Relationship", NS)
            if item.attrib.get("TargetMode") == "External"
        }

    found: dict[str, dict] = {}
    for paragraph in document.findall(".//w:p", NS):
        text = "".join(node.text or "" for node in paragraph.findall(".//w:t", NS)).strip()
        for hyperlink in paragraph.findall(".//w:hyperlink", NS):
            target = rels.get(hyperlink.attrib.get(f"{{{NS['r']}}}id", ""))
            if target and target.startswith(("http://", "https://")):
                found.setdefault(clean_url(target), {"context": text[:240]})
        for match in URL_RE.findall(text):
            found.setdefault(clean_url(match), {"context": text[:240]})

    rows = []
    for index, (url, meta) in enumerate(sorted(found.items()), 1):
        host = urlparse(url).hostname or "unknown"
        rows.append(
            {
                "id": f"src-{index:03d}",
                "name": meta["context"] or host,
                "url": url,
                "kind": infer_kind(url),
                "priority": infer_priority(url),
                "enabled": "google.com/search" not in url,
                "download_on_change": infer_kind(url) == "document",
                "tags": [host],
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("docx", type=Path)
    parser.add_argument("--output", type=Path, default=Path("sources.json"))
    args = parser.parse_args()
    payload = {
        "defaults": {
            "timeout_seconds": 30,
            "check_interval": "weekly",
            "user_agent": "CEMS-Regulation-Monitor/1.0 (+regulatory research)",
        },
        "sources": extract(args.docx),
    }
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {len(payload['sources'])} URLs to {args.output}")


if __name__ == "__main__":
    main()
