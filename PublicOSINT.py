#!/usr/bin/env python3
"""
PublicOSINTPy - pengumpul OSINT ringan dari sumber publik.

Gunakan secara legal dan etis: hanya kumpulkan data publik dari website yang
diizinkan/masuk akal untuk dianalisis. Jangan gunakan untuk doxxing, stalking,
pelecehan, atau mengakses data yang tidak dimaksudkan untuk publik.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable


USER_AGENT = "PublicOSINTPy/1.0 (+public website contact discovery)"
DEFAULT_TIMEOUT = 10

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(
    r"(?:(?:\+|00)\d{1,3}[\s().-]?)?(?:\(?\d{2,4}\)?[\s().-]?){2,5}\d{2,4}"
)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
META_RE = re.compile(
    r"<meta\s+[^>]*(?:name|property)=['\"]([^'\"]+)['\"][^>]*content=['\"]([^'\"]*)['\"][^>]*>",
    re.I,
)

SOCIAL_DOMAINS = {
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "x.com",
    "twitter.com",
    "youtube.com",
    "tiktok.com",
    "github.com",
    "gitlab.com",
    "medium.com",
    "threads.net",
    "telegram.me",
    "t.me",
    "wa.me",
    "api.whatsapp.com",
}

CONTACT_HINTS = (
    "contact",
    "kontak",
    "about",
    "tentang",
    "team",
    "tim",
    "staff",
    "privacy",
    "support",
    "help",
)


@dataclass(frozen=True)
class Evidence:
    value: str
    source_url: str
    context: str = ""


@dataclass
class OsintResult:
    start_url: str
    visited: list[str] = field(default_factory=list)
    emails: dict[str, list[Evidence]] = field(default_factory=dict)
    phones: dict[str, list[Evidence]] = field(default_factory=dict)
    social_links: dict[str, list[Evidence]] = field(default_factory=dict)
    names: dict[str, list[Evidence]] = field(default_factory=dict)
    page_titles: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, dict[str, str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def add(self, bucket: str, value: str, source_url: str, context: str = "") -> None:
        clean = value.strip()
        if not clean:
            return
        target = getattr(self, bucket)
        target.setdefault(clean, [])
        ev = Evidence(clean, source_url, context.strip()[:220])
        if ev not in target[clean]:
            target[clean].append(ev)


class WebParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        if tag == "a":
            href = attrs_dict.get("href", "")
            if href:
                self.links.append(href)

    def handle_data(self, data: str) -> None:
        if data and data.strip():
            self.text_parts.append(data.strip())

    @property
    def text(self) -> str:
        return " ".join(self.text_parts)


def normalize_url(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError("URL kosong.")
    if "://" not in value:
        value = "https://" + value
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL harus valid dan memakai http/https.")
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", "", parsed.query, ""))


def clean_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", "", parsed.query, ""))


def same_site(url: str, root_host: str, include_subdomains: bool) -> bool:
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if include_subdomains:
        return host == root_host or host.endswith("." + root_host)
    return host == root_host


def request_url(url: str, timeout: int) -> tuple[str, str, str]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.5",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(1_500_000).decode("utf-8", errors="ignore")
        return clean_url(resp.geturl()), body, resp.headers.get("content-type", "")


def deobfuscate_text(text: str) -> str:
    replacements = {
        " [at] ": "@",
        " (at) ": "@",
        " at ": "@",
        " [dot] ": ".",
        " (dot) ": ".",
        " dot ": ".",
    }
    lowered = text
    for old, new in replacements.items():
        lowered = re.sub(re.escape(old), new, lowered, flags=re.I)
    return lowered


def normalize_phone(raw: str) -> str:
    value = re.sub(r"\s+", " ", raw).strip(" .,-()")
    digits = re.sub(r"\D", "", value)
    if len(digits) < 8 or len(digits) > 16:
        return ""
    if re.fullmatch(r"0+", digits):
        return ""
    return value


def context_around(text: str, value: str, width: int = 90) -> str:
    idx = text.lower().find(value.lower())
    if idx == -1:
        return ""
    start = max(0, idx - width)
    end = min(len(text), idx + len(value) + width)
    return re.sub(r"\s+", " ", text[start:end])


def extract_title(html: str) -> str:
    match = TITLE_RE.search(html)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()


def extract_meta(html: str) -> dict[str, str]:
    meta = {}
    for name, content in META_RE.findall(html):
        key = name.strip().lower()
        if key in {"description", "keywords", "og:title", "og:description", "author"}:
            meta[key] = re.sub(r"\s+", " ", content).strip()
    return meta


def social_domain(url: str) -> str:
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    for domain in SOCIAL_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return domain
    return ""


def should_prioritize(url: str) -> bool:
    lower = url.lower()
    return any(hint in lower for hint in CONTACT_HINTS)


def load_names(args: argparse.Namespace) -> list[str]:
    names = list(args.name or [])
    if args.names_file:
        path = Path(args.names_file)
        names.extend(path.read_text(encoding="utf-8", errors="ignore").splitlines())
    unique = []
    seen = set()
    for name in names:
        clean = re.sub(r"\s+", " ", name).strip()
        if clean and clean.lower() not in seen:
            unique.append(clean)
            seen.add(clean.lower())
    return unique


def collect_from_page(result: OsintResult, url: str, html: str, names: list[str]) -> WebParser:
    parser = WebParser()
    parser.feed(html)
    text = deobfuscate_text(parser.text + " " + html)
    visible_text = deobfuscate_text(parser.text)

    title = extract_title(html)
    if title:
        result.page_titles[url] = title

    meta = extract_meta(html)
    if meta:
        result.metadata[url] = meta

    for email in sorted(set(EMAIL_RE.findall(text))):
        result.add("emails", email, url, context_around(visible_text or text, email))

    for phone_raw in sorted(set(PHONE_RE.findall(visible_text))):
        phone = normalize_phone(phone_raw)
        if phone:
            result.add("phones", phone, url, context_around(visible_text, phone_raw))

    for name in names:
        pattern = re.compile(r"\b" + re.escape(name) + r"\b", re.I)
        match = pattern.search(visible_text)
        if match:
            result.add("names", name, url, context_around(visible_text, match.group(0)))

    return parser


def scan(args: argparse.Namespace) -> OsintResult:
    start_url = normalize_url(args.url)
    root_host = urllib.parse.urlparse(start_url).hostname or ""
    names = load_names(args)
    result = OsintResult(start_url=start_url)

    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    seen = set()

    while queue and len(result.visited) < args.max_urls:
        url, depth = queue.popleft()
        url = clean_url(url)
        if url in seen:
            continue
        seen.add(url)
        if not same_site(url, root_host, args.include_subdomains):
            continue

        try:
            final_url, html, content_type = request_url(url, args.timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            result.errors.append(f"{url}: {exc}")
            continue

        result.visited.append(final_url)
        if "html" not in content_type.lower() and "text" not in content_type.lower():
            time.sleep(args.delay)
            continue

        parser = collect_from_page(result, final_url, html, names)

        if depth < args.depth:
            internal_links = []
            priority_links = []
            for href in parser.links:
                absolute = clean_url(urllib.parse.urljoin(final_url, href))
                domain = social_domain(absolute)
                if domain:
                    result.add("social_links", absolute, final_url, domain)
                    continue
                if same_site(absolute, root_host, args.include_subdomains) and absolute not in seen:
                    if should_prioritize(absolute):
                        priority_links.append(absolute)
                    else:
                        internal_links.append(absolute)
            for next_url in priority_links + internal_links:
                queue.append((next_url, depth + 1))

        time.sleep(args.delay)

    return result


def evidence_to_dict(items: dict[str, list[Evidence]]) -> dict[str, list[dict[str, str]]]:
    return {
        value: [{"source_url": ev.source_url, "context": ev.context} for ev in evidence]
        for value, evidence in sorted(items.items())
    }


def render_json(result: OsintResult) -> str:
    return json.dumps(
        {
            "start_url": result.start_url,
            "visited_count": len(result.visited),
            "visited": result.visited,
            "emails": evidence_to_dict(result.emails),
            "phones": evidence_to_dict(result.phones),
            "social_links": evidence_to_dict(result.social_links),
            "names": evidence_to_dict(result.names),
            "page_titles": result.page_titles,
            "metadata": result.metadata,
            "errors": result.errors,
        },
        indent=2,
        ensure_ascii=False,
    )


def render_text(result: OsintResult) -> str:
    lines = [
        f"Target        : {result.start_url}",
        f"URL dikunjungi: {len(result.visited)}",
        f"Email         : {len(result.emails)}",
        f"No. HP/Telp   : {len(result.phones)}",
        f"Link sosial   : {len(result.social_links)}",
        f"Nama cocok    : {len(result.names)}",
        "",
    ]

    sections = [
        ("Email", result.emails),
        ("No. HP/Telp", result.phones),
        ("Link Sosial", result.social_links),
        ("Nama", result.names),
    ]
    for title, bucket in sections:
        lines.append(title + ":")
        if not bucket:
            lines.append("  - tidak ditemukan")
        for value, evidence in sorted(bucket.items()):
            lines.append(f"  - {value}")
            for ev in evidence[:3]:
                lines.append(f"    sumber: {ev.source_url}")
                if ev.context:
                    lines.append(f"    konteks: {ev.context}")
            if len(evidence) > 3:
                lines.append(f"    ... {len(evidence) - 3} sumber lain")
        lines.append("")

    if result.errors:
        lines.append(f"Error ringan: {len(result.errors)}")
        for error in result.errors[:5]:
            lines.append(f"- {error}")

    return "\n".join(lines).rstrip()


def save_csv(result: OsintResult, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["type", "value", "source_url", "context"])
        for bucket_name in ("emails", "phones", "social_links", "names"):
            bucket = getattr(result, bucket_name)
            for value, evidence in sorted(bucket.items()):
                for ev in evidence:
                    writer.writerow([bucket_name, value, ev.source_url, ev.context])


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="OSINT publik dari website: email, nomor telepon, link sosial, metadata, dan kemunculan nama."
    )
    parser.add_argument("url", help="Website target, contoh: https://example.com")
    parser.add_argument("--name", action="append", help="Nama orang/organisasi yang dicari. Bisa dipakai berulang.")
    parser.add_argument("--names-file", help="File daftar nama, satu nama per baris.")
    parser.add_argument("--depth", type=int, default=2, help="Kedalaman crawl link internal.")
    parser.add_argument("--max-urls", type=int, default=120, help="Batas maksimal URL yang dikunjungi.")
    parser.add_argument("--delay", type=float, default=0.3, help="Jeda antar request dalam detik.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout request dalam detik.")
    parser.add_argument("--include-subdomains", action="store_true", help="Ikuti subdomain dari target.")
    parser.add_argument("--json", action="store_true", help="Output JSON.")
    parser.add_argument("--csv", help="Simpan hasil kontak ke CSV.")
    return parser.parse_args(list(argv))


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.depth < 0 or args.max_urls < 1 or args.delay < 0:
        print("Argumen depth, max-urls, dan delay harus valid.", file=sys.stderr)
        return 2

    try:
        result = scan(args)
    except ValueError as exc:
        print(f"Input salah: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Dibatalkan.", file=sys.stderr)
        return 130

    if args.csv:
        save_csv(result, args.csv)

    print(render_json(result) if args.json else render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
