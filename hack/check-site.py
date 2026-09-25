#!/usr/bin/env python3
"""Validate the static Pages site (site/) without a frontend build dependency.

Ported from terradune. Run: python3 hack/check-site.py"""

import json
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
BASE = "https://albatroxxx.github.io/zanskar/"
VERSION = re.search(r'^appVersion:\s*"?([^"\n]+)"?', (ROOT / "deploy/helm/zanskar/Chart.yaml").read_text(), re.M).group(1)


class Page(HTMLParser):
    def __init__(self, path):
        super().__init__(convert_charrefs=True)
        self.path = path
        self.ids = set()
        self.links = []
        self.meta = {}
        self.counts = {}
        self.canonical = None
        self.title = ""
        self.json_ld = ""
        self.in_title = False
        self.in_json = False
        self.feed(path.read_text())

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.counts[tag] = self.counts.get(tag, 0) + 1
        if "id" in attrs:
            assert attrs["id"] not in self.ids, (self.path, "duplicate id", attrs["id"])
            self.ids.add(attrs["id"])
        if tag == "html":
            assert attrs.get("lang") == "en", self.path
        if tag == "img":
            assert "alt" in attrs and attrs.get("width") and attrs.get("height"), self.path
        if tag == "meta":
            self.meta[attrs.get("name", attrs.get("property"))] = attrs.get("content", "")
        if tag == "link" and attrs.get("rel") == "canonical":
            self.canonical = attrs["href"]
        for attr in ("href", "src"):
            if attrs.get(attr):
                self.links.append(attrs[attr])
        self.in_title = self.in_title or tag == "title"
        self.in_json = self.in_json or (tag == "script" and attrs.get("type") == "application/ld+json")

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag == "script":
            self.in_json = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data
        if self.in_json:
            self.json_ld += data


pages = {path: Page(path) for path in SITE.rglob("*.html")}
assert len(pages) == 5, "Update the expected site page count when adding a page"
titles = set()
canonicals = set()
for path, page in pages.items():
    assert page.counts.get("h1") == 1 and page.counts.get("main") == 1, path
    assert page.title and page.title not in titles, path
    titles.add(page.title)
    assert page.meta.get("viewport"), path
    if path.name != "404.html":
        expected = BASE + path.relative_to(SITE).as_posix().removesuffix("index.html")
        assert page.canonical == expected, (path, page.canonical, expected)
        assert 50 <= len(page.meta.get("description", "")) <= 180, path
        assert page.meta.get("og:url") == expected and page.meta.get("og:image"), path
        assert page.meta.get("twitter:card") == "summary_large_image", path
        canonicals.add(expected)
    else:
        assert "noindex" in page.meta.get("robots", ""), path
    if page.json_ld:
        structured = json.loads(page.json_ld)
        assert structured["softwareVersion"] == VERSION
        assert structured["url"] == BASE
    for link in page.links + [page.meta.get("og:image", "")]:
        if not link:
            continue
        absolute = urljoin(BASE + path.relative_to(SITE).as_posix(), link)
        if not absolute.startswith(BASE):
            continue
        parsed = urlparse(absolute)
        target = SITE / unquote(parsed.path.removeprefix("/zanskar/"))
        if target.is_dir():
            target /= "index.html"
        assert target.is_relative_to(SITE) and target.is_file(), (path, link)
        if parsed.fragment:
            assert target in pages and unquote(parsed.fragment) in pages[target].ids, (path, link)

sitemap = ET.parse(SITE / "sitemap.xml")
locations = {node.text for node in sitemap.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")}
assert locations == canonicals, (locations, canonicals)
assert (SITE / ".nojekyll").is_file()
print(f"Site checks passed: {len(pages)} pages, local links/anchors, metadata, JSON-LD, sitemap, image alternatives")
