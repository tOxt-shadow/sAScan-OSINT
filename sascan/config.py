"""Application-wide constants and defaults."""

from __future__ import annotations

from pathlib import Path

from sascan import __app_name__, __version__

APP_NAME = __app_name__
VERSION = __version__

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent
SITES_FILE = PACKAGE_DIR / "data" / "sites.json"
TEMPLATE_DIR = PACKAGE_DIR / "reports" / "templates"

DEFAULT_TIMEOUT = 10.0
DEFAULT_CONCURRENCY = 30
DEFAULT_REGION = "SA"
DEFAULT_BODY_LIMIT = 300_000
DEFAULT_DEEP_LIMIT = 2
DEFAULT_OUTPUT_DIR = Path.cwd() / "reports"
REPORT_PREFIX = "sascan"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)
BASE_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
}

LEGAL_NOTICE = (
    "Scan your own footprint or obtain explicit permission from the data owner. "
    "Unauthorized scanning may violate laws and platform terms of service."
)

ENGINE_CHOICES = ("native", "auto", "both", "sherlock", "holehe", "phoneinfoga")
VERDICT_CHOICES = ("found", "absent", "unknown")
