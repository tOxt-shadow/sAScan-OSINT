"""Text formatting helpers used by the console and HTML reports."""

from __future__ import annotations

import re
from html import escape

_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")
_IDENTIFIER_RE = re.compile(
    r"(?<![\w.+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\w.-])"
)


def slugify(value: str, fallback: str = "target", max_length: int = 48) -> str:
    cleaned = _SLUG_RE.sub("_", value.strip()).strip("._-")
    cleaned = cleaned[:max_length].rstrip("._-")
    return cleaned or fallback


def human_duration(milliseconds: int) -> str:
    if milliseconds < 1000:
        return f"{max(0, milliseconds)} ms"
    seconds = milliseconds / 1000
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, seconds = divmod(int(seconds), 60)
    return f"{minutes}m {seconds}s"


def truncate(value: str, limit: int = 70) -> str:
    value = " ".join(str(value).split())
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)].rstrip() + "…"


def safe_text(value: object) -> str:
    return escape(str(value), quote=True)


def extract_emails(text: str) -> list[str]:
    seen: list[str] = []
    for match in _IDENTIFIER_RE.finditer(text):
        value = match.group(1).lower()
        if value not in seen:
            seen.append(value)
    return seen
