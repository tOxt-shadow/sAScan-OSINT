"""Load and validate the site rule set."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from sascan.config import SITES_FILE

logger = logging.getLogger(__name__)


class SitesConfigError(ValueError):
    """Invalid or missing sites configuration."""


def _int_set(value: object, field: str) -> frozenset[int]:
    if value is None:
        return frozenset()
    if not isinstance(value, list):
        raise SitesConfigError(f"Field '{field}' must be a list of integers.")
    try:
        return frozenset(int(item) for item in value)
    except (TypeError, ValueError) as exc:
        raise SitesConfigError(f"Field '{field}' contains a non-numeric value.") from exc


def _str_tuple(value: object, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise SitesConfigError(f"Field '{field}' must be a list of strings.")
    return tuple(str(item) for item in value if str(item).strip())


@dataclass(frozen=True, slots=True)
class SiteRule:
    name: str
    url_template: str
    category: str = "General"
    kind: str = "social"
    link_template: str = ""
    found_status: frozenset[int] = frozenset({200})
    absent_status: frozenset[int] = frozenset({404})
    blocked_status: frozenset[int] = frozenset({401, 403, 429, 999})
    present_markers: tuple[str, ...] = ()
    absent_markers: tuple[str, ...] = ()
    blocked_markers: tuple[str, ...] = ()
    missing_is_absent: bool = False
    enabled: bool = True

    @property
    def needs_body(self) -> bool:
        return bool(
            self.present_markers
            or self.absent_markers
            or self.blocked_markers
        )

    def url_for(self, account: str) -> str:
        return self.url_template.replace("{account}", quote(account, safe=""))

    def link_for(self, account: str) -> str:
        template = self.link_template or self.url_template
        return template.replace("{account}", quote(account, safe=""))

    def matches_filter(self, filters: set[str]) -> bool:
        if not filters:
            return True
        haystack = f"{self.name} {self.kind} {self.category}".casefold()
        return any(item in haystack for item in filters)


class SiteRegistry:
    """In-memory registry; no database, no persistent state."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else SITES_FILE
        self._rules: tuple[SiteRule, ...] = ()
        self._mtime = 0.0

    @property
    def rules(self) -> tuple[SiteRule, ...]:
        return self._rules

    def load(self) -> int:
        try:
            content = self.path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise SitesConfigError(f"Sites file not found: {self.path}") from exc
        except OSError as exc:
            raise SitesConfigError(f"Could not read {self.path}: {exc}") from exc

        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise SitesConfigError(f"Invalid JSON in {self.path}: {exc}") from exc

        items = payload.get("sites") if isinstance(payload, dict) else None
        if not isinstance(items, list) or not items:
            raise SitesConfigError("sites.json must contain a non-empty 'sites' list.")

        rules: list[SiteRule] = []
        seen: set[str] = set()
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise SitesConfigError(f"Item {index} is not a JSON object.")
            name = str(item.get("name", "")).strip()
            url = str(item.get("url", "")).strip()
            if not name or not url:
                raise SitesConfigError(f"Item {index}: 'name' and 'url' are required.")
            if name.casefold() in seen:
                raise SitesConfigError(f"Duplicate site name: {name}")
            if not url.startswith("https://"):
                raise SitesConfigError(f"{name}: 'url' must start with https://")
            if "{account}" not in url:
                raise SitesConfigError(f"{name}: 'url' must contain {{account}}")

            link = str(item.get("link", "")).strip()
            if link and (
                not link.startswith("https://") or "{account}" not in link
            ):
                raise SitesConfigError(
                    f"{name}: 'link' must start with https:// and contain {{account}}"
                )

            seen.add(name.casefold())
            rules.append(
                SiteRule(
                    name=name,
                    url_template=url,
                    category=str(item.get("category", "General")).strip() or "General",
                    kind=str(item.get("kind", "social")).strip() or "social",
                    link_template=link,
                    found_status=_int_set(item.get("found_status", [200]), "found_status"),
                    absent_status=_int_set(item.get("absent_status", [404]), "absent_status"),
                    blocked_status=_int_set(
                        item.get("blocked_status", [401, 403, 429, 999]),
                        "blocked_status",
                    ),
                    present_markers=_str_tuple(item.get("present_markers"), "present_markers"),
                    absent_markers=_str_tuple(item.get("absent_markers"), "absent_markers"),
                    blocked_markers=_str_tuple(item.get("blocked_markers"), "blocked_markers"),
                    missing_is_absent=bool(item.get("missing_is_absent", False)),
                    enabled=bool(item.get("enabled", True)),
                )
            )

        enabled = tuple(rule for rule in rules if rule.enabled)
        if not enabled:
            raise SitesConfigError("No enabled sites in sites.json.")
        self._rules = enabled
        try:
            self._mtime = self.path.stat().st_mtime
        except OSError:
            self._mtime = 0.0
        logger.debug("Loaded %d enabled sites from %s", len(enabled), self.path)
        return len(enabled)

    def ensure_loaded(self) -> None:
        if not self._rules:
            self.load()

    def select(self, filters: set[str]) -> tuple[SiteRule, ...]:
        self.ensure_loaded()
        return tuple(rule for rule in self._rules if rule.matches_filter(filters))
