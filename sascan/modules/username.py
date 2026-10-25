"""Native username scanning across configured platforms."""

from __future__ import annotations

import asyncio
import logging
import time

from sascan.core.classify import classify
from sascan.core.http import AsyncHttpClient
from sascan.core.progress import ScanProgress
from sascan.core.sites import SiteRule
from sascan.models import Finding, Verdict
from sascan.modules.base import ModuleResult

logger = logging.getLogger(__name__)


async def _check_site(
    http: AsyncHttpClient,
    rule: SiteRule,
    username: str,
    progress: ScanProgress | None,
) -> Finding:
    started = time.perf_counter()
    response = await http.get(rule.url_for(username), read_body=rule.needs_body)

    if response.status is None:
        verdict, note = Verdict.UNKNOWN, response.error or "Connection failed"
    else:
        verdict, note = classify(rule, response.status, response.body, username)

    if verdict is Verdict.FOUND:
        confidence = 92 if rule.present_markers else 88
    elif verdict is Verdict.ABSENT:
        confidence = 85
    else:
        confidence = 30

    finding = Finding(
        target=username,
        platform=rule.name,
        kind="account",
        verdict=verdict,
        url=rule.link_for(username),
        source="native",
        category=rule.category,
        detail=note or (f"HTTP {response.status}" if response.status else "No response"),
        confidence=confidence,
        http_status=response.status,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
        metadata={"site_kind": rule.kind},
    )
    if progress:
        progress.advance(rule.name)
    return finding


async def scan_username(
    username: str,
    sites: tuple[SiteRule, ...],
    http: AsyncHttpClient,
    *,
    progress: ScanProgress | None = None,
) -> ModuleResult:
    """Check a username against every selected native site concurrently."""
    result = ModuleResult()
    if not sites:
        result.errors.append("No sites were selected for scanning.")
        return result

    tasks = [asyncio.create_task(_check_site(http, site, username, progress)) for site in sites]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    for site, item in zip(sites, gathered):
        if isinstance(item, BaseException):
            logger.debug("Username check failed for %s", site.name, exc_info=item)
            result.findings.append(
                Finding(
                    target=username,
                    platform=site.name,
                    kind="account",
                    verdict=Verdict.UNKNOWN,
                    url=site.link_for(username),
                    source="native",
                    category=site.category,
                    detail="Unexpected error during the check",
                    confidence=20,
                    metadata={"site_kind": site.kind},
                )
            )
            if progress:
                progress.advance(site.name)
        else:
            result.findings.append(item)
    return result
