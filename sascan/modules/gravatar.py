"""Gravatar profile lookup — a high-signal bridge between email and accounts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from sascan.core.http import AsyncHttpClient
from sascan.models import Finding, Verdict
from sascan.modules.base import ModuleResult


@dataclass(slots=True)
class GravatarResult:
    module: ModuleResult = field(default_factory=ModuleResult)
    profile: dict[str, Any] = field(default_factory=dict)
    accounts: list[dict[str, Any]] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)


def gravatar_hash(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()


def _first(payload: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _parse_profile(payload: dict[str, Any]) -> dict[str, Any]:
    if "entry" in payload and isinstance(payload["entry"], list) and payload["entry"]:
        payload = payload["entry"][0]
    if not isinstance(payload, dict):
        return {}

    profile: dict[str, Any] = {
        "display_name": _first(payload, "display_name", "displayName", "preferredUsername"),
        "about_me": _first(payload, "about_me", "aboutMe", "description"),
        "location": _first(payload, "location", "currentLocation"),
        "job_title": _first(payload, "job_title", "jobTitle"),
        "company": _first(payload, "company", "companyName"),
        "avatar_url": _first(payload, "avatar_url", "thumbnailUrl", "avatarUrl"),
        "profile_url": _first(payload, "profile_url", "profileUrl"),
        "verified": bool(payload.get("verified", False)),
    }

    accounts: list[dict[str, Any]] = []
    raw_accounts = payload.get("accounts") or payload.get("verified_accounts") or []
    if isinstance(raw_accounts, list):
        for item in raw_accounts:
            if not isinstance(item, dict):
                continue
            url = _first(item, "url", "profile_url")
            shortname = _first(item, "shortname", "domain", "name")
            username = _first(item, "username", "user")
            if not url and not username:
                continue
            accounts.append(
                {
                    "domain": shortname,
                    "username": username,
                    "url": url,
                    "verified": bool(item.get("verified", False)),
                    "source": "gravatar",
                }
            )
    profile["accounts"] = accounts

    links = payload.get("urls") or payload.get("links") or []
    urls: list[str] = []
    if isinstance(links, list):
        for item in links:
            if isinstance(item, str) and item.startswith(("http://", "https://")):
                urls.append(item)
            elif isinstance(item, dict):
                value = _first(item, "url", "href")
                if value.startswith(("http://", "https://")):
                    urls.append(value)
    profile["links"] = urls
    return profile


def _parse_html_profile(html: str) -> dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")
    title = soup.find("meta", property="og:title")
    description = soup.find("meta", property="og:description")
    image = soup.find("meta", property="og:image")
    profile_url = soup.find("link", rel="canonical")
    profile: dict[str, Any] = {
        "display_name": (title.get("content") if title else "") or "",
        "about_me": (description.get("content") if description else "") or "",
        "avatar_url": (image.get("content") if image else "") or "",
        "profile_url": (profile_url.get("href") if profile_url else "") or "",
    }
    return {key: value for key, value in profile.items() if value}


async def check_gravatar(email: str, http: AsyncHttpClient) -> GravatarResult:
    """Look up a public Gravatar profile and its verified accounts."""
    digest = gravatar_hash(email)
    legacy_url = f"https://gravatar.com/{digest}.json"
    v3_url = f"https://api.gravatar.com/v3/profiles/{digest}"
    result = GravatarResult()

    payload: dict[str, Any] | None = None
    response = await http.get(v3_url, headers={"Accept": "application/json"})
    if response.status == 200 and response.body:
        try:
            parsed = json.loads(response.body)
            if isinstance(parsed, dict):
                payload = parsed
        except ValueError:
            payload = None

    source_url = v3_url
    if payload is None:
        response = await http.get(legacy_url, headers={"Accept": "application/json"})
        source_url = legacy_url
        if response.status == 200 and response.body:
            try:
                parsed = json.loads(response.body)
                if isinstance(parsed, dict):
                    payload = parsed
            except ValueError:
                payload = None
            if payload is None:
                html_profile = _parse_html_profile(response.body)
                if html_profile:
                    payload = html_profile

    if payload is None:
        status = response.status
        if status == 404:
            verdict = Verdict.ABSENT
            detail = "No public Gravatar profile is linked to this email"
        elif status is None:
            verdict = Verdict.UNKNOWN
            detail = response.error or "Could not reach Gravatar"
        else:
            verdict = Verdict.UNKNOWN
            detail = f"Inconclusive Gravatar response (HTTP {status})"
        result.module.findings.append(
            Finding(
                target=email,
                platform="Gravatar",
                kind="profile",
                verdict=verdict,
                url=f"https://gravatar.com/{digest}",
                source="gravatar",
                category="Profile",
                detail=detail,
                confidence=70 if verdict is Verdict.ABSENT else 25,
                http_status=status,
            )
        )
        return result

    profile = _parse_profile(payload)
    profile["hash"] = digest
    profile_url = profile.get("profile_url") or f"https://gravatar.com/{digest}"
    profile["profile_url"] = profile_url
    result.profile = profile
    result.accounts = list(profile.get("accounts", []))
    result.urls = list(profile.get("links", []))

    name = profile.get("display_name") or "Gravatar profile"
    details = [f"Name: {name}"]
    if profile.get("about_me"):
        details.append(f"Bio: {profile['about_me'][:160]}")
    if profile.get("location"):
        details.append(f"Location: {profile['location']}")
    if profile.get("job_title"):
        details.append(f"Job title: {profile['job_title']}")
    if profile.get("company"):
        details.append(f"Company: {profile['company']}")
    if result.accounts:
        details.append(f"Linked accounts: {len(result.accounts)}")

    result.module.findings.append(
        Finding(
            target=email,
            platform="Gravatar",
            kind="profile",
            verdict=Verdict.FOUND,
            url=profile_url,
            source="gravatar",
            category="Profile",
            detail=" · ".join(details),
            confidence=96,
            http_status=200,
            metadata={"accounts": result.accounts, "profile": profile},
        )
    )
    for account in result.accounts:
        url = account.get("url") or ""
        host = urlparse(url).netloc.removeprefix("www.") if url else account.get("domain", "")
        if not host and not account.get("username"):
            continue
        result.module.findings.append(
            Finding(
                target=email,
                platform=account.get("domain") or host or "Linked account",
                kind="account",
                verdict=Verdict.FOUND,
                url=url or (f"https://{host}" if host else ""),
                source="gravatar",
                category="Linked account",
                detail=(
                    f"Gravatar-linked account: {account.get('username') or host}"
                    + (" (verified)" if account.get("verified") else "")
                ),
                confidence=90 if account.get("verified") else 78,
                metadata=account,
            )
        )
        if account.get("username"):
            result.module.metadata.setdefault("usernames", []).append(account["username"])
    return result
