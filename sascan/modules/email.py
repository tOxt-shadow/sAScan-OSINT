"""Native email intelligence: DNS, MX/SPF/DMARC, Gravatar and public GitHub discovery."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import quote

from sascan.core.http import AsyncHttpClient
from sascan.models import Finding, Verdict
from sascan.modules.base import ModuleResult
from sascan.modules.gravatar import check_gravatar
from sascan.utils.validators import is_reserved_email_domain


def _dns_lookup(email: str, timeout: float) -> dict[str, Any]:
    """Blocking DNS work, executed in a worker thread."""
    domain = email.rsplit("@", 1)[-1]
    info: dict[str, Any] = {
        "domain": domain,
        "mx": [],
        "null_mx": False,
        "spf": "",
        "dmarc": "",
        "error": "",
        "nxdomain": False,
    }
    try:
        import dns.resolver
    except ModuleNotFoundError:
        info["error"] = "The dnspython package is not installed"
        return info

    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = max(1.5, min(float(timeout), 6.0))
    resolver.timeout = resolver.lifetime

    try:
        answers = resolver.resolve(domain, "MX")
        records = []
        for answer in answers:
            preference = getattr(answer, "preference", 0)
            exchange = str(getattr(answer, "exchange", answer)).rstrip(".")
            records.append((preference, exchange))
        info["mx"] = [exchange for _, exchange in sorted(records) if exchange]
        info["null_mx"] = any(not exchange for _, exchange in records)
    except dns.resolver.NXDOMAIN:
        info["nxdomain"] = True
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except Exception as exc:  # pragma: no cover - network dependent
        info["error"] = f"{type(exc).__name__}"

    try:
        answers = resolver.resolve(domain, "TXT")
        for answer in answers:
            text = b"".join(answer.strings).decode("utf-8", errors="ignore")
            if text.lower().startswith("v=spf1"):
                info["spf"] = text
                break
    except Exception:  # nosec B110 - a missing SPF record is a valid result
        pass

    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for answer in answers:
            text = b"".join(answer.strings).decode("utf-8", errors="ignore")
            if text.lower().startswith("v=dmarc1"):
                info["dmarc"] = text
                break
    except Exception:  # nosec B110 - a missing DMARC record is a valid result
        pass
    return info


async def _github_email_search(
    email: str,
    http: AsyncHttpClient,
) -> tuple[list[Finding], str | None, list[str], list[str]]:
    """Find public commits authored with this exact email.

    GitHub's user search with ``in:email`` returns unrelated accounts for common
    test addresses, so it is deliberately not used. Commit search filters on the
    exact author email and is therefore a trustworthy signal. A GitHub account is
    only reported when the API returns an ``author.login`` for a commit.
    """
    findings: list[Finding] = []
    notes: list[str] = []
    logins: list[str] = []
    if is_reserved_email_domain(email):
        notes.append(
            "GitHub commit search skipped: the email uses a reserved test domain, "
            "so public commits are not identity evidence."
        )
        return findings, None, logins, notes
    encoded = quote(email, safe="")
    url = f"https://api.github.com/search/commits?q=author-email%3A{encoded}&per_page=5"
    payload, response = await http.get_json(
        url,
        headers={"Accept": "application/vnd.github+json"},
    )
    if response.status is None:
        return findings, (response.error or "Could not reach GitHub"), logins, notes
    if response.status in {403, 429}:
        notes.append("GitHub rate-limited the commit search; GitHub evidence is incomplete.")
        return findings, None, logins, notes
    if response.status == 422:
        notes.append("GitHub rejected the commit search query.")
        return findings, None, logins, notes
    if response.status != 200 or not isinstance(payload, dict):
        notes.append(f"GitHub returned an unexpected response (HTTP {response.status}).")
        return findings, None, logins, notes

    total = int(payload.get("total_count", 0) or 0)
    search_url = f"https://github.com/search?q=author-email%3A{encoded}&type=commits"
    if total <= 0:
        findings.append(
            Finding(
                target=email,
                platform="GitHub commits",
                kind="evidence",
                verdict=Verdict.ABSENT,
                url=search_url,
                source="email-native",
                category="Development",
                detail="No public commit uses this email as its author email",
                confidence=70,
                http_status=200,
                metadata={"commit_count": 0},
            )
        )
        return findings, None, logins, notes

    items = [item for item in payload.get("items", []) if isinstance(item, dict)]
    commit_urls: list[str] = []
    commit_logins: list[str] = []
    for item in items[:5]:
        author = item.get("author")
        if isinstance(author, dict):
            login = str(author.get("login", "")).strip()
            if login and login not in commit_logins:
                commit_logins.append(login)
                logins.append(login)
        html_url = item.get("html_url")
        if isinstance(html_url, str) and html_url and html_url not in commit_urls:
            commit_urls.append(html_url)

    detail = f"{total} public commit(s) use this email as their author email"
    if commit_logins:
        detail += " · linked account(s): " + ", ".join(commit_logins[:5])
    else:
        detail += " · no commit is linked to a public GitHub account"
    shared = len(commit_logins) > 1
    if shared:
        detail += " · multiple accounts suggest a shared email"
        notes.append(
            "GitHub commit evidence maps to multiple accounts; the email may be shared. "
            "Account links were withheld."
        )

    findings.append(
        Finding(
            target=email,
            platform="GitHub commits",
            kind="evidence",
            verdict=Verdict.FOUND,
            url=commit_urls[0] if commit_urls else search_url,
            source="email-native",
            category="Development",
            detail=detail,
            confidence=70 if shared else 78,
            http_status=200,
            metadata={
                "commit_count": total,
                "sample_commits": commit_urls[:3],
                "logins": commit_logins[:5],
                "shared": shared,
            },
        )
    )

    if not shared:
        for login in commit_logins:
            findings.append(
                Finding(
                    target=email,
                    platform="GitHub",
                    kind="account",
                    verdict=Verdict.FOUND,
                    url=f"https://github.com/{login}",
                    source="email-native",
                    category="Development",
                    detail=f"GitHub account linked through commit authorship: {login}",
                    confidence=86,
                    http_status=200,
                    metadata={"username": login},
                )
            )
    return findings, None, ([] if shared else logins), notes


async def scan_email(
    email: str,
    http: AsyncHttpClient,
    *,
    timeout: float = 8.0,
    include_gravatar: bool = True,
    include_github: bool = True,
) -> ModuleResult:
    """Run native email checks. This proves domain/profile signals, not mailbox ownership."""
    result = ModuleResult()
    dns_info = await asyncio.to_thread(_dns_lookup, email, timeout)
    result.metadata["dns"] = dns_info

    if dns_info.get("nxdomain"):
        verdict = Verdict.ABSENT
        detail = "Email domain is not registered (NXDOMAIN)"
        confidence = 88
    elif dns_info.get("mx"):
        verdict = Verdict.FOUND
        detail = "MX: " + ", ".join(dns_info["mx"][:4])
        confidence = 90
    elif dns_info.get("null_mx"):
        verdict = Verdict.ABSENT
        detail = "Null MX (the domain explicitly does not accept email)"
        confidence = 88
    elif dns_info.get("error"):
        verdict = Verdict.UNKNOWN
        detail = f"Could not verify DNS: {dns_info['error']}"
        confidence = 25
    else:
        verdict = Verdict.UNKNOWN
        detail = "No explicit MX record (the domain may use A fallback)"
        confidence = 35

    dns_parts = [detail]
    if dns_info.get("spf"):
        dns_parts.append("SPF present")
    if dns_info.get("dmarc"):
        dns_parts.append("DMARC present")
    result.findings.append(
        Finding(
            target=email,
            platform="Email domain (DNS)",
            kind="infrastructure",
            verdict=verdict,
            source="native",
            category="Infrastructure",
            detail=" · ".join(dns_parts),
            confidence=confidence,
            metadata={
                "mx": dns_info.get("mx", []),
                "spf": bool(dns_info.get("spf")),
                "dmarc": bool(dns_info.get("dmarc")),
            },
        )
    )

    if include_gravatar:
        gravatar = await check_gravatar(email, http)
        result.findings.extend(gravatar.module.findings)
        result.errors.extend(gravatar.module.errors)
        result.notes.extend(gravatar.module.notes)
        if gravatar.profile:
            result.metadata["gravatar"] = gravatar.profile
            result.metadata["gravatar_accounts"] = gravatar.accounts
        for username in gravatar.module.metadata.get("usernames", []):
            result.metadata.setdefault("usernames", []).append(username)

    if include_github:
        github_findings, error, logins, github_notes = await _github_email_search(email, http)
        result.findings.extend(github_findings)
        result.notes.extend(github_notes)
        if error:
            result.errors.append(error)
        result.metadata.setdefault("usernames", []).extend(logins)

    result.notes.append(
        "Email findings do not prove ownership; they measure domain and public-profile signals."
    )
    return result
