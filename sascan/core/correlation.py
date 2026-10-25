"""Correlation engine: turn independent findings into one live footprint model."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from sascan.models import (
    Correlation,
    DerivedIdentifier,
    Finding,
    Seed,
    SeedKind,
    Verdict,
)
from sascan.utils.text import slugify
from sascan.utils.validators import USERNAME_RE, username_candidates

EMAIL_IN_TEXT_RE = re.compile(
    r"(?<![\w.+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\w.-])"
)

_PATH_USERNAME_RULES: dict[str, tuple[str, ...]] = {
    "github.com": ("{user}",),
    "gitlab.com": ("{user}",),
    "codeberg.org": ("{user}",),
    "dev.to": ("{user}",),
    "instagram.com": ("{user}",),
    "x.com": ("{user}",),
    "twitter.com": ("{user}",),
    "threads.net": ("@{user}",),
    "tiktok.com": ("@{user}",),
    "youtube.com": ("@{user}",),
    "medium.com": ("@{user}",),
    "twitch.tv": ("{user}",),
    "soundcloud.com": ("{user}",),
    "behance.net": ("{user}",),
    "dribbble.com": ("{user}",),
    "steamcommunity.com": ("id/{user}",),
    "keybase.io": ("{user}",),
    "linktr.ee": ("{user}",),
    "about.me": ("{user}",),
    "mastodon.social": ("@{user}",),
}
_RESERVED_SEGMENTS = {
    "about",
    "features",
    "login",
    "search",
    "settings",
    "explore",
    "signup",
    "pricing",
    "help",
    "user",
    "users",
    "id",
    "pages",
    "profile",
}


def _is_username(value: str) -> bool:
    return bool(USERNAME_RE.fullmatch(value)) and value.lower() not in _RESERVED_SEGMENTS


def username_from_url(url: str) -> str | None:
    """Extract an account handle from a known profile URL without guessing."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = parsed.netloc.lower().removeprefix("www.")
    segments = [part for part in parsed.path.split("/") if part]
    if not segments:
        return None

    if host == "reddit.com" and len(segments) >= 2 and segments[0] == "user":
        candidate = segments[1]
    elif host == "news.ycombinator.com" and parsed.path == "/user":
        candidate = parse_qs(parsed.query).get("id", [""])[0]
    elif host == "pypi.org" and len(segments) >= 2 and segments[0] == "user":
        candidate = segments[1]
    elif host == "t.me":
        candidate = segments[0]
    else:
        rules = _PATH_USERNAME_RULES.get(host, ())
        candidate = ""
        for rule in rules:
            if rule.startswith("@"):
                if segments[0].startswith("@"):
                    candidate = segments[0][1:]
                elif len(segments) >= 2 and segments[0] in {"@", "user"}:
                    candidate = segments[1]
            elif rule.startswith("id/"):
                if len(segments) >= 2 and segments[0] == "id":
                    candidate = segments[1]
            elif len(segments) >= 1:
                candidate = segments[0]
            if candidate:
                break
    candidate = candidate.strip("@")
    return candidate if candidate and _is_username(candidate) else None


def _add_unique(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def _collect_from_metadata(
    metadata: dict[str, Any],
    usernames: list[str],
    emails: list[str],
    phones: list[str],
    accounts: list[dict[str, Any]],
) -> None:
    for value in metadata.get("usernames", []) or []:
        if isinstance(value, str) and _is_username(value):
            _add_unique(usernames, value)
    for value in metadata.get("emails", []) or []:
        if isinstance(value, str) and EMAIL_IN_TEXT_RE.fullmatch(value):
            _add_unique(emails, value.lower())
    if isinstance(metadata.get("e164"), str):
        _add_unique(phones, metadata["e164"])

    gravatar_accounts = metadata.get("gravatar_accounts") or []
    if isinstance(gravatar_accounts, list):
        for item in gravatar_accounts:
            if not isinstance(item, dict):
                continue
            accounts.append(item)
            username = item.get("username")
            if isinstance(username, str) and _is_username(username):
                _add_unique(usernames, username)

    gravatar = metadata.get("gravatar")
    if isinstance(gravatar, dict):
        for item in gravatar.get("accounts", []) or []:
            if not isinstance(item, dict):
                continue
            accounts.append(item)
            username = item.get("username")
            if isinstance(username, str) and _is_username(username):
                _add_unique(usernames, username)
        for link in gravatar.get("links", []) or []:
            if not isinstance(link, str):
                continue
            for match in EMAIL_IN_TEXT_RE.finditer(link):
                _add_unique(emails, match.group(1).lower())


def _account_display(account: dict[str, Any]) -> tuple[str, str, str]:
    domain = str(account.get("domain") or "").strip()
    username = str(account.get("username") or "").strip()
    url = str(account.get("url") or "").strip()
    host = urlparse(url).netloc.removeprefix("www.") if url else ""
    platform = domain or host or "Linked account"
    if not username and url:
        username = username_from_url(url) or ""
    return platform, username, url


class CorrelationEngine:
    """Build identifier lists, a graph and a confidence score from findings."""

    def build(
        self,
        seed: Seed,
        findings: list[Finding],
        metadata: dict[str, Any] | None = None,
        *,
        scanned_targets: set[str] | None = None,
    ) -> Correlation:
        metadata = metadata or {}
        scanned = {value.casefold() for value in (scanned_targets or {seed.value})}
        usernames: list[str] = []
        emails: list[str] = []
        phones: list[str] = []
        linked_accounts: list[dict[str, Any]] = []

        if seed.kind is SeedKind.USERNAME:
            _add_unique(usernames, seed.value)
        elif seed.kind is SeedKind.EMAIL:
            _add_unique(emails, seed.value)
        else:
            _add_unique(phones, seed.value)

        _collect_from_metadata(metadata, usernames, emails, phones, linked_accounts)

        for finding in findings:
            if finding.verdict is not Verdict.FOUND:
                continue
            if isinstance(finding.metadata.get("username"), str):
                candidate = finding.metadata["username"]
                if _is_username(candidate):
                    _add_unique(usernames, candidate)
            for item in finding.metadata.get("accounts", []) or []:
                if isinstance(item, dict):
                    linked_accounts.append(item)
                    username = item.get("username")
                    if isinstance(username, str) and _is_username(username):
                        _add_unique(usernames, username)
            if finding.kind == "account" and finding.url:
                candidate = username_from_url(finding.url)
                if candidate:
                    _add_unique(usernames, candidate)
            if finding.kind == "profile":
                for match in EMAIL_IN_TEXT_RE.finditer(finding.detail):
                    _add_unique(emails, match.group(1).lower())

        candidates: list[DerivedIdentifier] = []
        if seed.kind is SeedKind.EMAIL:
            for candidate in username_candidates(seed.value):
                if candidate.casefold() in {item.casefold() for item in usernames}:
                    continue
                scanned_flag = candidate.casefold() in scanned
                candidates.append(
                    DerivedIdentifier(
                        kind="username",
                        value=candidate,
                        source="email-local-part",
                        reason="Derived from the email local-part",
                        confidence=58 if candidate == seed.value.partition("@")[0] else 44,
                        scanned=scanned_flag,
                    )
                )

        for account in linked_accounts:
            platform, username, url = _account_display(account)
            if not username:
                continue
            if username.casefold() in {item.casefold() for item in usernames}:
                continue
            candidates.append(
                DerivedIdentifier(
                    kind="username",
                    value=username,
                    source="gravatar-link",
                    reason=f"Linked Gravatar account on {platform}",
                    confidence=72,
                    scanned=username.casefold() in scanned,
                )
            )
            _add_unique(usernames, username)

        graph_nodes, graph_edges = self._build_graph(seed, findings, candidates)

        found_accounts = [
            f
            for f in findings
            if f.verdict is Verdict.FOUND and f.kind in {"account", "profile"}
        ]
        platforms = {f.platform.casefold() for f in found_accounts}
        external = [f for f in found_accounts if f.source not in {"native", "email-native", "gravatar"}]
        verified = sum(1 for account in linked_accounts if account.get("verified"))
        gravatar_profile = metadata.get("gravatar") if isinstance(metadata.get("gravatar"), dict) else {}
        dns_info = metadata.get("dns") if isinstance(metadata.get("dns"), dict) else {}
        phone_metadata = isinstance(metadata.get("e164"), str) and bool(metadata.get("carrier"))

        evidence = min(40, 10 + len(platforms) * 9) if platforms else 0
        if gravatar_profile:
            evidence += 15
        if dns_info.get("mx"):
            evidence += 6
        if phone_metadata:
            evidence += 12
        if external:
            evidence += 6
        if verified:
            evidence += 5
        confidence = min(96, 30 + evidence) if findings else 10
        if not found_accounts and not gravatar_profile:
            confidence = min(confidence, 35)

        notes: list[str] = []
        unknown_count = sum(1 for finding in findings if finding.verdict is Verdict.UNKNOWN)
        if unknown_count:
            notes.append(
                f"{unknown_count} check(s) were inconclusive (bot protection, rate limits or network errors)."
            )
        unscanned = [candidate for candidate in candidates if not candidate.scanned]
        if unscanned:
            notes.append(
                f"{len(unscanned)} derived username candidate(s) remain unscanned. "
                "Use --deep only when the email address is personal and non-generic."
            )
        if not found_accounts and not gravatar_profile:
            notes.append(
                "No verified public accounts were found. Absence of evidence is not evidence of absence."
            )
        notes.append(
            "Correlation links are leads, not identity proof. Verify every high-impact claim manually."
        )

        if found_accounts:
            summary = (
                f"{len(found_accounts)} public profile(s) across {len(platforms)} platform(s), "
                f"{len(usernames)} username(s), {len(emails)} email(s), {len(phones)} phone(s)."
            )
        elif gravatar_profile:
            summary = "No platform account was confirmed, but a public Gravatar identity was found."
        else:
            summary = "No public account was confirmed in this pass."

        return Correlation(
            usernames=usernames,
            emails=emails,
            phones=phones,
            candidates=candidates,
            graph_nodes=graph_nodes,
            graph_edges=graph_edges,
            profile=gravatar_profile,
            confidence=confidence,
            summary=summary,
            notes=notes,
        )

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------
    def _build_graph(
        self,
        seed: Seed,
        findings: list[Finding],
        candidates: list[DerivedIdentifier],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        nodes: dict[str, dict[str, Any]] = {}
        edges: dict[tuple[str, str, str], dict[str, Any]] = {}

        def add_node(node_id: str, label: str, group: str, title: str, **extra: Any) -> None:
            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id,
                    "label": label,
                    "group": group,
                    "title": title,
                    **extra,
                }

        def add_edge(source: str, target: str, label: str, **extra: Any) -> None:
            key = (source, target, label)
            if key not in edges and source != target:
                edges[key] = {
                    "from": source,
                    "to": target,
                    "label": label,
                    "arrows": "to",
                    **extra,
                }

        seed_id = f"seed:{seed.kind.value}:{seed.value}"
        add_node(
            seed_id,
            seed.value,
            "seed",
            f"Seed · {seed.kind.label}: {seed.value}",
            value=seed.value,
            kind=seed.kind.value,
        )

        identifier_ids: dict[str, str] = {seed.value.casefold(): seed_id}
        mention_nodes: dict[str, str] = {}

        for finding in findings:
            if finding.verdict is not Verdict.FOUND:
                continue
            if finding.kind not in {"account", "profile"}:
                continue
            target_key = finding.target.casefold()
            actor_id = identifier_ids.get(target_key, seed_id)
            if target_key != seed.value.casefold() and target_key not in identifier_ids:
                kind = (
                    "email"
                    if "@" in finding.target
                    else "phone"
                    if finding.target.startswith("+")
                    else "username"
                )
                actor_id = f"{kind}:{finding.target}"
                identifier_ids[target_key] = actor_id
                add_node(
                    actor_id,
                    finding.target,
                    kind,
                    f"Discovered {kind}: {finding.target}",
                    value=finding.target,
                    kind=kind,
                )
                add_edge(seed_id, actor_id, "discovered", dashes=True)

            platform_id = f"platform:{slugify(finding.platform).casefold()}"
            add_node(
                platform_id,
                finding.platform,
                "platform",
                f"{finding.platform} · {finding.category} · {finding.detail}",
                url=finding.url,
                source=finding.source,
            )
            edge_label = "profile" if finding.kind == "profile" else finding.source
            add_edge(actor_id, platform_id, edge_label)
            if finding.url:
                mention_nodes[finding.url] = platform_id
            if finding.metadata.get("username"):
                handle = str(finding.metadata["username"])
                handle_id = f"username:{handle}"
                add_node(handle_id, handle, "username", f"Username: {handle}", value=handle, kind="username")
                add_edge(platform_id, handle_id, "handle")

        for candidate in candidates:
            if candidate.scanned:
                node_id = f"username:{candidate.value}"
                add_node(
                    node_id,
                    candidate.value,
                    "username",
                    f"Scanned candidate · {candidate.reason}",
                    value=candidate.value,
                    kind="username",
                )
                add_edge(seed_id, node_id, "deep scan", dashes=True)
            else:
                node_id = f"candidate:{candidate.kind}:{candidate.value}"
                add_node(
                    node_id,
                    candidate.value,
                    "candidate",
                    f"Candidate · {candidate.reason}",
                    value=candidate.value,
                    kind=candidate.kind,
                )
                add_edge(seed_id, node_id, "derived", dashes=True)

        lead_count = 0
        for finding in findings:
            if finding.kind != "lead" or not finding.url or lead_count >= 24:
                continue
            lead_id = f"lead:{slugify(finding.platform)}"
            add_node(
                lead_id,
                finding.platform,
                "lead",
                f"Manual lead · {finding.detail}",
                url=finding.url,
                source=finding.source,
            )
            add_edge(seed_id, lead_id, "lead", dashes=True)
            lead_count += 1

        return list(nodes.values())[:100], list(edges.values())[:180]
