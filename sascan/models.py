"""Typed domain models shared by the scan engine, reports and CLI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sascan import __version__


class Verdict(str, Enum):
    """The only three honest outcomes of a remote existence check."""

    FOUND = "found"
    ABSENT = "absent"
    UNKNOWN = "unknown"

    @property
    def label(self) -> str:
        return {
            Verdict.FOUND: "FOUND",
            Verdict.ABSENT: "ABSENT",
            Verdict.UNKNOWN: "UNKNOWN",
        }[self]


class SeedKind(str, Enum):
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"

    @property
    def label(self) -> str:
        return {
            SeedKind.USERNAME: "username",
            SeedKind.EMAIL: "email",
            SeedKind.PHONE: "phone",
        }[self]


@dataclass(frozen=True, slots=True)
class Seed:
    """The normalized starting point of a scan."""

    kind: SeedKind
    value: str
    raw: str = ""

    @property
    def display(self) -> str:
        return self.value

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind.value,
            "value": self.value,
            "raw": self.raw or self.value,
            "label": self.kind.label,
        }


@dataclass(slots=True)
class Finding:
    """One check result for one platform or intelligence source."""

    target: str
    platform: str
    kind: str
    verdict: Verdict
    url: str = ""
    source: str = "native"
    category: str = "General"
    detail: str = ""
    confidence: int = 50
    http_status: int | None = None
    elapsed_ms: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_found(self) -> bool:
        return self.verdict is Verdict.FOUND

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "target": self.target,
            "platform": self.platform,
            "kind": self.kind,
            "verdict": self.verdict.value,
            "url": self.url,
            "source": self.source,
            "category": self.category,
            "detail": self.detail,
            "confidence": max(0, min(100, int(self.confidence))),
            "http_status": self.http_status,
            "elapsed_ms": self.elapsed_ms,
        }
        if self.metadata:
            payload["metadata"] = self.metadata
        return payload


@dataclass(slots=True)
class DerivedIdentifier:
    """An identifier inferred by the correlation engine."""

    kind: str
    value: str
    source: str
    reason: str
    confidence: int = 50
    scanned: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
            "reason": self.reason,
            "confidence": max(0, min(100, int(self.confidence))),
            "scanned": self.scanned,
        }


@dataclass(slots=True)
class Correlation:
    """The unified, live digital-footprint model."""

    usernames: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    candidates: list[DerivedIdentifier] = field(default_factory=list)
    graph_nodes: list[dict[str, Any]] = field(default_factory=list)
    graph_edges: list[dict[str, Any]] = field(default_factory=list)
    profile: dict[str, Any] = field(default_factory=dict)
    confidence: int = 0
    summary: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "usernames": self.usernames,
            "emails": self.emails,
            "phones": self.phones,
            "candidates": [c.to_dict() for c in self.candidates],
            "graph": {"nodes": self.graph_nodes, "edges": self.graph_edges},
            "profile": self.profile,
            "confidence": max(0, min(100, int(self.confidence))),
            "summary": self.summary,
            "notes": self.notes,
        }


@dataclass(slots=True)
class ScanStats:
    total: int = 0
    found: int = 0
    absent: int = 0
    unknown: int = 0
    platforms_found: int = 0
    duration_ms: int = 0

    @property
    def checked(self) -> int:
        return self.total

    def to_dict(self) -> dict[str, int]:
        return {
            "total": self.total,
            "found": self.found,
            "absent": self.absent,
            "unknown": self.unknown,
            "platforms_found": self.platforms_found,
            "duration_ms": self.duration_ms,
        }


@dataclass(slots=True)
class ScanResult:
    """Everything produced by one sAScan run."""

    seed: Seed
    findings: list[Finding] = field(default_factory=list)
    correlation: Correlation = field(default_factory=Correlation)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: int = 0
    engines: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def found(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict is Verdict.FOUND]

    @property
    def absent(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict is Verdict.ABSENT]

    @property
    def unknown(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict is Verdict.UNKNOWN]

    @property
    def stats(self) -> ScanStats:
        platforms = {
            f.platform.casefold()
            for f in self.findings
            if f.verdict is Verdict.FOUND and f.kind == "account"
        }
        return ScanStats(
            total=len(self.findings),
            found=len(self.found),
            absent=len(self.absent),
            unknown=len(self.unknown),
            platforms_found=len(platforms),
            duration_ms=self.duration_ms,
        )

    @property
    def duration_display(self) -> str:
        from sascan.utils.text import human_duration

        return human_duration(self.duration_ms)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "sAScan",
            "version": __version__,
            "seed": self.seed.to_dict(),
            "started_at": self.started_at.isoformat(),
            "duration_ms": self.duration_ms,
            "stats": self.stats.to_dict(),
            "engines": self.engines,
            "errors": self.errors,
            "notes": self.notes,
            "correlation": self.correlation.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }
