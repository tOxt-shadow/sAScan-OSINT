"""Scan orchestration: native modules, optional external engines and correlation."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from sascan import __version__
from sascan.config import (
    DEFAULT_BODY_LIMIT,
    DEFAULT_CONCURRENCY,
    DEFAULT_DEEP_LIMIT,
    DEFAULT_REGION,
    DEFAULT_TIMEOUT,
    ENGINE_CHOICES,
)
from sascan.core.correlation import CorrelationEngine
from sascan.core.http import AsyncHttpClient
from sascan.core.progress import ScanProgress
from sascan.core.sites import SiteRegistry, SiteRule, SitesConfigError
from sascan.models import Finding, ScanResult, Seed, SeedKind, Verdict
from sascan.modules.base import ModuleResult
from sascan.modules.email import scan_email
from sascan.modules.external import (
    TOOLS,
    available_tools,
    run_holehe,
    run_phoneinfoga,
    run_sherlock,
)
from sascan.modules.phone import scan_phone
from sascan.modules.username import scan_username
from sascan.utils.validators import (
    is_generic_email_local,
    is_reserved_email_domain,
    username_candidates,
)

logger = logging.getLogger(__name__)


class EngineError(RuntimeError):
    """A user-facing scan configuration or availability error."""


@dataclass(slots=True)
class ScanOptions:
    engine: str = "auto"
    deep: bool = False
    region: str = DEFAULT_REGION
    timeout: float = DEFAULT_TIMEOUT
    concurrency: int = DEFAULT_CONCURRENCY
    only: tuple[str, ...] = ()
    sites_path: str | None = None
    body_limit: int = DEFAULT_BODY_LIMIT
    max_followups: int = DEFAULT_DEEP_LIMIT
    external_timeout: float | None = None


def _merge_metadata(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, list) and isinstance(target.get(key), list):
            for item in value:
                if item not in target[key]:
                    target[key].append(item)
        else:
            target[key] = value


def _dedupe(findings: list[Finding]) -> list[Finding]:
    unique: list[Finding] = []
    seen: set[tuple[Any, ...]] = set()
    for finding in findings:
        key = (
            finding.target.casefold(),
            finding.platform.casefold(),
            finding.kind,
            finding.verdict.value,
            finding.url,
            finding.source,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    order = {Verdict.FOUND: 0, Verdict.UNKNOWN: 1, Verdict.ABSENT: 2}
    unique.sort(
        key=lambda item: (
            order.get(item.verdict, 9),
            -item.confidence,
            item.platform.casefold(),
        )
    )
    return unique


class ScanEngine:
    """Stateless scan engine. One instance can process multiple targets."""

    def __init__(self, options: ScanOptions | None = None) -> None:
        self.options = options or ScanOptions()
        if self.options.engine not in ENGINE_CHOICES:
            raise EngineError(
                f"Unknown engine '{self.options.engine}'. Choose: {', '.join(ENGINE_CHOICES)}."
            )
        self.registry = SiteRegistry(self.options.sites_path)
        try:
            self.site_count = self.registry.load()
        except SitesConfigError as exc:
            raise EngineError(str(exc)) from exc
        self.tools = available_tools()
        self.correlation = CorrelationEngine()

    @property
    def available_engines(self) -> list[str]:
        return ["native"] + [name for name, path in self.tools.items() if path]

    def _want_native(self) -> bool:
        return self.options.engine in {"native", "auto", "both"}

    def _external_enabled(self, name: str) -> bool:
        """External engines are opt-in; auto mode stays fast and native-only."""
        mode = self.options.engine
        return mode == name or mode == "both"

    def _require_external(self, name: str) -> None:
        if self._external_enabled(name) and not self.tools.get(name):
            tool = TOOLS[name]
            raise EngineError(
                f"{tool.label} is required for --engine {name}, but '{tool.command}' "
                f"was not found in PATH. Install it with: {tool.install}"
            )

    def _validate_seed_engine(self, seed: Seed) -> None:
        mode = self.options.engine
        incompatible = {
            "sherlock": SeedKind.USERNAME,
            "holehe": SeedKind.EMAIL,
            "phoneinfoga": SeedKind.PHONE,
        }
        if mode in incompatible and seed.kind is not incompatible[mode]:
            friendly = {
                "sherlock": "usernames",
                "holehe": "email addresses",
                "phoneinfoga": "phone numbers",
            }[mode]
            raise EngineError(f"--engine {mode} only supports {friendly}.")

    def _select_sites(self) -> tuple[SiteRule, ...]:
        filters = {item.strip().casefold() for item in self.options.only if item.strip()}
        try:
            sites = self.registry.select(filters)
        except SitesConfigError as exc:
            raise EngineError(str(exc)) from exc
        if not sites:
            available = ", ".join(rule.name for rule in self.registry.rules)
            raise EngineError(
                f"No site matched --only. Available sites: {available}"
            )
        return sites

    async def scan(
        self,
        seed: Seed,
        *,
        progress: ScanProgress | None = None,
    ) -> ScanResult:
        self._validate_seed_engine(seed)
        if seed.kind is SeedKind.USERNAME:
            self._require_external("sherlock")
        elif seed.kind is SeedKind.EMAIL:
            self._require_external("holehe")
        else:
            self._require_external("phoneinfoga")

        started_at = time.perf_counter()
        findings: list[Finding] = []
        errors: list[str] = []
        notes: list[str] = []
        metadata: dict[str, Any] = {}
        engines: list[str] = []
        scanned_targets: set[str] = {seed.value}
        if self.options.external_timeout:
            external_timeout = self.options.external_timeout
        elif self.options.engine in {"both", "sherlock", "holehe", "phoneinfoga"}:
            external_timeout = max(180.0, self.options.timeout * 18)
        else:
            external_timeout = max(60.0, self.options.timeout * 6)

        sites = self._select_sites() if self._want_native() and seed.kind is SeedKind.USERNAME else ()
        if seed.kind is SeedKind.USERNAME:
            if self._want_native() and not sites:
                raise EngineError("No native sites are available for a username scan.")
            total = len(sites) + (1 if self._external_enabled("sherlock") else 0)
            if progress:
                progress.set_total(total)
                if total:
                    progress.description = "Scanning username"
            result = await self._username_pass(
                seed.value,
                sites,
                progress,
                external_timeout=external_timeout,
                deep=False,
            )
            self._apply(result, findings, errors, notes, metadata)
            if self._want_native() and sites:
                engines.append("native")
            if self._external_enabled("sherlock"):
                engines.append("sherlock")

        elif seed.kind is SeedKind.EMAIL:
            total = (1 if self._want_native() else 0) + (1 if self._external_enabled("holehe") else 0)
            if progress:
                progress.set_total(total)
                if total:
                    progress.description = "Scanning email"
            result = await self._email_pass(seed.value, progress, external_timeout)
            self._apply(result, findings, errors, notes, metadata)
            if self._want_native():
                engines.append("native")
            if self._external_enabled("holehe"):
                engines.append("holehe")

        else:
            total = (1 if self._want_native() else 0) + (
                1 if self._external_enabled("phoneinfoga") else 0
            )
            if progress:
                progress.set_total(total)
                if total:
                    progress.description = "Scanning phone"
            result = await self._phone_pass(
                seed.value, progress, external_timeout
            )
            self._apply(result, findings, errors, notes, metadata)
            if self._want_native():
                engines.append("native")
            if self._external_enabled("phoneinfoga"):
                engines.append("phoneinfoga")

        # Deep follow-up: only username inference from an email has a defensible
        # next hop. The loop is bounded to prevent accidental network flooding.
        if (
            self.options.deep
            and seed.kind is SeedKind.EMAIL
            and self._want_native()
        ):
            followups = self._deep_usernames(seed, metadata, findings)
            if is_reserved_email_domain(seed.value) or is_generic_email_local(
                seed.value
            ):
                notes.append(
                    "Deep follow-up skipped: the email uses a reserved test domain "
                    "or a generic local-part, so derived usernames would not be "
                    "identity evidence."
                )
                followups = []
            if followups:
                deep_sites = self._select_sites()
                per_target = len(deep_sites) + (
                    1 if self._external_enabled("sherlock") else 0
                )
                if progress:
                    progress.set_total(
                        progress.total + per_target * len(followups)
                    )
                    progress.description = "Deep scanning derived usernames"
                notes.append(
                    "Deep follow-up scanned derived username(s): "
                    + ", ".join(followups)
                )
                for username in followups:
                    scanned_targets.add(username)
                    deep_result = await self._username_pass(
                        username,
                        deep_sites,
                        progress,
                        external_timeout=external_timeout,
                        deep=True,
                    )
                    self._apply(deep_result, findings, errors, notes, metadata)
                    if self._external_enabled("sherlock") and "sherlock" not in engines:
                        engines.append("sherlock")

        if self.options.deep and seed.kind is SeedKind.PHONE:
            notes.append("Deep mode has no safe automatic follow-up for phone numbers.")
        if self.options.deep and seed.kind is SeedKind.USERNAME:
            notes.append("Deep mode has no additional follow-up for a username seed.")
        if self.options.engine == "auto":
            relevant = {
                SeedKind.USERNAME: ("sherlock",),
                SeedKind.EMAIL: ("holehe",),
                SeedKind.PHONE: ("phoneinfoga",),
            }[seed.kind]
            installed = [name for name in relevant if self.tools.get(name)]
            if installed:
                notes.append(
                    "External engine(s) not used in auto mode: "
                    + ", ".join(installed)
                    + ". Pass --engine both, or --engine <name>, to include them."
                )
            else:
                notes.append(
                    "Optional engine(s) not installed: "
                    + ", ".join(relevant)
                    + ". The native engine was used instead."
                )
        if self.options.only and seed.kind is not SeedKind.USERNAME:
            notes.append("--only is ignored for non-username seeds.")
        if not engines:
            raise EngineError("No scan engine was selected.")

        findings = _dedupe(findings)
        correlation = self.correlation.build(
            seed,
            findings,
            metadata,
            scanned_targets=scanned_targets,
        )
        notes.extend(correlation.notes)
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        notes.append(
            "sAScan is stateless: no database or scan history was written."
        )
        notes.append(f"Engine build {__version__} · legal, consent-based use only.")

        deduped_notes = list(dict.fromkeys(note for note in notes if note))
        deduped_errors = list(dict.fromkeys(error for error in errors if error))
        return ScanResult(
            seed=seed,
            findings=findings,
            correlation=correlation,
            duration_ms=duration_ms,
            engines=list(dict.fromkeys(engines)),
            errors=deduped_errors,
            notes=deduped_notes,
        )

    # ------------------------------------------------------------------
    # Passes
    # ------------------------------------------------------------------
    async def _username_pass(
        self,
        username: str,
        sites: tuple[SiteRule, ...],
        progress: ScanProgress | None,
        *,
        external_timeout: float,
        deep: bool,
    ) -> ModuleResult:
        async with AsyncHttpClient(
            timeout=self.options.timeout,
            concurrency=self.options.concurrency,
            body_limit=self.options.body_limit,
        ) as http:
            tasks = []
            if self._want_native() and sites:
                tasks.append(
                    asyncio.create_task(
                        scan_username(username, sites, http, progress=progress)
                    )
                )
            if self._external_enabled("sherlock"):
                tasks.append(
                    asyncio.create_task(
                        self._progress_external(
                            run_sherlock(username, timeout=external_timeout), progress
                        )
                    )
                )
            results = await asyncio.gather(*tasks, return_exceptions=True)

        merged = ModuleResult()
        for result in results:
            if isinstance(result, BaseException):
                merged.errors.append(f"Username pass failed: {type(result).__name__}")
                logger.debug("Username pass exception", exc_info=result)
            else:
                merged.merge(result)
        merged.metadata.setdefault("scanned_usernames", []).append(username)
        return merged

    async def _email_pass(
        self,
        email: str,
        progress: ScanProgress | None,
        external_timeout: float,
    ) -> ModuleResult:
        async with AsyncHttpClient(
            timeout=self.options.timeout,
            concurrency=self.options.concurrency,
            body_limit=self.options.body_limit,
        ) as http:
            tasks = []
            if self._want_native():
                tasks.append(
                    asyncio.create_task(
                        self._progress_native(
                            scan_email(
                                email,
                                http,
                                timeout=self.options.timeout,
                                include_gravatar=True,
                                include_github=True,
                            ),
                            progress,
                        )
                    )
                )
            if self._external_enabled("holehe"):
                tasks.append(
                    asyncio.create_task(
                        self._progress_external(
                            run_holehe(email, timeout=external_timeout), progress
                        )
                    )
                )
            results = await asyncio.gather(*tasks, return_exceptions=True)

        merged = ModuleResult()
        for result in results:
            if isinstance(result, BaseException):
                merged.errors.append(f"Email pass failed: {type(result).__name__}")
                logger.debug("Email pass exception", exc_info=result)
            else:
                merged.merge(result)
        return merged

    async def _phone_pass(
        self,
        phone: str,
        progress: ScanProgress | None,
        external_timeout: float,
    ) -> ModuleResult:
        merged = ModuleResult()
        if self._want_native():
            try:
                native = scan_phone(phone, self.options.region)
                merged.merge(native)
            except Exception as exc:
                merged.errors.append(f"Phone metadata failed: {exc}")
            if progress:
                progress.advance("metadata")
        if self._external_enabled("phoneinfoga"):
            external = await self._progress_external(
                run_phoneinfoga(
                    phone,
                    timeout=external_timeout,
                    region=self.options.region,
                ),
                progress,
            )
            merged.merge(external)
        return merged

    async def _progress_native(
        self,
        coroutine: Any,
        progress: ScanProgress | None,
    ) -> ModuleResult:
        try:
            return await coroutine
        finally:
            if progress:
                progress.advance("native email")

    async def _progress_external(
        self,
        coroutine: Any,
        progress: ScanProgress | None,
    ) -> ModuleResult:
        try:
            return await coroutine
        finally:
            if progress:
                progress.advance("external engine")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _apply(
        self,
        module_result: ModuleResult,
        findings: list[Finding],
        errors: list[str],
        notes: list[str],
        metadata: dict[str, Any],
    ) -> None:
        findings.extend(module_result.findings)
        errors.extend(module_result.errors)
        notes.extend(module_result.notes)
        _merge_metadata(metadata, module_result.metadata)

    def _deep_usernames(
        self,
        seed: Seed,
        metadata: dict[str, Any],
        findings: list[Finding],
    ) -> list[str]:
        candidates: list[str] = []
        for value in username_candidates(seed.value, limit=self.options.max_followups):
            if value.casefold() not in {item.casefold() for item in candidates}:
                candidates.append(value)
        for value in metadata.get("usernames", []) or []:
            if (
                isinstance(value, str)
                and value.casefold() not in {item.casefold() for item in candidates}
            ):
                candidates.append(value)
        return candidates[: self.options.max_followups]
