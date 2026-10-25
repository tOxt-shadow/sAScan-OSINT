"""Engine configuration tests without network calls."""

from __future__ import annotations

import asyncio

import pytest

from sascan.core.engine import EngineError, ScanEngine, ScanOptions
from sascan.models import Seed, SeedKind
from sascan.modules.base import ModuleResult


def test_invalid_engine_is_rejected() -> None:
    with pytest.raises(EngineError, match="Unknown engine"):
        ScanEngine(ScanOptions(engine="not-a-thing"))


def test_explicit_engine_rejects_incompatible_seed() -> None:
    engine = ScanEngine(ScanOptions(engine="holehe"))
    with pytest.raises(EngineError, match="only supports email"):
        asyncio.run(engine.scan(Seed(SeedKind.USERNAME, "alice")))


def test_both_mode_requires_external_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = ScanEngine(ScanOptions(engine="both"))
    monkeypatch.setitem(engine.tools, "sherlock", None)
    with pytest.raises(EngineError, match="Sherlock is required"):
        asyncio.run(engine.scan(Seed(SeedKind.USERNAME, "alice")))


def test_auto_mode_keeps_external_engines_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = ScanEngine(ScanOptions(engine="auto"))
    monkeypatch.setitem(engine.tools, "sherlock", "/usr/bin/sherlock")

    assert engine._external_enabled("sherlock") is False
    assert engine._external_enabled("holehe") is False


def test_both_mode_enables_external_engines() -> None:
    engine = ScanEngine(ScanOptions(engine="both"))

    assert engine._external_enabled("sherlock") is True


def test_only_filter_with_no_match_fails_before_network() -> None:
    engine = ScanEngine(ScanOptions(engine="native", only=("does-not-exist",)))
    with pytest.raises(EngineError, match="No site matched"):
        asyncio.run(engine.scan(Seed(SeedKind.USERNAME, "alice")))


def test_shipped_sites_are_loaded() -> None:
    engine = ScanEngine(ScanOptions(engine="native"))
    assert engine.site_count == 19
    assert "native" in engine.available_engines


def test_deep_mode_skips_generic_email_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = ScanEngine(ScanOptions(engine="native", deep=True))

    async def fake_email_pass(*args: object, **kwargs: object) -> ModuleResult:
        return ModuleResult()

    monkeypatch.setattr(engine, "_email_pass", fake_email_pass)
    result = asyncio.run(
        engine.scan(Seed(SeedKind.EMAIL, "test@example.com"))
    )

    assert result.findings == []
    assert any("Deep follow-up skipped" in note for note in result.notes)
