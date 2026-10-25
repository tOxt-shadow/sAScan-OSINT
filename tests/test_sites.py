"""Site registry loading and validation tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sascan.core.sites import SiteRegistry, SitesConfigError


def test_shipped_registry_has_19_sites() -> None:
    registry = SiteRegistry()
    count = registry.load()
    names = {rule.name for rule in registry.rules}
    assert count == 19
    assert {"GitHub", "Telegram", "Reddit", "Hacker News"} <= names


def test_filter_selects_by_name_or_kind() -> None:
    registry = SiteRegistry()
    registry.load()
    assert [rule.name for rule in registry.select({"github"})] == ["GitHub"]
    developer_names = {rule.name for rule in registry.select({"developer"})}
    assert "GitHub" in developer_names
    assert "PyPI" in developer_names


def test_invalid_url_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "sites.json"
    path.write_text(
        json.dumps(
            {
                "sites": [
                    {
                        "name": "Bad",
                        "url": "http://example.com/{account}",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(SitesConfigError, match="https"):
        SiteRegistry(path).load()


def test_duplicate_names_are_rejected(tmp_path: Path) -> None:
    item = {"name": "Same", "url": "https://example.com/{account}"}
    path = tmp_path / "sites.json"
    path.write_text(json.dumps({"sites": [item, item]}), encoding="utf-8")
    with pytest.raises(SitesConfigError, match="Duplicate"):
        SiteRegistry(path).load()


def test_missing_account_placeholder_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "sites.json"
    path.write_text(
        json.dumps({"sites": [{"name": "Bad", "url": "https://example.com/"}]}),
        encoding="utf-8",
    )
    with pytest.raises(SitesConfigError, match="account"):
        SiteRegistry(path).load()
