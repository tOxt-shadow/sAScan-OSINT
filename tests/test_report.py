"""HTML report rendering and filesystem tests."""

from __future__ import annotations

from pathlib import Path

from sascan.core.correlation import CorrelationEngine
from sascan.models import Finding, ScanResult, Seed, SeedKind, Verdict
from sascan.reports.html import (
    default_report_path,
    render_html_report,
    write_html_report,
)


def make_result() -> ScanResult:
    seed = Seed(SeedKind.USERNAME, "alice")
    findings = [
        Finding(
            target="alice",
            platform="GitHub",
            kind="account",
            verdict=Verdict.FOUND,
            url="https://github.com/alice",
            source="native",
            category="Development",
            detail="HTTP 200",
            confidence=88,
        ),
        Finding(
            target="alice",
            platform="Telegram",
            kind="account",
            verdict=Verdict.UNKNOWN,
            url="https://t.me/alice",
            source="native",
            category="Social",
            detail="Blocked by bot protection or rate limiting",
            confidence=30,
        ),
        Finding(
            target="alice",
            platform="<script>alert(1)</script>",
            kind="account",
            verdict=Verdict.ABSENT,
            url="https://example.com/alice",
            source="native",
            detail="<b>must be escaped</b>",
        ),
    ]
    correlation = CorrelationEngine().build(seed, findings, scanned_targets={"alice"})
    return ScanResult(
        seed=seed,
        findings=findings,
        correlation=correlation,
        duration_ms=1234,
        engines=["native"],
        notes=["A note"],
    )


def test_render_contains_graph_and_escapes_html() -> None:
    html = render_html_report(make_result())
    assert "<!DOCTYPE html>" in html
    assert 'id="graph"' in html
    assert "GitHub" in html
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<b>must be escaped</b>" not in html
    assert "sascan-data" in html
    assert "1.2 s" in html


def test_write_report_to_file(tmp_path: Path) -> None:
    target = tmp_path / "custom" / "report.html"
    path = write_html_report(make_result(), target)
    assert path == target.resolve()
    assert path.exists()
    assert path.stat().st_size > 5_000


def test_write_report_to_directory(tmp_path: Path) -> None:
    path = write_html_report(make_result(), tmp_path)
    assert path.parent == tmp_path.resolve()
    assert path.name.startswith("sascan_username_alice_")
    assert path.suffix == ".html"


def test_default_report_name() -> None:
    path = default_report_path("alice@example.com", "email")
    assert path.name.startswith("sascan_email_alice_example.com_")
    assert path.parent.name == "reports"
