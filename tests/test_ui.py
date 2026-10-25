"""Presentation helpers should not show misleading scan metadata."""

from __future__ import annotations

from sascan.models import Seed, SeedKind
from sascan.ui import detected_phone_region, scan_header


def test_detected_phone_region_uses_the_number_not_the_hint() -> None:
    assert detected_phone_region("+14155552671", "SA") == "US"
    assert detected_phone_region("+966501234567", "US") == "SA"


def test_local_phone_region_falls_back_to_the_hint() -> None:
    assert detected_phone_region("0501234567", "sa") == "SA"


def test_scan_header_only_shows_region_for_phone_seeds() -> None:
    email_panel = scan_header(
        Seed(SeedKind.EMAIL, "alice@company.com"),
        engine="native",
        region="SA",
        deep=False,
    )
    phone_panel = scan_header(
        Seed(SeedKind.PHONE, "+14155552671"),
        engine="native",
        region="SA",
        deep=False,
    )

    assert "Region" not in email_panel.renderable.plain
    assert "Region   US" in phone_panel.renderable.plain


def test_scan_header_labels_native_site_rules() -> None:
    panel = scan_header(
        Seed(SeedKind.USERNAME, "alice"),
        engine="both",
        region="SA",
        deep=False,
        site_count=19,
    )

    assert "Native   19 site rule(s)" in panel.renderable.plain
