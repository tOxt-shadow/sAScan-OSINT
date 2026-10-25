"""Input normalization and auto-detection tests."""

from __future__ import annotations

import pytest

from sascan.models import SeedKind
from sascan.utils.validators import (
    InvalidSeed,
    detect_seed,
    normalize_email,
    normalize_phone,
    normalize_username,
    username_candidates,
)


def test_username_accepts_at_prefix_and_profile_url() -> None:
    assert normalize_username("@alice") == "alice"
    assert normalize_username("https://github.com/alice") == "alice"


def test_username_rejects_spaces_and_empty() -> None:
    with pytest.raises(InvalidSeed):
        normalize_username("bad user")
    with pytest.raises(InvalidSeed):
        normalize_username("   ")


def test_email_is_lowercased_and_validated() -> None:
    assert normalize_email("  Alice@Example.COM ") == "alice@example.com"
    with pytest.raises(InvalidSeed):
        normalize_email("alice@example")
    with pytest.raises(InvalidSeed):
        normalize_email("alice..bob@example.com")


def test_phone_normalization_to_e164() -> None:
    assert normalize_phone("+966 50 123 4567", "SA") == "+966501234567"
    assert normalize_phone("0501234567", "SA") == "+966501234567"


def test_invalid_phone_has_clear_error() -> None:
    with pytest.raises(InvalidSeed):
        normalize_phone("+999999", "SA")


def test_detect_email() -> None:
    seed = detect_seed("Alice@Example.com")
    assert seed.kind is SeedKind.EMAIL
    assert seed.value == "alice@example.com"


def test_detect_international_phone() -> None:
    seed = detect_seed("+966501234567")
    assert seed.kind is SeedKind.PHONE
    assert seed.value == "+966501234567"


def test_detect_local_phone_when_region_makes_it_valid() -> None:
    seed = detect_seed("0501234567", region="SA")
    assert seed.kind is SeedKind.PHONE


def test_detect_username() -> None:
    seed = detect_seed("@alice")
    assert seed.kind is SeedKind.USERNAME
    assert seed.value == "alice"


def test_email_candidates_are_derived_safely() -> None:
    candidates = username_candidates("alice.smith+news@example.com")
    assert "alice.smith" in candidates
    assert "alicesmith" in candidates
    assert all("+" not in item and "@" not in item for item in candidates)
