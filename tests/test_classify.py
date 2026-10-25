"""Classification precedence tests (pure, no network)."""

from __future__ import annotations

from sascan.core.classify import classify
from sascan.core.sites import SiteRule
from sascan.models import Verdict


def make_rule(**overrides: object) -> SiteRule:
    payload = {
        "name": "Example",
        "url_template": "https://example.com/{account}",
        "found_status": frozenset({200}),
        "absent_status": frozenset({404}),
        "blocked_status": frozenset({401, 403, 429}),
    }
    payload.update(overrides)
    return SiteRule(**payload)  # type: ignore[arg-type]


def test_absent_status_has_priority() -> None:
    verdict, _ = classify(make_rule(), 404, "welcome {account}")
    assert verdict is Verdict.ABSENT


def test_blocked_status_is_unknown() -> None:
    verdict, note = classify(make_rule(), 429, "")
    assert verdict is Verdict.UNKNOWN
    assert "Blocked" in note


def test_blocked_marker_is_unknown_before_present_marker() -> None:
    rule = make_rule(
        present_markers=("welcome",),
        blocked_markers=("captcha",),
    )
    verdict, _ = classify(rule, 200, "welcome alice captcha")
    assert verdict is Verdict.UNKNOWN


def test_absent_marker_wins_over_found_status() -> None:
    rule = make_rule(absent_markers=("profile not found",))
    verdict, _ = classify(rule, 200, "Profile Not Found")
    assert verdict is Verdict.ABSENT


def test_present_marker_required() -> None:
    rule = make_rule(present_markers=("tgme_page_title",))
    assert classify(rule, 200, "<html>nothing</html>")[0] is Verdict.UNKNOWN
    assert classify(rule, 200, "<div class='tgme_page_title'>alice</div>")[0] is Verdict.FOUND


def test_missing_is_absent_only_when_configured() -> None:
    rule = make_rule(present_markers=("profile",), missing_is_absent=True)
    assert classify(rule, 200, "nothing")[0] is Verdict.ABSENT


def test_marker_account_placeholder_is_case_insensitive() -> None:
    rule = make_rule(present_markers=("({account}) - Profile",))
    assert classify(rule, 200, "(ALICE) - profile", "alice")[0] is Verdict.FOUND


def test_found_status_fallback() -> None:
    assert classify(make_rule(), 200, "")[0] is Verdict.FOUND


def test_server_error_is_unknown() -> None:
    verdict, note = classify(make_rule(), 503, "")
    assert verdict is Verdict.UNKNOWN
    assert "Server" in note


def test_unexpected_status_is_unknown() -> None:
    assert classify(make_rule(), 204, "")[0] is Verdict.UNKNOWN
