"""Pure, testable response classification logic."""

from __future__ import annotations

from sascan.core.sites import SiteRule
from sascan.models import Verdict

NOTE_BLOCKED = "Blocked by bot protection or rate limiting"
NOTE_NO_MARKER = "No confirmation marker in the response"
NOTE_SERVER_ERROR = "Server error"
NOTE_UNEXPECTED = "Unexpected response"


def _matches(marker: str, lowered_body: str, account: str) -> bool:
    rendered = marker.replace("{account}", account).casefold()
    return rendered in lowered_body


def classify(
    rule: SiteRule,
    status: int,
    body: str = "",
    account: str = "",
) -> tuple[Verdict, str]:
    """Classify one HTTP response using an explicit precedence order."""
    lowered = body.casefold()

    if status in rule.absent_status:
        return Verdict.ABSENT, ""
    if status in rule.blocked_status:
        return Verdict.UNKNOWN, NOTE_BLOCKED

    for marker in rule.blocked_markers:
        if _matches(marker, lowered, account):
            return Verdict.UNKNOWN, NOTE_BLOCKED

    for marker in rule.absent_markers:
        if _matches(marker, lowered, account):
            return Verdict.ABSENT, ""

    if rule.present_markers:
        if any(_matches(marker, lowered, account) for marker in rule.present_markers):
            return Verdict.FOUND, ""
        if rule.missing_is_absent:
            return Verdict.ABSENT, ""
        return Verdict.UNKNOWN, NOTE_NO_MARKER

    if status in rule.found_status:
        return Verdict.FOUND, ""
    if status >= 500:
        return Verdict.UNKNOWN, NOTE_SERVER_ERROR
    return Verdict.UNKNOWN, NOTE_UNEXPECTED
