"""GitHub email evidence tests; no network calls."""

from __future__ import annotations

import asyncio
from typing import Any

from sascan.core.http import HttpResponse
from sascan.models import Verdict
from sascan.modules.email import _github_email_search
from sascan.utils.validators import is_generic_email_local, is_reserved_email_domain


class FakeHttp:
    def __init__(
        self,
        payload: Any,
        *,
        status: int | None = 200,
        error: str = "",
    ) -> None:
        self.payload = payload
        self.status = status
        self.error = error
        self.url = ""
        self.headers: dict[str, str] = {}

    async def get_json(self, url: str, **kwargs: Any) -> tuple[Any, HttpResponse]:
        self.url = url
        self.headers = kwargs.get("headers", {})
        return self.payload, HttpResponse(url=url, status=self.status, error=self.error)


def test_commit_search_does_not_create_accounts_without_author_login() -> None:
    payload = {
        "total_count": 3,
        "items": [
            {
                "html_url": "https://github.com/example/repo/commit/abc",
                "author": None,
                "commit": {"author": {"email": "test@example.com"}},
            }
        ],
    }
    fake = FakeHttp(payload)
    findings, error, logins, notes = asyncio.run(
        _github_email_search("alice@company.com", fake)
    )

    assert error is None
    assert notes == []
    assert logins == []
    assert "/search/commits" in fake.url
    assert "author-email%3Aalice%40company.com" in fake.url
    assert fake.headers["Accept"] == "application/vnd.github+json"
    assert not [finding for finding in findings if finding.kind == "account"]
    evidence = next(finding for finding in findings if finding.kind == "evidence")
    assert evidence.verdict is Verdict.FOUND
    assert evidence.platform == "GitHub commits"
    assert "no commit is linked" in evidence.detail
    assert evidence.metadata["commit_count"] == 3


def test_commit_search_reports_account_only_when_author_login_exists() -> None:
    payload = {
        "total_count": 1,
        "items": [
            {
                "html_url": "https://github.com/alice/repo/commit/abc",
                "author": {"login": "alice"},
            }
        ],
    }
    findings, error, logins, notes = asyncio.run(
        _github_email_search("alice@company.com", FakeHttp(payload))
    )

    assert error is None
    assert notes == []
    assert logins == ["alice"]
    account = next(finding for finding in findings if finding.kind == "account")
    assert account.verdict is Verdict.FOUND
    assert account.metadata["username"] == "alice"
    assert account.confidence >= 80


def test_zero_commits_is_absent_evidence_not_an_account_claim() -> None:
    findings, error, logins, notes = asyncio.run(
        _github_email_search(
            "alice@company.com", FakeHttp({"total_count": 0, "items": []})
        )
    )

    assert error is None
    assert notes == []
    assert logins == []
    assert len(findings) == 1
    finding = findings[0]
    assert finding.verdict is Verdict.ABSENT
    assert finding.kind == "evidence"
    assert finding.platform == "GitHub commits"
    assert "No public commit" in finding.detail


def test_rate_limit_is_reported_as_incomplete_evidence() -> None:
    findings, error, logins, notes = asyncio.run(
        _github_email_search("alice@company.com", FakeHttp(None, status=403))
    )

    assert findings == []
    assert logins == []
    assert error is None
    assert notes and "rate-limited" in notes[0]


def test_shared_email_with_multiple_logins_withholds_account_links() -> None:
    payload = {
        "total_count": 2,
        "items": [
            {"html_url": "https://github.com/a/repo/commit/1", "author": {"login": "alice"}},
            {"html_url": "https://github.com/b/repo/commit/2", "author": {"login": "bob"}},
        ],
    }
    findings, error, logins, notes = asyncio.run(
        _github_email_search("info@company.com", FakeHttp(payload))
    )

    assert error is None
    assert logins == []
    assert not [finding for finding in findings if finding.kind == "account"]
    evidence = next(finding for finding in findings if finding.kind == "evidence")
    assert evidence.metadata["shared"] is True
    assert "shared" in evidence.detail
    assert any("shared" in note for note in notes)


def test_reserved_test_domains_are_recognized() -> None:
    assert is_reserved_email_domain("test@example.com")
    assert is_reserved_email_domain("a@sub.example")
    assert is_reserved_email_domain("a@localhost")
    assert not is_reserved_email_domain("alice@example.dev")
    assert not is_reserved_email_domain("alice@company.com")


def test_generic_local_parts_are_recognized() -> None:
    assert is_generic_email_local("admin@company.com")
    assert is_generic_email_local("info+news@company.com")
    assert is_generic_email_local("no-reply@company.com")
    assert not is_generic_email_local("alice@company.com")


def test_reserved_test_domain_skips_commit_search() -> None:
    fake = FakeHttp({"total_count": 367824, "items": []})
    findings, error, logins, notes = asyncio.run(
        _github_email_search("test@example.com", fake)
    )

    assert findings == []
    assert logins == []
    assert error is None
    assert fake.url == ""
    assert notes and "reserved test domain" in notes[0]
