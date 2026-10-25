"""External output parser tests; no external binaries are executed."""

from __future__ import annotations

from sascan.modules.external import (
    _parse_holehe,
    _parse_phoneinfoga,
    _parse_sherlock,
    tool_status,
)


def test_sherlock_parser_extracts_profiles() -> None:
    output = """
[*] Checking username alice on:
[+] GitHub: https://github.com/alice
[+] Reddit: https://www.reddit.com/user/alice
[+] Documentation: https://github.com/sherlock-project/sherlock
"""
    result = _parse_sherlock("alice", output)
    urls = {item.url for item in result.findings}
    assert "https://github.com/alice" in urls
    assert "https://www.reddit.com/user/alice" in urls
    assert all(item.source == "sherlock" for item in result.findings)
    assert not any("sherlock-project" in item.url for item in result.findings)


def test_holehe_parser_handles_domains_and_urls() -> None:
    output = """
[+] instagram.com
[+] Email used for twitter.com
[-] github.com
"""
    result = _parse_holehe("alice@example.com", output)
    platforms = {item.platform for item in result.findings}
    assert "Instagram" in platforms
    assert "X (Twitter)" in platforms
    assert all(item.source == "holehe" for item in result.findings)
    assert not any("github" in item.platform.casefold() for item in result.findings)


def test_phoneinfoga_parser_marks_leads_as_unverified() -> None:
    output = """
Running scan for +966501234567
Country: Saudi Arabia
[+] https://www.truecaller.com/search/sa/966501234567
[+] https://github.com/sundowndev/phoneinfoga
[+] Contact: alice@example.com
"""
    result = _parse_phoneinfoga("+966501234567", output)
    assert result.findings
    assert all(item.verdict.value == "unknown" for item in result.findings)
    assert result.metadata["emails"] == ["alice@example.com"]
    assert any("Country" in note for note in result.notes)


def test_tool_status_has_three_engines() -> None:
    status = tool_status()
    assert len(status) == 3
    assert {item[0] for item in status} == {"Sherlock", "Holehe", "PhoneInfoga"}
