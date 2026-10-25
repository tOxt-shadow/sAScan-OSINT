"""Correlation engine tests (pure logic)."""

from __future__ import annotations

from sascan.core.correlation import CorrelationEngine, username_from_url
from sascan.models import Finding, Seed, SeedKind, Verdict


def finding(**overrides: object) -> Finding:
    payload = {
        "target": "alice@example.com",
        "platform": "Example",
        "kind": "account",
        "verdict": Verdict.FOUND,
        "url": "https://example.com/alice",
        "source": "native",
    }
    payload.update(overrides)
    return Finding(**payload)  # type: ignore[arg-type]


def test_username_from_known_profile_urls() -> None:
    assert username_from_url("https://github.com/alice") == "alice"
    assert username_from_url("https://www.reddit.com/user/alice_1/") == "alice_1"
    assert username_from_url("https://t.me/alice") == "alice"
    assert username_from_url("https://news.ycombinator.com/user?id=alice") == "alice"
    assert username_from_url("https://github.com/features") is None


def test_email_footprint_links_accounts_and_candidates() -> None:
    seed = Seed(SeedKind.EMAIL, "alice@example.com")
    accounts = [
        {
            "domain": "instagram.com",
            "username": "alice.ig",
            "url": "https://instagram.com/alice.ig",
            "verified": True,
        }
    ]
    findings = [
        finding(
            platform="GitHub",
            url="https://github.com/alicegh",
            source="email-native",
            metadata={"username": "alicegh"},
        ),
        finding(
            platform="Gravatar",
            kind="profile",
            url="https://gravatar.com/alice",
            source="gravatar",
            metadata={"accounts": accounts},
        ),
        finding(
            platform="Email domain (DNS)",
            kind="infrastructure",
            detail="MX: mx.example.com",
        ),
    ]
    correlation = CorrelationEngine().build(
        seed,
        findings,
        metadata={
            "dns": {"mx": ["mx.example.com"]},
            "gravatar": {"display_name": "Alice", "accounts": accounts},
        },
        scanned_targets={"alice@example.com"},
    )

    assert correlation.emails == ["alice@example.com"]
    assert "alicegh" in correlation.usernames
    assert "alice.ig" in correlation.usernames
    assert any(candidate.value == "alice" for candidate in correlation.candidates)
    assert correlation.confidence >= 40
    assert correlation.graph_nodes
    assert any(node["group"] == "seed" for node in correlation.graph_nodes)
    assert any(node["group"] == "platform" for node in correlation.graph_nodes)
    assert any("unscanned" in note for note in correlation.notes)
    assert correlation.profile["display_name"] == "Alice"


def test_username_seed_keeps_root_identifier() -> None:
    seed = Seed(SeedKind.USERNAME, "alice")
    correlation = CorrelationEngine().build(
        seed,
        [finding(target="alice", platform="GitHub", url="https://github.com/alice")],
        scanned_targets={"alice"},
    )
    assert correlation.usernames == ["alice"]
    assert correlation.emails == []
    assert correlation.phones == []
    assert correlation.confidence >= 25
    assert correlation.summary.startswith("1 public profile")


def test_no_found_is_not_reported_as_proof() -> None:
    seed = Seed(SeedKind.USERNAME, "missing")
    correlation = CorrelationEngine().build(
        seed,
        [
            finding(
                target="missing",
                platform="GitHub",
                verdict=Verdict.ABSENT,
                url="https://github.com/missing",
            )
        ],
        scanned_targets={"missing"},
    )
    assert "No public account was confirmed" in correlation.summary
    assert any("Absence of evidence" in note for note in correlation.notes)


def test_scanned_deep_candidate_is_marked() -> None:
    seed = Seed(SeedKind.EMAIL, "bob@example.com")
    correlation = CorrelationEngine().build(
        seed,
        [],
        scanned_targets={"bob@example.com", "bob"},
    )
    bob = next(candidate for candidate in correlation.candidates if candidate.value == "bob")
    assert bob.scanned is True
