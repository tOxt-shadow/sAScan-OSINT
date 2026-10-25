"""Small validation and normalization helpers."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from sascan.models import Seed, SeedKind

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,39}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
PHONE_LOOKS_RE = re.compile(r"^\+?[\d\s().-]{7,24}$")

RESERVED_EMAIL_DOMAINS = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "test.com",
        "test.org",
        "test.net",
        "localhost",
        "invalid",
        "test",
    }
)
RESERVED_EMAIL_SUFFIXES = (".test", ".example", ".invalid", ".localhost")
GENERIC_EMAIL_LOCALS = frozenset(
    {
        "admin",
        "administrator",
        "abuse",
        "billing",
        "careers",
        "contact",
        "demo",
        "donotreply",
        "do-not-reply",
        "email",
        "example",
        "hello",
        "hostmaster",
        "info",
        "jobs",
        "legal",
        "mail",
        "media",
        "no-reply",
        "noreply",
        "office",
        "postmaster",
        "press",
        "privacy",
        "root",
        "sales",
        "security",
        "support",
        "team",
        "test",
        "testing",
        "user",
        "username",
        "webmaster",
    }
)


def is_reserved_email_domain(email: str) -> bool:
    """Return True for RFC 2606 / test domains that are not real identities."""
    domain = email.rsplit("@", 1)[-1].strip().lower().rstrip(".")
    return domain in RESERVED_EMAIL_DOMAINS or domain.endswith(
        RESERVED_EMAIL_SUFFIXES
    )


def is_generic_email_local(email: str) -> bool:
    """Return True for role/test local-parts that do not identify one person."""
    local = email.partition("@")[0].strip().lower().split("+", 1)[0]
    return local in GENERIC_EMAIL_LOCALS



class InvalidSeed(ValueError):
    """Raised when the user input cannot be normalized safely."""


def normalize_username(raw: str) -> str:
    value = raw.strip()
    if value.startswith("@"):
        value = value[1:]
    value = value.strip().strip("/")
    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        segments = [part for part in parsed.path.split("/") if part]
        value = segments[-1] if segments else ""
    if not value:
        raise InvalidSeed("Username is empty.")
    if not USERNAME_RE.fullmatch(value):
        raise InvalidSeed(
            "Username must be 1-39 characters using only letters, digits, '.', '_' or '-'."
        )
    return value


def normalize_email(raw: str) -> str:
    value = raw.strip().strip("<>").lower()
    if not value:
        raise InvalidSeed("Email address is empty.")
    if len(value) > 254 or not EMAIL_RE.fullmatch(value):
        raise InvalidSeed("Invalid email address format.")
    local, _, domain = value.partition("@")
    if not local or not domain or ".." in value:
        raise InvalidSeed("Invalid email address format.")
    return value


def normalize_phone(raw: str, region: str = "SA") -> str:
    """Normalize a phone number to E.164; raises InvalidSeed with a clear reason."""
    try:
        import phonenumbers
    except ModuleNotFoundError as exc:  # pragma: no cover - defensive
        raise InvalidSeed("The 'phonenumbers' package is not installed.") from exc

    value = raw.strip()
    if not value:
        raise InvalidSeed("Phone number is empty.")
    try:
        parsed = phonenumbers.parse(value, region.upper() or None)
    except phonenumbers.NumberParseException as exc:
        raise InvalidSeed(
            "Could not parse the phone number. Use E.164 such as +9665XXXXXXXX, "
            "or pass --region to specify the country code."
        ) from exc

    if not phonenumbers.is_possible_number(parsed):
        raise InvalidSeed("Phone number has an impossible digit count.")
    if not phonenumbers.is_valid_number(parsed):
        raise InvalidSeed("Phone number is not valid for the selected region.")
    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)


def detect_seed(
    raw: str,
    *,
    forced_kind: SeedKind | None = None,
    region: str = "SA",
) -> Seed:
    """Detect and normalize a target, or normalize using an explicit kind."""
    value = raw.strip()
    if not value:
        raise InvalidSeed("Target is empty.")

    if forced_kind is SeedKind.EMAIL:
        return Seed(SeedKind.EMAIL, normalize_email(value), value)
    if forced_kind is SeedKind.PHONE:
        return Seed(SeedKind.PHONE, normalize_phone(value, region), value)
    if forced_kind is SeedKind.USERNAME:
        return Seed(SeedKind.USERNAME, normalize_username(value), value)

    if value.startswith("@"):
        return Seed(SeedKind.USERNAME, normalize_username(value), value)
    if "@" in value and not PHONE_LOOKS_RE.fullmatch(value):
        return Seed(SeedKind.EMAIL, normalize_email(value), value)
    if PHONE_LOOKS_RE.fullmatch(value):
        try:
            return Seed(SeedKind.PHONE, normalize_phone(value, region), value)
        except InvalidSeed:
            if value.startswith("+"):
                raise
    return Seed(SeedKind.USERNAME, normalize_username(value), value)


def username_candidates(email: str, limit: int = 4) -> list[str]:
    """Derive plausible usernames from an email local-part, most likely first."""
    local = email.partition("@")[0].lower()
    local = local.split("+", 1)[0]
    candidates: list[str] = []

    def add(candidate: str) -> None:
        candidate = candidate.strip("._-")
        if (
            candidate
            and len(candidate) <= 39
            and USERNAME_RE.fullmatch(candidate)
            and candidate not in candidates
        ):
            candidates.append(candidate)

    add(local)
    add(re.sub(r"[._-]+", "", local))
    parts = [p for p in re.split(r"[._-]+", local) if p]
    if len(parts) > 1:
        add(parts[0] + parts[-1])
        add(parts[0])
        add(parts[-1])
    return candidates[:limit]
