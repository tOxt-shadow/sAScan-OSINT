"""Native phone metadata and verified public search leads."""

from __future__ import annotations

from urllib.parse import quote

from sascan.models import Finding, Verdict
from sascan.modules.base import ModuleResult


def _type_label(number_type: int) -> str:
    import phonenumbers

    labels = {
        phonenumbers.PhoneNumberType.MOBILE: "Mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE: "Landline",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Landline or mobile",
        phonenumbers.PhoneNumberType.TOLL_FREE: "Toll-free",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium rate",
        phonenumbers.PhoneNumberType.SHARED_COST: "Shared cost",
        phonenumbers.PhoneNumberType.VOIP: "VoIP",
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal number",
        phonenumbers.PhoneNumberType.PAGER: "Pager",
        phonenumbers.PhoneNumberType.UAN: "UAN",
        phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
    }
    return labels.get(number_type, "Unknown")


def scan_phone(phone: str, region: str = "SA") -> ModuleResult:
    """Extract deterministic metadata from a valid E.164 number."""
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone

    result = ModuleResult()
    parsed = phonenumbers.parse(phone, region.upper() or None)
    region_code = phonenumbers.region_code_for_number(parsed) or "—"
    number_type = _type_label(phonenumbers.number_type(parsed))
    carrier_name = carrier.name_for_number(parsed, "en") or "Unknown"
    location = geocoder.description_for_number(parsed, "en") or ""
    zones = ", ".join(timezone.time_zones_for_number(parsed)) or "—"
    national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    international = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
    )
    is_valid = phonenumbers.is_valid_number(parsed)

    details = [
        f"Region: {region_code}",
        f"Line type: {number_type}",
        f"Carrier: {carrier_name}",
        f"Location: {location or '—'}",
        f"Time zone: {zones}",
        f"National format: {national}",
        f"International format: {international}",
        f"Valid: {'yes' if is_valid else 'no'}",
    ]
    metadata = {
        "e164": phone,
        "region": region_code,
        "carrier": carrier_name,
        "type": number_type,
        "location": location or "",
        "timezones": zones,
        "national": national,
        "international": international,
        "valid": is_valid,
    }
    result.findings.append(
        Finding(
            target=phone,
            platform="Phone metadata",
            kind="phone-metadata",
            verdict=Verdict.FOUND if is_valid else Verdict.UNKNOWN,
            source="native",
            category="Metadata",
            detail=" · ".join(details),
            confidence=94 if is_valid else 35,
            metadata=metadata,
        )
    )
    result.metadata.update(metadata)

    raw = phone.lstrip("+")
    search_region = (
        region_code.lower()
        if len(region_code) == 2 and region_code.isalpha()
        else (region.lower() or "us")
    )
    leads = [
        (
            "Truecaller (manual lookup)",
            f"https://www.truecaller.com/search/{search_region}/{quote(raw)}",
            "May show a name or photo; verify manually.",
        ),
        (
            "Google (manual search)",
            f"https://www.google.com/search?q=%22{quote(phone)}%22",
            "Public search for the number in indexed pages.",
        ),
        (
            "WhatsApp",
            f"https://wa.me/{quote(raw)}",
            "A WhatsApp landing page does not prove the number is active or owns the account.",
        ),
    ]
    for platform, url, note in leads:
        result.findings.append(
            Finding(
                target=phone,
                platform=platform,
                kind="lead",
                verdict=Verdict.UNKNOWN,
                url=url,
                source="native",
                category="Lookup leads",
                detail=note,
                confidence=25,
            )
        )
    result.notes.append(
        "phonenumbers provides reliable metadata, but there is no free public API "
        "that proves social accounts linked to a number."
    )
    return result
