"""Synthetic GTI API v3 payloads.

Minimal and hand-written rather than captured. Each builder produces the shape
GTI documents, trimmed to what TI Recon normalizes, so a fixture stays readable
and carries no licensed provider content.

The example values are RFC 5737 / RFC 3849 documentation addresses, the
``.example`` reserved TLD, and the well-known SHA-256 of the empty file.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "EMPTY_FILE_MD5",
    "EMPTY_FILE_SHA1",
    "EMPTY_FILE_SHA256",
    "assessment",
    "behaviour_summary_payload",
    "descriptor_page",
    "domain_object",
    "file_object",
    "ip_object",
    "object_page",
    "overall_quotas_payload",
    "threat_severity",
    "url_object",
]

EMPTY_FILE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
EMPTY_FILE_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
EMPTY_FILE_MD5 = "d41d8cd98f00b204e9800998ecf8427e"

#: 2026-08-01T12:00:00Z, so fixtures have stable, readable timestamps.
_T0 = 1_785_326_400


def assessment(
    verdict: str = "VERDICT_MALICIOUS",
    *,
    severity: str | None = "SEVERITY_HIGH",
    threat_score: int | None = 88,
    description: str | None = "Synthetic assessment for tests.",
    contributing_factors: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A ``gti_assessment`` block.

    GTI nests the interesting values one level down under ``value``, which is
    exactly the kind of shape a normalizer has to traverse defensively.
    """
    block: dict[str, Any] = {"verdict": {"value": verdict}}
    if severity is not None:
        block["severity"] = {"value": severity}
    if threat_score is not None:
        block["threat_score"] = {"value": threat_score}
    if description is not None:
        block["description"] = description
    block["contributing_factors"] = (
        contributing_factors
        if contributing_factors is not None
        else {
            "mandiant_association_actor": ["APT-SYNTHETIC"],
            "mandiant_association_report": True,
            "malicious_sandbox_verdict": True,
            "gti_dtm_alert": False,
        }
    )
    return block


def threat_severity(
    level: str | None = "SEVERITY_HIGH",
    *,
    description: str | None = "Severity HIGH because it was considered malware.",
    last_analysis_date: str | int | None = _T0 - 3_600,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A top-level ``threat_severity`` block.

    Distinct from ``gti_assessment.severity``: this is the graded description
    GTI derives from detections and relationships, with no verdict attached.
    ``last_analysis_date`` defaults to a string because that is the shape GTI
    documents here, unlike the integer epochs elsewhere on the object.
    """
    block: dict[str, Any] = {}
    if level is not None:
        block["threat_severity_level"] = level
    if description is not None:
        block["level_description"] = description
    if last_analysis_date is not None:
        block["last_analysis_date"] = str(last_analysis_date)
    block["threat_severity_data"] = (
        data
        if data is not None
        else {
            "popular_threat_category": "trojan",
            "num_gav_detections": 3,
            "belongs_to_bad_collection": True,
            "can_be_detonated": True,
            "type_tag": "peexe",
            "has_bad_contacted_domains": True,
            "has_bad_dropped_files": True,
            "has_bad_referring_files": False,
        }
    )
    return block


def _analysis_stats(
    malicious: int = 12,
    suspicious: int = 3,
    harmless: int = 4,
    undetected: int = 55,
) -> dict[str, int]:
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": 1,
        "failure": 0,
        "type-unsupported": 2,
    }


def file_object(
    *,
    object_id: str = EMPTY_FILE_SHA256,
    with_assessment: bool = True,
    with_stats: bool = True,
    with_threat_severity: bool = True,
    confidence: int | None = 91,
    relationships: dict[str, Any] | None = None,
    extra_attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    attributes: dict[str, Any] = {
        "md5": EMPTY_FILE_MD5,
        "sha1": EMPTY_FILE_SHA1,
        "sha256": EMPTY_FILE_SHA256,
        "size": 4096,
        "type_description": "Win32 EXE",
        "type_tag": "peexe",
        "meaningful_name": "synthetic-sample.exe",
        "reputation": -18,
        "tags": ["peexe", "persistence"],
        "first_submission_date": _T0 - 86_400 * 30,
        "last_submission_date": _T0 - 3_600,
        "last_analysis_date": _T0 - 1_800,
        "times_submitted": 7,
    }
    if with_stats:
        attributes["last_analysis_stats"] = _analysis_stats()
    if with_assessment:
        attributes["gti_assessment"] = assessment()
    if with_threat_severity:
        attributes["threat_severity"] = threat_severity()
    if confidence is not None:
        attributes["gti_confidence_score"] = confidence
    if extra_attributes:
        attributes.update(extra_attributes)
    payload: dict[str, Any] = {
        "type": "file",
        "id": object_id,
        "attributes": attributes,
    }
    if relationships:
        payload["relationships"] = relationships
    return payload


def domain_object(
    *,
    object_id: str = "evil.example",
    with_assessment: bool = True,
    verdict: str = "VERDICT_SUSPICIOUS",
    extra_attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    attributes: dict[str, Any] = {
        "reputation": -6,
        "last_analysis_stats": _analysis_stats(malicious=4, suspicious=2),
        "categories": {"synthetic-feed": "malware"},
        "registrar": "Synthetic Registrar Ltd",
        "creation_date": _T0 - 86_400 * 400,
        "last_modification_date": _T0 - 7_200,
        "tags": ["dga"],
        "gti_confidence_score": 72,
    }
    if with_assessment:
        attributes["gti_assessment"] = assessment(
            verdict, severity="SEVERITY_MEDIUM", threat_score=61
        )
    if extra_attributes:
        attributes.update(extra_attributes)
    return {"type": "domain", "id": object_id, "attributes": attributes}


def ip_object(
    *,
    object_id: str = "198.51.100.7",
    with_assessment: bool = True,
    verdict: str = "VERDICT_UNDETECTED",
    extra_attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    attributes: dict[str, Any] = {
        "asn": 64500,
        "as_owner": "Synthetic Hosting BV",
        "network": "198.51.100.0/24",
        "country": "NL",
        "continent": "EU",
        "regional_internet_registry": "RIPE NCC",
        "reputation": 0,
        "last_analysis_stats": _analysis_stats(
            malicious=0, suspicious=0, harmless=6, undetected=60
        ),
        "last_modification_date": _T0 - 900,
        "gti_confidence_score": 30,
    }
    if with_assessment:
        # No contributing factors: an undetected IP with clean statistics is
        # the realistic shape, and it keeps "context does not become malicious"
        # testable without a threat association muddying it.
        attributes["gti_assessment"] = assessment(
            verdict,
            severity="SEVERITY_NONE",
            threat_score=4,
            description=None,
            contributing_factors={},
        )
    if extra_attributes:
        attributes.update(extra_attributes)
    return {"type": "ip_address", "id": object_id, "attributes": attributes}


def url_object(
    *,
    object_id: str = "u-synthetic-url-identifier-0001",
    url: str = "https://evil.example/payload",
    with_assessment: bool = True,
    verdict: str = "VERDICT_MALICIOUS",
    extra_attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    attributes: dict[str, Any] = {
        "url": url,
        "last_final_url": f"{url}?stage=2",
        "title": "Synthetic landing page",
        "reputation": -22,
        "last_analysis_stats": _analysis_stats(malicious=17, suspicious=1),
        "first_submission_date": _T0 - 86_400 * 3,
        "last_submission_date": _T0 - 600,
        "last_analysis_date": _T0 - 600,
        "times_submitted": 3,
        "categories": {"synthetic-feed": "phishing"},
        "tags": ["phishing"],
        "gti_confidence_score": 95,
    }
    if with_assessment:
        attributes["gti_assessment"] = assessment(verdict)
    if extra_attributes:
        attributes.update(extra_attributes)
    return {"type": "url", "id": object_id, "attributes": attributes}


def descriptor_page(*items: tuple[str, str]) -> dict[str, Any]:
    """A relationship descriptor page: identity only, no attributes."""
    return {"data": [{"type": item_type, "id": item_id} for item_type, item_id in items]}


def object_page(*objects: dict[str, Any]) -> dict[str, Any]:
    """A relationship page carrying full objects."""
    return {"data": list(objects)}


def overall_quotas_payload(
    *,
    hourly_used: int = 120,
    hourly_allowed: int = 1_000,
    daily_used: int = 4_500,
    daily_allowed: int = 20_000,
    monthly_used: int = 51_000,
    monthly_allowed: int = 500_000,
) -> dict[str, Any]:
    """The ``/users/{apikey}/overall_quotas`` response shape."""
    return {
        "data": {
            "api_requests_hourly": {"user": {"used": hourly_used, "allowed": hourly_allowed}},
            "api_requests_daily": {"user": {"used": daily_used, "allowed": daily_allowed}},
            "api_requests_monthly": {"user": {"used": monthly_used, "allowed": monthly_allowed}},
            "intelligence_searches_monthly": {"user": {"used": 3, "allowed": 300}},
        }
    }


def behaviour_summary_payload(
    *,
    domains: tuple[str, ...] = ("c2.evil.example", "beacon.evil.example"),
    ips: tuple[str, ...] = ("198.51.100.9",),
    urls: tuple[str, ...] = ("http://c2.evil.example/gate",),
    dropped: tuple[str, ...] = (EMPTY_FILE_SHA256,),
) -> dict[str, Any]:
    """A trimmed ``behaviour_summary`` response."""
    return {
        "data": {
            "dns_lookups": [{"hostname": name} for name in domains],
            "ip_traffic": [{"destination_ip": address, "destination_port": 443} for address in ips],
            "http_conversations": [{"url": target} for target in urls],
            "files_dropped": [{"sha256": digest, "path": "C:\\Temp\\x.tmp"} for digest in dropped],
            "tags": ["persistence", "network"],
            "verdicts": ["MALWARE"],
            "calls_highlighted": ["RegSetValueExW"],
        }
    }
