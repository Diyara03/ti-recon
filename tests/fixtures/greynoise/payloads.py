"""Representative GreyNoise payloads for tests.

Hand-written rather than captured, so nothing here contains a real API key or
anybody's real infrastructure. Every address is in a reserved documentation
range (RFC 5737) and every identifier is obviously synthetic.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "BUSINESS_SERVICE_IP",
    "SCANNER_IP",
    "UNSEEN_IP",
    "community_payload",
    "full_context_payload",
    "quick_context_payload",
]

#: A noisy scanner: classified, tagged, with sensor detail.
SCANNER_IP = "198.51.100.7"

#: A known business service: no scanning record, a Business Services entry.
BUSINESS_SERVICE_IP = "203.0.113.53"

#: An address GreyNoise has never observed.
UNSEEN_IP = "192.0.2.99"


def full_context_payload(**overrides: Any) -> dict[str, Any]:
    """A complete ``/v3/ip/{ip}`` document for a classified scanner."""
    payload: dict[str, Any] = {
        "ip": SCANNER_IP,
        "business_service_intelligence": {
            "found": False,
        },
        "internet_scanner_intelligence": {
            "found": True,
            "classification": "malicious",
            "actor": "unknown",
            "first_seen": "2026-02-01",
            "last_seen": "2026-08-20",
            "bot": False,
            "vpn": False,
            "vpn_service": "",
            "tor": False,
            "spoofable": False,
            "link": "https://viz.greynoise.io/ip/198.51.100.7",
            "cves": ["CVE-2021-44228", "CVE-2023-1389", "not-a-cve"],
            "tags": [
                {
                    "name": "SSH Bruteforcer",
                    "category": "activity",
                    "intention": "malicious",
                    "description": "Attempts SSH authentication against many hosts.",
                },
                {"name": "Log4Shell Scanner", "category": "activity", "intention": "malicious"},
            ],
            "metadata": {
                "asn": "AS64500",
                "organization": "Example Hosting LLC",
                "source_country": "Netherlands",
                "source_country_code": "NL",
                "source_city": "Amsterdam",
                "region": "North Holland",
                "rdns": "scanner-7.node.example",
                "rdns_parent": "node.example",
                "domain": "example",
                "os": "Linux 3.11+",
                "category": "hosting",
                "datacenter": "Example DC",
                "mobile": False,
                "sensor_count": 412,
                "sensor_hits": 90_112,
                "single_destination": False,
            },
            "raw_data": {
                "scan": [
                    {"port": 22, "protocol": "TCP"},
                    {"port": 2222, "protocol": "TCP"},
                    {"port": 8080, "protocol": "TCP"},
                ],
                "web": {
                    "paths": ["/", "/.env", "/wp-login.php"],
                    "useragents": ["curl/8.5.0"],
                },
                "ja3": [{"ja3": "a" * 32, "port": 443}],
                "hassh": [{"hassh": "b" * 32, "port": 22}],
            },
        },
    }
    payload.update(overrides)
    return payload


def quick_context_payload(**overrides: Any) -> dict[str, Any]:
    """The reduced ``?quick=true`` form: found and classified, nothing else."""
    payload: dict[str, Any] = {
        "ip": SCANNER_IP,
        "business_service_intelligence": {"found": False},
        "internet_scanner_intelligence": {
            "found": True,
            "classification": "suspicious",
        },
    }
    payload.update(overrides)
    return payload


def business_service_payload(**overrides: Any) -> dict[str, Any]:
    """A full document for an address that is a known business service."""
    payload: dict[str, Any] = {
        "ip": BUSINESS_SERVICE_IP,
        "business_service_intelligence": {
            "found": True,
            "name": "Example Public Resolver",
            "category": "public_dns",
            "description": "A public recursive DNS resolver.",
            "explanation": "Commonly seen in DNS traffic; rarely worth investigating.",
            "reference": "https://example.com/resolver",
            "trust_level": "1",
            "last_updated": "2026-08-01T00:00:00Z",
        },
        "internet_scanner_intelligence": {"found": False},
    }
    payload.update(overrides)
    return payload


def community_payload(**overrides: Any) -> dict[str, Any]:
    """A ``/v3/community/{ip}`` document: flat, and much smaller."""
    payload: dict[str, Any] = {
        "ip": SCANNER_IP,
        "noise": True,
        "riot": False,
        "classification": "malicious",
        "name": "unknown",
        "link": "https://viz.greynoise.io/ip/198.51.100.7",
        "last_seen": "2026-08-20",
        "message": "Success",
    }
    payload.update(overrides)
    return payload
