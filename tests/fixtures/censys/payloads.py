"""Representative Censys Platform payloads for tests.

Hand-written rather than captured, so nothing here contains a real token or
anybody's real infrastructure. Every address is in a reserved documentation range
(RFC 5737), every hostname is in a reserved example domain, and every fingerprint
is obviously synthetic.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "HOST_IP",
    "LEAF_FINGERPRINT",
    "WEB_PROPERTY_HOST",
    "host_payload",
    "organization_credits_payload",
    "user_credits_payload",
    "web_property_payload",
]

HOST_IP = "198.51.100.7"
WEB_PROPERTY_HOST = "login.example.com"

#: A synthetic SHA-256 leaf fingerprint.
LEAF_FINGERPRINT = "a" * 64


def host_payload(**overrides: Any) -> dict[str, Any]:
    """A ``/v3/global/asset/host/{ip}`` document with a broad exposure."""
    resource: dict[str, Any] = {
        "ip": HOST_IP,
        "last_updated_at": "2026-08-21T04:05:06.000Z",
        "autonomous_system": {
            "asn": 64500,
            "name": "EXAMPLE-AS",
            "description": "Example Hosting LLC",
            "bgp_prefix": "198.51.100.0/24",
            "country_code": "NL",
        },
        "location": {
            "country": "Netherlands",
            "country_code": "NL",
            "city": "Amsterdam",
            "province": "North Holland",
            "continent": "Europe",
            "timezone": "Europe/Amsterdam",
            # Present in real responses and deliberately never normalized.
            "coordinates": {"latitude": 52.37, "longitude": 4.89},
            "postal_code": "1011",
        },
        "operating_system": {"vendor": "Canonical", "product": "Ubuntu", "version": "22.04"},
        "dns": {
            "names": ["login.example.com", "cdn.example.com", "not a hostname"],
            "reverse_dns": {"names": ["host-7.example.net"]},
        },
        "labels": ["remote-access", {"value": "login-page"}],
        "services": [
            {
                "port": 22,
                "transport_protocol": "TCP",
                "protocol": "SSH",
                "extended_service_name": "SSH",
                # Present in real responses and deliberately never normalized.
                "banner": "SSH-2.0-OpenSSH_8.9p1 ATTACKER-CONTROLLED-TEXT",
                "software": [{"vendor": "OpenBSD", "product": "OpenSSH", "version": "8.9p1"}],
                "labels": ["remote-access"],
            },
            {
                "port": 443,
                "transport_protocol": "TCP",
                "protocol": "HTTP",
                "extended_service_name": "HTTPS",
                "banner": "HTTP/1.1 200 OK",
                "software": [{"vendor": "F5", "product": "NGINX", "version": "1.18.0"}],
                "tls": {
                    "certificates": {
                        "leaf_data": {
                            "fingerprint_sha256": LEAF_FINGERPRINT,
                            "subject_dn": "CN=login.example.com",
                            "issuer_dn": "CN=Example CA R3, O=Example CA",
                            "names": ["login.example.com", "www.login.example.com"],
                        }
                    }
                },
                "vulnerabilities": [
                    {"cve_id": "CVE-2021-23017", "severity": "high", "cvss_score": 7.7}
                ],
            },
            {
                "port": 3389,
                "transport_protocol": "TCP",
                "protocol": "RDP",
                "banner": "RDP",
            },
        ],
    }
    resource.update(overrides)
    return {"result": {"resource": resource}}


def web_property_payload(**overrides: Any) -> dict[str, Any]:
    """A ``/v3/global/asset/webproperty/{host}:{port}`` document."""
    resource: dict[str, Any] = {
        "hostname": WEB_PROPERTY_HOST,
        "port": 443,
        "last_updated_at": "2026-08-21T04:05:06.000Z",
        "labels": ["login-page"],
        "software": [{"vendor": "F5", "product": "NGINX", "version": "1.18.0"}],
        "endpoints": [
            {
                "path": "/",
                "status_code": 200,
                "protocol": "HTTP",
                "body_hashes": ["sha256:" + "b" * 64],
                # Present in real responses and deliberately never normalized.
                "body": "<html><body>ATTACKER CONTROLLED PAGE</body></html>",
                "html_title": "Sign in",
            },
            {"path": "/admin", "status_code": 403, "protocol": "HTTP"},
        ],
        "tls": {
            "certificates": {
                "leaf_data": {
                    "fingerprint_sha256": LEAF_FINGERPRINT,
                    "subject_dn": "CN=login.example.com",
                    "issuer_dn": "CN=Example CA R3, O=Example CA",
                }
            }
        },
    }
    resource.update(overrides)
    return {"result": {"resource": resource}}


def user_credits_payload(*, remaining: int = 240, limit: int = 250) -> dict[str, Any]:
    """A ``/v3/accounts/users/credits`` document."""
    return {
        "result": {
            "credits": {
                "limit": limit,
                "used": limit - remaining,
                "remaining": remaining,
            }
        }
    }


def organization_credits_payload(*, remaining: int = 9_000) -> dict[str, Any]:
    """A ``/v3/accounts/organizations/{id}/credits`` document.

    A different shape from the user one on purpose: the parser has to find the
    counters wherever Censys put them, and a test that only ever sees one nesting
    proves nothing about that.
    """
    return {"credits": {"balance": remaining, "total": 10_000}}
