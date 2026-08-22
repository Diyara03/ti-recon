"""Representative urlscan payloads for tests.

Hand-written rather than captured, so nothing here contains a real API key, a
real private scan, or anybody's browsing history. Every domain is in a reserved
example range and every identifier is obviously synthetic.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "SCAN_ID",
    "SECOND_SCAN_ID",
    "quotas_payload",
    "result_payload",
    "search_payload",
]

SCAN_ID = "0195f3c2-4d6e-7a8b-9c0d-1e2f3a4b5c6d"
SECOND_SCAN_ID = "0195f3c2-4d6e-7a8b-9c0d-1e2f3a4b5c70"


def result_payload(**overrides: Any) -> dict[str, Any]:
    """A completed scan of a phishing-looking page."""
    payload: dict[str, Any] = {
        "task": {
            "uuid": SCAN_ID,
            "url": "https://login.evil.example/office/",
            "domain": "login.evil.example",
            "time": "2026-08-20T10:00:00.000Z",
            "method": "api",
            "source": "api",
            "visibility": "public",
            "tags": ["phishing-hunt"],
        },
        "page": {
            "url": "https://login.evil.example/office/index.html",
            "domain": "login.evil.example",
            "ip": "198.51.100.7",
            "asn": "AS64500",
            "asnname": "EXAMPLE-AS, US",
            "country": "US",
            "city": "Ashburn",
            "server": "nginx/1.24.0",
            "mimeType": "text/html",
            "status": "200",
            "title": "Sign in to your account",
            "tlsIssuer": "R11",
            "tlsValidFrom": "2026-08-01T00:00:00.000Z",
            "tlsValidDays": 90,
            "tlsAgeDays": 19,
            "redirected": "login.evil.example",
        },
        "verdicts": {
            "overall": {
                "score": 100,
                "malicious": True,
                "categories": ["phishing"],
                "brands": [{"key": "microsoft", "name": "Microsoft"}],
            },
            "urlscan": {
                "score": 100,
                "malicious": True,
                "categories": ["phishing"],
                "brands": [{"key": "microsoft", "name": "Microsoft", "vertical": ["technology"]}],
                "tags": ["credential-harvest"],
            },
            "engines": {
                "score": 60,
                "malicious": ["GoogleSafeBrowsing", "PhishTank"],
                "benign": ["ExampleEngine"],
                "maliciousTotal": 2,
                "benignTotal": 1,
                "enginesTotal": 12,
            },
            "community": {"score": 0, "votesMalicious": 3, "votesBenign": 0, "votesTotal": 3},
        },
        "lists": {
            "domains": ["login.evil.example", "cdn.evil.example", "fonts.example.com"],
            "ips": ["198.51.100.7", "203.0.113.9"],
            "asns": ["AS64500", "AS64501"],
            "urls": [
                "https://login.evil.example/office/index.html",
                "https://cdn.evil.example/kit.js",
            ],
            "servers": ["nginx/1.24.0"],
            "hashes": ["a" * 64],
            "countries": ["US", "DE"],
        },
        "data": {
            "requests": [
                {
                    "request": {
                        "request": {"url": "https://evil.example/", "method": "GET"},
                        "redirectResponse": {"status": 302},
                    },
                    "response": {
                        "response": {
                            "url": "https://login.evil.example/office/index.html",
                            "status": 200,
                            "mimeType": "text/html",
                            "hash": "a" * 64,
                            "headers": {"set-cookie": "session=SHOULD-NOT-BE-KEPT"},
                        }
                    },
                }
            ]
        },
        "stats": {
            "uniqIPs": 2,
            "uniqCountries": 2,
            "dataLength": 120345,
            "requests": 14,
            "malicious": 1,
        },
        "meta": {
            "processors": {
                "wappa": {"data": [{"app": "Cloudflare", "confidence": [{"confidence": 100}]}]}
            }
        },
    }
    payload.update(overrides)
    return payload


def search_payload(*scan_ids: str) -> dict[str, Any]:
    """A search response listing the given scans, newest first."""
    ids = scan_ids or (SCAN_ID,)
    return {
        "results": [
            {
                "_id": scan_id,
                "task": {
                    "url": "https://login.evil.example/office/",
                    "time": f"2026-08-{20 - index:02d}T10:00:00.000Z",
                    "visibility": "public",
                },
                "page": {
                    "url": "https://login.evil.example/office/index.html",
                    "domain": "login.evil.example",
                    "ip": "198.51.100.7",
                    "asn": "AS64500",
                },
                "sort": [1755680400000 - index, scan_id],
            }
            for index, scan_id in enumerate(ids)
        ],
        "total": len(ids),
        "took": 12,
        "has_more": False,
    }


def quotas_payload() -> dict[str, Any]:
    """A quota response with room on the read actions."""
    return {
        "limits": {
            "public": {"day": {"limit": 5000, "used": 5000, "remaining": 0}},
            "private": {"day": {"limit": 1000, "used": 1000, "remaining": 0}},
            "search": {
                "day": {"limit": 1000, "used": 40, "remaining": 960, "reset": 3600},
                "minute": {"limit": 60, "used": 2, "remaining": 58},
            },
            "retrieve": {"day": {"limit": 10000, "used": 120, "remaining": 9880}},
        }
    }
