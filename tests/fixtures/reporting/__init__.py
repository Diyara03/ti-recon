"""Report fixtures (Task 20)."""

from fixtures.reporting.cases import (
    DIGEST,
    FAKE_SECRET,
    application_for,
    benign_report,
    cached_report,
    conflicted_report,
    hash_request,
    inconclusive_report,
    malicious_report,
    report_for,
    scripted_application,
    suspicious_report,
    unconfigured_report,
)

__all__ = [
    "DIGEST",
    "FAKE_SECRET",
    "application_for",
    "benign_report",
    "cached_report",
    "conflicted_report",
    "hash_request",
    "inconclusive_report",
    "malicious_report",
    "report_for",
    "scripted_application",
    "suspicious_report",
    "unconfigured_report",
]
