"""Hybrid Analysis fixtures: realistic payloads and a scriptable fake client."""

from fixtures.hybrid_analysis.fake_client import ClientFactory, FakeHybridAnalysisClient
from fixtures.hybrid_analysis.payloads import (
    EICAR_SHA256,
    SAMPLE_MD5,
    SAMPLE_SHA1,
    SAMPLE_SHA256,
    key_current,
    search_hash_divergent,
    search_hash_failed_only,
    search_hash_malicious,
    search_hash_no_reports,
    summary_hostile_text,
    summary_malicious,
    summary_no_specific_threat,
)

__all__ = [
    "EICAR_SHA256",
    "SAMPLE_MD5",
    "SAMPLE_SHA1",
    "SAMPLE_SHA256",
    "ClientFactory",
    "FakeHybridAnalysisClient",
    "key_current",
    "search_hash_divergent",
    "search_hash_failed_only",
    "search_hash_malicious",
    "search_hash_no_reports",
    "summary_hostile_text",
    "summary_malicious",
    "summary_no_specific_threat",
]
