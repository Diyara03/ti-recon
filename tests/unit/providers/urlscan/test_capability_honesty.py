"""urlscan advertises only what a stored scan can honestly answer (Task 24, US-02).

A Search API hit is a historical scan record. The page's address, network,
server and certificate are what a browser saw at ``task.time`` -- at DEEP,
possibly years ago -- and nothing in the integration establishes that any of
it is observable now. That is ``HISTORICAL_INFRASTRUCTURE``, which stays
declared. ``CURRENT_INFRASTRUCTURE`` is not declared any more, so a scan-time
snapshot can no longer close a goal that a provider observing the present
would answer. No freshness threshold was added to keep it.
"""

from __future__ import annotations

from fixtures.reasoning import urlscan_scan_envelope
from ti_recon.enums import IntelObjectType, InvestigationDepth, ProviderCapability
from ti_recon.providers import ProviderRegistry
from ti_recon.providers.catalog import build_default_adapters
from ti_recon.providers.urlscan import (
    URLSCAN_CAPABILITIES,
    build_urlscan_descriptor,
    build_urlscan_planning_profile,
)
from ti_recon.providers.urlscan.descriptor import URLSCAN_UNDECLARED_CAPABILITIES
from ti_recon.providers.urlscan.qualification import qualify
from ti_recon.reasoning.extraction import QualificationContext
from ti_recon.reasoning.models import TemporalFactKind

CURRENT = ProviderCapability.CURRENT_INFRASTRUCTURE
HISTORICAL = ProviderCapability.HISTORICAL_INFRASTRUCTURE


def test_current_infrastructure_is_deliberately_undeclared() -> None:
    assert URLSCAN_UNDECLARED_CAPABILITIES == {CURRENT}
    assert CURRENT not in URLSCAN_CAPABILITIES
    assert CURRENT not in build_urlscan_descriptor().capabilities
    assert CURRENT not in build_urlscan_planning_profile().planning_capabilities


def test_historical_infrastructure_stays_declared_for_every_supported_type() -> None:
    descriptor = build_urlscan_descriptor()
    assert HISTORICAL in descriptor.capabilities
    for object_type in descriptor.supported_object_types:
        assert descriptor.supports(object_type, HISTORICAL)
        assert not descriptor.supports(object_type, CURRENT)


def test_the_registry_no_longer_offers_urlscan_for_current_infrastructure() -> None:
    registry = ProviderRegistry(build_default_adapters())
    for object_type in (
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.IPV6_ADDR,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.URL,
        IntelObjectType.FILE,
    ):
        current = {a.descriptor.provider_id for a in registry.find_compatible(object_type, CURRENT)}
        historical = {
            a.descriptor.provider_id for a in registry.find_compatible(object_type, HISTORICAL)
        }
        assert "urlscan" not in current
        assert "urlscan" in historical


def test_a_scan_answers_historically_with_its_own_instant() -> None:
    """What urlscan says about hosting carries the scan instant and nothing
    that claims the present: the qualification is SCANNED_AT, never a current
    observation."""
    envelope = urlscan_scan_envelope()
    context = QualificationContext.build(objects=envelope.objects)
    result = qualify(envelope, context)
    kinds = {fact.kind for fact in result.temporal_facts}
    assert TemporalFactKind.SCANNED_AT in kinds
    assert TemporalFactKind.LAST_OBSERVED not in kinds
    for record in envelope.evidence:
        if record.claim_type in {"urlscan_page_context", "urlscan_scan_observation"}:
            assert record.observed_at is not None


def test_the_profile_is_otherwise_unchanged() -> None:
    profile = build_urlscan_planning_profile()
    assert profile.minimum_depth is InvestigationDepth.QUICK
    assert profile.capability_invariant_response is False
    assert profile.elevated_cost_capabilities == {ProviderCapability.WEB_FORENSICS}
