"""Real provider envelopes for Task 15 tests.

Task 15 qualifies what the shipped adapters actually produce, so these helpers
run the **real** adapters against the existing payload fixtures rather than
hand-building evidence. A test that invented an ``Evidence`` with the fields it
hoped for would pass forever while the provider drifted underneath it; running
the normalizer means a claim type renamed in Task 10 breaks Task 15 loudly.

Everything here is offline: fake clients, in-memory credentials, a manual clock.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from pydantic import SecretStr

from fixtures.abusech import payloads as abusech_payloads
from fixtures.abusech.fake_clients import (
    ClientFactory as AbuseChClientFactory,
)
from fixtures.abusech.fake_clients import (
    FakeMalwareBazaarClient,
    FakeThreatFoxClient,
    FakeUrlhausClient,
)
from fixtures.censys import payloads as censys_payloads
from fixtures.greynoise import payloads as greynoise_payloads
from fixtures.gti import payloads as gti_payloads
from fixtures.hybrid_analysis import payloads as sandbox_payloads
from fixtures.hybrid_analysis.fake_client import ClientFactory as SandboxClientFactory
from fixtures.hybrid_analysis.fake_client import FakeHybridAnalysisClient
from fixtures.urlscan import payloads as urlscan_payloads
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
    ProviderCapability,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution.clock import ManualClock
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.censys import CensysAdapter
from ti_recon.providers.greynoise import GreyNoiseAdapter
from ti_recon.providers.gti import GTIAdapter
from ti_recon.providers.hybrid_analysis import HybridAnalysisAdapter
from ti_recon.providers.malwarebazaar import MalwareBazaarAdapter
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.providers.threatfox import ThreatFoxAdapter
from ti_recon.providers.urlhaus import UrlhausAdapter
from ti_recon.providers.urlscan import UrlscanAdapter

FAKE_KEY = "fixture-key-SHOULD-NOT-LEAK-0987654321"

#: A fixed instant every temporal test measures against. Chosen rather than
#: computed, so an assertion about age is an assertion about arithmetic.
AS_OF = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def credential(provider_id: str, group: str = "abuse_ch") -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id="analyst-a",
        provider_id=provider_id,
        credential_group=group,
        auth_type=AuthType.AUTH_KEY,
        secret=SecretStr(FAKE_KEY),
    )


def observable(value: str) -> IntelObject:
    return normalize_observable(value).intel_object


def file_object(**hashes: str) -> IntelObject:
    named = {
        {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[key]: value
        for key, value in hashes.items()
    }
    strongest = named.get("SHA-256") or named.get("SHA-1") or next(iter(named.values()))
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=strongest,
        display_value=strongest,
        properties={"hashes": named},
    )


def request_for(
    subject: IntelObject,
    *,
    capability: ProviderCapability = ProviderCapability.REPUTATION,
    depth: InvestigationDepth = InvestigationDepth.STANDARD,
) -> ProviderRequest:
    return ProviderRequest(
        investigation_id="inv-1",
        intel_object=subject,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({capability}),
        depth=depth,
    )


def _run(adapter: Any, request: ProviderRequest, material: CredentialMaterial) -> Any:
    return asyncio.run(adapter.lookup(request, material))


def urlhaus_url_envelope(
    *, subject: IntelObject | None = None, **payload_overrides: Any
) -> ProviderResultEnvelope:
    """URLhaus's real exact-URL record, normalized by the real adapter."""
    payload = abusech_payloads.urlhaus_url_result(**payload_overrides)
    adapter = UrlhausAdapter(
        client_factory=AbuseChClientFactory(FakeUrlhausClient(url_payload=payload)),
        clock=ManualClock(),
    )
    subject = observable(str(payload["url"])) if subject is None else subject
    return _run(adapter, request_for(subject), credential("urlhaus"))


def threatfox_ip_envelope(
    *, subject: IntelObject | None = None, **payload_overrides: Any
) -> ProviderResultEnvelope:
    """ThreatFox's real current-IOC record for an address."""
    payload = abusech_payloads.threatfox_ioc_result(**payload_overrides)
    adapter = ThreatFoxAdapter(
        client_factory=AbuseChClientFactory(FakeThreatFoxClient(ioc_payload=payload)),
        clock=ManualClock(),
    )
    subject = observable(abusech_payloads.SCANNER_IP) if subject is None else subject
    return _run(adapter, request_for(subject), credential("threatfox"))


def threatfox_compromised_envelope(
    *, subject: IntelObject | None = None, **payload_overrides: Any
) -> ProviderResultEnvelope:
    """ThreatFox's real record for a domain it marks compromised."""
    payload = abusech_payloads.threatfox_domain_result(**payload_overrides)
    adapter = ThreatFoxAdapter(
        client_factory=AbuseChClientFactory(FakeThreatFoxClient(ioc_payload=payload)),
        clock=ManualClock(),
    )
    subject = observable(abusech_payloads.MALICIOUS_DOMAIN) if subject is None else subject
    return _run(adapter, request_for(subject), credential("threatfox"))


def threatfox_absent_envelope() -> ProviderResultEnvelope:
    """ThreatFox answering with no current record."""
    adapter = ThreatFoxAdapter(
        client_factory=AbuseChClientFactory(
            FakeThreatFoxClient(ioc_payload=abusech_payloads.threatfox_no_result())
        ),
        clock=ManualClock(),
    )
    subject = observable(abusech_payloads.SCANNER_IP)
    return _run(adapter, request_for(subject), credential("threatfox"))


def urlhaus_payload_envelope(
    *, subject: IntelObject | None = None, **payload_overrides: Any
) -> ProviderResultEnvelope:
    """URLhaus's real payload record: which tracked URLs served this file."""
    payload = abusech_payloads.urlhaus_payload_result(**payload_overrides)
    adapter = UrlhausAdapter(
        client_factory=AbuseChClientFactory(FakeUrlhausClient(payload_payload=payload)),
        clock=ManualClock(),
    )
    subject = file_object(sha256=str(payload["sha256_hash"])) if subject is None else subject
    return _run(adapter, request_for(subject), credential("urlhaus"))


def malwarebazaar_envelope(
    *, subject: IntelObject | None = None, **payload_overrides: Any
) -> ProviderResultEnvelope:
    """MalwareBazaar's real vetted-sample record."""
    payload = abusech_payloads.malwarebazaar_found(**payload_overrides)
    adapter = MalwareBazaarAdapter(
        client_factory=AbuseChClientFactory(FakeMalwareBazaarClient(info_payload=payload)),
        clock=ManualClock(),
    )
    record = payload["data"][0]
    subject = file_object(sha256=str(record["sha256_hash"])) if subject is None else subject
    return _run(
        adapter,
        request_for(subject, capability=ProviderCapability.MALWARE_INTELLIGENCE),
        credential("malwarebazaar"),
    )


def sandbox_envelope(
    search: list[dict[str, Any]] | None = None,
    summaries: dict[str, dict[str, Any]] | None = None,
    *,
    subject: IntelObject | None = None,
    depth: InvestigationDepth = InvestigationDepth.STANDARD,
) -> ProviderResultEnvelope:
    """Hybrid Analysis's real passive report index plus bounded summaries."""
    index = sandbox_payloads.search_hash_malicious() if search is None else search
    client = FakeHybridAnalysisClient(search_payload=index, summaries=summaries)
    adapter = HybridAnalysisAdapter(client_factory=SandboxClientFactory(client))
    digest = str(index[0]["sha256"]) if index else "a" * 64
    resolved = file_object(sha256=digest) if subject is None else subject
    return _run(
        adapter,
        request_for(
            resolved,
            capability=ProviderCapability.FILE_BEHAVIOR,
            depth=depth,
        ),
        credential("hybrid_analysis", group="hybrid_analysis"),
    )


def _from_normalized(
    adapter: Any, request: ProviderRequest, payload: Any
) -> ProviderResultEnvelope:
    """Wrap an adapter's pure ``normalize`` output in the envelope Task 15 reads.

    ``normalize`` needs no client, no credential and no network, so a fixture can
    exercise the real Task 7/8 normalizers without a fake transport at all.
    """
    return ProviderResultEnvelope.from_payload(
        provider=adapter.descriptor.provider_id,
        operation=ProviderOperation.LOOKUP,
        status=ProviderRunStatus.SUCCESS,
        adapter_version=adapter.descriptor.adapter_version,
        api_version=adapter.descriptor.api_version,
        payload=adapter.normalize(request, payload),
    )


def gti_file_envelope(
    *, subject: IntelObject | None = None, **attribute_overrides: Any
) -> ProviderResultEnvelope:
    """One GTI file object, through the real Task 7 normalizer."""
    payload = gti_payloads.file_object(**attribute_overrides)
    adapter = GTIAdapter()
    subject = file_object(sha256=str(payload["id"])) if subject is None else subject
    return _from_normalized(adapter, request_for(subject), payload)


def urlscan_scan_envelope(
    scanned_at: str | None = None, *, subject: IntelObject | None = None
) -> ProviderResultEnvelope:
    """One stored urlscan result, through the real Task 8 normalizer."""
    payload = urlscan_payloads.result_payload()
    if scanned_at is not None:
        payload["task"]["time"] = scanned_at
    adapter = UrlscanAdapter()
    subject = observable(str(payload["task"]["url"])) if subject is None else subject
    return _from_normalized(
        adapter,
        request_for(subject, capability=ProviderCapability.WEB_BEHAVIOR),
        payload,
    )


def greynoise_envelope(
    payload: dict[str, Any] | None = None, *, subject: IntelObject | None = None
) -> ProviderResultEnvelope:
    """One GreyNoise context document, through the real Task 9 normalizer."""
    document = greynoise_payloads.full_context_payload() if payload is None else payload
    adapter = GreyNoiseAdapter()
    subject = observable(greynoise_payloads.SCANNER_IP) if subject is None else subject
    return _from_normalized(adapter, request_for(subject), document)


def censys_host_envelope(
    *, subject: IntelObject | None = None, **overrides: Any
) -> ProviderResultEnvelope:
    """One Censys host document, through the real Task 9 normalizer."""
    payload = censys_payloads.host_payload(**overrides)
    adapter = CensysAdapter()
    subject = observable(censys_payloads.HOST_IP) if subject is None else subject
    return _from_normalized(adapter, request_for(subject), payload)
