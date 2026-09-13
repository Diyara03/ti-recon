"""What a GreyNoise answer looks like by the time an analyst reads it (Task 24).

The shipped composition -- every catalogue adapter, the real planner, the real
correlation, reasoning, fusion and readiness engines, and the Task 20 report
builder -- with the GreyNoise adapter's client replaced by a scripted fake and
one GreyNoise credential configured. Every other remote source is registered
and unconfigured, exactly as a workstation with one key looks.

These are the regressions for the three report-level findings of the live
validation of one scanner address:

* **L / M** -- the access path and the raw classification survive into the
  analyst report, as bounded ``said:`` lines on the claim (GN-FINDING-01);
* **N** -- the source check says which capabilities the one call carried, so
  ``reputation`` beside scanner evidence no longer reads as a contradiction
  (GN-FINDING-02);
* the scanner-context requirement's yield is ``directional`` where the
  scanner classification is the claim that answered it (GN-FINDING-03);
* a malicious classification from one origin is ``SUSPICIOUS``, never an
  automatic ``MALICIOUS`` (§13 rule 2) -- asserted as the current policy's
  behaviour, not tuned here;
* a Community ``404`` reaches the report as ``no_data`` with
  ``produced_evidence`` true, and the verdict is ``INCONCLUSIVE`` rather than
  anything reassuring (§11);
* no credential reaches the report, its text or its JSON (§17 O).
"""

from __future__ import annotations

import json
from typing import Any

from fixtures.greynoise import payloads
from fixtures.greynoise.fake_client import FakeGreyNoiseClient, FakeGreyNoiseClientFactory
from ti_recon.application import AnalystInvestigationRequest
from ti_recon.application.composition import build_default_application
from ti_recon.enums import (
    InvestigationDepth,
    ProviderErrorCategory,
    Verdict,
)
from ti_recon.execution import ExecutionContext
from ti_recon.execution.clock import ManualClock
from ti_recon.providers.catalog import build_default_adapters
from ti_recon.providers.errors import provider_error_for
from ti_recon.providers.greynoise import GreyNoiseAdapter
from ti_recon.providers.greynoise.claim_semantics import ACCESS_PATH_HIGHLIGHT
from ti_recon.reporting import render_text
from ti_recon.reporting.models import ANALYST_REPORT_SCHEMA_VERSION, AnalystInvestigationReport

FAKE_KEY = "greynoise-key-SHOULD-NOT-LEAK-report-0001"
USER = "analyst-report-fidelity"
FULL = FakeGreyNoiseClient.FULL
COMMUNITY = FakeGreyNoiseClient.COMMUNITY


async def investigate(
    client: FakeGreyNoiseClient,
    *,
    observable: str = payloads.SCANNER_IP,
    depth: InvestigationDepth = InvestigationDepth.STANDARD,
) -> AnalystInvestigationReport:
    """The default application with GreyNoise's transport scripted."""
    clock = ManualClock()
    adapters = [
        adapter
        for adapter in build_default_adapters()
        if adapter.descriptor.provider_id != "greynoise"
    ]
    adapters.append(
        GreyNoiseAdapter(
            client_factory=FakeGreyNoiseClientFactory(client),  # type: ignore[arg-type]
            clock=clock,
        )
    )
    application, credentials = await build_default_application(
        user_id=USER,
        adapters=adapters,
        environment={"GREYNOISE_API_KEY": FAKE_KEY},
        clock=clock,
    )
    assert credentials.configured_groups == frozenset({"greynoise"})
    return await application.investigate(
        AnalystInvestigationRequest(observable=observable, depth=depth),
        ExecutionContext(authenticated_user_id=USER, request_id="req-1"),
    )


def greynoise_check(report: AnalystInvestigationReport) -> Any:
    (item,) = [item for item in report.source_checks.items if item.provider_id == "greynoise"]
    return item


def greynoise_basis(report: AnalystInvestigationReport) -> Any:
    items = [
        item
        for section in (report.assessment_basis, report.opposing_evidence)
        for item in section.items
        if item.source_family == "greynoise"
    ]
    assert len(items) == 1, items
    return items[0]


def coverage_for(report: AnalystInvestigationReport, capability: str) -> Any:
    (item,) = [item for item in report.coverage.items if item.capability == capability]
    return item


# --------------------------------------------------------------------------- #
# The live shape: full context, malicious, one call carrying two questions
# --------------------------------------------------------------------------- #


async def test_m_the_raw_classification_and_the_scanning_fact_reach_the_report() -> None:
    report = await investigate(FakeGreyNoiseClient())
    basis = greynoise_basis(report)
    assert basis.semantic == "scanner_activity"
    assert basis.effect == "supports_malicious"
    assert "raw_classification: malicious" in basis.highlights
    assert "observed_scanning: True" in basis.highlights
    assert "known_business_service: False" in basis.highlights
    assert "actor: unknown" in basis.highlights
    assert "last_seen: 2026-08-20T00:00:00Z" in basis.highlights
    text = render_text(report)
    assert "said: raw_classification: malicious" in text
    assert "said: observed_scanning: True" in text


async def test_l_the_access_path_reaches_the_report() -> None:
    report = await investigate(FakeGreyNoiseClient())
    assert f"{ACCESS_PATH_HIGHLIGHT}: full" in greynoise_basis(report).highlights


async def test_l_a_community_answer_says_so_in_the_report() -> None:
    client = FakeGreyNoiseClient()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    report = await investigate(client)
    assert client.call_count(FULL) == 1
    assert client.call_count(COMMUNITY) == 1
    basis = greynoise_basis(report)
    assert f"{ACCESS_PATH_HIGHLIGHT}: community" in basis.highlights
    assert "raw_classification: malicious" in basis.highlights
    check = greynoise_check(report)
    assert check.status == "success"
    assert check.called_provider is True
    assert f"said: {ACCESS_PATH_HIGHLIGHT}: community" in render_text(report)


async def test_n_the_source_check_names_every_capability_the_one_call_carried() -> None:
    report = await investigate(FakeGreyNoiseClient())
    check = greynoise_check(report)
    assert check.capability in check.capabilities
    assert {"reputation", "scanner_context"} <= set(check.capabilities)
    assert check.capabilities == tuple(sorted(check.capabilities))
    # One physical call, one check: the bundle did not become several rows.
    assert (
        len([item for item in report.source_checks.items if item.provider_id == "greynoise"]) == 1
    )
    text = render_text(report)
    others = [name for name in check.capabilities if name != check.capability]
    assert f"greynoise / {check.capability} (+{', '.join(others)}): success" in text


async def test_the_scanner_context_yield_is_attributed_to_the_scanner_claim() -> None:
    report = await investigate(FakeGreyNoiseClient())
    scanner = coverage_for(report, "scanner_context")
    assert scanner.status == "satisfied"
    assert scanner.completion == "complete"
    assert scanner.information_yield == "directional"
    reputation = coverage_for(report, "reputation")
    assert reputation.information_yield == "directional"


async def test_a_malicious_classification_from_one_origin_is_suspicious_not_malicious() -> None:
    """§13 rule 2, as the current fusion policy already decides it.

    One asserted scanner classification is real, corroborative, exact-scope
    support from one origin; nothing decisive and nothing independent. The
    verdict is affirmative concern, and it is not MALICIOUS.
    """
    report = await investigate(FakeGreyNoiseClient())
    assert report.assessment.verdict is Verdict.SUSPICIOUS
    assert greynoise_basis(report).decision_role == "corroborative"


async def test_the_asn_relationship_is_provider_reported_from_the_full_document() -> None:
    """The live ASN relationship came from the full context's ``metadata.asn``."""
    report = await investigate(FakeGreyNoiseClient())
    asn = [
        item
        for item in report.related_observables.items
        if item.relationship_type == "belongs-to-asn"
    ]
    assert len(asn) == 1
    assert asn[0].canonical_value == "AS64500"
    assert asn[0].source_families == ("greynoise",)
    assert asn[0].observation_basis == "provider_reported"
    assert asn[0].assessed is False


async def test_a_community_document_carries_no_asn_relationship() -> None:
    """The Community document has no metadata block, so no ASN is invented."""
    client = FakeGreyNoiseClient()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    report = await investigate(client)
    assert not [
        item
        for item in report.related_observables.items
        if item.relationship_type == "belongs-to-asn"
    ]


# --------------------------------------------------------------------------- #
# Community 404
# --------------------------------------------------------------------------- #


async def test_a_community_404_reaches_the_report_as_no_data_and_nothing_reassuring() -> None:
    client = FakeGreyNoiseClient()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    client.fail(COMMUNITY, provider_error_for(ProviderErrorCategory.NOT_FOUND, "greynoise"))
    report = await investigate(client)
    check = greynoise_check(report)
    assert check.status == "no_data"
    assert check.error_category == ""
    # The check wrote down which door answered and that nothing was found:
    # records about the check, which is what ``produced_evidence`` counts.
    assert check.produced_evidence is True
    assert not [
        item
        for section in (report.assessment_basis, report.opposing_evidence)
        for item in section.items
        if item.source_family == "greynoise"
    ]
    assert report.assessment.verdict is Verdict.INCONCLUSIVE
    assert coverage_for(report, "scanner_context").information_yield in {"no_data", "unattributed"}
    text = render_text(report)
    assert "greynoise / " in text
    assert "no_data — checked; held nothing applicable (not evidence of safety)" in text


# --------------------------------------------------------------------------- #
# Contract and secrecy
# --------------------------------------------------------------------------- #


def test_the_schema_version_moved_with_the_added_field() -> None:
    assert ANALYST_REPORT_SCHEMA_VERSION == "1.2.0"
    schema = AnalystInvestigationReport.model_json_schema()
    check = schema["$defs"]["SourceCheckItem"]["properties"]
    assert "capabilities" in check
    assert "one call" in check["capabilities"]["description"].lower()
    assert "never directional evidence" in check["produced_evidence"]["description"]


async def test_o_no_credential_reaches_the_report_in_any_rendering() -> None:
    client = FakeGreyNoiseClient()
    client.fail(FULL, provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "greynoise"))
    report = await investigate(client)
    for rendering in (
        render_text(report),
        report.model_dump_json(),
        json.dumps(report.model_dump(mode="json")),
    ):
        assert FAKE_KEY not in rendering
        assert "SHOULD-NOT-LEAK" not in rendering
    for item in (*report.assessment_basis.items, *report.opposing_evidence.items):
        for line in item.highlights:
            assert not line.lstrip().startswith("{"), "a highlight is never raw JSON"
