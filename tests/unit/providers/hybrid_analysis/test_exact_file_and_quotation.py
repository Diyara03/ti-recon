"""A sandbox verdict is about the file we asked about, and it says why (Task 24).

Three defects found auditing this integration before live validation, each at
the boundary where the fact is known:

**HA-01 — a hash search answers with per-sample records.** Every report in every
record was merged into one view, so a record describing a *different* file
contributed its detonations, its verdict and possibly its identity to the file
an analyst typed. MD5 and SHA-1 collisions are practical, and a search by either
is exactly how two samples arrive in one response. Records are now re-validated
against the digests TI Recon already holds, by parsing and comparing for
equality, and a record that states a digest we know and states it differently is
dropped and counted.

**HA-02 — the detonation instant was the wall clock.** Every record carried
``observed_at = now``, and correlation copies that onto each relationship the
record supports, so hosts a sample contacted during a 2021 run were reported as
observed today. The behaviour record now carries its own run's
``analysis_start_time``; records that span several runs carry no instant at all.

**HA-03 — the claim quoted nothing.** Only ``highlights`` reach an analyst
report, so a verdict resting on this provider arrived as "a sandbox classified
this sample" with no verdict word, no environment, no family and no date. The
claim now quotes the provider's own bounded statements — and still not the
threat score or the AV count, which are not votes.

The fusion section pins what current policy permits rather than changing it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import SecretStr

import fixtures.fusion as fusion_fixtures
from fixtures.hybrid_analysis import payloads
from fixtures.hybrid_analysis.fake_client import ClientFactory, FakeHybridAnalysisClient
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
    Verdict,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers import ProviderRequest
from ti_recon.providers.errors import ProviderError, provider_error_for
from ti_recon.providers.hybrid_analysis import (
    ASSESSMENT_CLAIM_TYPE,
    BEHAVIOUR_CLAIM_TYPE,
    COVERAGE_CLAIM_TYPE,
    HYBRID_ANALYSIS_PROVIDER_ID,
    NO_REPORT_CLAIM_TYPE,
    HybridAnalysisAdapter,
)
from ti_recon.providers.hybrid_analysis.claim_semantics import (
    HIGHLIGHT_ATTRIBUTES,
    RUN_HIGHLIGHT,
)
from ti_recon.providers.hybrid_analysis.claim_semantics import translate as ha_translate
from ti_recon.providers.hybrid_analysis.models import read_search_result
from ti_recon.reasoning.claims import (
    CLAIM_SEMANTICS_POLICY_VERSION,
    ClaimAssertionStrength,
    ClaimQualification,
    ClaimSemantic,
    ClaimTranslationContext,
)
from ti_recon.reasoning.claims.models import MAX_CLAIM_HIGHLIGHTS
from ti_recon.reasoning.fusion.models import ClaimDecisionRole

FAKE_KEY = "ha-key-SHOULD-NOT-LEAK-scope-0001"
OTHER_SHA256 = "d" * 64
OTHER_MD5 = "e" * 32
DETONATED_AT = datetime(2026, 8, 2, 11, 4, 19, tzinfo=UTC)


def credential() -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id="analyst-a",
        provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
        credential_group=HYBRID_ANALYSIS_PROVIDER_ID,
        auth_type=AuthType.API_KEY,
        secret=SecretStr(FAKE_KEY),
    )


def file_object(**hashes: str) -> IntelObject:
    resolved = hashes or {"SHA-256": payloads.SAMPLE_SHA256}
    strongest = resolved.get("SHA-256") or resolved.get("SHA-1") or next(iter(resolved.values()))
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=strongest,
        display_value=strongest,
        properties={"hashes": resolved},
    )


def request_for(
    subject: IntelObject | None = None, depth: InvestigationDepth = InvestigationDepth.STANDARD
) -> ProviderRequest:
    return ProviderRequest(
        investigation_id="inv-1",
        intel_object=file_object() if subject is None else subject,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
        depth=depth,
    )


async def lookup(
    *,
    search_payload: Any | None = None,
    summary: Any | None = None,
    subject: IntelObject | None = None,
    depth: InvestigationDepth = InvestigationDepth.STANDARD,
) -> Any:
    client = FakeHybridAnalysisClient(search_payload=search_payload, default_summary=summary)
    adapter = HybridAnalysisAdapter(client_factory=ClientFactory(client))  # type: ignore[arg-type]
    return await adapter.lookup(request_for(subject, depth), credential())


def record_of(envelope: Any, claim_type: str) -> Any:
    return next((item for item in envelope.evidence if item.claim_type == claim_type), None)


def directional(envelope: Any) -> list[Any]:
    return [item for item in envelope.evidence if item.effect is not EvidenceEffect.CONTEXT_ONLY]


def claims_of(envelope: Any) -> tuple[Any, ...]:
    context = ClaimTranslationContext.build(
        objects=envelope.objects, policy_version=CLAIM_SEMANTICS_POLICY_VERSION
    )
    return ha_translate(envelope, context)


def foreign_record(sha256: str = OTHER_SHA256, verdict: str = "malicious") -> dict[str, Any]:
    """A search record describing a different sample entirely."""
    return {
        "sha256": sha256,
        "sha1": "f" * 40,
        "md5": OTHER_MD5,
        "reports": [
            {
                "report_id": "job-999:140",
                "environment_id": "140",
                "environment_description": "Windows 11 64 bit",
                "state": "SUCCESS",
                "verdict": verdict,
            }
        ],
    }


# --------------------------------------------------------------------------- #
# HA-01 -- the reports are this file's, or they are not counted
# --------------------------------------------------------------------------- #


async def test_a_record_for_another_sample_never_joins_this_samples_view() -> None:
    envelope = await lookup(search_payload=[*payloads.search_hash_malicious(), foreign_record()])

    assessment = record_of(envelope, ASSESSMENT_CLAIM_TYPE)
    assert assessment is not None
    ours = len(payloads.search_hash_malicious()[0]["reports"])
    assert assessment.attributes["report_count"] == ours, "the foreign record's run was merged in"
    coverage = record_of(envelope, COVERAGE_CLAIM_TYPE)
    assert coverage.attributes["foreign_records_discarded"] == 1


async def test_a_foreign_record_cannot_supply_the_sample_identity() -> None:
    """Even when it arrives first: identity is the file we asked about."""
    envelope = await lookup(search_payload=[foreign_record(), *payloads.search_hash_malicious()])

    coverage = record_of(envelope, COVERAGE_CLAIM_TYPE)
    assert coverage.attributes["sample_sha256"] == payloads.SAMPLE_SHA256
    for evidence in envelope.evidence:
        assert OTHER_SHA256 not in evidence.model_dump_json()


async def test_a_malicious_record_for_another_sample_leaves_this_file_undirected() -> None:
    """The collision case, stated plainly: their detonation is not our verdict."""
    quiet = {
        "sha256": payloads.SAMPLE_SHA256,
        "md5": payloads.SAMPLE_MD5,
        "reports": [
            {
                "report_id": "job-700:120",
                "environment_id": "120",
                "state": "SUCCESS",
                "verdict": "no specific threat",
            }
        ],
    }
    envelope = await lookup(
        search_payload=[quiet, foreign_record()],
        summary=payloads.summary_no_specific_threat(),
    )
    assert directional(envelope) == []


async def test_an_md5_query_refuses_a_record_whose_md5_disagrees() -> None:
    """A file known only by MD5 still re-validates what came back."""
    envelope = await lookup(
        search_payload=[
            {"md5": payloads.SAMPLE_MD5, "reports": payloads.search_hash_malicious()[0]["reports"]},
            {"md5": OTHER_MD5, "reports": foreign_record()["reports"]},
        ],
        subject=file_object(MD5=payloads.SAMPLE_MD5),
    )
    coverage = record_of(envelope, COVERAGE_CLAIM_TYPE)
    assert coverage.attributes["foreign_records_discarded"] == 1
    assert coverage.attributes["queried_hash_algorithm"] == "MD5"


async def test_a_record_stating_nothing_we_can_check_is_kept() -> None:
    """Re-validation of what the provider said, not a demand that it say it."""
    envelope = await lookup(
        search_payload=[{"reports": payloads.search_hash_malicious()[0]["reports"]}]
    )
    coverage = record_of(envelope, COVERAGE_CLAIM_TYPE)
    assert "foreign_records_discarded" not in coverage.attributes
    assert coverage.attributes["report_count"] >= 1


async def test_an_ordinary_answer_is_unaffected() -> None:
    envelope = await lookup()
    coverage = record_of(envelope, COVERAGE_CLAIM_TYPE)
    assert "foreign_records_discarded" not in coverage.attributes
    assert envelope.status is ProviderRunStatus.SUCCESS


def test_the_digest_comparison_is_equality_and_case_insensitive() -> None:
    known = {"SHA-256": payloads.SAMPLE_SHA256}
    same = read_search_result([{"sha256": payloads.SAMPLE_SHA256.upper()}], hashes=known)
    assert same.foreign_records == 0

    off_by_one = payloads.SAMPLE_SHA256[:-1] + "b"
    other = read_search_result([{"sha256": off_by_one}], hashes=known)
    assert other.foreign_records == 1
    assert other.reports == ()


def test_without_known_hashes_nothing_is_discarded() -> None:
    """The reader keeps its old behaviour for a caller that knows no digest."""
    index = read_search_result([foreign_record()])
    assert index.foreign_records == 0
    assert len(index.reports) == 1


# --------------------------------------------------------------------------- #
# HA-02 -- when the sandbox watched, not when we asked
# --------------------------------------------------------------------------- #


async def test_a_behaviour_record_is_dated_by_the_detonation() -> None:
    envelope = await lookup()
    behaviour = record_of(envelope, BEHAVIOUR_CLAIM_TYPE)
    assert behaviour is not None
    assert behaviour.observed_at == DETONATED_AT


async def test_records_spanning_several_runs_carry_no_instant() -> None:
    """The index states no analysis time, so neither do they."""
    envelope = await lookup()
    for claim_type in (ASSESSMENT_CLAIM_TYPE, COVERAGE_CLAIM_TYPE):
        record = record_of(envelope, claim_type)
        assert record is not None
        assert record.observed_at is None
        # What *is* known is when TI Recon asked.
        assert record.retrieved_at is not None


async def test_an_absent_report_invents_no_instant() -> None:
    envelope = await lookup(search_payload=payloads.search_hash_no_reports())
    record = record_of(envelope, NO_REPORT_CLAIM_TYPE)
    assert record is not None
    assert record.observed_at is None


async def test_a_watched_connection_is_dated_when_it_was_watched() -> None:
    """Correlation copies this instant onto the relationship, which is the whole
    reason a wall clock here was wrong."""
    envelope = await lookup()
    assert envelope.relationships
    by_id = {item.id: item for item in envelope.evidence}
    for relationship in envelope.relationships:
        for reference in relationship.evidence_refs:
            assert by_id[reference].observed_at == DETONATED_AT


async def test_a_run_with_no_stated_analysis_time_gets_none() -> None:
    envelope = await lookup(summary=payloads.summary_malicious(analysis_start_time=None))
    behaviour = record_of(envelope, BEHAVIOUR_CLAIM_TYPE)
    assert behaviour is not None
    assert behaviour.observed_at is None


# --------------------------------------------------------------------------- #
# HA-03 -- the claim says what the sandbox said
# --------------------------------------------------------------------------- #


async def test_the_claim_quotes_the_verdict_the_family_and_the_environments() -> None:
    envelope = await lookup(search_payload=payloads.search_hash_divergent())
    (claim,) = claims_of(envelope)

    quoted = "\n".join(claim.highlights)
    assert "sandbox_verdict: malicious" in quoted
    assert "verdicts_by_environment:" in quoted
    assert "divergent_verdicts: True" in quoted
    assert "Trojan.Dridex" in quoted


async def test_the_claim_quotes_the_run_that_was_actually_read() -> None:
    envelope = await lookup()
    (claim,) = claims_of(envelope)

    runs = [line for line in claim.highlights if line.startswith(f"{RUN_HIGHLIGHT}:")]
    assert len(runs) == 1
    assert "job-100:110" in runs[0], "the run a reader would look up"
    assert "environment=140" in runs[0]
    assert DETONATED_AT.isoformat() in runs[0]
    assert "signatures" in runs[0]


async def test_the_claim_never_quotes_a_threat_score_or_an_av_count() -> None:
    """Neither is a vote, and printing one beside a verdict invites it to be read
    as one."""
    envelope = await lookup()
    (claim,) = claims_of(envelope)

    quoted = " ".join(claim.highlights).lower()
    for forbidden in ("threat_score", "av_detect", "threat_level", "detections"):
        assert forbidden not in quoted
    # The fixture's AV count, which no line may carry.
    assert str(payloads.summary_malicious()["av_detect"]) not in quoted
    for forbidden in ("threat_score", "av_detect", "threat_level"):
        assert forbidden not in HIGHLIGHT_ATTRIBUTES


async def test_a_lookup_that_bought_no_summary_quotes_no_run() -> None:
    """QUICK reads the index alone: absent record, absent line."""
    envelope = await lookup(depth=InvestigationDepth.QUICK)
    (claim,) = claims_of(envelope)

    assert claim.highlights
    assert not [line for line in claim.highlights if line.startswith(f"{RUN_HIGHLIGHT}:")]


async def test_two_runs_are_two_distinct_lines() -> None:
    """A DEEP lookup reads two reports; one line each, each naming its run."""
    envelope = await lookup(depth=InvestigationDepth.DEEP)
    (claim,) = claims_of(envelope)

    runs = [line for line in claim.highlights if line.startswith(f"{RUN_HIGHLIGHT}:")]
    assert len(runs) == 2
    assert len(set(runs)) == 2


async def test_highlights_stay_within_their_bound() -> None:
    envelope = await lookup(search_payload=payloads.search_hash_divergent())
    (claim,) = claims_of(envelope)
    assert len(claim.highlights) <= MAX_CLAIM_HIGHLIGHTS
    for line in claim.highlights:
        assert "\n" not in line and "\r" not in line


async def test_quoting_changes_no_direction_and_no_strength() -> None:
    envelope = await lookup()
    (claim,) = claims_of(envelope)
    assert claim.semantic is ClaimSemantic.SANDBOX_CLASSIFICATION
    assert claim.strength is ClaimAssertionStrength.ASSERTED
    assert claim.effect is EvidenceEffect.SUPPORTS_MALICIOUS


# --------------------------------------------------------------------------- #
# What current fusion policy permits -- pinned, not changed
# --------------------------------------------------------------------------- #


async def test_this_sandbox_alone_corroborates_and_never_decides() -> None:
    """No provider-owned strength test exists for this sandbox, so its claim is
    ``UNQUALIFIED`` and the verdict it can reach alone is SUSPICIOUS. GTI's
    strong-direct rule is GTI's, over GTI's own documented fields."""
    root = file_object()
    envelope = await lookup(subject=root)
    result = fusion_fixtures.fuse(fusion_fixtures.scenario(root).with_envelope(envelope))

    (claim,) = [c for c in result.normalized_claims if c.source_family == "hybrid_analysis"]
    assert claim.qualification is ClaimQualification.UNQUALIFIED
    contribution = next(item for item in result.contributions if item.claim_id == claim.claim_id)
    assert contribution.decision_role is ClaimDecisionRole.CORROBORATIVE
    assert result.assessment.verdict is Verdict.SUSPICIOUS


async def test_a_hedged_verdict_is_weaker_than_an_asserted_one() -> None:
    suspicious = payloads.search_hash_malicious()
    for report in suspicious[0]["reports"]:
        report["verdict"] = "suspicious"
    envelope = await lookup(
        search_payload=suspicious, summary=payloads.summary_malicious(verdict="suspicious")
    )
    (claim,) = claims_of(envelope)
    assert claim.strength is ClaimAssertionStrength.SUSPECTED


# --------------------------------------------------------------------------- #
# Audit cases: what must never become a direction
# --------------------------------------------------------------------------- #


async def test_a_high_threat_score_with_a_quiet_verdict_creates_no_direction() -> None:
    quiet = payloads.search_hash_malicious()
    for report in quiet[0]["reports"]:
        report["verdict"] = "no specific threat"
    envelope = await lookup(
        search_payload=quiet,
        summary=payloads.summary_no_specific_threat(threat_score=100, av_detect=62),
    )
    assert directional(envelope) == []
    assert claims_of(envelope) == ()
    assessment = record_of(envelope, ASSESSMENT_CLAIM_TYPE)
    assert assessment.attributes["means_benign"] is False


async def test_informative_identifiers_never_support_malicious() -> None:
    """Technique detail lives on a context record whatever it is labelled."""
    envelope = await lookup(summary=payloads.summary_no_specific_threat())
    behaviour = record_of(envelope, BEHAVIOUR_CLAIM_TYPE)
    assert behaviour is not None
    assert behaviour.effect is EvidenceEffect.CONTEXT_ONLY


async def test_a_transient_failure_contributes_no_evidence() -> None:
    client = FakeHybridAnalysisClient()
    client.fail(
        FakeHybridAnalysisClient.SEARCH,
        provider_error_for(ProviderErrorCategory.PROVIDER_UNAVAILABLE, HYBRID_ANALYSIS_PROVIDER_ID),
    )
    adapter = HybridAnalysisAdapter(client_factory=ClientFactory(client))  # type: ignore[arg-type]

    with pytest.raises(ProviderError) as raised:
        await adapter.lookup(request_for(), credential())
    assert raised.value.category is ProviderErrorCategory.PROVIDER_UNAVAILABLE
