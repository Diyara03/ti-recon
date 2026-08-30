"""What the analyst contract must never say (Task 20).

The report is a projection, so the failures worth testing are the ones where a
presentation layer quietly says more than the engine did: a contacted host
becoming an indicator, a source holding nothing becoming reassurance, one
explanation covering every finding, a historical detection reading as current
activity. Each of those is a sentence an analyst would act on, and none of them
is a sentence any engine wrote.
"""

from __future__ import annotations

import json

import pytest

from fixtures.investigation import claim_evidence, file_root, spec
from fixtures.investigation.stack import InvestigationStack, ScriptedProvider
from fixtures.reporting import (
    benign_report,
    inconclusive_report,
    malicious_report,
    suspicious_report,
)
from ti_recon.correlation import PivotMode
from ti_recon.correlation.policy import PivotPolicy
from ti_recon.enums import (
    IntelObjectType,
    ProviderCapability,
    RelationshipType,
    Verdict,
)
from ti_recon.investigation import InvestigationRequest
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reporting import AnalystInvestigationReport, build_analyst_report, render_text
from ti_recon.reporting.models import ANALYST_REPORT_SCHEMA_VERSION

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
DIGEST = "a" * 64
CONTACTED = "contacted.example"


# --------------------------------------------------------------------------- #
# The four verdicts, copied and never recomputed
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "verdict"),
    [
        (malicious_report, Verdict.MALICIOUS),
        (suspicious_report, Verdict.SUSPICIOUS),
        (inconclusive_report, Verdict.INCONCLUSIVE),
        (benign_report, Verdict.LIKELY_BENIGN),
    ],
)
async def test_the_report_states_the_verdict_the_engine_reached(case, verdict) -> None:
    """Every field traceable to Task 17, including the rule that produced it.

    The rule id matters as much as the verdict: two MALICIOUS results reached by
    different arguments are different claims, and an analyst asking "why" is
    asking which rule fired.
    """
    result, report = await case()

    assert report.assessment.verdict is verdict
    assert report.assessment.verdict is result.assessment.assessment.verdict
    assert report.assessment.confidence == result.assessment.assessment.confidence.value
    assert report.assessment.verdict_rule_id == result.assessment.assessment.verdict_rule_id
    assert report.assessment.assessment_id == result.assessment.assessment.assessment_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", [malicious_report, suspicious_report, inconclusive_report, benign_report]
)
async def test_readiness_is_copied_not_reinterpreted(case) -> None:
    """A different question from the verdict, and never merged into it."""
    result, report = await case()

    assert report.readiness.status == result.readiness.readiness_status.value
    assert report.readiness.coverage_adequacy == result.readiness.coverage_adequacy.value
    assert report.readiness.continuation_state == result.readiness.continuation_state.value


@pytest.mark.asyncio
async def test_an_inconclusive_report_invents_no_cause() -> None:
    """Nothing was established, so nothing is offered as the reason.

    The temptation is to fill the basis section with whatever was collected.
    An analyst reading a populated "why" under INCONCLUSIVE would reasonably
    conclude the engine had found something.
    """
    _, report = await inconclusive_report()

    assert report.assessment_basis.items == ()
    assert report.unexplained_evidence.items == ()
    rendered = render_text(report)
    assert "No claim supported the assessment" in rendered
    # And no opposition section was invented to fill the space.
    assert "Evidence against this assessment" not in rendered


@pytest.mark.asyncio
async def test_a_benign_verdict_and_incomplete_coverage_stay_separate() -> None:
    """ "Likely benign" and "nobody independent has looked" are both true.

    Collapsing them into "safe" is the most consequential thing this layer
    could do: a benign finding is an absence, and an absence is only as good as
    the search behind it.
    """
    _, report = await benign_report()

    assert report.assessment.verdict is Verdict.LIKELY_BENIGN
    assert report.readiness.status == "needs_more_data"
    rendered = render_text(report)
    assert "LIKELY_BENIGN" in rendered
    assert "NEEDS_MORE_DATA" in rendered
    assert "safe" not in rendered.lower()


# --------------------------------------------------------------------------- #
# Task 17 owns the basis
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_basis_is_task_17s_contributions() -> None:
    """Not a provider ranking of our own.

    Every basis item corresponds to a contribution Task 17 recorded, with the
    role Task 17 gave it. Choosing "the most important source" here would be
    presentation inventing an argument the engine never made.
    """
    result, report = await malicious_report()

    contributions = {item.claim_id: item for item in result.assessment.contributions}
    assert report.assessment_basis.items
    for item in report.assessment_basis.items:
        original = contributions[item.claim_id]
        assert item.role == original.role.value
        assert item.decision_role == original.decision_role.value
        assert item.semantic == original.semantic.value


@pytest.mark.asyncio
async def test_no_score_percentage_or_provider_tally_appears() -> None:
    """No number that could be read as how-bad-is-it.

    The engine produces a verdict and a band, and nothing anywhere multiplies,
    divides or counts who agreed. A percentage in the report would reintroduce
    exactly the provider voting the lineage rules exist to prevent.
    """
    _, report = await malicious_report()
    rendered = render_text(report).lower()
    document = report.model_dump_json().lower()

    for forbidden in ("risk_score", "threat_score", "malicious_score", "probability", "%"):
        assert forbidden not in rendered, forbidden
        assert forbidden not in document, forbidden
    assert "of 1 providers" not in rendered
    assert "majority" not in rendered


@pytest.mark.asyncio
async def test_no_remediation_language_reaches_an_analyst() -> None:
    """A MALICIOUS assessment is not an instruction.

    Blocking shared or compromised infrastructure has bystanders, and closing an
    alert needs organisational context this engine does not have. Both decisions
    belong to somebody who has that context.
    """
    _, report = await malicious_report()
    rendered = render_text(report).lower()

    for verb in ("block ", "quarantine", "isolate", "close the alert", "escalate", "suppress"):
        assert verb not in rendered, verb


# --------------------------------------------------------------------------- #
# Related observables are relationships
# --------------------------------------------------------------------------- #


async def _contacting_report() -> AnalystInvestigationReport:
    """A malicious file that contacted a domain nobody has accused of anything."""
    provider = ScriptedProvider(
        spec(
            "repo",
            family="fam_repo",
            capabilities=frozenset({INTELLIGENCE, REPUTATION}),
            object_types=frozenset({IntelObjectType.FILE, IntelObjectType.DOMAIN_NAME}),
        ),
        {
            DIGEST: claim_evidence(
                ClaimSemantic.MALWARE_SAMPLE_IDENTITY,
                relations=((RelationshipType.CONTACTS, CONTACTED, "contacted"),),
            )
        },
    )
    stack = InvestigationStack(providers=[provider])
    await stack.add_credentials()
    result = await stack.orchestrator.investigate(
        InvestigationRequest(root=file_root(DIGEST)),
        stack.context(),
        pivot_policy=PivotPolicy(mode=PivotMode.RECOMMEND),
    )
    return build_analyst_report(result)


@pytest.mark.asyncio
async def test_a_contacted_object_is_not_called_malicious() -> None:
    """The single most dangerous sentence this layer could write.

    A malicious sample contacted a domain. The domain is a relationship, not a
    finding: resolvers, CDNs and shared hosts all appear this way, and rendering
    them as indicators is how an analyst ends up blocking a public resolver.
    """
    report = await _contacting_report()
    rendered = render_text(report)

    related = {item.canonical_value: item for item in report.related_observables.items}
    assert CONTACTED in related
    entry = related[CONTACTED]
    assert entry.relationship_type == RelationshipType.CONTACTS.value
    # No verdict was reached about it, and the report says so by omission.
    assert entry.assessed is False
    assert "not assessments of these objects" in rendered
    for forbidden in ("malicious ioc", "malicious infrastructure", "ioc:"):
        assert forbidden not in rendered.lower(), forbidden


@pytest.mark.asyncio
async def test_only_the_assessed_target_is_marked_assessed() -> None:
    """Task 17 votes on the root and declines to vote on anything else."""
    report = await _contacting_report()

    assessed = [item for item in report.related_observables.items if item.assessed]
    assert assessed == []
    assert report.target.canonical_key.endswith(DIGEST)


@pytest.mark.asyncio
async def test_observed_and_reported_relationships_stay_distinct() -> None:
    """Watching a connection happen is different knowledge from hearing about it.

    Task 14 corrected this deliberately; flattening it here would put the
    correction back.
    """
    report = await _contacting_report()

    bases = {item.observation_basis for item in report.related_observables.items}
    assert bases
    assert bases <= {"provider_observed", "provider_reported", "engine_derived", ""}


# --------------------------------------------------------------------------- #
# Coverage vocabulary
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_source_that_held_nothing_is_not_rendered_as_benign() -> None:
    """``NO_DATA`` is a completed check, and completion is not reassurance.

    "Nothing known about this sample" is also true of every threat nobody has
    caught yet.
    """
    _, report = await inconclusive_report()
    rendered = render_text(report).lower()

    assert "benign" not in rendered
    assert "clean" not in rendered
    assert report.assessment.verdict is Verdict.INCONCLUSIVE


@pytest.mark.asyncio
async def test_completion_and_yield_are_reported_separately() -> None:
    """Five distinct states, and none folded into another.

    ``NOT_ATTEMPTED`` is not ``NO_DATA``; ``UNATTRIBUTED`` is neither. Each says
    something different about what was searched.
    """
    result, report = await malicious_report()

    reported = {
        (item.capability, item.completion, item.information_yield) for item in report.coverage.items
    }
    expected = {
        (
            item.requirement.capability.value,
            item.completion.value,
            item.information_yield.value,
        )
        for item in result.readiness.requirement_evaluations
    }
    assert reported == expected


# --------------------------------------------------------------------------- #
# Determinism and bounds
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_same_result_always_builds_the_same_report() -> None:
    """Pure: no clock, no randomness, no environment."""
    result, first = await malicious_report()
    second = build_analyst_report(result)

    assert second == first
    assert second.model_dump_json() == first.model_dump_json()
    assert render_text(second) == render_text(first)
    assert first.report_id == second.report_id


@pytest.mark.asyncio
async def test_a_report_round_trips() -> None:
    """Stored, read back, and identical — no object identity anywhere."""
    _, report = await malicious_report()
    dumped = report.model_dump_json()

    restored = AnalystInvestigationReport.model_validate_json(dumped)

    assert restored == report
    assert restored.model_dump_json() == dumped
    assert json.loads(dumped)["schema_version"] == ANALYST_REPORT_SCHEMA_VERSION
