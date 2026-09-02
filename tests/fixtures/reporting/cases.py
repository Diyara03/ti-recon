"""Whole investigations that end in each verdict (Task 20).

Real engines throughout — Tasks 13 to 19 all run — with scripted providers on
top, so a report fixture is a projection of something the engine actually
concluded rather than a hand-written object asserting what a report should say.
A report test built on a stubbed assessment would prove only that a value can be
copied between two models.
"""

from __future__ import annotations

from fixtures.investigation import InvestigationStack, claim_evidence, file_root, spec
from fixtures.investigation.stack import FAKE_SECRET_MARKER, ScriptedProvider
from ti_recon.application.models import AnalystInvestigationRequest, ObservableInputType
from ti_recon.application.service import InvestigationApplication
from ti_recon.enums import EvidenceEffect, ProviderCapability
from ti_recon.investigation import InvestigationRequest, InvestigationResult
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reporting.builder import build_analyst_report
from ti_recon.reporting.models import AnalystInvestigationReport

FAKE_SECRET = FAKE_SECRET_MARKER

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
DIGEST = "a" * 64


def report_for(result: InvestigationResult) -> AnalystInvestigationReport:
    return build_analyst_report(result)


async def _run(providers: list[ScriptedProvider], **overrides: object) -> InvestigationResult:
    stack = InvestigationStack(providers=providers)
    await stack.add_credentials()
    request = InvestigationRequest(root=file_root(DIGEST), **overrides)  # type: ignore[arg-type]
    return await stack.orchestrator.investigate(request, stack.context())


async def malicious_report() -> tuple[InvestigationResult, AnalystInvestigationReport]:
    """A curated repository holding this exact sample."""
    repo = ScriptedProvider(
        spec("repo", family="fam_repo", capabilities=frozenset({INTELLIGENCE, REPUTATION})),
        {DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)},
    )
    result = await _run([repo])
    return result, report_for(result)


async def suspicious_report() -> tuple[InvestigationResult, AnalystInvestigationReport]:
    """One generic reputation claim: concern, short of a decisive identification."""
    reputation = ScriptedProvider(
        spec("rep", family="fam_rep", capabilities=frozenset({REPUTATION})),
        {DIGEST: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION)},
    )
    result = await _run([reputation])
    return result, report_for(result)


async def inconclusive_report() -> tuple[InvestigationResult, AnalystInvestigationReport]:
    """Everybody applicable was asked and nobody knew anything."""
    quiet = ScriptedProvider(
        spec("quiet", family="fam_quiet", capabilities=frozenset({REPUTATION, INTELLIGENCE})),
        {},
    )
    result = await _run([quiet])
    return result, report_for(result)


async def benign_report() -> tuple[InvestigationResult, AnalystInvestigationReport]:
    """One unopposed benign assertion, which readiness will want challenged."""
    benign = ScriptedProvider(
        spec("benign", family="fam_a", capabilities=frozenset({REPUTATION, INTELLIGENCE})),
        {
            DIGEST: claim_evidence(
                ClaimSemantic.BENIGN_REPUTATION, effect=EvidenceEffect.SUPPORTS_BENIGN
            )
        },
    )
    result = await _run([benign])
    return result, report_for(result)


async def unconfigured_report() -> tuple[InvestigationResult, AnalystInvestigationReport]:
    """A source that would have covered this, with no credential to reach it.

    The stack's credentials are deliberately **not** created, so Task 6 answers
    ``NOT_CONFIGURED`` — the state a remote analyst with no provider keys sees
    for every remote source. It is not a provider failure, not an authorization
    failure, and not a check that came back empty: nothing was contacted.
    """
    repo = ScriptedProvider(
        spec("repo", family="fam_repo", capabilities=frozenset({INTELLIGENCE, REPUTATION})),
        {DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)},
    )
    stack = InvestigationStack(providers=[repo])
    request = InvestigationRequest(root=file_root(DIGEST))
    result = await stack.orchestrator.investigate(request, stack.context())
    return result, report_for(result)


async def cached_report() -> tuple[InvestigationResult, AnalystInvestigationReport]:
    """The second identical investigation, answered from Task 6's cache.

    Two runs against one stack, so the second reuses the first's cached result:
    a completed check that made no new request. Both halves matter to a reader —
    the answer stands, and the source was not contacted again for it.
    """
    repo = ScriptedProvider(
        spec("repo", family="fam_repo", capabilities=frozenset({INTELLIGENCE, REPUTATION})),
        {DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)},
    )
    stack = InvestigationStack(providers=[repo])
    await stack.add_credentials()
    request = InvestigationRequest(root=file_root(DIGEST))
    await stack.orchestrator.investigate(request, stack.context())
    result = await stack.orchestrator.investigate(request, stack.context())
    return result, report_for(result)


async def conflicted_report() -> tuple[InvestigationResult, AnalystInvestigationReport]:
    """Two independent origins asserting opposite things about one proposition.

    Same subject, same semantic, same scope, opposite directions. Task 17
    preserves the disagreement rather than averaging it or picking a winner, and
    caps the confidence band by name.
    """
    adverse = ScriptedProvider(
        spec("adverse", family="fam_adverse", capabilities=frozenset({REPUTATION})),
        {DIGEST: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION)},
    )
    favourable = ScriptedProvider(
        spec("favourable", family="fam_favourable", capabilities=frozenset({REPUTATION})),
        {
            DIGEST: claim_evidence(
                ClaimSemantic.MALICIOUS_REPUTATION, effect=EvidenceEffect.SUPPORTS_BENIGN
            )
        },
    )
    result = await _run([adverse, favourable])
    return result, report_for(result)


def scripted_application(providers: list[ScriptedProvider]) -> InvestigationStack:
    """A stack whose orchestrator an application service can be built on."""
    return InvestigationStack(providers=providers)


def application_for(stack: InvestigationStack) -> InvestigationApplication:
    return InvestigationApplication(orchestrator=stack.orchestrator)


def hash_request(**overrides: object) -> AnalystInvestigationRequest:
    return AnalystInvestigationRequest(
        observable=DIGEST,
        observable_type=ObservableInputType.FILE_HASH,
        **overrides,  # type: ignore[arg-type]
    )


__all__ = [
    "DIGEST",
    "FAKE_SECRET",
    "INTELLIGENCE",
    "REPUTATION",
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
