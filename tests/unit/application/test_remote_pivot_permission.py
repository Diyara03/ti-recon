"""Who may be told about a related observable (Task 20 correction).

Task 14 gates remote pivot enrichment on *two* switches: the mode has to be
``ENRICH`` and ``allow_remote_pivot_lookup`` has to be true. That is deliberate
— following a lead the engine found is a wider disclosure than looking up what
the analyst typed, and one flag would make the escalation invisible.

The public request exposed only the first, so `pivot_mode=ENRICH` promised
something it could not deliver: pivots were enriched through local providers
only, silently. These tests pin the second switch end to end, and pin that
turning it on changes *who may be asked* and nothing else.
"""

from __future__ import annotations

import pytest

from fixtures.investigation import claim_evidence, file_root, observable_root, spec
from fixtures.investigation.stack import InvestigationStack, ScriptedProvider
from ti_recon.application.models import AnalystInvestigationRequest, ObservableInputType
from ti_recon.application.service import InvestigationApplication
from ti_recon.correlation.policy import PivotMode
from ti_recon.enums import (
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    RelationshipType,
)
from ti_recon.reasoning.claims.models import ClaimSemantic

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
DIGEST = "a" * 64
CONTACTED = "contacted.example"


def _stack() -> InvestigationStack:
    """A sample that contacted a domain, and one remote source that answers both."""
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
            ),
            CONTACTED: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION),
        },
    )
    return InvestigationStack(providers=[provider])


async def _investigate(**overrides: object) -> tuple[InvestigationStack, object]:
    stack = _stack()
    await stack.add_credentials()
    application = InvestigationApplication(orchestrator=stack.orchestrator)
    request = AnalystInvestigationRequest(
        observable=DIGEST,
        observable_type=ObservableInputType.FILE_HASH,
        **overrides,  # type: ignore[arg-type]
    )
    # The fixture's own analyst: credential resolution is per user, so the
    # CLI's local identity would correctly find no connection here.
    report = await application.investigate(request, stack.context())
    return stack, report


def _asked_about_the_pivot(stack: InvestigationStack) -> bool:
    return CONTACTED in {value for value, _ in stack.requests_for("repo")}


# --------------------------------------------------------------------------- #
# The default discloses nothing extra
# --------------------------------------------------------------------------- #


def test_the_default_request_does_not_permit_remote_pivot_lookup() -> None:
    """Off unless asked for, which is what every existing caller relies on."""
    request = AnalystInvestigationRequest(observable="example.com")

    assert request.allow_remote_pivot_lookup is False
    assert request.pivot_mode is PivotMode.RECOMMEND


@pytest.mark.asyncio
async def test_recommend_graphs_a_related_object_without_querying_it() -> None:
    """The default: the lead is recorded and nobody is told about it."""
    stack, report = await _investigate()

    assert not _asked_about_the_pivot(stack)
    assert report.request.pivot_mode == PivotMode.RECOMMEND.value
    assert report.request.allow_remote_pivot_lookup is False
    # Recorded as a relationship, and never queried.
    assert CONTACTED in {item.canonical_value for item in report.related_observables.items}


@pytest.mark.asyncio
async def test_enrich_without_the_opt_in_reaches_no_remote_provider() -> None:
    """The gap this correction closes.

    ``ENRICH`` alone authorises the *engine* to follow a lead. It does not
    authorise telling a third party about it, so a remote source is still not
    asked — which is exactly what Task 14 always did, and what the public
    request previously failed to say.
    """
    stack, report = await _investigate(pivot_mode=PivotMode.ENRICH)

    assert not _asked_about_the_pivot(stack)
    assert report.request.pivot_mode == PivotMode.ENRICH.value
    assert report.request.allow_remote_pivot_lookup is False


@pytest.mark.asyncio
async def test_enrich_with_the_opt_in_permits_the_remote_pivot() -> None:
    """Both switches on, and the related observable is genuinely investigated.

    Task 14 still decides *whether* — the budgets, the one-hop limit and the
    privacy rules all apply — and Task 13 still decides *who*. This only
    authorises the disclosure.
    """
    stack, report = await _investigate(pivot_mode=PivotMode.ENRICH, allow_remote_pivot_lookup=True)

    assert _asked_about_the_pivot(stack)
    assert report.request.allow_remote_pivot_lookup is True
    # The pivot ran once, under Task 14's own accounting.
    assert report.related_observables.items


@pytest.mark.asyncio
async def test_the_opt_in_changes_nothing_but_who_may_be_asked() -> None:
    """Depth, budgets and the hop limit are untouched by the permission.

    A disclosure control must not quietly become a cost control: the same depth
    buys the same allowance either way.
    """
    from ti_recon.correlation.policy import MAX_AUTOMATIC_PIVOT_HOP

    local, _ = await _investigate(pivot_mode=PivotMode.ENRICH)
    remote_stack, remote_report = await _investigate(
        pivot_mode=PivotMode.ENRICH, allow_remote_pivot_lookup=True
    )

    assert remote_report.request.depth is InvestigationDepth.STANDARD
    assert MAX_AUTOMATIC_PIVOT_HOP == 1
    # Every enriched object is still at most one hop from the root.
    assert all(
        item.hop <= MAX_AUTOMATIC_PIVOT_HOP for item in remote_report.related_observables.items
    )
    del local, remote_stack


# --------------------------------------------------------------------------- #
# The combination that cannot mean anything
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("mode", [PivotMode.NONE, PivotMode.RECOMMEND])
def test_the_permission_is_refused_without_enrich(mode: PivotMode) -> None:
    """Rejected rather than ignored.

    There is no pivot enrichment for the permission to apply to, so accepting
    it silently would leave a caller believing they had authorised something
    that was never going to happen — and the next reader assuming the setting
    works.
    """
    with pytest.raises(ValueError, match="only be enabled when pivot mode"):
        AnalystInvestigationRequest(
            observable="example.com", pivot_mode=mode, allow_remote_pivot_lookup=True
        )


def test_a_request_that_omits_the_field_still_serializes_and_reloads() -> None:
    """Additive: an existing caller's payload is unchanged and still valid."""
    stored = '{"observable": "example.com"}'

    request = AnalystInvestigationRequest.model_validate_json(stored)

    assert request.allow_remote_pivot_lookup is False
    reloaded = AnalystInvestigationRequest.model_validate_json(request.model_dump_json())
    assert reloaded == request


def test_the_cli_defaults_to_no_remote_pivot_lookup() -> None:
    """An ordinary command discloses nothing about related observables."""
    from ti_recon.cli.parser import build_parser

    args = build_parser().parse_args(["investigate", "example.com"])

    assert args.allow_remote_pivot_lookup is False
    assert args.pivot_mode == PivotMode.RECOMMEND.value


def test_the_cli_refuses_the_flag_without_enrich() -> None:
    """Reported as input, before anything is asked of anybody."""
    import io

    from ti_recon.cli import run

    out, err = io.StringIO(), io.StringIO()
    code = run(
        ["investigate", "example.com", "--allow-remote-pivot-lookup"],
        stdout=out,
        stderr=err,
    )

    assert code == 2
    assert out.getvalue() == ""
    assert "pivot mode" in err.getvalue()


def test_observable_root_helper_is_available() -> None:
    """Guard for the fixture import this module relies on."""
    assert observable_root(CONTACTED).canonical_value == CONTACTED
    assert file_root(DIGEST).canonical_value == DIGEST
