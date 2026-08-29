"""Context scope, graph interactions and sandbox quality (Task 15).

The warninglist cases run against the **shipped snapshot** rather than a
synthetic one. Task 15's slug mapping is a claim about that exact dataset, so a
test that invented ``public-dns-v4`` would keep passing after a refresh dropped
it — the whole point of pinning the mapping is that a rename fails loudly.

Every test here checks a boundary that, crossed, would turn context into a
verdict: host scope not clearing an exact URL, a public resolver not making a
sample benign, a scanner range not making an alert false, a sandbox's silence
not becoming a clean bill of health.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import pytest

from fixtures.reasoning import (
    AS_OF,
    file_object,
    observable,
    sandbox_envelope,
    urlhaus_url_envelope,
)
from ti_recon.correlation import (
    CorrelationEngine,
    InvestigationGraph,
    RelationBasis,
)
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    MatchScope,
    ProviderCapability,
    ProviderOperation,
    ProviderRunStatus,
    RelationshipType,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers import ProviderRequest
from ti_recon.providers.misp_warninglists import (
    DEFAULT_SNAPSHOT_ROOT,
    MispWarningListsAdapter,
)
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning import (
    WARNINGLIST_SIGNAL_MAP,
    ContextSignalType,
    InterpretationCueType,
    SignalOrigin,
    TemporalContextEngine,
    signal_for_warninglist,
)
from ti_recon.reasoning.results import TemporalContextResult

pytestmark = pytest.mark.skipif(
    not (DEFAULT_SNAPSHOT_ROOT / "manifest.json").is_file(),
    reason="no shipped warninglist snapshot in this checkout",
)

#: Real values, verified present in the shipped snapshot.
PUBLIC_RESOLVER = "8.8.8.8"
CENSYS_SCANNER = "162.142.125.1"
PRIVATE_ADDRESS = "10.0.0.5"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
POPULAR_HOST = "github.com"


@pytest.fixture(scope="module")
def warninglists() -> MispWarningListsAdapter:
    """One adapter for the module: the shipped dataset loads once."""
    return MispWarningListsAdapter()


def warninglist_envelope(
    adapter: MispWarningListsAdapter, subject: str | IntelObject
) -> ProviderResultEnvelope:
    """One real warninglist lookup against the shipped snapshot.

    Synchronous on purpose: several tests need a warninglist result *and* an
    envelope from another provider builder, and an ``async def`` test cannot run
    the latter's own event loop.
    """
    target = observable(subject) if isinstance(subject, str) else subject
    return asyncio.run(
        adapter.lookup(
            ProviderRequest(
                investigation_id="inv-1",
                intel_object=target,
                operation=ProviderOperation.LOOKUP,
                requested_capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
            ),
            None,
        )
    )


def qualify(*envelopes: ProviderResultEnvelope, **kwargs: object) -> TemporalContextResult:
    return TemporalContextEngine().evaluate(as_of=AS_OF, results=envelopes, **kwargs)  # type: ignore[arg-type]


def slugs_for(result: TemporalContextResult, signal: ContextSignalType) -> set[str]:
    return {item.source_key for item in result.signals_of(signal) if item.source_key is not None}


# --------------------------------------------------------------------------- #
# The mapping is about the dataset that actually ships
# --------------------------------------------------------------------------- #


def test_every_mapped_slug_exists_in_the_shipped_snapshot() -> None:
    """A refresh that renames or drops a mapped list must fail here.

    The mapping is a claim about this exact corpus. Left unchecked, a rename
    would silently downgrade a categorized signal to a generic one, and nothing
    would say so.
    """
    manifest = json.loads((DEFAULT_SNAPSHOT_ROOT / "manifest.json").read_text(encoding="utf-8"))
    shipped = {entry["slug"] for entry in manifest["lists"]}
    assert set(WARNINGLIST_SIGNAL_MAP) <= shipped


def test_an_unmapped_list_is_still_a_warninglist_match_and_never_a_guess() -> None:
    """No substring rule, no prefix rule, no regex: a slug either is a key or it
    is not, and a list TI Recon has not classified is reported as one."""
    assert signal_for_warninglist("sinkholes") is ContextSignalType.WARNINGLIST_MATCH
    assert signal_for_warninglist("ti-falsepositives") is ContextSignalType.WARNINGLIST_MATCH
    # "censys-scanning" is mapped; a name merely containing "scanning" is not.
    assert signal_for_warninglist("censys-scanning") is ContextSignalType.KNOWN_SCANNER
    assert signal_for_warninglist("something-scanning-else") is (
        ContextSignalType.WARNINGLIST_MATCH
    )


def test_the_mapping_can_never_express_safety() -> None:
    """Structural: there is no category to reach for, in either direction."""
    values = {item.value for item in ContextSignalType}
    assert not [item for item in values if "safe" in item or "trust" in item]
    assert not [item for item in values if "benign" in item or "allow" in item]


# --------------------------------------------------------------------------- #
# Warninglist categories, against real data
# --------------------------------------------------------------------------- #


def test_a_public_resolver_address_is_categorized_from_the_real_snapshot(
    warninglists: MispWarningListsAdapter,
) -> None:
    result = qualify(warninglist_envelope(warninglists, PUBLIC_RESOLVER))
    assert "public-dns-v4" in slugs_for(result, ContextSignalType.PUBLIC_RESOLVER)
    # The category is TI Recon's judgement about a match the provider made, and
    # the signal says so rather than pretending MISP supplied the category.
    assert all(
        item.origin is SignalOrigin.ENGINE_POLICY
        for item in result.signals_of(ContextSignalType.PUBLIC_RESOLVER)
    )


def test_a_scanner_range_raises_a_scanner_cue_and_no_verdict(
    warninglists: MispWarningListsAdapter,
) -> None:
    """ "Observed traffic may be consistent with known internet scanning" — not
    "the alert is false", not "the traffic is safe", and not "this host cannot
    itself be compromised"."""
    result = qualify(warninglist_envelope(warninglists, CENSYS_SCANNER))

    assert "censys-scanning" in slugs_for(result, ContextSignalType.KNOWN_SCANNER)
    cues = result.cues_of(InterpretationCueType.KNOWN_SCANNER_MAY_EXPLAIN_ACTIVITY)
    assert cues
    assert _no_conclusion(result)


def test_private_and_special_use_ranges_are_categorized(
    warninglists: MispWarningListsAdapter,
) -> None:
    result = qualify(warninglist_envelope(warninglists, PRIVATE_ADDRESS))
    assert "rfc1918" in slugs_for(result, ContextSignalType.PRIVATE_OR_SPECIAL_USE)


def test_the_eicar_hash_is_a_test_artifact_rather_than_an_ordinary_file(
    warninglists: MispWarningListsAdapter,
) -> None:
    """A test artifact is not a benign file: it is a file that means somebody was
    testing, which is a different thing to tell an analyst."""
    result = qualify(warninglist_envelope(warninglists, file_object(md5=EICAR_MD5)))
    assert "eicar.com" in slugs_for(result, ContextSignalType.TEST_ARTIFACT)
    assert result.cues_of(InterpretationCueType.TEST_ARTIFACT_CONTEXT)
    assert _no_conclusion(result)


def test_the_empty_file_digest_is_an_empty_artifact(
    warninglists: MispWarningListsAdapter,
) -> None:
    result = qualify(warninglist_envelope(warninglists, file_object(md5=EMPTY_MD5)))
    assert "empty-hashes" in slugs_for(result, ContextSignalType.EMPTY_ARTIFACT)
    assert result.cues_of(InterpretationCueType.EMPTY_ARTIFACT_CONTEXT)


# --------------------------------------------------------------------------- #
# Scope: a host is not a URL
# --------------------------------------------------------------------------- #


def test_host_level_context_never_clears_the_exact_url(
    warninglists: MispWarningListsAdapter,
) -> None:
    """``https://github.com/attacker/payload.exe`` matching a popular-domain list
    is a fact about ``github.com``.

    Letting it speak for the URL is how every living-off-trusted-sites payload
    gets waved through, so the signal is scoped to the host, flagged
    ``host_component_only``, and paired with a cue that says so out loud.
    """
    url = f"https://{POPULAR_HOST}/attacker/payload.exe"
    result = qualify(warninglist_envelope(warninglists, url))

    popular = result.signals_of(ContextSignalType.POPULAR_OR_COMMON_SERVICE)
    assert popular
    assert all(item.host_component_only for item in popular)
    assert all(item.match_scope is MatchScope.SAME_HOST for item in popular)
    # Never claimed about the artifact itself.
    assert not [item for item in popular if item.match_scope is MatchScope.EXACT_OBSERVABLE]

    assert result.signals_of(ContextSignalType.HOST_COMPONENT_CONTEXT)
    cues = result.cues_of(InterpretationCueType.HOST_CONTEXT_DOES_NOT_CLEAR_EXACT_URL)
    assert cues
    assert all(item.match_scope is MatchScope.SAME_HOST for item in cues)


def test_a_bare_popular_domain_is_exact_scope_not_host_component(
    warninglists: MispWarningListsAdapter,
) -> None:
    """The counterweight: when the observable *is* the host, the context is
    about the observable, and no scope cue is raised."""
    result = qualify(warninglist_envelope(warninglists, POPULAR_HOST))
    popular = result.signals_of(ContextSignalType.POPULAR_OR_COMMON_SERVICE)
    assert popular
    assert not any(item.host_component_only for item in popular)
    assert not result.cues_of(InterpretationCueType.HOST_CONTEXT_DOES_NOT_CLEAR_EXACT_URL)


def test_a_malicious_url_keeps_its_direction_beside_host_level_context(
    warninglists: MispWarningListsAdapter,
) -> None:
    """The full Task 15 example: a confirmed malicious URL, its host in a
    common-infrastructure list, and nothing cancelling anything."""
    malicious = urlhaus_url_envelope()
    record = next(item for item in malicious.evidence if item.claim_type == "urlhaus_malware_url")
    context = warninglist_envelope(warninglists, f"https://{POPULAR_HOST}/attacker/payload.exe")

    result = qualify(malicious, context)

    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert result.cues_of(InterpretationCueType.HISTORICAL_MALICIOUS_CURRENTLY_INACTIVE)
    assert result.cues_of(InterpretationCueType.HOST_CONTEXT_DOES_NOT_CLEAR_EXACT_URL)
    assert _no_conclusion(result)


# --------------------------------------------------------------------------- #
# The graph: one edge, and only one
# --------------------------------------------------------------------------- #


def test_a_sandbox_contact_with_a_public_resolver_is_explained_not_erased(
    warninglists: MispWarningListsAdapter,
) -> None:
    """A sample that resolved a name contacted a resolver. That is what programs
    do.

    The observed relationship survives untouched, the resolver gets its context,
    and an edge-scoped cue says the contact may have an ordinary explanation. No
    conclusion is drawn about the sample, and none about the resolver.
    """
    sample = file_object(sha256="c" * 64)
    resolver = observable(PUBLIC_RESOLVER)
    graph = InvestigationGraph(investigation_id="inv-1", authenticated_user_id="analyst-a")
    engine = CorrelationEngine(graph=graph)
    engine.add_root(sample)
    engine.ingest(_observed_contact(sample, resolver))

    edge = graph.edges[0]
    assert any(item.basis is RelationBasis.PROVIDER_OBSERVED for item in edge.assertions)

    result = qualify(warninglist_envelope(warninglists, resolver), graph=graph)

    cues = result.cues_of(InterpretationCueType.PUBLIC_SERVICE_MAY_EXPLAIN_CONTACT)
    assert cues
    assert cues[0].subject.key == f"{sample.canonical_key}|contacts|{resolver.canonical_key}"

    # The graph was read, never written.
    assert graph.edge_count == 1
    assert graph.edges[0] == edge
    assert _no_conclusion(result)


def test_context_does_not_travel_a_second_hop(
    warninglists: MispWarningListsAdapter,
) -> None:
    """A sample that dropped a file that contacted a public resolver gains
    nothing from the resolver.

    Transitive context is how an unremarkable-looking conclusion gets built out
    of a chain of ordinary links, so the one edge-scoped rule reads exactly one
    edge and stops. Here the dropper is two hops away and must stay untouched.
    """
    sample = file_object(sha256="d" * 64)
    dropped = file_object(sha256="e" * 64)
    resolver = observable(PUBLIC_RESOLVER)
    graph = InvestigationGraph(investigation_id="inv-1", authenticated_user_id="analyst-a")
    engine = CorrelationEngine(graph=graph)
    engine.add_root(sample)
    engine.ingest(_observed_contact(sample, dropped, RelationshipType.DROPS))
    engine.ingest(_observed_contact(dropped, resolver))
    assert graph.edge_count == 2

    result = qualify(warninglist_envelope(warninglists, resolver), graph=graph)

    subjects = {
        item.subject.key
        for item in result.cues_of(InterpretationCueType.PUBLIC_SERVICE_MAY_EXPLAIN_CONTACT)
    }
    # Only the edge that actually ends at the resolver, and only because it is a
    # contact. The dropper's own edge is not a contact and gets nothing.
    assert subjects == {f"{dropped.canonical_key}|contacts|{resolver.canonical_key}"}
    assert f"{sample.canonical_key}|drops|{dropped.canonical_key}" not in subjects

    # And no signal was copied onto either file. Context stays where it was said.
    signalled = {item.subject.key for item in result.context_signals}
    assert sample.canonical_key not in signalled
    assert dropped.canonical_key not in signalled


def _observed_contact(
    source: IntelObject,
    target: IntelObject,
    relationship: RelationshipType = RelationshipType.CONTACTS,
) -> ProviderResultEnvelope:
    """One provider result asserting a link the provider watched happen."""
    from ti_recon.models.evidence import Evidence
    from ti_recon.models.relationship import Relationship

    evidence = Evidence(
        investigation_id="inv-1",
        subject_object_id=source.id,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="sandbox_contact",
        effect=EvidenceEffect.CONTEXT_ONLY,
        transport_provider="sandbox_x",
        origin_provider="sandbox_x",
        source_family="sandbox_x",
    )
    return ProviderResultEnvelope(
        provider="sandbox_x",
        operation=ProviderOperation.LOOKUP,
        status=ProviderRunStatus.SUCCESS,
        adapter_version="1.0.0",
        api_version="v1",
        evidence=(evidence,),
        objects=(source, target),
        relationships=(
            Relationship(
                source_object_id=source.id,
                relationship_type=relationship,
                target_object_id=target.id,
                evidence_refs=(evidence.id,),
                raw_relationship_type="contacted_hosts",
                directly_observed=True,
            ),
        ),
    )


# --------------------------------------------------------------------------- #
# Sandbox quality
# --------------------------------------------------------------------------- #


def test_a_negative_run_that_executed_nothing_is_weakly_informative() -> None:
    """The sample may have wanted a click, the wrong OS, a live C2, or have
    noticed it was being watched. "Nothing happened" and "nothing could have
    happened" must not read alike."""
    index, summary = _quiet_run(executed=False)
    result = qualify(sandbox_envelope(search=index, summaries={QUIET_REPORT_ID: summary}))

    assert result.signals_of(ContextSignalType.SANDBOX_LOW_EXECUTION)
    assert result.cues_of(InterpretationCueType.SANDBOX_NEGATIVE_LOW_INFORMATION)
    assert not result.signals_of(ContextSignalType.SANDBOX_MEANINGFUL_EXECUTION)
    assert _no_conclusion(result)


def test_a_negative_run_that_did_execute_is_the_more_informative_negative() -> None:
    """Still not a benign verdict — a better-grounded absence of findings."""
    index, summary = _quiet_run(executed=True)
    result = qualify(sandbox_envelope(search=index, summaries={QUIET_REPORT_ID: summary}))

    assert result.signals_of(ContextSignalType.SANDBOX_MEANINGFUL_EXECUTION)
    assert result.cues_of(InterpretationCueType.SANDBOX_NEGATIVE_WITH_MEANINGFUL_EXECUTION)
    assert not result.signals_of(ContextSignalType.SANDBOX_LOW_EXECUTION)
    assert _no_conclusion(result)


def test_environment_divergence_is_preserved_rather_than_averaged() -> None:
    """Malicious on one machine and quiet on another is environment-dependent
    malware describing itself. Nothing here votes, averages or cancels."""
    from fixtures.hybrid_analysis import payloads

    result = qualify(sandbox_envelope(search=payloads.search_hash_divergent()))
    assert result.signals_of(ContextSignalType.SANDBOX_DIVERGENCE)
    assert result.cues_of(InterpretationCueType.SANDBOX_ENVIRONMENT_DIVERGENCE)
    assert _no_conclusion(result)


QUIET_REPORT_ID = "job-200:120"


def _quiet_run(*, executed: bool) -> tuple[list[dict[str, object]], dict[str, object]]:
    """One completed run with a non-directional verdict and a chosen quality.

    The index and the summary have to agree on the report id: the verdict lives
    on the index record and the execution quality lives on the summary, and the
    provider's extractor joins the two. A fixture where they disagreed would
    silently produce no signal at all.
    """
    from fixtures.hybrid_analysis import payloads

    index = [
        {
            "sha256": payloads.SAMPLE_SHA256,
            "reports": [
                {
                    "report_id": QUIET_REPORT_ID,
                    "environment_id": "120",
                    "environment_description": "Windows 7 32 bit",
                    "state": "SUCCESS",
                    "verdict": "no specific threat",
                }
            ],
        }
    ]
    summary = payloads.summary_no_specific_threat(job_id=QUIET_REPORT_ID)
    if executed:
        summary["total_processes"] = 11
        summary["total_network_connections"] = 40
    return index, summary


def _no_conclusion(result: TemporalContextResult) -> bool:
    """No qualification may serialize anything that reads as a decision."""
    dumped = result.model_dump_json().lower()
    return not any(
        word in dumped
        for word in (
            "supports_benign",
            "likely_benign",
            "is_false_positive",
            "risk_score",
            "malicious_score",
        )
    )


def test_a_naive_as_of_is_refused_rather_than_guessed() -> None:
    """Assuming the local zone would shift every age by hours, invisibly."""
    with pytest.raises(ValueError, match="timezone-aware"):
        TemporalContextEngine().evaluate(as_of=datetime(2026, 8, 29, 12, 0))  # noqa: DTZ001
    assert (
        TemporalContextEngine()
        .evaluate(as_of=datetime(2026, 8, 29, 12, 0, tzinfo=UTC))
        .evaluated_at
        == AS_OF
    )
