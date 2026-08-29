"""Versioned engine policy for alternative-explanation reasoning (Task 16).

Three things live here, and all three are TI Recon's opinions rather than any
provider's: which rule produces which reason, what each reason does *not*
establish, and how a reason is worded for a human.

Everything is a table. A rule body decides *whether* it fires; what the finding
then means comes from data in this module, so the whole vocabulary can be read in
one place and a test can assert that every reason has a role, a dimension and a
boundary.

Why the messages live here too
------------------------------

Task 16 output will eventually be read by an analyst, and a sentence is the part
they will read first. Generating one per finding at runtime -- from a model, from
provider prose, from anything but a fixed template -- would mean the authoritative
machine-readable reason and the sentence beside it could drift, and the sentence
is the half nobody diffs. So each reason has exactly one template, filled from
structured parameters, and no rule ever reads a message back.

The scanner deferral
--------------------

There is deliberately no rule mapping :attr:`ContextSignalType.KNOWN_SCANNER` to
an alternative explanation. Scanner context could legitimately explain a
*scanning-reputation* claim, but the generic evidence model cannot say what a
claim asserts: a scanner classification and a botnet-C2 indicator are both
``CURATED_THREAT_ASSERTION`` with ``SUPPORTS_MALICIOUS``, and the only thing that
separates them is a provider-prefixed ``claim_type`` this layer may not read.
Guessing would let scanner context explain away a C2 finding because both concern
one address. So the rule emits a scoped limitation instead, and the explanation
waits for a generic claim-kind seam that does not exist yet.
"""

from __future__ import annotations

from typing import Final

from ti_recon.reasoning.false_positive.models import (
    DoesNotEstablish,
    ReasonCode,
    ReasoningDimension,
    ReasoningRole,
)
from ti_recon.reasoning.models import ContextSignalType

__all__ = [
    "EXPLAINABLE_CONTEXT_SIGNALS",
    "FALSE_POSITIVE_REASONING_POLICY_VERSION",
    "HOST_SCOPED_CONTEXT_SIGNALS",
    "REASON_BOUNDARIES",
    "REASON_SEMANTICS",
    "RULE_IDS",
    "message_for",
]

#: Version of every rule, reason and boundary in this package.
#:
#: Recorded on every finding and on the result. Without it, re-reading a stored
#: result after a rule change would silently reinterpret it, and a finding id --
#: which is derived partly from this string -- would collide with a finding that
#: meant something else.
FALSE_POSITIVE_REASONING_POLICY_VERSION: Final[str] = "1.0.0"

#: Every rule this package can run, by stable id.
#:
#: Named constants rather than inline strings so a rename is a compile-time
#: problem rather than a silently-never-matching filter in somebody's query. The
#: ``.v1`` suffix is part of the identity: a rule whose meaning changes gets a
#: new id rather than quietly producing different findings under the old one.
RULE_IDS: Final[dict[str, str]] = {
    "test_artifact": "fp.test_artifact.explains_detection.v1",
    "empty_artifact": "fp.empty_artifact.explains_reputation_detection.v1",
    "public_resolver": "fp.public_resolver.explains_contact.v1",
    "business_service": "fp.business_service.explains_connection.v1",
    "host_context": "fp.host_context.does_not_explain_exact_url.v1",
    "private_address": "fp.private_address.public_intelligence_scope_mismatch.v1",
    "known_scanner": "fp.known_scanner.claim_alignment_unavailable.v1",
    "shared_infrastructure": "fp.shared_infrastructure.limits_attribution.v1",
    "compromised_infrastructure": "fp.compromised_infrastructure.separates_owner_from_actor.v1",
    "inactive_by_source": "fp.inactive_by_source.current_activity_only.v1",
    "sandbox_low_execution": "fp.sandbox.negative_without_execution.v1",
    "sandbox_meaningful_execution": "fp.sandbox.negative_with_execution.v1",
    "sandbox_divergence": "fp.sandbox.environment_divergence.v1",
    "relayed_source": "fp.relayed_source.not_independent.v1",
    "opposing_evidence": "fp.opposing_evidence.unresolved.v1",
}

#: Reason -> the role and dimension it carries.
#:
#: Only four reasons map to :attr:`ReasoningRole.ALTERNATIVE_EXPLANATION`, and
#: that scarcity is deliberate. Everything else here is a caution about how to
#: read evidence, not a suggestion that the evidence was wrong.
REASON_SEMANTICS: Final[dict[ReasonCode, tuple[ReasoningRole, ReasoningDimension]]] = {
    ReasonCode.EXPECTED_TEST_ARTIFACT_DETECTION: (
        ReasoningRole.ALTERNATIVE_EXPLANATION,
        ReasoningDimension.OBJECT_NATURE,
    ),
    ReasonCode.EMPTY_ARTIFACT_MAY_EXPLAIN_REPUTATION_DETECTION: (
        ReasoningRole.ALTERNATIVE_EXPLANATION,
        ReasoningDimension.OBJECT_NATURE,
    ),
    ReasonCode.PUBLIC_RESOLVER_MAY_EXPLAIN_CONTACT: (
        ReasoningRole.ALTERNATIVE_EXPLANATION,
        ReasoningDimension.RELATIONSHIP_INTERPRETATION,
    ),
    ReasonCode.KNOWN_BUSINESS_SERVICE_MAY_EXPLAIN_CONNECTION: (
        ReasoningRole.ALTERNATIVE_EXPLANATION,
        ReasoningDimension.RELATIONSHIP_INTERPRETATION,
    ),
    ReasonCode.HOST_CONTEXT_DOES_NOT_EXPLAIN_EXACT_URL: (
        ReasoningRole.INTERPRETATION_LIMITATION,
        ReasoningDimension.INFRASTRUCTURE_CONTEXT,
    ),
    ReasonCode.PUBLIC_INTELLIGENCE_SCOPE_MISMATCH: (
        ReasoningRole.INTERPRETATION_LIMITATION,
        ReasoningDimension.INFRASTRUCTURE_CONTEXT,
    ),
    ReasonCode.SCANNER_CONTEXT_ALIGNMENT_NOT_ESTABLISHED: (
        ReasoningRole.INTERPRETATION_LIMITATION,
        ReasoningDimension.INFRASTRUCTURE_CONTEXT,
    ),
    ReasonCode.SHARED_INFRASTRUCTURE_LIMITS_ATTRIBUTION: (
        ReasoningRole.ATTRIBUTION_CAUTION,
        ReasoningDimension.ATTRIBUTION,
    ),
    ReasonCode.COMPROMISED_INFRASTRUCTURE_SEPARATES_OWNER_FROM_ACTOR: (
        ReasoningRole.ATTRIBUTION_CAUTION,
        ReasoningDimension.ATTRIBUTION,
    ),
    ReasonCode.CURRENT_INACTIVITY_DOES_NOT_ERASE_HISTORICAL_MALICIOUSNESS: (
        ReasoningRole.TEMPORAL_RELEVANCE,
        ReasoningDimension.CURRENT_ACTIVITY,
    ),
    ReasonCode.SANDBOX_NEGATIVE_NOT_INFORMATIVE_WITHOUT_EXECUTION: (
        ReasoningRole.ANALYSIS_QUALITY_LIMITATION,
        ReasoningDimension.ANALYSIS_QUALITY,
    ),
    ReasonCode.SANDBOX_NEGATIVE_REMAINS_NON_VERDICT: (
        ReasoningRole.ANALYSIS_QUALITY_LIMITATION,
        ReasoningDimension.ANALYSIS_QUALITY,
    ),
    ReasonCode.SANDBOX_RESULT_ENVIRONMENT_DEPENDENT: (
        ReasoningRole.ANALYSIS_QUALITY_LIMITATION,
        ReasoningDimension.ANALYSIS_QUALITY,
    ),
    ReasonCode.RELAYED_FINDINGS_NOT_INDEPENDENT: (
        ReasoningRole.SOURCE_DEPENDENCE,
        ReasoningDimension.SOURCE_INDEPENDENCE,
    ),
    ReasonCode.OPPOSING_DIRECTIONAL_EVIDENCE_UNRESOLVED: (
        ReasoningRole.UNRESOLVED_TENSION,
        ReasoningDimension.OBJECT_NATURE,
    ),
}

#: Reason -> what a finding carrying it explicitly does not prove.
#:
#: Every alternative explanation denies ``OBJECT_BENIGN``, without exception.
#: That is the single most valuable line in this module: it is the inference a
#: reader makes by default, and the one none of these findings support.
REASON_BOUNDARIES: Final[dict[ReasonCode, tuple[DoesNotEstablish, ...]]] = {
    ReasonCode.EXPECTED_TEST_ARTIFACT_DETECTION: (DoesNotEstablish.OBJECT_BENIGN,),
    ReasonCode.EMPTY_ARTIFACT_MAY_EXPLAIN_REPUTATION_DETECTION: (DoesNotEstablish.OBJECT_BENIGN,),
    ReasonCode.PUBLIC_RESOLVER_MAY_EXPLAIN_CONTACT: (
        DoesNotEstablish.OBJECT_BENIGN,
        DoesNotEstablish.INFRASTRUCTURE_SAFE,
    ),
    ReasonCode.KNOWN_BUSINESS_SERVICE_MAY_EXPLAIN_CONNECTION: (
        DoesNotEstablish.OBJECT_BENIGN,
        DoesNotEstablish.INFRASTRUCTURE_SAFE,
    ),
    ReasonCode.HOST_CONTEXT_DOES_NOT_EXPLAIN_EXACT_URL: (
        DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE,
        DoesNotEstablish.OBJECT_BENIGN,
    ),
    ReasonCode.PUBLIC_INTELLIGENCE_SCOPE_MISMATCH: (
        DoesNotEstablish.OBJECT_BENIGN,
        DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE,
    ),
    ReasonCode.SCANNER_CONTEXT_ALIGNMENT_NOT_ESTABLISHED: (
        DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE,
        DoesNotEstablish.INFRASTRUCTURE_SAFE,
    ),
    ReasonCode.SHARED_INFRASTRUCTURE_LIMITS_ATTRIBUTION: (
        DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE,
        DoesNotEstablish.INFRASTRUCTURE_SAFE,
    ),
    ReasonCode.COMPROMISED_INFRASTRUCTURE_SEPARATES_OWNER_FROM_ACTOR: (
        DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE,
        DoesNotEstablish.INFRASTRUCTURE_SAFE,
    ),
    ReasonCode.CURRENT_INACTIVITY_DOES_NOT_ERASE_HISTORICAL_MALICIOUSNESS: (
        DoesNotEstablish.HISTORICAL_EVIDENCE_FALSE,
        DoesNotEstablish.OBJECT_BENIGN,
    ),
    ReasonCode.SANDBOX_NEGATIVE_NOT_INFORMATIVE_WITHOUT_EXECUTION: (
        DoesNotEstablish.OBJECT_BENIGN,
        DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE,
    ),
    ReasonCode.SANDBOX_NEGATIVE_REMAINS_NON_VERDICT: (
        DoesNotEstablish.OBJECT_BENIGN,
        DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE,
    ),
    ReasonCode.SANDBOX_RESULT_ENVIRONMENT_DEPENDENT: (
        DoesNotEstablish.OBJECT_BENIGN,
        DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE,
    ),
    ReasonCode.RELAYED_FINDINGS_NOT_INDEPENDENT: (
        DoesNotEstablish.INDEPENDENT_CORROBORATION,
        DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE,
    ),
    ReasonCode.OPPOSING_DIRECTIONAL_EVIDENCE_UNRESOLVED: (
        DoesNotEstablish.OBJECT_BENIGN,
        DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE,
    ),
}

#: Host-level context that can never speak for an exact artifact.
#:
#: A warninglist entry for ``github.com`` is a fact about GitHub. Reading it as a
#: fact about ``https://github.com/attacker/payload.exe`` is how every
#: living-off-trusted-sites payload gets waved through, so these signals produce
#: a scope limitation and never an explanation when they arrive host-scoped.
HOST_SCOPED_CONTEXT_SIGNALS: Final[frozenset[ContextSignalType]] = frozenset(
    {
        ContextSignalType.HOST_COMPONENT_CONTEXT,
        ContextSignalType.SHARED_CLOUD_OR_CDN,
        ContextSignalType.POPULAR_OR_COMMON_SERVICE,
        ContextSignalType.BUSINESS_SERVICE,
    }
)

#: Context that can support an alternative explanation *for the object itself*,
#: and only at exact scope.
#:
#: Two members, both of which say something about what the artifact **is** rather
#: than about where it lives. Popularity, cloud ranges and business-service
#: membership are deliberately absent: they describe hosting, and hosting has
#: never been a reason a detection was wrong.
EXPLAINABLE_CONTEXT_SIGNALS: Final[dict[ContextSignalType, ReasonCode]] = {
    ContextSignalType.TEST_ARTIFACT: ReasonCode.EXPECTED_TEST_ARTIFACT_DETECTION,
    ContextSignalType.EMPTY_ARTIFACT: (ReasonCode.EMPTY_ARTIFACT_MAY_EXPLAIN_REPUTATION_DETECTION),
}

#: One fixed sentence per reason, filled from structured parameters.
#:
#: Deliberately dull and deliberately hedged. Every one of them says what the
#: finding does *not* mean, because the sentence is what an analyst reads first
#: and "may explain" without "does not mean benign" is the reading that causes
#: harm.
_MESSAGES: Final[dict[ReasonCode, str]] = {
    ReasonCode.EXPECTED_TEST_ARTIFACT_DETECTION: (
        "This file matches a known test artifact ({source_key}). A malicious "
        "classification of it is the expected behaviour of a scanner rather than "
        "an error, which may explain {explained} detection(s). It does not "
        "determine whether the object is benign."
    ),
    ReasonCode.EMPTY_ARTIFACT_MAY_EXPLAIN_REPUTATION_DETECTION: (
        "This digest identifies an empty file ({source_key}), which has no "
        "content to be malicious and accumulates reputation from everything that "
        "ever produced one. That may explain {explained} reputation detection(s). "
        "It does not determine whether the object is benign."
    ),
    ReasonCode.PUBLIC_RESOLVER_MAY_EXPLAIN_CONTACT: (
        "The contacted address is a known public DNS resolver. This may explain "
        "the connection as routine name resolution, but does not determine "
        "whether the object that made it is benign."
    ),
    ReasonCode.KNOWN_BUSINESS_SERVICE_MAY_EXPLAIN_CONNECTION: (
        "The connected address is common business-service infrastructure. This "
        "may explain the connection as ordinary service traffic. It is not an "
        "allow list and does not certify the activity as safe."
    ),
    ReasonCode.HOST_CONTEXT_DOES_NOT_EXPLAIN_EXACT_URL: (
        "Host-level context applies to the host, not to the exact artifact. It "
        "does not explain {explained} exact-scope detection(s), which remain "
        "unaccounted for."
    ),
    ReasonCode.PUBLIC_INTELLIGENCE_SCOPE_MISMATCH: (
        "This address is in a private or special-use range, so public internet "
        "intelligence does not identify the same asset inside an organisation. "
        "The {explained} claim(s) about it cannot be assumed to describe this "
        "host."
    ),
    ReasonCode.SCANNER_CONTEXT_ALIGNMENT_NOT_ESTABLISHED: (
        "This address is known scanning infrastructure. Whether that explains "
        "the {explained} claim(s) about it cannot be determined, because the "
        "evidence does not state what kind of activity each claim asserts."
    ),
    ReasonCode.SHARED_INFRASTRUCTURE_LIMITS_ATTRIBUTION: (
        "This address or host is shared infrastructure, so its operator is not "
        "necessarily the actor behind the {explained} finding(s), and blocking "
        "it broadly would affect unrelated tenants. The findings themselves are "
        "unaffected."
    ),
    ReasonCode.COMPROMISED_INFRASTRUCTURE_SEPARATES_OWNER_FROM_ACTOR: (
        "The source reports this infrastructure as compromised rather than "
        "attacker-operated. The {explained} malicious finding(s) may be entirely "
        "genuine; its owner is a victim rather than the actor."
    ),
    ReasonCode.CURRENT_INACTIVITY_DOES_NOT_ERASE_HISTORICAL_MALICIOUSNESS: (
        "The source reports this artifact as no longer active. That describes its "
        "current state; the {explained} historical finding(s) about what it did "
        "remain unchanged."
    ),
    ReasonCode.SANDBOX_NEGATIVE_NOT_INFORMATIVE_WITHOUT_EXECUTION: (
        "This sandbox run completed without observing any execution, so its "
        "absence of findings says as much about the run as about the sample and "
        "supports no conclusion in either direction."
    ),
    ReasonCode.SANDBOX_NEGATIVE_REMAINS_NON_VERDICT: (
        "This sandbox run observed execution and reported nothing malicious, "
        "which is better grounded than a run that executed nothing. It is still "
        "one environment and is not a verdict."
    ),
    ReasonCode.SANDBOX_RESULT_ENVIRONMENT_DEPENDENT: (
        "Completed sandbox runs disagreed across environments. That is how "
        "environment-dependent malware behaves; neither result cancels the other."
    ),
    ReasonCode.RELAYED_FINDINGS_NOT_INDEPENDENT: (
        "This finding reached TI Recon through {transport} but was produced by "
        "{origin}. It is real, and it is not independent corroboration of "
        "anything else from the same source."
    ),
    ReasonCode.OPPOSING_DIRECTIONAL_EVIDENCE_UNRESOLVED: (
        "Evidence about this object points in both directions: {malicious} "
        "finding(s) toward malicious and {benign} toward benign. Both are "
        "retained; resolving them is not this layer's decision."
    ),
}


def message_for(reason: ReasonCode, **parameters: object) -> str:
    """Render a reason's fixed template with structured parameters.

    Presentation only. A missing parameter yields the template's placeholder
    rather than an exception: a wording problem must never take down a run whose
    machine-readable output is already correct.
    """
    template = _MESSAGES[reason]
    try:
        return template.format(**parameters)
    except (KeyError, IndexError):  # pragma: no cover - defensive
        return template
