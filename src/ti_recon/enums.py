"""Shared TI Recon vocabularies.

Every vocabulary is a :class:`enum.StrEnum` so that serialized values are
stable, human-readable strings rather than positional integers. Object-type
values follow STIX Cyber-observable naming (``ipv4-addr``, ``domain-name``,
``file``, ...) so the model can be mapped to STIX later without a rename.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "ActivityMode",
    "AssessmentState",
    "ConflictSeverity",
    "ConflictStatus",
    "ConflictType",
    "ContributionRole",
    "CoverageRelevance",
    "CoverageStatus",
    "EvidenceClass",
    "EvidenceEffect",
    "InformationCredibilityGrade",
    "IntelObjectType",
    "InvestigationDepth",
    "InvestigationStatus",
    "MatchScope",
    "ObjectClass",
    "ProviderCapability",
    "ProviderErrorCategory",
    "ProviderOperation",
    "ProviderRunStatus",
    "RelationshipType",
    "SourceReliabilityGrade",
    "Verdict",
]


class ObjectClass(StrEnum):
    """Broad role an :class:`~ti_recon.models.intel_object.IntelObject` plays.

    ``OBSERVABLE`` covers concrete observed artifacts — what an analyst submits
    and what providers report on. The remaining classes cover objects TI Recon
    derives while enriching, which are never themselves submitted as input.
    """

    OBSERVABLE = "observable"
    INFRASTRUCTURE = "infrastructure"
    THREAT = "threat"


class IntelObjectType(StrEnum):
    """Concrete object type, using STIX-friendly serialized names.

    There are deliberately no ``md5`` / ``sha1`` / ``sha256`` object types: a
    file hash identifies a ``file`` object and is carried in that object's
    ``hashes`` property.
    """

    IPV4_ADDR = "ipv4-addr"
    IPV6_ADDR = "ipv6-addr"
    DOMAIN_NAME = "domain-name"
    URL = "url"
    FILE = "file"
    AUTONOMOUS_SYSTEM = "autonomous-system"
    X509_CERTIFICATE = "x509-certificate"
    MALWARE = "malware"


#: Object types an analyst may submit directly as an investigation input.
SUBMITTABLE_OBJECT_TYPES: frozenset[IntelObjectType] = frozenset(
    {
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.IPV6_ADDR,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.URL,
        IntelObjectType.FILE,
    }
)


class InvestigationDepth(StrEnum):
    """How much enrichment an investigation is allowed to perform."""

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class ActivityMode(StrEnum):
    """Whether an investigation may cause new interaction with the target.

    ``PASSIVE`` is the default everywhere. ``ACTIVE`` operations (submission,
    rescan, sandboxing) are a separate future path requiring explicit user
    approval and are not implemented.
    """

    PASSIVE = "passive"
    ACTIVE = "active"


class InvestigationStatus(StrEnum):
    """Lifecycle state of an investigation."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ProviderRunStatus(StrEnum):
    """Outcome of a single provider operation within an investigation.

    This is per-run and per-operation. It is not a statement about the
    provider's overall health (see ``ProviderHealth``) nor about the validity
    of the credential used (see ``CredentialStatus``).
    """

    SUCCESS = "success"
    NO_DATA = "no_data"
    NOT_CONFIGURED = "not_configured"
    NOT_SUPPORTED = "not_supported"
    PLAN_LIMITED = "plan_limited"
    QUOTA_EXCEEDED = "quota_exceeded"
    PARTIAL = "partial"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
    ERROR = "error"


class EvidenceClass(StrEnum):
    """What *kind* of claim a piece of evidence is.

    Evidence classes are not interchangeable, which is why TI Recon weighs
    evidence rather than counting providers. A curated threat assertion about
    an exact artifact and an aggregated third-party detection count carry very
    different meaning even when both point the same way.
    """

    DIRECT_OBSERVATION = "direct_observation"
    CURATED_THREAT_ASSERTION = "curated_threat_assertion"
    AGGREGATED_REPUTATION = "aggregated_reputation"
    CONTEXT = "context"
    RELATIONSHIP = "relationship"


class EvidenceEffect(StrEnum):
    """Direction a piece of evidence points, independent of its strength."""

    SUPPORTS_MALICIOUS = "supports_malicious"
    SUPPORTS_BENIGN = "supports_benign"
    CONTEXT_ONLY = "context_only"


class MatchScope(StrEnum):
    """How precisely a claim applies to the object it is attached to.

    An exact-artifact malware association and a "something in this /24 was
    bad" observation are both real evidence, but the former is specific to the
    submitted observable and the latter is not.
    """

    EXACT_OBSERVABLE = "exact_observable"
    SAME_HOST = "same_host"
    PARENT_DOMAIN = "parent_domain"
    SAME_IP = "same_ip"
    IP_NETWORK = "ip_network"
    SAME_ASN = "same_asn"
    SAME_CERTIFICATE = "same_certificate"
    CLUSTER = "cluster"
    UNKNOWN = "unknown"


class CoverageStatus(StrEnum):
    """Whether a requested intelligence capability was actually satisfied."""

    COVERED = "covered"
    PARTIAL = "partial"
    NOT_COVERED = "not_covered"
    NOT_APPLICABLE = "not_applicable"


class CoverageRelevance(StrEnum):
    """How important a capability is for the object type under investigation."""

    REQUIRED = "required"
    RELEVANT = "relevant"
    OPTIONAL = "optional"
    NOT_APPLICABLE = "not_applicable"


class Verdict(StrEnum):
    """Final investigation verdict vocabulary.

    There is deliberately no ``BENIGN``: passive external intelligence cannot
    prove the absence of malice, only support a likelihood.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    INCONCLUSIVE = "inconclusive"
    LIKELY_BENIGN = "likely_benign"


class AssessmentState(StrEnum):
    """Lifecycle/qualification state of an assessment.

    Kept separate from :class:`Verdict`: the verdict says what TI Recon thinks,
    the state says how much weight that opinion deserves.
    """

    PRELIMINARY = "preliminary"
    COMPLETE = "complete"
    INSUFFICIENT_COVERAGE = "insufficient_coverage"
    CONFLICTED = "conflicted"
    SUPERSEDED = "superseded"


class SourceReliabilityGrade(StrEnum):
    """Admiralty-code source reliability, ``A`` (best) through ``F``.

    This grades the *source* — how dependable the provider has proven to be —
    and is never merged with provider-reported confidence or with information
    credibility.

    ``A`` completely reliable, ``B`` usually reliable, ``C`` fairly reliable,
    ``D`` not usually reliable, ``E`` unreliable, ``F`` cannot be judged.
    """

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"


class InformationCredibilityGrade(StrEnum):
    """Admiralty-code information credibility, ``1`` (best) through ``6``.

    This grades the *claim*, not the source: ``1`` confirmed by other sources,
    ``2`` probably true, ``3`` possibly true, ``4`` doubtful, ``5`` improbable,
    ``6`` cannot be judged.
    """

    CONFIRMED = "1"
    PROBABLY_TRUE = "2"
    POSSIBLY_TRUE = "3"
    DOUBTFUL = "4"
    IMPROBABLE = "5"
    CANNOT_BE_JUDGED = "6"


class ProviderCapability(StrEnum):
    """An intelligence capability, independent of any vendor.

    The engine asks for a capability and the registry answers with whichever
    configured providers can serve it. No engine code names a vendor, which is
    what makes every provider optional and substitutable.

    This vocabulary lives here rather than in ``ti_recon.providers`` because the
    data model refers to it (an investigation requests capabilities, a provider
    run serves one, coverage is reported per capability); the data model must not
    depend on the provider framework.
    """

    REPUTATION = "reputation"
    MALWARE_INTELLIGENCE = "malware_intelligence"
    WEB_BEHAVIOR = "web_behavior"
    SCANNER_CONTEXT = "scanner_context"
    NETWORK_OWNERSHIP = "network_ownership"
    CURRENT_INFRASTRUCTURE = "current_infrastructure"
    HISTORICAL_INFRASTRUCTURE = "historical_infrastructure"
    CERTIFICATE_CONTEXT = "certificate_context"
    RELATIONSHIPS = "relationships"
    FALSE_POSITIVE_CONTEXT = "false_positive_context"
    # Curated attribution: which malware families, actors or campaigns a
    # provider associates with an observable. Distinct from
    # MALWARE_INTELLIGENCE, which is about the malware itself rather than the
    # association graph around it.
    THREAT_ASSOCIATIONS = "threat_associations"
    # Sandbox/dynamic-analysis observations of what a file did when run.
    FILE_BEHAVIOR = "file_behavior"
    BATCH_LOOKUP = "batch_lookup"
    ACTIVE_SCAN = "active_scan"


#: Capabilities that cause new interaction with the target and therefore
#: require ``ActivityMode.ACTIVE`` plus explicit user approval.
ACTIVE_CAPABILITIES: frozenset[ProviderCapability] = frozenset({ProviderCapability.ACTIVE_SCAN})


class ProviderOperation(StrEnum):
    """The kind of call being made against a provider."""

    LOOKUP = "lookup"
    BATCH_LOOKUP = "batch_lookup"
    PIVOT = "pivot"
    ACTIVE_ACTION = "active_action"
    VALIDATE_CREDENTIALS = "validate_credentials"
    DISCOVER_CAPABILITIES = "discover_capabilities"
    HEALTH = "health"


class ProviderErrorCategory(StrEnum):
    """Provider-neutral error categories.

    Adapters map their vendor's failure modes onto these so the engine can
    reason about failures without knowing any provider's HTTP conventions.
    """

    AUTHENTICATION_ERROR = "authentication_error"
    PERMISSION_ERROR = "permission_error"
    PLAN_LIMITED = "plan_limited"
    RATE_LIMITED = "rate_limited"
    QUOTA_EXCEEDED = "quota_exceeded"
    NOT_FOUND = "not_found"
    INVALID_REQUEST = "invalid_request"
    PARTIAL_RESULT = "partial_result"
    TRANSIENT_ERROR = "transient_error"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    SCHEMA_ERROR = "schema_error"
    UNKNOWN_ERROR = "unknown_error"


class RelationshipType(StrEnum):
    """Initial relationship vocabulary between intelligence objects."""

    RESOLVES_TO = "resolves-to"
    REDIRECTS_TO = "redirects-to"
    CONTACTS = "contacts"
    DOWNLOADS = "downloads"
    DROPS = "drops"
    HOSTS = "hosts"
    USES_CERTIFICATE = "uses-certificate"
    BELONGS_TO_ASN = "belongs-to-asn"
    ASSOCIATED_WITH_MALWARE = "associated-with-malware"
    SIMILAR_TO = "similar-to"
    DERIVED_FROM = "derived-from"
    DUPLICATE_OF = "duplicate-of"
    RELATED_TO = "related-to"


class ConflictType(StrEnum):
    """Why two pieces of evidence are in tension."""

    DIRECTIONAL = "directional"
    TEMPORAL = "temporal"
    VALUE_MISMATCH = "value_mismatch"
    SCOPE_MISMATCH = "scope_mismatch"
    ATTRIBUTION = "attribution"


class ConflictSeverity(StrEnum):
    """How much a conflict should matter to an assessment."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ConflictStatus(StrEnum):
    """Triage state of a conflict.

    ``UNRESOLVED`` is distinct from ``OPEN``: open means nobody has looked yet,
    unresolved means it was examined and could not be reconciled — which is
    itself a meaningful input to confidence.
    """

    OPEN = "open"
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"


class ContributionRole(StrEnum):
    """The role a piece of evidence played in an assessment."""

    SUPPORTING = "supporting"
    BENIGN = "benign"
    CONTEXT = "context"
