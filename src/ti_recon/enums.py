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
    "ProviderRunStatus",
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
