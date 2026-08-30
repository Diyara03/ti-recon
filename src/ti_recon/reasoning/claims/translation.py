"""The contract between a provider and the claim layer (Task 17A).

Knowing that ``threat_type == "botnet_cc"`` means command and control, and that
``greynoise_classification`` is a statement about scanning rather than about
hosting, is **provider knowledge**. It stays in the provider's package, exactly
as temporal field semantics did in Task 15.

The alternative fails in a specific way this repository has already met once.
Task 16 could not distinguish a scanner classification from a C2 indicator
because both arrive as ``CURATED_THREAT_ASSERTION`` + ``SUPPORTS_MALICIOUS``,
and the only discriminator was a provider-prefixed ``claim_type`` a generic layer
may not read. Putting the translation here rather than in fusion is what lets
that distinction exist without a vendor name reaching the reasoning core.

A translator is handed no clock, no graph and no other provider's output. It
reads one envelope and returns claims.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

from ti_recon.enums import EvidenceEffect
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.claims.models import NormalizedClaim

__all__ = [
    "UNRESOLVED_SUBJECT_PREFIX",
    "ClaimTranslationContext",
    "ClaimTranslator",
    "directional_evidence",
    "is_unresolved_subject",
]


#: Prefix marking a subject nothing in the run could resolve.
#:
#: Deliberately not a canonical key shape, so an unresolved claim can never
#: collide with a real object and can always be recognised again downstream.
UNRESOLVED_SUBJECT_PREFIX: Final[str] = "unresolved-subject:"


def is_unresolved_subject(subject_key: str) -> bool:
    """Whether a claim's subject is one this run could not place."""
    return subject_key.startswith(UNRESOLVED_SUBJECT_PREFIX)


@dataclass(frozen=True)
class ClaimTranslationContext:
    """Everything a translator may know, and nothing it may not.

    The one service offered is resolving a piece of evidence's
    ``subject_object_id`` -- a per-run UUID -- onto the canonical key correlation
    uses, so a claim attaches to the same identity every other layer sees.
    """

    #: Task 3 object id -> canonical node key.
    node_keys: Mapping[str, str] = field(default_factory=dict)
    #: The observable the run was about, when the caller supplied one.
    root_key: str | None = None
    #: ``True`` when the provider reported an incomplete answer.
    source_partial: bool = False
    #: The claim-semantics policy version, so a claim id records what produced it.
    policy_version: str = "0"

    def subject_key_for(self, object_id: str | None) -> str:
        """The canonical key a piece of evidence is about.

        Three outcomes, and the third is the point:

        * the id resolves — to the root object or to any other object this run
          knows — and the claim is about that object;
        * the id resolves to nothing, and the claim is **unresolved**. It keeps a
          key of its own, prefixed so it can never collide with a canonical one.

        Unresolved is deliberately not the root. An earlier version fell back to
        ``root_key``, on the reading that an adapter anchoring a claim to the
        requested observable would arrive that way. It does not: ``build``
        indexes the root object's own id, so a legitimate root claim resolves
        explicitly through :attr:`node_keys`. The fallback therefore only ever
        fired on an id nothing could account for — and handed that claim the
        root's identity, letting a malformed or misrouted record vote on the
        assessment of whatever the analyst had typed.

        **Unknown is not root.** A claim nobody can place is retained, reported
        as an issue, and excluded from the verdict rather than guessed at.
        """
        if object_id is None:
            return f"{UNRESOLVED_SUBJECT_PREFIX}missing"
        resolved = self.node_keys.get(object_id)
        if resolved is not None:
            return resolved
        return f"{UNRESOLVED_SUBJECT_PREFIX}{object_id}"

    @classmethod
    def build(
        cls,
        *,
        objects: tuple[IntelObject, ...] = (),
        root: IntelObject | None = None,
        source_partial: bool = False,
        policy_version: str = "0",
    ) -> ClaimTranslationContext:
        resolved = {item.id: item.canonical_key for item in objects}
        if root is not None:
            resolved.setdefault(root.id, root.canonical_key)
        return cls(
            node_keys=resolved,
            root_key=root.canonical_key if root is not None else None,
            source_partial=source_partial,
            policy_version=policy_version,
        )


class ClaimTranslator(Protocol):
    """One provider's pure translation of its own evidence into propositions."""

    def __call__(
        self,
        envelope: ProviderResultEnvelope,
        context: ClaimTranslationContext,
    ) -> tuple[NormalizedClaim, ...]: ...


def directional_evidence(envelope: ProviderResultEnvelope) -> tuple[Evidence, ...]:
    """Every piece of evidence in a result that makes a claim.

    Context-only evidence is not a claim and never becomes one. A warninglist
    hit, a coverage record and a "nothing found" note all say something worth
    keeping, and none of them asserts a proposition for fusion to weigh.
    """
    return tuple(
        item for item in envelope.evidence if item.effect is not EvidenceEffect.CONTEXT_ONLY
    )


def text_attribute(attributes: Mapping[str, Any], name: str) -> str | None:
    """One provider-supplied string, lowercased for exact comparison.

    Exact comparison only. Every translator that uses this matches against a
    closed set of values its own provider documents; nothing substring-matches,
    and nothing infers meaning from a value it does not recognise.
    """
    value = attributes.get(name)
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    return None
