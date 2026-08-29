"""The contract between a provider and the qualification engine (Task 15).

Task 15 has to know that ``last_analysis_date`` is a scan time and
``last_online`` is a serving time. That knowledge is **provider knowledge**, and
it stays in the provider's own package: each integration exposes one pure
function that turns its already-normalized result into the generic vocabulary in
:mod:`ti_recon.reasoning.models`, and the engine never learns a field name.

The alternative — a generic evaluator with ``if provider == "urlhaus"`` in it —
fails in a specific and expensive way. Every new provider would edit the
reasoning core, provider semantics would drift from the code that produced them,
and the one module allowed to know about vendors would be the one module that
must not.

An extractor is deliberately given no clock. It reports what a source said; the
engine alone knows ``as_of``, so a rule can never quietly become time-dependent
in a place that is never handed a time.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol

from ti_recon.enums import ProviderRunStatus
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.models import (
    ContextSignal,
    SubjectRef,
    TemporalFact,
    observable_subject,
)

__all__ = [
    "PARTIAL_STATUSES",
    "ProviderQualification",
    "ProviderQualifier",
    "QualificationContext",
]


@dataclass(frozen=True, slots=True)
class ProviderQualification:
    """What one provider's result said about time and context.

    A plain frozen dataclass rather than a model: it is an intermediate the
    engine consumes immediately, and its two members are already validated
    models.
    """

    temporal_facts: tuple[TemporalFact, ...] = ()
    context_signals: tuple[ContextSignal, ...] = ()

    def merge(self, other: ProviderQualification) -> ProviderQualification:
        return ProviderQualification(
            temporal_facts=(*self.temporal_facts, *other.temporal_facts),
            context_signals=(*self.context_signals, *other.context_signals),
        )


@dataclass(frozen=True)
class QualificationContext:
    """Everything an extractor may know, and nothing it may not.

    No clock, no credential, no HTTP client, no graph mutation. The one service
    offered is resolving a piece of evidence's ``subject_object_id`` — a per-run
    UUID — onto the canonical node key a Task 14 graph uses, so a fact attaches to
    the same identity correlation gave the object.
    """

    #: Task 3 object id -> canonical node key.
    node_keys: Mapping[str, str] = field(default_factory=dict)
    #: The observable the run was about, when the caller supplied it.
    root_key: str | None = None
    #: ``True`` when the provider itself reported an incomplete answer, so a
    #: qualification says "from what was returned" rather than "from the record".
    source_partial: bool = False

    def subject_for(self, object_id: str | None) -> SubjectRef:
        """The subject a piece of evidence is about.

        Falls back to the run's root observable, which is what an adapter anchors
        to when a claim has no object of its own. If even that is unknown the
        subject is the object id: honest, and never a fabricated key.
        """
        if object_id is not None:
            resolved = self.node_keys.get(object_id)
            if resolved is not None:
                return observable_subject(resolved)
        if self.root_key is not None:
            return observable_subject(self.root_key)
        return observable_subject(object_id or "unknown")

    @classmethod
    def build(
        cls,
        *,
        objects: tuple[IntelObject, ...] = (),
        node_keys: Mapping[str, str] | None = None,
        root: IntelObject | None = None,
        source_partial: bool = False,
    ) -> QualificationContext:
        """Index the objects in play by their per-run id."""
        resolved: dict[str, str] = dict(node_keys) if node_keys is not None else {}
        for item in objects:
            resolved.setdefault(item.id, item.canonical_key)
        if root is not None:
            resolved.setdefault(root.id, root.canonical_key)
        return cls(
            node_keys=resolved,
            root_key=root.canonical_key if root is not None else None,
            source_partial=source_partial,
        )


class ProviderQualifier(Protocol):
    """One provider's pure translation into the Task 15 vocabulary."""

    def __call__(
        self,
        envelope: ProviderResultEnvelope,
        context: QualificationContext,
    ) -> ProviderQualification: ...


#: Statuses whose results carry a partial view of the source's own record.
PARTIAL_STATUSES: frozenset[ProviderRunStatus] = frozenset(
    {ProviderRunStatus.PARTIAL, ProviderRunStatus.PLAN_LIMITED}
)
