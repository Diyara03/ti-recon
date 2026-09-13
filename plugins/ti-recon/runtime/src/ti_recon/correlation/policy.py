"""Pivot modes, budgets and safety policy (Task 14).

Discovering that a sample contacted a domain is knowledge. Asking six third-party
providers about that domain is a *disclosure*, and the gap between the two is what
this module governs.

Why pivoting is explicit
------------------------

A provider's related objects are not a curated list of leads. They routinely
include an internal address a sandbox saw, a customer hostname, a URL carrying a
session token, shared hosting that answers for thousands of unrelated sites, and
hundreds of passive-DNS names. Automatically forwarding all of that to other
companies is not a cost problem, it is a disclosure problem: it tells them what an
organisation's malware talked to, and some of those values are the organisation's
own. So the default is to build the graph and, at most, *recommend*.

Budgets are global, not per target
----------------------------------

Task 13 spends a budget per observable. Five pivots at STANDARD would therefore be
five fresh budgets — twenty remote calls from one submitted hash. The pivot budget
here is shared across the whole session and handed down to each Task 13 run as a
reduction, so the total is bounded no matter how many candidates the graph found.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from pydantic import Field, model_validator

from ti_recon.enums import InvestigationDepth
from ti_recon.models.base import FrozenTiReconModel

__all__ = [
    "DEFAULT_PIVOT_BUDGETS",
    "MAX_AUTOMATIC_PIVOT_HOP",
    "PIVOT_DEPTH_DOWNSHIFT",
    "PivotBudget",
    "PivotMode",
    "PivotPolicy",
    "PivotSelectionReason",
    "PivotSkipReason",
]

#: Automatic enrichment reaches one hop from the root and stops.
#:
#: Not a performance guess. A file contacts forty domains; each resolves to ten
#: addresses; each address serves a hundred URLs. Two hops is already tens of
#: thousands of third-party queries about objects nobody chose to investigate.
#: Objects found at hop 2 still enter the graph — discovery is cheap and useful —
#: they are simply never queried about.
MAX_AUTOMATIC_PIVOT_HOP: Final[int] = 1

#: A pivot is investigated less deeply than the thing that was submitted.
#:
#: The root is what the analyst asked about; a contacted domain is a lead. Running
#: the lead at the root's depth spends as much on a guess as on the question.
PIVOT_DEPTH_DOWNSHIFT: Final[dict[InvestigationDepth, InvestigationDepth]] = {
    InvestigationDepth.QUICK: InvestigationDepth.QUICK,
    InvestigationDepth.STANDARD: InvestigationDepth.QUICK,
    InvestigationDepth.DEEP: InvestigationDepth.STANDARD,
}


class PivotMode(StrEnum):
    """How far correlation may go beyond building the graph."""

    #: Correlate only. No candidate ranking, no queries.
    NONE = "none"
    #: Rank candidates and explain them. Still zero additional provider calls.
    RECOMMEND = "recommend"
    #: Permit bounded enrichment of selected pivots through Task 13.
    ENRICH = "enrich"


class PivotSelectionReason(StrEnum):
    """Why a candidate was chosen. Operational, never a judgement about threat."""

    EXPLICIT_SELECTION = "explicit_selection"
    DIRECT_ARTIFACT_RELATION = "direct_artifact_relation"
    DIRECT_BEHAVIOR_RELATION = "direct_behavior_relation"
    ENRICHABLE_TARGET = "enrichable_target"


class PivotSkipReason(StrEnum):
    """Why a candidate was not enriched.

    Every one is operational. None of them says anything about whether the target
    matters — "we did not ask" is not "there was nothing to find".
    """

    MODE_DISABLED = "mode_disabled"
    RECOMMEND_ONLY = "recommend_only"
    RELATION_NOT_ELIGIBLE = "relation_not_eligible"
    ALREADY_ENRICHED = "already_enriched"
    NON_GLOBAL_IP = "non_global_ip"
    SENSITIVE_URL = "sensitive_url"
    #: The provider-returned value does not survive TI Recon's own normalizer
    #: unchanged, so it is not an observable this engine would accept from an
    #: analyst and is never sent to a third party (Task 24 Phase 3).
    UNNORMALIZABLE_TARGET = "unnormalizable_target"
    UNLINKED_OBJECT = "unlinked_object"
    UNSUPPORTED_TARGET = "unsupported_target"
    HOP_LIMIT = "hop_limit"
    TARGET_BUDGET = "target_budget"
    REMOTE_BUDGET = "remote_budget"
    REMOTE_PIVOTS_DISABLED = "remote_pivots_disabled"
    GRAPH_LIMIT = "graph_limit"


class PivotBudget(FrozenTiReconModel):
    """What a whole pivot session may spend, across every target.

    ``remote_runs_used`` follows Task 13's rule exactly: only a run that actually
    contacted a provider counts. A cache hit, an unconfigured credential, a
    cooldown, a quota pre-check and every local provider are free, because none of
    them disclosed anything to anyone.
    """

    max_targets: int = Field(ge=0)
    max_remote_provider_runs: int = Field(ge=0)
    targets_used: int = Field(default=0, ge=0)
    remote_runs_used: int = Field(default=0, ge=0)

    @property
    def targets_remaining(self) -> int:
        return max(0, self.max_targets - self.targets_used)

    @property
    def remote_remaining(self) -> int:
        return max(0, self.max_remote_provider_runs - self.remote_runs_used)

    @property
    def exhausted(self) -> bool:
        return self.targets_remaining <= 0 or self.remote_remaining <= 0

    def charge(self, *, remote_runs: int) -> PivotBudget:
        """Account for one completed pivot."""
        return self.model_copy(
            update={
                "targets_used": self.targets_used + 1,
                "remote_runs_used": self.remote_runs_used + max(0, remote_runs),
            }
        )


#: Targets and total remote runs per root depth, when pivoting is explicitly on.
#:
#: TI Recon safety defaults, not provider quotas. QUICK is zero on purpose: it is
#: the triage depth, and triage that quietly fans out to third parties is not
#: triage.
DEFAULT_PIVOT_BUDGETS: Final[dict[InvestigationDepth, tuple[int, int]]] = {
    InvestigationDepth.QUICK: (0, 0),
    InvestigationDepth.STANDARD: (2, 3),
    InvestigationDepth.DEEP: (5, 8),
}


class PivotPolicy(FrozenTiReconModel):
    """The caller's pivot settings for one investigation.

    Two switches must both be on before anything leaves the machine.
    ``allow_remote_lookup`` is Task 13's existing control over the root
    investigation; ``allow_remote_pivot_lookup`` is this task's, and it defaults to
    off. Following a lead the *provider* chose is a wider disclosure than looking
    up the observable an analyst typed, so consenting to the second does not
    consent to the first — and a single flag would make that escalation invisible.
    """

    mode: PivotMode = PivotMode.RECOMMEND
    #: Remote pivot enrichment requires this *and* the root's allow_remote_lookup.
    allow_remote_pivot_lookup: bool = False
    #: Node keys the caller asked for by name. An explicit selection outranks the
    #: automatic rules but never bypasses the privacy or budget ones.
    explicit_targets: frozenset[str] = frozenset()
    #: Reduce the target ceiling below the depth default. Reduction only.
    max_targets: int | None = Field(default=None, ge=0)
    #: Reduce the shared remote-run ceiling. Reduction only.
    max_remote_provider_runs: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _validate_policy(self) -> PivotPolicy:
        if self.allow_remote_pivot_lookup and self.mode is not PivotMode.ENRICH:
            # Not an error worth raising — the flag is simply inert without the
            # mode — but silently accepting it would let a caller believe pivots
            # were running. Say so at construction instead.
            msg = "allow_remote_pivot_lookup has no meaning unless mode is ENRICH"
            raise ValueError(msg)
        return self

    def budget_for(self, depth: InvestigationDepth) -> PivotBudget:
        """The session budget at this root depth, after caller reductions."""
        targets, remote = DEFAULT_PIVOT_BUDGETS[depth]
        if self.max_targets is not None:
            targets = min(targets, self.max_targets)
        if self.max_remote_provider_runs is not None:
            remote = min(remote, self.max_remote_provider_runs)
        return PivotBudget(max_targets=targets, max_remote_provider_runs=remote)

    def pivot_depth_for(self, depth: InvestigationDepth) -> InvestigationDepth:
        return PIVOT_DEPTH_DOWNSHIFT[depth]
