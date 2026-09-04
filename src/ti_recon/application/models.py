"""The public request an interface hands the engine (Task 20).

The smallest thing a CLI, an MCP server or a future UI needs to say. Everything
else about how an investigation runs — which providers answer, in what order,
for what budget, under which credential — is engine policy, and exposing any of
it here would let an interface make decisions Task 13 exists to make.

Notably absent, and deliberately:

* **provider selection.** No allowlist, no per-provider flag, no "skip this
  one". Ranking is Task 13's and stays reproducible only while it is.
* **credentials.** A secret never travels in a request object. Resolution is
  per user, in the credential layer, where it already is.
* **budgets and planner internals.** The depth already expresses how much work
  the caller is buying.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from ti_recon.correlation.policy import PivotMode
from ti_recon.enums import InvestigationDepth
from ti_recon.investigation.models import InvestigationObjective
from ti_recon.models.base import FrozenTiReconModel

__all__ = ["MAX_OBSERVABLE_INPUT", "AnalystInvestigationRequest", "ObservableInputType"]

#: An upper bound on raw input, applied before any parsing.
#:
#: The normalizer has its own limit; this one exists so an interface rejects an
#: absurd value at the boundary rather than passing it inwards.
MAX_OBSERVABLE_INPUT: int = 2048


class ObservableInputType(StrEnum):
    """How to read the caller's text.

    ``AUTO`` uses the engine's own detection, which is ordered and refuses what
    it cannot place rather than guessing. The explicit members exist for the
    cases where a caller knows better than a heuristic can — a bare host that
    must be read as a domain, a digest they want rejected unless it really is
    one — and each maps onto a normalizer the repository already has.
    """

    AUTO = "auto"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"


class AnalystInvestigationRequest(FrozenTiReconModel):
    """One investigation, as an application asks for it.

    ``depth`` and ``pivot_mode`` are the two ceilings a caller genuinely owns,
    and both default to what the engine already defaults to: STANDARD
    enrichment, and pivots that are recommended rather than followed. Neither
    default is chosen here — deepening an investigation or authorising a lookup
    about something the observable merely touched is the caller's decision, and
    silently making it on their behalf would spend somebody's quota and disclose
    somebody's infrastructure.
    """

    #: Raw analyst input. Canonicalised by the engine's own normalizer, never by
    #: a parser this layer invents.
    observable: str = Field(min_length=1, max_length=MAX_OBSERVABLE_INPUT)
    observable_type: ObservableInputType = ObservableInputType.AUTO

    depth: InvestigationDepth = InvestigationDepth.STANDARD
    pivot_mode: PivotMode = PivotMode.RECOMMEND

    #: Whether an *enriching* pivot may reach external providers.
    #:
    #: The public half of Task 14's deliberate double gate. ``ENRICH`` alone
    #: authorises following a lead the *engine* found; this authorises telling a
    #: third party about it. Those are different disclosures — looking up what
    #: the analyst typed is one thing, and looking up an address a provider
    #: mentioned is a wider one — so the second needs its own yes.
    #:
    #: Defaults to ``False``, which is what every existing caller gets: related
    #: observables are graphed and recommended, and nothing about them leaves
    #: the machine. Turning it on changes *who may be asked*, and nothing else:
    #: depth, budgets, the one-hop limit, the privacy rules that refuse private
    #: and credential-bearing targets, and Task 13's provider selection all
    #: apply exactly as before.
    allow_remote_pivot_lookup: bool = False

    #: What the collection stops on (Task 24 Phase 2).
    #:
    #: ``triage`` -- the default and every existing caller's behaviour -- stops
    #: when readiness says coverage is adequate for triage. ``corroborate``
    #: asks for at most one more round after that point: an adverse search
    #: from a source family independent of the ones the assessment rests on,
    #: if one is eligible and the budget permits. It adds no capability, raises
    #: no depth, names no provider and repeats no call. It is the structured
    #: form of an analyst saying "confirm this with another source"; the
    #: engine never infers it from a verdict.
    objective: InvestigationObjective = InvestigationObjective.TRIAGE

    @model_validator(mode="after")
    def _validate_request(self) -> AnalystInvestigationRequest:
        """Refuse input that cannot mean what it appears to say.

        The remote-pivot permission is meaningless without ``ENRICH`` — there
        would be no pivot enrichment for it to apply to. Accepting it silently
        would leave a caller believing they had authorised something that was
        never going to happen, which is the more dangerous of the two failures:
        the next reader assumes the setting works.
        """
        if not self.observable.strip():
            msg = "observable must not be blank"
            raise ValueError(msg)
        if self.allow_remote_pivot_lookup and self.pivot_mode is not PivotMode.ENRICH:
            msg = (
                "remote pivot lookup can only be enabled when pivot mode is "
                f"{PivotMode.ENRICH.value!r}"
            )
            raise ValueError(msg)
        return self
