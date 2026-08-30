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

    @model_validator(mode="after")
    def _reject_blank(self) -> AnalystInvestigationRequest:
        """A value of only whitespace is a mistake, not an observable."""
        if not self.observable.strip():
            msg = "observable must not be blank"
            raise ValueError(msg)
        return self
