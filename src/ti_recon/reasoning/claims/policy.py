"""Versioned claim-semantics policy (Task 17A).

Two things live here: the version every claim records, and the explicit,
deliberately small table of which semantics may corroborate one another.

Compatibility is stated, never inferred
---------------------------------------

Two claims corroborate when they assert compatible propositions about the same
subject at the same scope. What counts as compatible is a judgement, so it is
written down rather than derived from enum names -- an ``in`` test over strings
would eventually decide that ``SCANNER_ACTIVITY`` and ``C2_ASSOCIATION`` are
related because both mention activity on an address.

Only two pairings are compatible today, and both are about the same object:

* a curated repository holding a sample, and a sandbox watching that same sample
  behave maliciously;
* a curated malicious reputation, and a sandbox verdict on the same file.

Everything else corroborates only itself. In particular
:attr:`ClaimSemantic.SCANNER_ACTIVITY` is compatible with nothing but scanner
activity, which is the whole point of naming it separately:
internet-wide scanning and command-and-control are different accusations, and a
layer that let one vouch for the other would resurrect exactly the confusion
Task 16 refused to guess at.

:attr:`ClaimSemantic.AGGREGATED_REPUTATION` is compatible with nothing, itself
included. It is one source reporting many opinions, so two aggregates are still
not two sources, and letting them corroborate would be vendor counting with
extra steps.
"""

from __future__ import annotations

from typing import Final

from ti_recon.reasoning.claims.models import ClaimSemantic

__all__ = [
    "CLAIM_SEMANTICS_POLICY_VERSION",
    "COMPATIBLE_SEMANTICS",
    "NON_CORROBORATING_SEMANTICS",
    "compatible",
]

#: Version of the translation tables and the compatibility policy.
#:
#: Recorded on every claim id, so a translation change produces different claims
#: rather than silently reinterpreting stored ones.
CLAIM_SEMANTICS_POLICY_VERSION: Final[str] = "1.2.0"

#: Semantics that may corroborate one another, stated symmetrically.
#:
#: A semantic is always compatible with itself unless it appears in
#: :data:`NON_CORROBORATING_SEMANTICS`.
COMPATIBLE_SEMANTICS: Final[frozenset[frozenset[ClaimSemantic]]] = frozenset(
    {
        # A repository holds this exact sample, and a sandbox watched this exact
        # sample misbehave. Two different kinds of knowledge about one file.
        frozenset({ClaimSemantic.MALWARE_SAMPLE_IDENTITY, ClaimSemantic.SANDBOX_CLASSIFICATION}),
        # A curated verdict about the object, and a sandbox verdict about the
        # same object. Both are judgements about what it is.
        frozenset({ClaimSemantic.MALICIOUS_REPUTATION, ClaimSemantic.SANDBOX_CLASSIFICATION}),
    }
)

#: Semantics that corroborate nothing, including another instance of themselves.
#:
#: An aggregate is one source reporting many opinions. Two aggregates are two
#: relayed roll-ups, not two independent observers, and treating them as
#: corroboration would be vendor counting wearing a different name.
#:
#: An unclassified claim corroborates nothing because nobody knows what it says.
NON_CORROBORATING_SEMANTICS: Final[frozenset[ClaimSemantic]] = frozenset(
    {ClaimSemantic.AGGREGATED_REPUTATION, ClaimSemantic.UNCLASSIFIED_DIRECTIONAL}
)


def compatible(first: ClaimSemantic, second: ClaimSemantic) -> bool:
    """Whether two semantics may corroborate one another.

    Exact set membership, in both directions. No name inspection, no prefix
    rule, no distance metric -- a compatibility that could be inferred is a
    compatibility nobody reviewed.
    """
    if first in NON_CORROBORATING_SEMANTICS or second in NON_CORROBORATING_SEMANTICS:
        return False
    if first is second:
        return True
    return frozenset({first, second}) in COMPATIBLE_SEMANTICS
