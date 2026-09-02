"""The one contract this layer owns (Task 21).

Everything analytical an MCP client receives is Task 20's
:class:`~ti_recon.reporting.models.AnalystInvestigationReport`, unchanged. This
module defines only the configuration diagnostic, which has no Task 20
equivalent because it is not an assessment: it describes *this installation*,
not an observable.

Deliberately says less than it could
------------------------------------

``configured`` means one thing: *this caller* has the configuration a provider
needs stored. It does not mean the credential is valid, that authentication
would succeed, that quota remains, or that the provider is reachable — none of
which can be known without contacting somebody, which this diagnostic must never
do. The field is named for what it knows.

It is also not a statement about what was *asked*. This report describes the
installation; which sources an investigation actually consulted is
``source_checks`` in the analyst report, and the two are different questions with
different answers.

Never a place to collect a secret
---------------------------------

No tool here accepts a credential, and none ever will: a provider key passed as
a tool argument travels through a model prompt and into a conversation
transcript. A client must never ask anyone to paste a provider API key into a
conversation.
"""

from __future__ import annotations

from pydantic import Field

from ti_recon.models.base import FrozenTiReconModel

__all__ = ["ProviderStatusItem", "ProviderStatusReport"]


class ProviderStatusItem(FrozenTiReconModel):
    """One intelligence source, as this installation is set up to use it."""

    provider_id: str = Field(min_length=1, max_length=64)
    source_family: str = Field(min_length=1, max_length=64)
    #: ``local`` or ``remote``, taken from Task 13's planning profile.
    #:
    #: Read rather than restated: locality is a *disclosure* property, and a
    #: second opinion here could tell an analyst a source reveals nothing when
    #: the planner believes otherwise.
    locality: str = Field(min_length=1, max_length=16)
    capabilities: tuple[str, ...] = ()
    supported_object_types: tuple[str, ...] = ()
    requires_credentials: bool = Field(
        default=False,
        description=(
            "Whether this source needs a credential at all. A credential-free "
            "source is always configured, because there is nothing to "
            "configure -- it is not thereby local or private."
        ),
    )
    #: Providers sharing a group share one stored secret — three abuse.ch
    #: datasets and one key, so an analyst configures it once.
    credential_group: str = Field(default="", max_length=64)
    #: Whether *this caller* has the configuration this provider needs.
    #: Never whether it works: see the module docstring.
    configured: bool = Field(
        default=False,
        description=(
            "Whether this caller has the configuration this source needs. It "
            "does NOT mean the credential has been validated, that "
            "authentication would succeed, that an entitlement covers the "
            "operation, that quota remains, or that the source is healthy -- "
            "none of which is knowable without contacting somebody, which this "
            "diagnostic never does. It also does not mean the source was asked "
            "about anything: what an investigation actually consulted is its "
            "own 'source_checks'."
        ),
    )
    #: The pinned local dataset a provider answers from, where it has one.
    dataset_version: str | None = Field(default=None, max_length=200)


class ProviderStatusReport(FrozenTiReconModel):
    """What this installation can consult, and what this caller has set up.

    The counts are configuration facts — how many sources exist, how many are
    set up, how many disclose nothing. They are not a quality measure and
    nothing downstream may read them as one: this engine never counts providers
    to decide anything, and a "7 of 9 configured" is a setup checklist rather
    than a statement about coverage. Task 18 answers coverage, per capability.
    """

    providers: tuple[ProviderStatusItem, ...] = ()
    total: int = Field(default=0, ge=0)
    configured_count: int = Field(default=0, ge=0)
    local_count: int = Field(default=0, ge=0)
    remote_count: int = Field(default=0, ge=0)
