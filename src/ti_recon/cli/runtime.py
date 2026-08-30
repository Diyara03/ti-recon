"""What a local invocation runs on (Task 20).

A thin adapter over :mod:`ti_recon.application.composition`. It exists to name
the identity a local run uses and nothing else — the provider catalogue, the
credential loading and the execution stores all live in the application layer,
so a future MCP server gets the same engine without going through here.
"""

from __future__ import annotations

from ti_recon.application.composition import (
    CredentialLoadReport,
    build_default_application,
)
from ti_recon.application.service import InvestigationApplication
from ti_recon.execution import ExecutionContext
from ti_recon.providers.adapter import ProviderAdapter
from ti_recon.providers.catalog import build_default_adapters

__all__ = [
    "LOCAL_CLI_USER",
    "build_local_adapters",
    "build_local_application",
    "build_local_context",
]

#: The identity a local invocation runs under.
#:
#: Every execution store is keyed by this, so it has to be *something*. A fixed
#: local name rather than the operating-system user: it partitions a cache and a
#: quota bucket, and it reaches metrics — putting a real account name there would
#: make a person identifiable in operational data for no analytical gain. A
#: deployment serving several analysts supplies its own.
LOCAL_CLI_USER: str = "local-cli"


def build_local_adapters() -> list[ProviderAdapter]:
    """Every provider the repository ships.

    The same catalogue the investigation runtime uses, which is the point: a
    diagnostic listing a different set from the one that actually runs would be
    worse than no diagnostic.
    """
    return build_default_adapters()


def build_local_context(*, user_id: str = LOCAL_CLI_USER) -> ExecutionContext:
    """The isolation boundary for one local run."""
    return ExecutionContext(authenticated_user_id=user_id)


async def build_local_application(
    *, user_id: str = LOCAL_CLI_USER
) -> tuple[InvestigationApplication, CredentialLoadReport]:
    """The default application for a local invocation.

    Credentials come from the environment variable names ``.env.example``
    documents, into the ordinary per-user credential store. Whatever is absent
    stays absent: the provider remains registered and reports ``NOT_CONFIGURED``
    if it is selected, rather than vanishing from the catalogue and looking like
    a capability nobody implements.
    """
    return await build_default_application(user_id=user_id)
