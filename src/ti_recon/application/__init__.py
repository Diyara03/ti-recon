"""The transport-neutral application boundary (Task 20).

What a CLI, an MCP server or a UI calls. One request model, one service, one
report — so every interface consumes the same contract instead of each
interpreting the investigation engine for itself.
"""

from ti_recon.application.models import (
    MAX_OBSERVABLE_INPUT,
    AnalystInvestigationRequest,
    ObservableInputType,
)
from ti_recon.application.service import (
    FILE_HASH_ALGORITHM,
    InvalidObservableError,
    InvestigationApplication,
    hash_local_file,
    resolve_observable,
)

__all__ = [
    "FILE_HASH_ALGORITHM",
    "MAX_OBSERVABLE_INPUT",
    "AnalystInvestigationRequest",
    "InvalidObservableError",
    "InvestigationApplication",
    "ObservableInputType",
    "hash_local_file",
    "resolve_observable",
]
